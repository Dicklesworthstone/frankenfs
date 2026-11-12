#![forbid(unsafe_code)]
//! Shared bounded read-only fuzzing infrastructure, independent resource-budget
//! trackers, strict zero-write-authority `ByteDevice` wrappers, and cached
//! deterministic multi-format baseline images (`bd-2tzok`).

use std::collections::BTreeMap;
use std::io::Error;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use asupersync::types::CancelKind;
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::fat::short_name_checksum;
use ffs_ondisk::ntfs::DATA;
use ffs_ondisk::partition::{write_gpt_partition_table, PartUuid, SyntheticGptPartitionSpec};
use ffs_ondisk::zfs::{
    checksum as zfs_checksum, label_offsets, Endian, DATA_OFFSET, LABEL_BYTES, LABEL_CONFIG_BYTES,
    LABEL_CONFIG_OFFSET, UBERBLOCK_RING_OFFSET,
};
use ffs_types::ByteOffset;
use sha2::{Digest, Sha256};

/// Deterministic cursor over fuzzer-supplied control and payload bytes.
pub struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn next_u8(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
    }

    pub fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    pub fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
    }

    pub fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    pub fn next_u64(&mut self) -> u64 {
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

    pub fn next_index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            (self.next_u32() as usize) % len
        }
    }

    pub fn next_vec(&mut self, max_len: usize) -> Vec<u8> {
        if max_len == 0 {
            return Vec::new();
        }
        let available = self.remainder().len();
        if available == 0 {
            return Vec::new();
        }
        let wanted = (usize::from(self.next_u16()) % (max_len + 1)).min(available);
        let out = self.data[self.pos..self.pos + wanted].to_vec();
        self.pos += wanted;
        out
    }

    #[must_use]
    pub fn remainder(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }
}

/// Six independent per-iteration resource bounds (`bd-2tzok` Refinement 4).
#[derive(Debug, Clone, Copy)]
pub struct FuzzBudgets {
    pub max_physical_read_bytes: u64,
    pub max_decoded_bytes: u64,
    pub max_retained_bytes: u64,
    pub max_depth: usize,
    pub max_ops: usize,
    pub max_replica_attempts: usize,
}

impl Default for FuzzBudgets {
    fn default() -> Self {
        Self {
            max_physical_read_bytes: 8 * 1024 * 1024,
            max_decoded_bytes: 4 * 1024 * 1024,
            max_retained_bytes: 4 * 1024 * 1024,
            max_depth: 16,
            max_ops: 768,
            max_replica_attempts: 48,
        }
    }
}

/// Thread-safe tracker enforcing [`FuzzBudgets`] across device I/O and engine walks.
#[derive(Debug)]
pub struct FuzzBudgetTracker {
    budgets: FuzzBudgets,
    physical_read_bytes: AtomicU64,
    decoded_bytes: AtomicU64,
    retained_bytes: AtomicU64,
    ops: AtomicUsize,
    window_hits: Mutex<BTreeMap<(u64, usize), usize>>,
}

impl FuzzBudgetTracker {
    #[must_use]
    pub fn new(budgets: FuzzBudgets) -> Arc<Self> {
        Arc::new(Self {
            budgets,
            physical_read_bytes: AtomicU64::new(0),
            decoded_bytes: AtomicU64::new(0),
            retained_bytes: AtomicU64::new(0),
            ops: AtomicUsize::new(0),
            window_hits: Mutex::new(BTreeMap::new()),
        })
    }

    #[must_use]
    pub const fn budgets(&self) -> FuzzBudgets {
        self.budgets
    }

    pub fn charge_op(&self) -> Result<usize> {
        let prev = self.ops.fetch_add(1, Ordering::SeqCst);
        let current = prev.saturating_add(1);
        if current > self.budgets.max_ops {
            return Err(FfsError::Io(Error::other("fuzz max_ops budget exceeded")));
        }
        Ok(current)
    }

    pub fn charge_physical_read(&self, offset: u64, len: usize) -> Result<()> {
        let add = u64::try_from(len)
            .map_err(|_| FfsError::InvalidGeometry("fuzz read length overflow".to_owned()))?;
        let prev = self.physical_read_bytes.fetch_add(add, Ordering::SeqCst);
        if prev.saturating_add(add) > self.budgets.max_physical_read_bytes {
            return Err(FfsError::Io(Error::other(
                "fuzz max_physical_read_bytes budget exceeded",
            )));
        }
        let mut map = self
            .window_hits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = map.entry((offset, len)).or_insert(0);
        *entry = entry.saturating_add(1);
        if *entry > self.budgets.max_replica_attempts {
            return Err(FfsError::Io(Error::other(
                "fuzz max_replica_attempts budget exceeded",
            )));
        }
        Ok(())
    }

    pub fn charge_decoded(&self, len: usize) -> Result<()> {
        let add = u64::try_from(len)
            .map_err(|_| FfsError::InvalidGeometry("fuzz decoded length overflow".to_owned()))?;
        let prev = self.decoded_bytes.fetch_add(add, Ordering::SeqCst);
        if prev.saturating_add(add) > self.budgets.max_decoded_bytes {
            return Err(FfsError::Io(Error::other(
                "fuzz max_decoded_bytes budget exceeded",
            )));
        }
        Ok(())
    }

    pub fn charge_retained(&self, len: usize) -> Result<()> {
        let add = u64::try_from(len)
            .map_err(|_| FfsError::InvalidGeometry("fuzz retained length overflow".to_owned()))?;
        let prev = self.retained_bytes.fetch_add(add, Ordering::SeqCst);
        if prev.saturating_add(add) > self.budgets.max_retained_bytes {
            return Err(FfsError::Io(Error::other(
                "fuzz max_retained_bytes budget exceeded",
            )));
        }
        Ok(())
    }

    pub fn check_depth(&self, depth: usize) -> Result<()> {
        if depth > self.budgets.max_depth {
            return Err(FfsError::Io(Error::other("fuzz max_depth budget exceeded")));
        }
        Ok(())
    }

    #[must_use]
    pub fn ops(&self) -> usize {
        self.ops.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn physical_read_bytes(&self) -> u64 {
        self.physical_read_bytes.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        self.retained_bytes.load(Ordering::SeqCst)
    }
}

/// Immutable virtual image backing (owned bytes or zero-copy static base + sparse patches).
#[derive(Clone, Debug)]
pub enum FuzzBacking {
    Owned(Vec<u8>),
    PatchedStatic {
        base: &'static [u8],
        base_digest: blake3::Hash,
        effective_len: u64,
        patches: Vec<(u64, Vec<u8>)>,
    },
}

impl FuzzBacking {
    #[must_use]
    pub fn from_owned(bytes: Vec<u8>) -> Self {
        Self::Owned(bytes)
    }

    #[must_use]
    pub fn len_bytes(&self) -> u64 {
        match self {
            Self::Owned(bytes) => bytes.len() as u64,
            Self::PatchedStatic { effective_len, .. } => *effective_len,
        }
    }

    #[must_use]
    pub fn digest(&self) -> blake3::Hash {
        match self {
            Self::Owned(bytes) => blake3::hash(bytes),
            Self::PatchedStatic {
                base_digest,
                effective_len,
                patches,
                ..
            } => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"ffs-fuzz-patched-static-v1");
                hasher.update(base_digest.as_bytes());
                hasher.update(&effective_len.to_le_bytes());
                hasher.update(&(patches.len() as u64).to_le_bytes());
                for (offset, data) in patches {
                    hasher.update(&offset.to_le_bytes());
                    hasher.update(&(data.len() as u64).to_le_bytes());
                    hasher.update(data);
                }
                hasher.finalize()
            }
        }
    }

    pub fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let len_u64 = u64::try_from(buf.len())
            .map_err(|_| FfsError::InvalidGeometry("fuzz read buffer overflow".to_owned()))?;
        let end = offset
            .checked_add(len_u64)
            .ok_or_else(|| FfsError::InvalidGeometry("fuzz read offset overflow".to_owned()))?;
        if end > self.len_bytes() {
            return Err(FfsError::Io(Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "fuzz read past backing end",
            )));
        }
        match self {
            Self::Owned(bytes) => {
                let start = usize::try_from(offset)
                    .map_err(|_| FfsError::InvalidGeometry("offset overflow".to_owned()))?;
                buf.copy_from_slice(&bytes[start..start + buf.len()]);
            }
            Self::PatchedStatic { base, patches, .. } => {
                let start = usize::try_from(offset)
                    .map_err(|_| FfsError::InvalidGeometry("offset overflow".to_owned()))?;
                buf.copy_from_slice(&base[start..start + buf.len()]);
                for (patch_off, patch_bytes) in patches {
                    let patch_end = patch_off.saturating_add(patch_bytes.len() as u64);
                    let overlap_start = offset.max(*patch_off);
                    let overlap_end = end.min(patch_end);
                    if overlap_start < overlap_end {
                        let dst_start = (overlap_start - offset) as usize;
                        let src_start = (overlap_start - *patch_off) as usize;
                        let count = (overlap_end - overlap_start) as usize;
                        buf[dst_start..dst_start + count]
                            .copy_from_slice(&patch_bytes[src_start..src_start + count]);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Zero-copy sparse patch builder over a cached static baseline image.
#[derive(Clone, Debug)]
pub struct PatchBuilder {
    base: &'static [u8],
    base_digest: blake3::Hash,
    effective_len: u64,
    patches: Vec<(u64, Vec<u8>)>,
}

impl PatchBuilder {
    #[must_use]
    pub fn from_static(base: &'static [u8], base_digest: blake3::Hash) -> Self {
        Self {
            base,
            base_digest,
            effective_len: base.len() as u64,
            patches: Vec::new(),
        }
    }

    #[must_use]
    pub const fn len_bytes(&self) -> u64 {
        self.effective_len
    }

    pub fn truncate(&mut self, new_len: u64) {
        self.effective_len = new_len.min(self.base.len() as u64);
    }

    pub fn write(&mut self, offset: u64, bytes: &[u8]) {
        if offset >= self.effective_len || bytes.is_empty() {
            return;
        }
        let max_len = (self.effective_len - offset).min(bytes.len() as u64) as usize;
        self.patches.push((offset, bytes[..max_len].to_vec()));
    }

    pub fn xor_byte(&mut self, offset: u64, mask: u8) {
        if offset >= self.effective_len || mask == 0 {
            return;
        }
        let mut cur = [0_u8; 1];
        self.read_slice(offset, &mut cur);
        cur[0] ^= mask;
        self.write(offset, &cur);
    }

    pub fn read_slice(&self, offset: u64, out: &mut [u8]) {
        if out.is_empty() || offset >= self.effective_len {
            return;
        }
        let avail = (self.effective_len - offset).min(out.len() as u64) as usize;
        let start = offset as usize;
        out[..avail].copy_from_slice(&self.base[start..start + avail]);
        let end = offset + avail as u64;
        for (patch_off, patch_bytes) in &self.patches {
            let patch_end = patch_off.saturating_add(patch_bytes.len() as u64);
            let overlap_start = offset.max(*patch_off);
            let overlap_end = end.min(patch_end);
            if overlap_start < overlap_end {
                let dst_start = (overlap_start - offset) as usize;
                let src_start = (overlap_start - *patch_off) as usize;
                let count = (overlap_end - overlap_start) as usize;
                out[dst_start..dst_start + count]
                    .copy_from_slice(&patch_bytes[src_start..src_start + count]);
            }
        }
    }

    pub fn apply_interesting_mutations(
        &mut self,
        cursor: &mut ByteCursor<'_>,
        interesting_offsets: &[u64],
        max_mutations: usize,
    ) {
        if self.effective_len == 0 {
            return;
        }
        let mutations = usize::from(cursor.next_u8()) % (max_mutations + 1);
        for _ in 0..mutations {
            let use_interesting =
                !interesting_offsets.is_empty() && !cursor.next_u8().is_multiple_of(4);
            let offset = if use_interesting {
                let base_off = interesting_offsets[cursor.next_index(interesting_offsets.len())];
                let jitter = u64::from(cursor.next_u8() % 32);
                base_off.saturating_add(jitter) % self.effective_len
            } else {
                cursor.next_u64() % self.effective_len
            };
            match cursor.next_u8() % 4 {
                0 => self.xor_byte(offset, cursor.next_u8() | 1),
                1 => {
                    let word = cursor.next_u32().to_le_bytes();
                    self.write(offset, &word);
                }
                2 => {
                    let zeroes = [0_u8; 16];
                    let count = 1 + usize::from(cursor.next_u8() % 16);
                    self.write(offset, &zeroes[..count]);
                }
                _ => {
                    let ff = [0xFF_u8; 8];
                    let count = 1 + usize::from(cursor.next_u8() % 8);
                    self.write(offset, &ff[..count]);
                }
            }
        }
    }

    #[must_use]
    pub fn finish(self) -> FuzzBacking {
        FuzzBacking::PatchedStatic {
            base: self.base,
            base_digest: self.base_digest,
            effective_len: self.effective_len,
            patches: self.patches,
        }
    }
}

/// Strict read-only `ByteDevice` enforcing [`FuzzBudgetTracker`] and zero write/sync/discard authority.
#[derive(Debug)]
pub struct BoundedRoFuzzDevice {
    backing: FuzzBacking,
    initial_digest: blake3::Hash,
    tracker: Arc<FuzzBudgetTracker>,
    cancel_after_ops: Option<usize>,
    mutation_calls: AtomicUsize,
}

impl BoundedRoFuzzDevice {
    #[must_use]
    pub fn new(
        backing: FuzzBacking,
        tracker: Arc<FuzzBudgetTracker>,
        cancel_after_ops: Option<usize>,
    ) -> Arc<Self> {
        let initial_digest = backing.digest();
        Arc::new(Self {
            backing,
            initial_digest,
            tracker,
            cancel_after_ops,
            mutation_calls: AtomicUsize::new(0),
        })
    }

    #[must_use]
    pub fn tracker(&self) -> &Arc<FuzzBudgetTracker> {
        &self.tracker
    }

    #[must_use]
    pub fn mutation_calls(&self) -> usize {
        self.mutation_calls.load(Ordering::SeqCst)
    }

    /// Verify zero mutating calls occurred and virtual image digest is unchanged.
    pub fn assert_invariants(&self) {
        assert_eq!(
            self.mutation_calls(),
            0,
            "strict RO fuzz device observed forbidden write/sync/discard call"
        );
        assert_eq!(
            self.backing.digest(),
            self.initial_digest,
            "strict RO fuzz device backing digest mutated during read-only execution"
        );
    }
}

impl ByteDevice for BoundedRoFuzzDevice {
    fn len_bytes(&self) -> u64 {
        self.backing.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let op_index = self.tracker.charge_op()?;
        if self.cancel_after_ops.is_some_and(|limit| op_index >= limit) {
            cx.cancel_with(CancelKind::User, Some("fuzz deterministic cancellation"));
            return Err(FfsError::Cancelled);
        }
        self.tracker.charge_physical_read(offset.0, buf.len())?;
        self.backing.read_exact_at(offset.0, buf)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _buf: &[u8]) -> Result<()> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        panic!("BoundedRoFuzzDevice: forbidden write_all_at on read-only fuzz target");
    }

    fn write_vectored_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bufs: &[&[u8]]) -> Result<()> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        panic!("BoundedRoFuzzDevice: forbidden write_vectored_all_at on read-only fuzz target");
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        panic!("BoundedRoFuzzDevice: forbidden sync on read-only fuzz target");
    }

    fn discard(&self, _cx: &Cx, _offset: ByteOffset, _length: u64) -> Result<()> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        panic!("BoundedRoFuzzDevice: forbidden discard on read-only fuzz target");
    }
}

// ── Cached Deterministic Six-Format + MBR/GPT Baseline Images ────────────────

fn encode_lfn_slot(ordinal: u8, chars: &[u16], checksum: u8) -> [u8; 32] {
    let mut slot = [0xFF_u8; 32];
    slot[0] = ordinal;
    slot[11] = 0x0F;
    slot[12] = 0;
    slot[13] = checksum;
    slot[26] = 0;
    slot[27] = 0;
    let offsets = [1_usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    for (idx, &at) in offsets.iter().enumerate() {
        let unit = if idx < chars.len() {
            chars[idx]
        } else if idx == chars.len() {
            0x0000
        } else {
            0xFFFF
        };
        slot[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }
    slot
}

fn encode_short_entry(short_name: &[u8; 11], attr: u8, first_cluster: u32, size: u32) -> [u8; 32] {
    let mut slot = [0_u8; 32];
    slot[..11].copy_from_slice(short_name);
    slot[11] = attr;
    let date: u16 = ((2026 - 1980) << 9) | (11 << 5) | 11;
    let time: u16 = (12 << 11) | (30 << 5) | 10;
    slot[14..16].copy_from_slice(&time.to_le_bytes());
    slot[16..18].copy_from_slice(&date.to_le_bytes());
    slot[18..20].copy_from_slice(&date.to_le_bytes());
    slot[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
    slot[22..24].copy_from_slice(&time.to_le_bytes());
    slot[24..26].copy_from_slice(&date.to_le_bytes());
    slot[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
    slot[28..32].copy_from_slice(&size.to_le_bytes());
    slot
}

fn write_lfn_and_short(
    dir_buf: &mut [u8],
    slot_cursor: &mut usize,
    long_name: &str,
    short_name: &[u8; 11],
    attr: u8,
    first_cluster: u32,
    size: u32,
) {
    let checksum = short_name_checksum(short_name);
    let units: Vec<u16> = long_name.encode_utf16().collect();
    let chunks: Vec<&[u16]> = units.chunks(13).collect();
    for (rev_idx, chunk) in chunks.iter().enumerate().rev() {
        let mut ordinal = u8::try_from(rev_idx + 1).unwrap();
        if rev_idx + 1 == chunks.len() {
            ordinal |= 0x40;
        }
        let slot = encode_lfn_slot(ordinal, chunk, checksum);
        let at = *slot_cursor * 32;
        dir_buf[at..at + 32].copy_from_slice(&slot);
        *slot_cursor += 1;
    }
    let short_slot = encode_short_entry(short_name, attr, first_cluster, size);
    let at = *slot_cursor * 32;
    dir_buf[at..at + 32].copy_from_slice(&short_slot);
    *slot_cursor += 1;
}

fn build_fat16_image() -> Vec<u8> {
    const SECTOR: usize = 512;
    const RESERVED: usize = 1;
    const FAT_COUNT: usize = 2;
    const FAT_SECTORS: usize = 17;
    const ROOT_ENTRIES: usize = 64;
    const ROOT_SECTORS: usize = (ROOT_ENTRIES * 32) / SECTOR;
    const DATA_CLUSTERS: usize = 4_100;
    const FIRST_DATA_SECTOR: usize = RESERVED + FAT_COUNT * FAT_SECTORS + ROOT_SECTORS;
    const TOTAL_SECTORS: usize = FIRST_DATA_SECTOR + DATA_CLUSTERS;

    let mut img = vec![0_u8; TOTAL_SECTORS * SECTOR];
    let boot = &mut img[..SECTOR];
    boot[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    boot[3..11].copy_from_slice(b"FRANKEN ");
    boot[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    boot[13] = 1;
    boot[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    boot[16] = FAT_COUNT as u8;
    boot[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    boot[19..21].copy_from_slice(&(TOTAL_SECTORS as u16).to_le_bytes());
    boot[21] = 0xF8;
    boot[22..24].copy_from_slice(&(FAT_SECTORS as u16).to_le_bytes());
    boot[24..26].copy_from_slice(&32_u16.to_le_bytes());
    boot[26..28].copy_from_slice(&64_u16.to_le_bytes());
    boot[36] = 0x80;
    boot[38] = 0x29;
    boot[39..43].copy_from_slice(&0x1122_3344_u32.to_le_bytes());
    boot[43..54].copy_from_slice(b"FFS_FAT16  ");
    boot[54..62].copy_from_slice(b"FAT16   ");
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);

    let set_fat16 = |buf: &mut [u8], cluster: usize, val: u16| {
        for copy in 0..FAT_COUNT {
            let at = (RESERVED + copy * FAT_SECTORS) * SECTOR + cluster * 2;
            buf[at..at + 2].copy_from_slice(&val.to_le_bytes());
        }
    };
    set_fat16(&mut img, 0, 0xFFF8);
    set_fat16(&mut img, 1, 0xFFFF);
    // Cluster 3 -> 4 -> EOC: `/Native payload.bin` (700 bytes across 2 clusters)
    set_fat16(&mut img, 3, 4);
    set_fat16(&mut img, 4, 0xFFFF);
    // Cluster 5 -> EOC: `/SUBDIR`
    set_fat16(&mut img, 5, 0xFFFF);
    // Cluster 6 -> EOC: `/SUBDIR/nested.txt`
    set_fat16(&mut img, 6, 0xFFFF);

    let cluster_off = |c: usize| (FIRST_DATA_SECTOR + (c - 2)) * SECTOR;
    let mut payload = vec![0_u8; 700];
    let prefix = b"hello from fat16 native engine!\n";
    payload[..prefix.len()].copy_from_slice(prefix);
    for (idx, b) in payload[prefix.len()..].iter_mut().enumerate() {
        *b = b'a' + u8::try_from(idx % 26).unwrap();
    }
    let c3 = cluster_off(3);
    img[c3..c3 + SECTOR].copy_from_slice(&payload[..SECTOR]);
    let c4 = cluster_off(4);
    img[c4..c4 + (payload.len() - SECTOR)].copy_from_slice(&payload[SECTOR..]);

    let nested = b"nested fat16 file\n";
    let c6 = cluster_off(6);
    img[c6..c6 + nested.len()].copy_from_slice(nested);

    // Populate root directory
    let root_off = (RESERVED + FAT_COUNT * FAT_SECTORS) * SECTOR;
    let mut slot_cursor = 0_usize;
    write_lfn_and_short(
        &mut img[root_off..root_off + ROOT_SECTORS * SECTOR],
        &mut slot_cursor,
        "Native payload.bin",
        b"NATIVE~1BIN",
        0x20,
        3,
        payload.len() as u32,
    );
    let subdir_slot = encode_short_entry(b"SUBDIR     ", 0x10, 5, 0);
    img[root_off + slot_cursor * 32..root_off + (slot_cursor + 1) * 32]
        .copy_from_slice(&subdir_slot);

    // Populate SUBDIR at cluster 5 with `.`, `..`, and `nested.txt`
    let c5 = cluster_off(5);
    let dot = encode_short_entry(b".          ", 0x10, 5, 0);
    let dotdot = encode_short_entry(b"..         ", 0x10, 0, 0);
    img[c5..c5 + 32].copy_from_slice(&dot);
    img[c5 + 32..c5 + 64].copy_from_slice(&dotdot);
    let mut sub_cursor = 2_usize;
    write_lfn_and_short(
        &mut img[c5..c5 + SECTOR],
        &mut sub_cursor,
        "nested.txt",
        b"NESTED  TXT",
        0x20,
        6,
        nested.len() as u32,
    );
    img
}

fn build_fat32_image() -> Vec<u8> {
    const SECTOR: usize = 512;
    const RESERVED: usize = 32;
    const FAT_COUNT: usize = 2;
    const FAT_SECTORS: usize = 513;
    const DATA_CLUSTERS: usize = 65_530;
    const FIRST_DATA_SECTOR: usize = RESERVED + FAT_COUNT * FAT_SECTORS;
    const TOTAL_SECTORS: usize = FIRST_DATA_SECTOR + DATA_CLUSTERS;

    let mut img = vec![0_u8; TOTAL_SECTORS * SECTOR];
    {
        let boot = &mut img[..SECTOR];
        boot[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"FRANKEN ");
        boot[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
        boot[16] = FAT_COUNT as u8;
        boot[21] = 0xF8;
        boot[24..26].copy_from_slice(&32_u16.to_le_bytes());
        boot[26..28].copy_from_slice(&64_u16.to_le_bytes());
        boot[32..36].copy_from_slice(&(TOTAL_SECTORS as u32).to_le_bytes());
        boot[36..40].copy_from_slice(&(FAT_SECTORS as u32).to_le_bytes());
        boot[44..48].copy_from_slice(&2_u32.to_le_bytes()); // root_cluster = 2
        boot[48..50].copy_from_slice(&1_u16.to_le_bytes()); // fs_info = 1
        boot[50..52].copy_from_slice(&6_u16.to_le_bytes()); // backup_boot = 6
        boot[64] = 0x80;
        boot[66] = 0x29;
        boot[67..71].copy_from_slice(&0x5566_7788_u32.to_le_bytes());
        boot[71..82].copy_from_slice(b"FFS_FAT32  ");
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    }
    // Copy boot sector to backup sector 6
    let boot_copy = img[..SECTOR].to_vec();
    img[6 * SECTOR..7 * SECTOR].copy_from_slice(&boot_copy);

    // Populate FSInfo at sector 1 and backup FSInfo at sector 7 (5 allocated clusters: 2..=6)
    let free_clusters = (DATA_CLUSTERS - 5) as u32;
    for fsinfo_sector in [1_usize, 7] {
        let fsinfo = &mut img[fsinfo_sector * SECTOR..(fsinfo_sector + 1) * SECTOR];
        fsinfo[0..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
        fsinfo[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
        fsinfo[488..492].copy_from_slice(&free_clusters.to_le_bytes());
        fsinfo[492..496].copy_from_slice(&7_u32.to_le_bytes());
        fsinfo[508..512].copy_from_slice(&0xAA55_0000_u32.to_le_bytes());
    }

    let set_fat32 = |buf: &mut [u8], cluster: usize, val: u32| {
        for copy in 0..FAT_COUNT {
            let at = (RESERVED + copy * FAT_SECTORS) * SECTOR + cluster * 4;
            buf[at..at + 4].copy_from_slice(&val.to_le_bytes());
        }
    };
    set_fat32(&mut img, 0, 0x0FFF_FFF8);
    set_fat32(&mut img, 1, 0x0FFF_FFFF);
    set_fat32(&mut img, 2, 0x0FFF_FFFF); // root dir
    set_fat32(&mut img, 3, 4);
    set_fat32(&mut img, 4, 0x0FFF_FFFF);
    set_fat32(&mut img, 5, 0x0FFF_FFFF);
    set_fat32(&mut img, 6, 0x0FFF_FFFF);

    let cluster_off = |c: usize| (FIRST_DATA_SECTOR + (c - 2)) * SECTOR;
    let mut payload = vec![0_u8; 700];
    let prefix = b"hello from fat32 native engine!\n";
    payload[..prefix.len()].copy_from_slice(prefix);
    for (idx, b) in payload[prefix.len()..].iter_mut().enumerate() {
        *b = b'A' + u8::try_from(idx % 26).unwrap();
    }
    let c3 = cluster_off(3);
    img[c3..c3 + SECTOR].copy_from_slice(&payload[..SECTOR]);
    let c4 = cluster_off(4);
    img[c4..c4 + (payload.len() - SECTOR)].copy_from_slice(&payload[SECTOR..]);

    let nested = b"nested fat32 file\n";
    let c6 = cluster_off(6);
    img[c6..c6 + nested.len()].copy_from_slice(nested);

    let c2 = cluster_off(2);
    let mut slot_cursor = 0_usize;
    write_lfn_and_short(
        &mut img[c2..c2 + SECTOR],
        &mut slot_cursor,
        "Native payload.bin",
        b"NATIVE~1BIN",
        0x20,
        3,
        payload.len() as u32,
    );
    let subdir_slot = encode_short_entry(b"SUBDIR     ", 0x10, 5, 0);
    img[c2 + slot_cursor * 32..c2 + (slot_cursor + 1) * 32].copy_from_slice(&subdir_slot);

    let c5 = cluster_off(5);
    let dot = encode_short_entry(b".          ", 0x10, 5, 0);
    let dotdot = encode_short_entry(b"..         ", 0x10, 0, 0);
    img[c5..c5 + 32].copy_from_slice(&dot);
    img[c5 + 32..c5 + 64].copy_from_slice(&dotdot);
    let mut sub_cursor = 2_usize;
    write_lfn_and_short(
        &mut img[c5..c5 + SECTOR],
        &mut sub_cursor,
        "nested.txt",
        b"NESTED  TXT",
        0x20,
        6,
        nested.len() as u32,
    );
    img
}

fn ntfs_resident_attr(kind: u32, id: u16, name: &str, value: &[u8]) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let start = (24 + units.len() * 2).next_multiple_of(8);
    let length = (start + value.len()).next_multiple_of(8);
    let mut attr = vec![0_u8; length];
    attr[..4].copy_from_slice(&kind.to_le_bytes());
    attr[4..8].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
    attr[9] = u8::try_from(units.len()).unwrap();
    attr[10..12].copy_from_slice(&24_u16.to_le_bytes());
    attr[14..16].copy_from_slice(&id.to_le_bytes());
    attr[16..20].copy_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
    attr[20..22].copy_from_slice(&u16::try_from(start).unwrap().to_le_bytes());
    for (idx, unit) in units.iter().enumerate() {
        attr[24 + idx * 2..26 + idx * 2].copy_from_slice(&unit.to_le_bytes());
    }
    attr[start..start + value.len()].copy_from_slice(value);
    attr
}

fn ntfs_mapped_attr(kind: u32, id: u16, pairs: &[u8], clusters: u64, size: u64) -> Vec<u8> {
    let start = 64_usize;
    let length = (start + pairs.len()).next_multiple_of(8);
    let mut attr = vec![0_u8; length];
    attr[..4].copy_from_slice(&kind.to_le_bytes());
    attr[4..8].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
    attr[8] = 1;
    attr[14..16].copy_from_slice(&id.to_le_bytes());
    attr[24..32].copy_from_slice(&(clusters - 1).to_le_bytes());
    attr[32..34].copy_from_slice(&u16::try_from(start).unwrap().to_le_bytes());
    attr[40..48].copy_from_slice(&(clusters * 512).to_le_bytes());
    attr[48..56].copy_from_slice(&size.to_le_bytes());
    attr[56..64].copy_from_slice(&size.to_le_bytes());
    attr[start..start + pairs.len()].copy_from_slice(pairs);
    attr
}

fn ntfs_record(number: u32, directory: bool, links: u16, attrs: &[Vec<u8>]) -> Vec<u8> {
    const SEQ: u16 = 7;
    let mut raw = vec![0_u8; 1024];
    raw[..4].copy_from_slice(b"FILE");
    raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
    raw[16..18].copy_from_slice(&SEQ.to_le_bytes());
    raw[18..20].copy_from_slice(&links.to_le_bytes());
    raw[20..22].copy_from_slice(&56_u16.to_le_bytes());
    raw[22..24].copy_from_slice(&(if directory { 3_u16 } else { 1 }).to_le_bytes());
    raw[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    raw[44..48].copy_from_slice(&number.to_le_bytes());
    let mut at = 56_usize;
    for attr in attrs {
        raw[at..at + attr.len()].copy_from_slice(attr);
        at += attr.len();
    }
    raw[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    raw[24..28].copy_from_slice(&u32::try_from(at + 8).unwrap().to_le_bytes());
    raw[48..50].copy_from_slice(&0x1234_u16.to_le_bytes());
    for part in 1..=2 {
        let saved = [raw[part * 512 - 2], raw[part * 512 - 1]];
        raw[48 + part * 2..50 + part * 2].copy_from_slice(&saved);
        raw[part * 512 - 2..part * 512].copy_from_slice(&0x1234_u16.to_le_bytes());
    }
    raw
}

fn build_ntfs_image() -> Vec<u8> {
    const SEQ: u16 = 7;
    const UNIX_FILETIME: u64 = 116_444_736_000_000_000;
    let mut image = vec![0_u8; 1024 * 512];

    let boot = &mut image[..512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
    boot[13] = 1;
    boot[21] = 0xF8;
    boot[40..48].copy_from_slice(&1023_u64.to_le_bytes());
    boot[48..56].copy_from_slice(&4_u64.to_le_bytes());
    boot[56..64].copy_from_slice(&128_u64.to_le_bytes());
    boot[64] = 0xF6;
    boot[68] = 0xF4;
    boot[72..80].copy_from_slice(&0x4646_5336_2026_1111_u64.to_le_bytes());
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);

    let standard = || {
        let mut info = [0_u8; 72];
        for (idx, t) in [UNIX_FILETIME; 4].iter().enumerate() {
            info[idx * 8..idx * 8 + 8].copy_from_slice(&t.to_le_bytes());
        }
        ntfs_resident_attr(0x10, 0, "", &info)
    };
    let filename = |parent: u64, name: &str, ns: u8| {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut raw = vec![0_u8; 66 + units.len() * 2];
        raw[..8].copy_from_slice(&((u64::from(SEQ) << 48) | parent).to_le_bytes());
        raw[64] = u8::try_from(units.len()).unwrap();
        raw[65] = ns;
        for (i, u) in units.iter().enumerate() {
            raw[66 + i * 2..68 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        raw
    };
    let index_root = |children: &[(u32, &str, u8)], parent: u64| {
        let mut root = vec![0_u8; 32];
        root[..4].copy_from_slice(&0x30_u32.to_le_bytes());
        root[4..8].copy_from_slice(&1_u32.to_le_bytes());
        root[8..12].copy_from_slice(&4096_u32.to_le_bytes());
        root[12] = 8;
        root[16..20].copy_from_slice(&16_u32.to_le_bytes());
        for &(rec, name, ns) in children {
            let val = filename(parent, name, ns);
            let len = (16 + val.len()).next_multiple_of(8);
            let mut entry = vec![0_u8; len];
            entry[..8].copy_from_slice(&((u64::from(SEQ) << 48) | u64::from(rec)).to_le_bytes());
            entry[8..10].copy_from_slice(&u16::try_from(len).unwrap().to_le_bytes());
            entry[10..12].copy_from_slice(&u16::try_from(val.len()).unwrap().to_le_bytes());
            entry[16..16 + val.len()].copy_from_slice(&val);
            root.extend(entry);
        }
        let mut last = [0_u8; 16];
        last[8] = 16;
        last[12] = 2;
        root.extend(last);
        let used = u32::try_from(root.len() - 16).unwrap();
        root[20..24].copy_from_slice(&used.to_le_bytes());
        root[24..28].copy_from_slice(&used.to_le_bytes());
        ntfs_resident_attr(0x90, 2, "$I30", &root)
    };
    let put_rec = |img: &mut [u8], num: u32, raw: &[u8]| {
        let at = 4 * 512 + (num as usize) * 1024;
        img[at..at + 1024].copy_from_slice(raw);
    };

    let mut mft_bitmap = [0_u8; 5];
    for slot in [0_usize, 1, 2, 3, 5, 6, 10, 24, 25] {
        mft_bitmap[slot / 8] |= 1_u8 << (slot % 8);
    }
    let mft_rec = ntfs_record(
        0,
        false,
        0,
        &[
            standard(),
            ntfs_mapped_attr(DATA, 1, &[0x11, 80, 4, 0], 80, 40_960),
            ntfs_resident_attr(0xB0, 2, "", &mft_bitmap),
        ],
    );
    let mft_mirr_rec = ntfs_record(
        1,
        false,
        0,
        &[
            standard(),
            ntfs_mapped_attr(DATA, 1, &[0x21, 8, 128, 0, 0], 8, 4096),
        ],
    );
    let logfile_rec = ntfs_record(
        2,
        false,
        0,
        &[
            standard(),
            ntfs_mapped_attr(DATA, 1, &[0x21, 64, 192, 0, 0], 64, 32_768),
        ],
    );
    let mut vol_info = [0_u8; 12];
    vol_info[8..10].copy_from_slice(&[3, 1]);
    let volume_rec = ntfs_record(
        3,
        false,
        0,
        &[standard(), ntfs_resident_attr(0x70, 1, "", &vol_info)],
    );

    // Sorted ASCII uppercase order: MAPPED.BIN (rec 25) before HELLO.TXT? Wait: 'H' < 'M'!
    // Keep exact NTFS UpCase lexical order in $I30: "hello.txt" ('H') then "mapped.bin" ('M').
    let root_children = [(24_u32, "hello.txt", 1_u8), (25_u32, "mapped.bin", 1_u8)];
    let root_dir_rec = ntfs_record(
        5,
        true,
        1,
        &[
            standard(),
            ntfs_resident_attr(0x30, 1, "", &filename(5, ".", 3)),
            index_root(&root_children, 5),
        ],
    );

    // Non-resident mapped payload at clusters 600..602 (2 clusters = 1024 bytes).
    let mut vol_bitmap = [0_u8; 128];
    for c in (4..84)
        .chain(128..136)
        .chain(192..256)
        .chain(300..556)
        .chain(600..602)
    {
        vol_bitmap[c / 8] |= 1_u8 << (c % 8);
    }
    let bitmap_rec = ntfs_record(
        6,
        false,
        0,
        &[standard(), ntfs_resident_attr(DATA, 1, "", &vol_bitmap)],
    );
    let upcase_rec = ntfs_record(
        10,
        false,
        0,
        &[
            standard(),
            ntfs_mapped_attr(DATA, 1, &[0x22, 0, 1, 44, 1, 0], 256, 131_072),
        ],
    );
    let hello_file_rec = ntfs_record(
        24,
        false,
        1,
        &[
            standard(),
            ntfs_resident_attr(0x30, 1, "", &filename(5, "hello.txt", 1)),
            ntfs_resident_attr(DATA, 2, "", b"hello from ntfs\n"),
            ntfs_resident_attr(DATA, 3, "note", b"secret alternate stream\n"),
        ],
    );
    // LCN 600 = 0x0258 -> 2-byte little-endian positive signed offset `[0x58, 0x02]` (`header = 0x21`, len = 2)
    let mapped_file_rec = ntfs_record(
        25,
        false,
        1,
        &[
            standard(),
            ntfs_resident_attr(0x30, 1, "", &filename(5, "mapped.bin", 1)),
            ntfs_mapped_attr(DATA, 2, &[0x21, 2, 0x58, 0x02, 0], 2, 700),
        ],
    );

    put_rec(&mut image, 0, &mft_rec);
    put_rec(&mut image, 1, &mft_mirr_rec);
    put_rec(&mut image, 2, &logfile_rec);
    put_rec(&mut image, 3, &volume_rec);
    put_rec(&mut image, 5, &root_dir_rec);
    put_rec(&mut image, 6, &bitmap_rec);
    put_rec(&mut image, 10, &upcase_rec);
    put_rec(&mut image, 24, &hello_file_rec);
    put_rec(&mut image, 25, &mapped_file_rec);

    let mft_head = image[4 * 512..4 * 512 + 4096].to_vec();
    image[128 * 512..128 * 512 + 4096].copy_from_slice(&mft_head);
    image[192 * 512..256 * 512].fill(0xFF);

    let mut mapped_payload = vec![0_u8; 700];
    mapped_payload[..20].copy_from_slice(b"mapped ntfs payload\n");
    for (idx, b) in mapped_payload[20..].iter_mut().enumerate() {
        *b = u8::try_from((idx * 7 + 3) % 251).unwrap();
    }
    image[600 * 512..600 * 512 + 700].copy_from_slice(&mapped_payload);

    for unit in 0..=u16::MAX {
        let upper = if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
            unit - 32
        } else {
            unit
        };
        let at = 300 * 512 + usize::from(unit) * 2;
        image[at..at + 2].copy_from_slice(&upper.to_le_bytes());
    }
    image
}

#[allow(clippy::too_many_lines)]
fn build_zfs_image() -> Vec<u8> {
    const LENGTH: usize = 8 * 1024 * 1024;
    const POOL_GUID: u64 = 424_242;
    const LEAF_GUID: u64 = 1_001;
    let order = Endian::Little;
    let mut image = vec![0_u8; LENGTH];

    let xstring = |val: &str| -> Vec<u8> {
        let mut b = u32::try_from(val.len()).unwrap().to_be_bytes().to_vec();
        b.extend_from_slice(val.as_bytes());
        b.resize(b.len().next_multiple_of(4), 0);
        b
    };
    let nv_pair = |name: &str, kind: u32, data: &[u8]| -> Vec<u8> {
        let mut b = vec![0_u8; 8];
        b.extend_from_slice(&xstring(name));
        b.extend_from_slice(&kind.to_be_bytes());
        b.extend_from_slice(&1_u32.to_be_bytes());
        b.extend_from_slice(data);
        let len = u32::try_from(b.len()).unwrap();
        b[..4].copy_from_slice(&len.to_be_bytes());
        b[4..8].copy_from_slice(&64_u32.to_be_bytes());
        b
    };
    let nv_uint = |name: &str, val: u64| nv_pair(name, 8, &val.to_be_bytes());
    let nv_list = |pairs: &[Vec<u8>]| -> Vec<u8> {
        let mut b = vec![0, 0, 0, 0, 0, 0, 0, 1];
        for p in pairs {
            b.extend_from_slice(p);
        }
        b.extend_from_slice(&[0; 8]);
        b
    };
    let stamp = |block: &mut [u8], offset: u64| {
        let at = block.len() - 40;
        block[at..at + 8].copy_from_slice(&order.encode(0x0210_da7a_b10c_7a11));
        block[at + 8..].fill(0);
        block[at + 8..at + 16].copy_from_slice(&order.encode(offset));
        let digest = Sha256::digest(&*block);
        for i in 0..4 {
            let word = u64::from_be_bytes(std::array::from_fn(|n| digest[i * 8 + n]));
            block[at + 8 + i * 8..at + 16 + i * 8].copy_from_slice(&order.encode(word));
        }
    };
    let bp = |raw: &[u8], at: u64, kind: u8, level: u8, birth: u64| -> Vec<u8> {
        let sectors = u64::try_from(raw.len() / 512).unwrap();
        let mut words = [0_u64; 16];
        words[0] = sectors;
        words[1] = (at - DATA_OFFSET) / 512;
        words[6] = (sectors - 1)
            | ((sectors - 1) << 16)
            | (2 << 32)
            | (7 << 40)
            | (u64::from(kind) << 48)
            | (u64::from(level) << 56)
            | (1_u64 << 63);
        words[10] = birth;
        words[12..].copy_from_slice(&zfs_checksum(raw, 7, order).unwrap());
        words.into_iter().flat_map(|w| order.encode(w)).collect()
    };
    let dnode = |kind: u8,
                 block: usize,
                 levels: u8,
                 max_blk: u64,
                 bonus: &[u8],
                 bonus_type: u8|
     -> Vec<u8> {
        let mut raw = vec![0_u8; 512];
        raw[0] = kind;
        raw[1] = 12;
        raw[2] = levels;
        raw[3] = 1;
        raw[4] = bonus_type;
        raw[7] = 1;
        raw[8..10].copy_from_slice(&u16::try_from(block / 512).unwrap().to_le_bytes());
        raw[10..12].copy_from_slice(&u16::try_from(bonus.len()).unwrap().to_le_bytes());
        raw[16..24].copy_from_slice(&order.encode(max_blk));
        raw[192..192 + bonus.len()].copy_from_slice(bonus);
        raw
    };
    let micro_zap = |entries: &[(&[u8], u64)]| -> Vec<u8> {
        let mut raw = vec![0_u8; 512];
        raw[..8].copy_from_slice(&order.encode((1_u64 << 63) + 3));
        for (i, (name, val)) in entries.iter().enumerate() {
            let at = 64 + i * 64;
            raw[at..at + 8].copy_from_slice(&order.encode(*val));
            raw[at + 14..at + 14 + name.len()].copy_from_slice(name);
        }
        raw
    };
    let legacy_znode = |mode: u64, size: u64, parent: u64| -> Vec<u8> {
        let mut raw = vec![0_u8; 264];
        for (at, val) in [
            (0_usize, 1_700_000_000_u64),
            (8, 0),
            (64, 10),
            (72, mode),
            (80, size),
            (88, parent),
            (96, 1),
            (128, 0),
            (136, 0),
        ] {
            raw[at..at + 8].copy_from_slice(&order.encode(val));
        }
        raw
    };
    let store = |img: &mut [u8], at: u64, data: &[u8]| {
        let start = usize::try_from(at).unwrap();
        img[start..start + data.len()].copy_from_slice(data);
    };

    let master_zap = micro_zap(&[(b"ROOT", 2), (b"VERSION", 4)]);
    let root_dir_zap = micro_zap(&[(b"hello.txt", (8_u64 << 60) | 3)]);
    let mut file_block = vec![0_u8; 512];
    let payload = b"hello from zfs\n";
    file_block[..payload.len()].copy_from_slice(payload);

    let master_at = DATA_OFFSET + 0x25_000;
    let root_dir_at = DATA_OFFSET + 0x26_000;
    let file_data_at = DATA_OFFSET + 0x28_000;
    let zpl_table_at = DATA_OFFSET + 0x20_000;
    let os_at = DATA_OFFSET + 0x18_000;

    store(&mut image, master_at, &master_zap);
    store(&mut image, root_dir_at, &root_dir_zap);
    store(&mut image, file_data_at, &file_block);

    let mut zpl_table = vec![0_u8; 16_384];
    let mut obj1 = dnode(21, 512, 1, 0, &[], 0);
    obj1[64..192].copy_from_slice(&bp(&master_zap, master_at, 21, 0, 20));
    zpl_table[512..1024].copy_from_slice(&obj1);

    let mut obj2 = dnode(20, 512, 1, 0, &legacy_znode(0o040_755, 3, 2), 17);
    obj2[64..192].copy_from_slice(&bp(&root_dir_zap, root_dir_at, 20, 0, 20));
    zpl_table[1024..1536].copy_from_slice(&obj2);

    let mut obj3 = dnode(
        19,
        512,
        1,
        0,
        &legacy_znode(0o100_644, payload.len() as u64, 2),
        17,
    );
    obj3[24..32].copy_from_slice(&order.encode(512));
    obj3[64..192].copy_from_slice(&bp(&file_block, file_data_at, 19, 0, 20));
    zpl_table[1536..2048].copy_from_slice(&obj3);
    store(&mut image, zpl_table_at, &zpl_table);

    let mut os = vec![0_u8; 1024];
    let mut os_meta = dnode(10, 16_384, 1, 0, &[], 0);
    os_meta[64..192].copy_from_slice(&bp(&zpl_table, zpl_table_at, 10, 0, 30));
    os[..512].copy_from_slice(&os_meta);
    os[704..712].copy_from_slice(&order.encode(2));
    store(&mut image, os_at, &os);

    let pool_dir_zap = micro_zap(&[(b"root_dataset", 2)]);
    let snapnames_zap = micro_zap(&[(b"snap1", 5)]);
    let child_map_zap = micro_zap(&[(b"app", 7)]);
    let empty_zap = micro_zap(&[]);

    let pool_dir_at = DATA_OFFSET + 0x14_000;
    let snapnames_at = DATA_OFFSET + 0x15_000;
    let child_map_at = DATA_OFFSET + 0x16_000;
    let empty_zap_at = DATA_OFFSET + 0x17_000;
    let mos_table_at = DATA_OFFSET + 0x10_000;
    let mos_os_at = DATA_OFFSET + 0x0C_000;

    store(&mut image, pool_dir_at, &pool_dir_zap);
    store(&mut image, snapnames_at, &snapnames_zap);
    store(&mut image, child_map_at, &child_map_zap);
    store(&mut image, empty_zap_at, &empty_zap);

    let mut mos_table = vec![0_u8; 16_384];
    let mut mos_obj1 = dnode(1, 512, 1, 0, &[], 0);
    mos_obj1[64..192].copy_from_slice(&bp(&pool_dir_zap, pool_dir_at, 1, 0, 20));
    mos_table[512..1024].copy_from_slice(&mos_obj1);

    let mut root_dsl_dir = vec![0_u8; 256];
    root_dsl_dir[8..16].copy_from_slice(&order.encode(3));
    root_dsl_dir[32..40].copy_from_slice(&order.encode(6));
    mos_table[1024..1536].copy_from_slice(&dnode(12, 512, 1, 0, &root_dsl_dir, 12));

    let os_bp = bp(&os, os_at, 11, 0, 30);
    let mut root_ds = vec![0_u8; 320];
    for (at, val) in [
        (0_usize, 2_u64),
        (8, 5),
        (16, 35),
        (32, 4),
        (48, 1_700_000_010),
        (56, 45),
        (112, 987_001),
    ] {
        root_ds[at..at + 8].copy_from_slice(&order.encode(val));
    }
    root_ds[128..256].copy_from_slice(&os_bp);
    mos_table[1536..2048].copy_from_slice(&dnode(16, 512, 1, 0, &root_ds, 16));

    let mut mos_obj4 = dnode(196, 512, 1, 0, &[], 0);
    mos_obj4[64..192].copy_from_slice(&bp(&snapnames_zap, snapnames_at, 196, 0, 35));
    mos_table[2048..2560].copy_from_slice(&mos_obj4);

    let mut snap_ds = vec![0_u8; 320];
    for (at, val) in [
        (0_usize, 2_u64),
        (24, 3),
        (40, 1),
        (48, 1_700_000_000),
        (56, 35),
        (112, 987_000),
    ] {
        snap_ds[at..at + 8].copy_from_slice(&order.encode(val));
    }
    snap_ds[128..256].copy_from_slice(&os_bp);
    mos_table[2560..3072].copy_from_slice(&dnode(16, 512, 1, 0, &snap_ds, 16));

    let mut mos_obj6 = dnode(13, 512, 1, 0, &[], 0);
    mos_obj6[64..192].copy_from_slice(&bp(&child_map_zap, child_map_at, 13, 0, 40));
    mos_table[3072..3584].copy_from_slice(&mos_obj6);

    let mut app_dsl_dir = vec![0_u8; 256];
    app_dsl_dir[8..16].copy_from_slice(&order.encode(8));
    app_dsl_dir[16..24].copy_from_slice(&order.encode(2));
    mos_table[3584..4096].copy_from_slice(&dnode(12, 512, 1, 0, &app_dsl_dir, 12));

    let mut app_ds = vec![0_u8; 320];
    for (at, val) in [
        (0_usize, 7_u64),
        (32, 9),
        (48, 1_700_000_020),
        (56, 46),
        (112, 987_002),
    ] {
        app_ds[at..at + 8].copy_from_slice(&order.encode(val));
    }
    app_ds[128..256].copy_from_slice(&os_bp);
    mos_table[4096..4608].copy_from_slice(&dnode(16, 512, 1, 0, &app_ds, 16));

    let mut mos_obj9 = dnode(196, 512, 1, 0, &[], 0);
    mos_obj9[64..192].copy_from_slice(&bp(&empty_zap, empty_zap_at, 196, 0, 46));
    mos_table[4608..5120].copy_from_slice(&mos_obj9);

    store(&mut image, mos_table_at, &mos_table);

    let mut mos_os = vec![0_u8; 1024];
    let mut mos_meta = dnode(10, 16_384, 1, 0, &[], 0);
    mos_meta[64..192].copy_from_slice(&bp(&mos_table, mos_table_at, 10, 0, 55));
    mos_os[..512].copy_from_slice(&mos_meta);
    mos_os[704..712].copy_from_slice(&order.encode(1));
    store(&mut image, mos_os_at, &mos_os);

    let vdev_tree = nv_list(&[
        nv_pair("type", 9, &xstring("file")),
        nv_uint("id", 0),
        nv_uint("guid", LEAF_GUID),
        nv_uint("ashift", 9),
        nv_uint("asize", LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES),
        nv_uint("is_log", 0),
    ]);
    let mut cfg = vec![1, 1, 0, 0];
    cfg.extend_from_slice(&nv_list(&[
        nv_uint("version", 28),
        nv_uint("state", 1),
        nv_uint("txg", 60),
        nv_uint("pool_guid", POOL_GUID),
        nv_uint("guid", LEAF_GUID),
        nv_uint("top_guid", LEAF_GUID),
        nv_uint("vdev_children", 1),
        nv_pair("name", 9, &xstring("tank")),
        nv_pair("vdev_tree", 19, &vdev_tree),
    ]));

    let mos_bp = bp(&mos_os, mos_os_at, 11, 0, 60);
    let mut ub = vec![0_u8; 1024];
    for (at, val) in [
        (0_usize, 0x00ba_b10c_u64),
        (8, 28),
        (16, 60),
        (24, POOL_GUID + LEAF_GUID),
        (32, 1_700_000_100),
    ] {
        ub[at..at + 8].copy_from_slice(&order.encode(val));
    }
    ub[40..168].copy_from_slice(&mos_bp);

    for lbl_off in label_offsets(LENGTH as u64).unwrap() {
        let cfg_off = lbl_off + LABEL_CONFIG_OFFSET;
        let mut cfg_blk = vec![0_u8; LABEL_CONFIG_BYTES];
        cfg_blk[..cfg.len()].copy_from_slice(&cfg);
        stamp(&mut cfg_blk, cfg_off);
        store(&mut image, cfg_off, &cfg_blk);

        let ub_off = lbl_off + UBERBLOCK_RING_OFFSET;
        let mut ub_blk = ub.clone();
        stamp(&mut ub_blk, ub_off);
        store(&mut image, ub_off, &ub_blk);
    }

    image
}

fn build_gpt_multi_format_image() -> Vec<u8> {
    let (ntfs, _) = ntfs_baseline();
    let (fat16, _) = fat16_baseline();

    let p1_lba = 64_u64;
    let p1_sectors = (ntfs.len() / 512) as u64;
    let p2_lba = p1_lba + p1_sectors + 8;
    let p2_sectors = (fat16.len() / 512) as u64;
    let total_lbas = p2_lba + p2_sectors + 64;
    let mut disk = vec![0_u8; (total_lbas as usize) * 512];

    let basic_data_guid = PartUuid::from_str("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").unwrap();
    let disk_guid = PartUuid::from_str("99999999-1111-2222-3333-444455556666").unwrap();
    let p1_uuid = PartUuid::from_str("cccccccc-0000-4000-8000-000000000001").unwrap();
    let p2_uuid = PartUuid::from_str("cccccccc-0000-4000-8000-000000000002").unwrap();

    write_gpt_partition_table(
        &mut disk,
        disk_guid,
        &[
            SyntheticGptPartitionSpec {
                type_guid: basic_data_guid,
                part_uuid: p1_uuid,
                start_lba: p1_lba,
                end_lba_inclusive: p1_lba + p1_sectors - 1,
                label: "NTFS_SYS".to_owned(),
                attributes: 0,
            },
            SyntheticGptPartitionSpec {
                type_guid: basic_data_guid,
                part_uuid: p2_uuid,
                start_lba: p2_lba,
                end_lba_inclusive: p2_lba + p2_sectors - 1,
                label: "FAT16_DATA".to_owned(),
                attributes: 0,
            },
        ],
    )
    .unwrap();

    let p1_start = (p1_lba as usize) * 512;
    disk[p1_start..p1_start + ntfs.len()].copy_from_slice(ntfs);
    let p2_start = (p2_lba as usize) * 512;
    disk[p2_start..p2_start + fat16.len()].copy_from_slice(fat16);
    disk
}

fn build_mbr_multi_format_image() -> Vec<u8> {
    let (ntfs, _) = ntfs_baseline();
    let (fat16, _) = fat16_baseline();

    let p1_lba = 8_u32;
    let p1_sectors = u32::try_from(ntfs.len() / 512).unwrap();
    let p2_lba = p1_lba + p1_sectors + 8;
    let p2_sectors = u32::try_from(fat16.len() / 512).unwrap();
    let total_lbas = (p2_lba + p2_sectors + 8) as usize;
    let mut disk = vec![0_u8; total_lbas * 512];

    disk[440..444].copy_from_slice(&0xCAFE_BABE_u32.to_le_bytes());
    // Entry 1 at 446: NTFS (0x07), bootable (0x80)
    disk[446] = 0x80;
    disk[446 + 4] = 0x07;
    disk[446 + 8..446 + 12].copy_from_slice(&p1_lba.to_le_bytes());
    disk[446 + 12..446 + 16].copy_from_slice(&p1_sectors.to_le_bytes());
    // Entry 2 at 462: FAT16 (0x06)
    disk[462 + 4] = 0x06;
    disk[462 + 8..462 + 12].copy_from_slice(&p2_lba.to_le_bytes());
    disk[462 + 12..462 + 16].copy_from_slice(&p2_sectors.to_le_bytes());
    disk[510..512].copy_from_slice(&[0x55, 0xAA]);

    let p1_start = (p1_lba as usize) * 512;
    disk[p1_start..p1_start + ntfs.len()].copy_from_slice(ntfs);
    let p2_start = (p2_lba as usize) * 512;
    disk[p2_start..p2_start + fat16.len()].copy_from_slice(fat16);
    disk
}

pub fn fat16_baseline() -> (&'static [u8], blake3::Hash) {
    static IMAGE: OnceLock<(Vec<u8>, blake3::Hash)> = OnceLock::new();
    let (bytes, hash) = IMAGE.get_or_init(|| {
        let img = build_fat16_image();
        let digest = blake3::hash(&img);
        (img, digest)
    });
    (bytes.as_slice(), *hash)
}

pub fn fat32_baseline() -> (&'static [u8], blake3::Hash) {
    static IMAGE: OnceLock<(Vec<u8>, blake3::Hash)> = OnceLock::new();
    let (bytes, hash) = IMAGE.get_or_init(|| {
        let img = build_fat32_image();
        let digest = blake3::hash(&img);
        (img, digest)
    });
    (bytes.as_slice(), *hash)
}

pub fn ntfs_baseline() -> (&'static [u8], blake3::Hash) {
    static IMAGE: OnceLock<(Vec<u8>, blake3::Hash)> = OnceLock::new();
    let (bytes, hash) = IMAGE.get_or_init(|| {
        let img = build_ntfs_image();
        let digest = blake3::hash(&img);
        (img, digest)
    });
    (bytes.as_slice(), *hash)
}

pub fn zfs_baseline() -> (&'static [u8], blake3::Hash) {
    static IMAGE: OnceLock<(Vec<u8>, blake3::Hash)> = OnceLock::new();
    let (bytes, hash) = IMAGE.get_or_init(|| {
        let img = build_zfs_image();
        let digest = blake3::hash(&img);
        (img, digest)
    });
    (bytes.as_slice(), *hash)
}

pub fn gpt_multi_format_baseline() -> (&'static [u8], blake3::Hash) {
    static IMAGE: OnceLock<(Vec<u8>, blake3::Hash)> = OnceLock::new();
    let (bytes, hash) = IMAGE.get_or_init(|| {
        let img = build_gpt_multi_format_image();
        let digest = blake3::hash(&img);
        (img, digest)
    });
    (bytes.as_slice(), *hash)
}

pub fn mbr_multi_format_baseline() -> (&'static [u8], blake3::Hash) {
    static IMAGE: OnceLock<(Vec<u8>, blake3::Hash)> = OnceLock::new();
    let (bytes, hash) = IMAGE.get_or_init(|| {
        let img = build_mbr_multi_format_image();
        let digest = blake3::hash(&img);
        (img, digest)
    });
    (bytes.as_slice(), *hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs::{
        open_read_only_device, FsFormatKind, InodeNumber, PartitionSelector, ReadOnlyOpenOptions,
        RequestScope,
    };
    use ffs_fat::FatVolume;
    use ffs_ntfs::reader::allocation::{
        AllocationLimits as NtfsAllocLimits, NamespaceLimits as NtfsNamespaceLimits,
        RecordOwnershipLimits as NtfsOwnershipLimits,
    };
    use ffs_ntfs::NtfsVolume;
    use ffs_ondisk::{lznt1, lzx, xpress};
    use ffs_zfs::reader::dmu::scrub::ScrubLimits as ZfsScrubLimits;
    use ffs_zfs::{Leaf, Pool};
    use std::ffi::OsStr;

    #[test]
    fn baselines_admit_cleanly_and_preserve_zero_write_authority() {
        let cx = Cx::for_testing();

        // 1. FAT16 & FAT32 baselines pass FatVolume::check + open_read_only_device.
        for (expected, (bytes, digest)) in [
            (FsFormatKind::Fat16, fat16_baseline()),
            (FsFormatKind::Fat32, fat32_baseline()),
        ] {
            let tracker = FuzzBudgetTracker::new(FuzzBudgets {
                max_ops: 8_192,
                ..FuzzBudgets::default()
            });
            let backing = PatchBuilder::from_static(bytes, digest).finish();
            let dev = BoundedRoFuzzDevice::new(backing, Arc::clone(&tracker), None);
            let vol = FatVolume::from_device(
                &cx,
                Box::new(Arc::clone(&dev) as Arc<dyn ByteDevice>),
                0,
                dev.len_bytes(),
            )
            .expect("admit FAT baseline");
            let report = vol.check(&cx).expect("check FAT baseline");
            assert!(
                report.clean,
                "FAT baseline must be clean: {:?}",
                report.issues
            );

            let opened = open_read_only_device(
                &cx,
                Arc::clone(&dev) as Arc<dyn ByteDevice>,
                &ReadOnlyOpenOptions::default(),
            )
            .expect("open FAT baseline via facade");
            assert_eq!(opened.format, expected);
            let mut scope = RequestScope::empty();
            let entry = opened
                .filesystem
                .lookup(
                    &cx,
                    &mut scope,
                    InodeNumber(1),
                    OsStr::new("Native payload.bin"),
                )
                .expect("lookup Native payload.bin");
            let payload = opened
                .filesystem
                .read(&cx, &mut scope, entry.ino, 0, 1024)
                .expect("read Native payload.bin");
            assert_eq!(payload.len(), 700);
            assert!(matches!(
                opened.filesystem.write(&cx, &mut scope, entry.ino, 0, b"x"),
                Err(FfsError::ReadOnly)
            ));
            dev.assert_invariants();
        }

        // 2. NTFS baseline passes MFT mirror, ownership, allocation, namespace & facade open.
        let (ntfs_bytes, ntfs_digest) = ntfs_baseline();
        let tracker = FuzzBudgetTracker::new(FuzzBudgets {
            max_ops: 8_192,
            ..FuzzBudgets::default()
        });
        let ntfs_dev = BoundedRoFuzzDevice::new(
            PatchBuilder::from_static(ntfs_bytes, ntfs_digest).finish(),
            Arc::clone(&tracker),
            None,
        );
        let ntfs_vol = NtfsVolume::from_device(
            &cx,
            Box::new(Arc::clone(&ntfs_dev) as Arc<dyn ByteDevice>),
            0,
            ntfs_dev.len_bytes(),
        )
        .expect("admit NTFS baseline");
        assert!(ntfs_vol
            .check_mft_mirror(&cx, NtfsOwnershipLimits::default())
            .unwrap()
            .is_consistent());
        assert!(ntfs_vol
            .check_record_ownership(&cx, NtfsOwnershipLimits::default())
            .unwrap()
            .is_consistent());
        assert!(ntfs_vol
            .check_allocations(&cx, NtfsAllocLimits::default())
            .unwrap()
            .is_consistent());
        assert!(ntfs_vol
            .check_namespace(&cx, NtfsNamespaceLimits::default())
            .unwrap()
            .is_consistent());
        let ntfs_opened = open_read_only_device(
            &cx,
            Arc::clone(&ntfs_dev) as Arc<dyn ByteDevice>,
            &ReadOnlyOpenOptions::default(),
        )
        .expect("open NTFS baseline");
        assert_eq!(ntfs_opened.format, FsFormatKind::Ntfs);
        ntfs_dev.assert_invariants();

        // 3. ZFS baseline passes Pool import, datasets, scrub & facade open.
        let (zfs_bytes, zfs_digest) = zfs_baseline();
        let zfs_tracker = FuzzBudgetTracker::new(FuzzBudgets {
            max_ops: 8_192,
            ..FuzzBudgets::default()
        });
        let zfs_dev = BoundedRoFuzzDevice::new(
            PatchBuilder::from_static(zfs_bytes, zfs_digest).finish(),
            Arc::clone(&zfs_tracker),
            None,
        );
        let leaf = Leaf::from_device(
            &cx,
            Box::new(Arc::clone(&zfs_dev) as Arc<dyn ByteDevice>),
            0,
            zfs_dev.len_bytes(),
        )
        .expect("open ZFS leaf");
        let pool = Pool::from_leaves(vec![leaf]).expect("assemble ZFS pool");
        let mut objects = pool.import_objects(&cx, None).expect("import ZFS objects");
        assert_eq!(objects.datasets(&cx).expect("datasets").len(), 2);
        let scrub = objects
            .scrub(&cx, ZfsScrubLimits::default())
            .expect("scrub ZFS pool");
        assert!(
            scrub.issues.is_empty(),
            "ZFS baseline scrub issues: {:?}",
            scrub.issues
        );
        let zfs_opened = open_read_only_device(
            &cx,
            Arc::clone(&zfs_dev) as Arc<dyn ByteDevice>,
            &ReadOnlyOpenOptions::default(),
        )
        .expect("open ZFS baseline via facade");
        assert_eq!(zfs_opened.format, FsFormatKind::Zfs);
        zfs_dev.assert_invariants();

        // 4. GPT and MBR multi-partition baselines open both NTFS (#1) and FAT16 (#2).
        for (disk_bytes, disk_digest) in [gpt_multi_format_baseline(), mbr_multi_format_baseline()]
        {
            let part_tracker = FuzzBudgetTracker::new(FuzzBudgets {
                max_ops: 8_192,
                ..FuzzBudgets::default()
            });
            let disk_dev = BoundedRoFuzzDevice::new(
                PatchBuilder::from_static(disk_bytes, disk_digest).finish(),
                Arc::clone(&part_tracker),
                None,
            );
            for (idx, fmt) in [(1_u32, FsFormatKind::Ntfs), (2_u32, FsFormatKind::Fat16)] {
                let opened = open_read_only_device(
                    &cx,
                    Arc::clone(&disk_dev) as Arc<dyn ByteDevice>,
                    &ReadOnlyOpenOptions {
                        partition: Some(PartitionSelector::Index(idx)),
                        ..ReadOnlyOpenOptions::default()
                    },
                )
                .expect("open partition slice");
                assert_eq!(opened.format, fmt);
            }
            disk_dev.assert_invariants();
        }
    }

    #[test]
    fn planted_bombs_cycles_and_final_element_corruptions_fail_closed_within_budgets() {
        let cx = Cx::for_testing();

        // 1. Independent budget dimensions & mid-flight cancellation all fail closed.
        let tight = FuzzBudgetTracker::new(FuzzBudgets {
            max_physical_read_bytes: 1024,
            max_decoded_bytes: 512,
            max_retained_bytes: 256,
            max_depth: 2,
            max_ops: 4,
            max_replica_attempts: 2,
        });
        assert!(tight.charge_decoded(513).is_err());
        assert!(tight.charge_retained(257).is_err());
        assert!(tight.check_depth(3).is_err());

        let (fat16, fat16_digest) = fat16_baseline();
        let replica_dev = BoundedRoFuzzDevice::new(
            PatchBuilder::from_static(fat16, fat16_digest).finish(),
            FuzzBudgetTracker::new(FuzzBudgets {
                max_replica_attempts: 2,
                ..FuzzBudgets::default()
            }),
            None,
        );
        let mut sector = [0_u8; 512];
        assert!(replica_dev
            .read_exact_at(&cx, ByteOffset(0), &mut sector)
            .is_ok());
        assert!(replica_dev
            .read_exact_at(&cx, ByteOffset(0), &mut sector)
            .is_ok());
        assert!(
            replica_dev
                .read_exact_at(&cx, ByteOffset(0), &mut sector)
                .is_err(),
            "third identical window read must trip max_replica_attempts"
        );
        replica_dev.assert_invariants();

        // 2. Planted FAT16 cluster-chain cycle (3 -> 4 -> 3) fails closed within budget.
        let mut cyclic_fat = PatchBuilder::from_static(fat16, fat16_digest);
        for copy in 0..2_u64 {
            let fat_entry_4 = (1 + copy * 17) * 512 + 4 * 2;
            cyclic_fat.write(fat_entry_4, &3_u16.to_le_bytes());
        }
        let cyc_dev = BoundedRoFuzzDevice::new(
            cyclic_fat.finish(),
            FuzzBudgetTracker::new(FuzzBudgets::default()),
            None,
        );
        let cyc_opened = open_read_only_device(
            &cx,
            Arc::clone(&cyc_dev) as Arc<dyn ByteDevice>,
            &ReadOnlyOpenOptions::default(),
        )
        .expect("volume admission precedes file-chain walk");
        let mut scope = RequestScope::empty();
        let cyc_outcome = cyc_opened
            .filesystem
            .lookup(
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new("Native payload.bin"),
            )
            .and_then(|entry| {
                cyc_opened
                    .filesystem
                    .read(&cx, &mut scope, entry.ino, 0, 1024)
            });
        assert!(
            cyc_outcome.is_err(),
            "planted FAT cluster cycle must return Err on lookup/read without hanging"
        );
        cyc_dev.assert_invariants();

        // 3. Planted NTFS LZNT1 / XPRESS / LZX truncated final-element streams fail closed.
        assert!(lznt1::decompress_unit(&[0x03, 0xB0, b'a', b'b'], 4096).is_err());
        assert!(xpress::decompress_chunk(&[0xFF, 0xFF, 0xFF, 0xFF, b'x'], 4096).is_err());
        assert!(lzx::decompress_chunk(&[0xAA, 0x55, 0x01], 32_768).is_err());

        // 4. Planted ZFS final data-block single-bit corruption fails closed with zero partial output.
        let (zfs, zfs_digest) = zfs_baseline();
        let mut bad_zfs = PatchBuilder::from_static(zfs, zfs_digest);
        bad_zfs.xor_byte(DATA_OFFSET + 0x28_000 + 511, 0x01);
        let bad_zfs_dev = BoundedRoFuzzDevice::new(
            bad_zfs.finish(),
            FuzzBudgetTracker::new(FuzzBudgets::default()),
            None,
        );
        let bad_zfs_opened = open_read_only_device(
            &cx,
            Arc::clone(&bad_zfs_dev) as Arc<dyn ByteDevice>,
            &ReadOnlyOpenOptions::default(),
        )
        .expect("dataset metadata intact before file block verification");
        let hello = bad_zfs_opened
            .filesystem
            .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("hello.txt"))
            .unwrap();
        assert!(
            bad_zfs_opened
                .filesystem
                .read(&cx, &mut scope, hello.ino, 0, 64)
                .is_err(),
            "planted ZFS final-byte corruption must fail checksum verification"
        );
        bad_zfs_dev.assert_invariants();

        // 5. Planted nested GPT-inside-GPT bomb fails closed on select_partition_device / open_read_only_device.
        let (gpt, gpt_digest) = gpt_multi_format_baseline();
        let mut nested_bomb = PatchBuilder::from_static(gpt, gpt_digest);
        // Copy outer protective MBR + primary GPT header into the start of partition 1 (LBA 64)!
        nested_bomb.write(64 * 512, &gpt[..2 * 512]);
        let bomb_dev = BoundedRoFuzzDevice::new(
            nested_bomb.finish(),
            FuzzBudgetTracker::new(FuzzBudgets::default()),
            None,
        );
        assert!(
            ffs::select_partition_device(
                &cx,
                Arc::clone(&bomb_dev) as Arc<dyn ByteDevice>,
                &PartitionSelector::Index(1),
                &ffs::PartitionParseOptions::default(),
                ffs_block::io_engine::VolumeAccess::ReadOnly,
            )
            .is_err(),
            "select_partition_device must reject truncated nested GPT header bomb directly"
        );
        assert!(
            open_read_only_device(
                &cx,
                Arc::clone(&bomb_dev) as Arc<dyn ByteDevice>,
                &ReadOnlyOpenOptions {
                    partition: Some(PartitionSelector::Index(1)),
                    ..ReadOnlyOpenOptions::default()
                },
            )
            .is_err(),
            "nested GPT table inside partition slice must be rejected"
        );
        bomb_dev.assert_invariants();
    }

    fn resolve_required_oracle_binary(candidates: &[&str]) -> std::result::Result<String, String> {
        for candidate in candidates {
            if candidate.starts_with('/') {
                if std::path::Path::new(candidate).is_file() {
                    return Ok((*candidate).to_owned());
                }
            } else if let Ok(output) = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("command -v {candidate}"))
                .output()
            {
                if output.status.success() {
                    let resolved = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                    if !resolved.is_empty() {
                        return Ok(resolved);
                    }
                }
            }
        }
        Err(format!(
            "required native oracle missing (searched {candidates:?}); soft-skip forbidden"
        ))
    }

    fn verify_campaign_gate_counts(
        multiformat_targets_present: usize,
        selected_tests: usize,
    ) -> std::result::Result<(), &'static str> {
        if multiformat_targets_present < 4 {
            return Err("missing required FAT/NTFS/ZFS/partition fuzz targets");
        }
        if selected_tests == 0 {
            return Err("zero selected tests must fail closed");
        }
        Ok(())
    }

    #[test]
    fn native_mkfs_fat_oracles_and_negative_controls_hold() {
        let cx = Cx::for_testing();

        // Planted negative controls: missing oracle, zero multi-format targets, and zero selected tests MUST fail!
        assert!(
            resolve_required_oracle_binary(&["__missing_oracle_bd_2tzok__"]).is_err(),
            "missing required oracle must fail closed rather than soft-skipping"
        );
        assert!(
            verify_campaign_gate_counts(0, 5).is_err(),
            "previous 0-multiformat-target defect must fail closed"
        );
        assert!(
            verify_campaign_gate_counts(4, 0).is_err(),
            "zero selected tests must fail closed"
        );
        assert!(verify_campaign_gate_counts(4, 3).is_ok());

        // Real native tool generation: mkfs.fat (FAT16 + FAT32) -> BoundedRoFuzzDevice -> open_read_only_device.
        let mkfs_fat =
            resolve_required_oracle_binary(&["/usr/sbin/mkfs.fat", "/sbin/mkfs.fat", "mkfs.fat"])
                .expect("mkfs.fat required for native FAT oracle verification");

        for (bits, size_mib, secs_per_clus, expected_fmt) in [
            ("16", 16_u64, "2", FsFormatKind::Fat16),
            ("32", 64_u64, "1", FsFormatKind::Fat32),
        ] {
            let fat_tmp = tempfile::NamedTempFile::new().expect("create temp FAT file");
            fat_tmp
                .as_file()
                .set_len(size_mib * 1024 * 1024)
                .expect("size temp FAT image");
            let status = std::process::Command::new(&mkfs_fat)
                .args([
                    "-F",
                    bits,
                    "-s",
                    secs_per_clus,
                    "-i",
                    "12345678",
                    "-n",
                    "FUZZNATIVE",
                ])
                .arg(fat_tmp.path())
                .status()
                .expect("invoke mkfs.fat");
            assert!(
                status.success(),
                "mkfs.fat -F {bits} failed with status {status}"
            );

            let native_fat_bytes = std::fs::read(fat_tmp.path()).expect("read native FAT image");
            let native_fat_hash = *blake3::hash(&native_fat_bytes).as_bytes();
            println!(
                "NATIVE_FAT_ORACLE|bits={bits}|tool={mkfs_fat}|bytes={}|blake3={}",
                native_fat_bytes.len(),
                blake3::Hash::from_bytes(native_fat_hash).to_hex()
            );

            let fat_dev = BoundedRoFuzzDevice::new(
                FuzzBacking::from_owned(native_fat_bytes.clone()),
                FuzzBudgetTracker::new(FuzzBudgets {
                    max_ops: 8_192,
                    ..FuzzBudgets::default()
                }),
                None,
            );
            let fat_vol = FatVolume::from_device(
                &cx,
                Box::new(Arc::clone(&fat_dev) as Arc<dyn ByteDevice>),
                0,
                fat_dev.len_bytes(),
            )
            .expect("admit native mkfs.fat image");
            assert!(fat_vol.check(&cx).expect("check native mkfs.fat").clean);
            let opened_fat = open_read_only_device(
                &cx,
                Arc::clone(&fat_dev) as Arc<dyn ByteDevice>,
                &ReadOnlyOpenOptions::default(),
            )
            .expect("open native mkfs.fat via facade");
            assert_eq!(opened_fat.format, expected_fmt);
            fat_dev.assert_invariants();

            if bits == "16" {
                // Embed the real mkfs.fat FAT16 volume into an MBR partition at LBA 64 and verify partitioned open!
                let start_lba = 64_u32;
                let sectors = u32::try_from(native_fat_bytes.len() / 512).unwrap();
                let mut mbr_disk = vec![0_u8; 64 * 512 + native_fat_bytes.len()];
                mbr_disk[440..444].copy_from_slice(&0x55AA_1234_u32.to_le_bytes());
                mbr_disk[446 + 4] = 0x0E;
                mbr_disk[446 + 8..446 + 12].copy_from_slice(&start_lba.to_le_bytes());
                mbr_disk[446 + 12..446 + 16].copy_from_slice(&sectors.to_le_bytes());
                mbr_disk[510] = 0x55;
                mbr_disk[511] = 0xAA;
                mbr_disk[64 * 512..].copy_from_slice(&native_fat_bytes);

                let disk_dev = BoundedRoFuzzDevice::new(
                    FuzzBacking::from_owned(mbr_disk),
                    FuzzBudgetTracker::new(FuzzBudgets::default()),
                    None,
                );
                let opened_part = open_read_only_device(
                    &cx,
                    Arc::clone(&disk_dev) as Arc<dyn ByteDevice>,
                    &ReadOnlyOpenOptions {
                        partition: Some(PartitionSelector::Index(1)),
                        ..ReadOnlyOpenOptions::default()
                    },
                )
                .expect("open partitioned native mkfs.fat image");
                assert_eq!(opened_part.format, FsFormatKind::Fat16);
                disk_dev.assert_invariants();
            }
        }
    }
}
