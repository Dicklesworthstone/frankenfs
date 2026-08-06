/// Number of page-lock shards to provision per available CPU.
pub const PAGE_LOCK_SHARDS_PER_CORE: usize = 4;
/// Minimum page-lock shard count.
pub const MIN_PAGE_LOCK_SHARDS: usize = 16;
/// Maximum page-lock shard count.
pub const MAX_PAGE_LOCK_SHARDS: usize = 1024;
const PAGE_LOCK_INLINE_CAPACITY: usize = 8;

#[derive(Debug)]
enum InFlightBlocks {
    Inline(Vec<BlockNumber>),
    Large(HashSet<BlockNumber>),
}

impl InFlightBlocks {
    fn new() -> Self {
        Self::Inline(Vec::with_capacity(PAGE_LOCK_INLINE_CAPACITY))
    }

    fn len(&self) -> usize {
        match self {
            Self::Inline(blocks) => blocks.len(),
            Self::Large(blocks) => blocks.len(),
        }
    }

    fn contains(&self, block: BlockNumber) -> bool {
        match self {
            Self::Inline(blocks) => blocks.contains(&block),
            Self::Large(blocks) => blocks.contains(&block),
        }
    }

    fn insert(&mut self, block: BlockNumber) -> bool {
        match self {
            Self::Inline(blocks) => {
                if blocks.contains(&block) {
                    return false;
                }
                if blocks.len() < PAGE_LOCK_INLINE_CAPACITY {
                    blocks.push(block);
                    return true;
                }

                let mut promoted = HashSet::with_capacity(PAGE_LOCK_INLINE_CAPACITY * 2);
                promoted.extend(blocks.drain(..));
                let inserted = promoted.insert(block);
                *self = Self::Large(promoted);
                inserted
            }
            Self::Large(blocks) => blocks.insert(block),
        }
    }

    fn remove(&mut self, block: BlockNumber) -> bool {
        match self {
            Self::Inline(blocks) => blocks
                .iter()
                .position(|existing| *existing == block)
                .map(|idx| blocks.swap_remove(idx))
                .is_some(),
            Self::Large(blocks) => {
                let removed = blocks.remove(&block);
                if blocks.len() <= PAGE_LOCK_INLINE_CAPACITY / 2 {
                    let mut demoted = Vec::with_capacity(PAGE_LOCK_INLINE_CAPACITY);
                    demoted.extend(blocks.drain());
                    *self = Self::Inline(demoted);
                }
                removed
            }
        }
    }
}

/// One shard of the cache miss page-lock table.
///
/// Wait protocol: a waiter holds `in_flight`, loops on the target block
/// membership predicate, increments `waiters` immediately before parking on
/// `ready`, and decrements after every wake before re-checking the predicate.
/// A permit drop must remove the block while holding `in_flight`, release that
/// mutex, then notify waiters so the cleared predicate is visible before wakeup.
struct PageLockShard {
    in_flight: Mutex<InFlightBlocks>,
    ready: Condvar,
    waiters: AtomicUsize,
}

impl PageLockShard {
    fn new() -> Self {
        Self {
            in_flight: Mutex::new(InFlightBlocks::new()),
            ready: Condvar::new(),
            waiters: AtomicUsize::new(0),
        }
    }
}

impl std::fmt::Debug for PageLockShard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageLockShard")
            .field("in_flight", &self.in_flight.lock().len())
            .finish_non_exhaustive()
    }
}

/// Sharded per-block miss coalescer for cache read misses.
///
/// The table serializes only concurrent cold reads for the same block. Distinct
/// blocks map to independent shards, so large readdir/readahead and metadata
/// walks can continue to exploit device-level parallelism while avoiding a
/// same-block stampede during hot metadata warm-up.
pub struct PageLockTable {
    shards: Vec<PageLockShard>,
}

impl PageLockTable {
    /// Create a page-lock table with a rounded, bounded shard count.
    #[must_use]
    pub fn new(shard_count: usize) -> Self {
        let shard_count = shard_count
            .clamp(1, MAX_PAGE_LOCK_SHARDS)
            .next_power_of_two();
        let shards = (0..shard_count).map(|_| PageLockShard::new()).collect();
        Self { shards }
    }

    /// Create a host-sized table (`available_parallelism * 4`, bounded).
    #[must_use]
    pub fn for_host_parallelism() -> Self {
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let shard_count = cores
            .saturating_mul(PAGE_LOCK_SHARDS_PER_CORE)
            .clamp(MIN_PAGE_LOCK_SHARDS, MAX_PAGE_LOCK_SHARDS);
        Self::new(shard_count)
    }

    /// Number of lock shards in the table.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Current number of blocks being loaded through this table.
    #[must_use]
    pub fn in_flight_len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.in_flight.lock().len())
            .sum()
    }

    fn acquire(&self, block: BlockNumber) -> PageLockPermit<'_> {
        let shard = &self.shards[self.shard_index(block)];
        let mut in_flight = shard.in_flight.lock();
        while in_flight.contains(block) {
            shard.waiters.fetch_add(1, Ordering::AcqRel);
            shard.ready.wait(&mut in_flight);
            shard.waiters.fetch_sub(1, Ordering::AcqRel);
        }
        let inserted = in_flight.insert(block);
        debug_assert!(inserted, "block should not already be in flight");
        drop(in_flight);
        PageLockPermit { shard, block }
    }

    fn shard_index(&self, block: BlockNumber) -> usize {
        let len = self.shards.len();
        let mixed = mix_block_number(block.0);
        let len_u64 = u64::try_from(len).unwrap_or(u64::MAX);
        let idx = if len.is_power_of_two() {
            mixed & len_u64.saturating_sub(1)
        } else {
            mixed % len_u64
        };
        usize::try_from(idx).unwrap_or(0)
    }
}

impl std::fmt::Debug for PageLockTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageLockTable")
            .field("shard_count", &self.shard_count())
            .field("in_flight", &self.in_flight_len())
            .finish()
    }
}

/// Held while a single block is being populated after a cache miss.
pub struct PageLockPermit<'a> {
    shard: &'a PageLockShard,
    block: BlockNumber,
}

impl Drop for PageLockPermit<'_> {
    fn drop(&mut self) {
        let mut in_flight = self.shard.in_flight.lock();
        let removed = in_flight.remove(self.block);
        drop(in_flight);
        if removed && self.shard.waiters.load(Ordering::Acquire) > 0 {
            self.shard.ready.notify_all();
        }
    }
}

#[inline]
fn mix_block_number(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "s3fifo", allow(dead_code))]
enum ArcList {
    T1,
    T2,
    B1,
    B2,
}

#[cfg(not(feature = "s3fifo"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CleanResidentEntry {
    recency: u64,
    block: BlockNumber,
}

#[cfg(not(feature = "s3fifo"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResidentRecency {
    list: ArcList,
    entry: CleanResidentEntry,
}

#[cfg(feature = "s3fifo")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct S3GhostEntry {
    key: BlockNumber,
    generation: u64,
}

#[cfg(feature = "s3fifo")]
type GhostQueueEntry = S3GhostEntry;

#[cfg(not(feature = "s3fifo"))]
type GhostQueueEntry = BlockNumber;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirtyState {
    InFlight,
    Committed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirtyEntry {
    seq: u64,
    bytes: usize,
    txn_id: TxnId,
    commit_seq: Option<CommitSeq>,
    state: DirtyState,
}

impl DirtyEntry {
    fn is_flushable(self) -> bool {
        matches!(self.state, DirtyState::Committed)
    }
}

#[derive(Debug, Clone)]
struct FlushCandidate {
    block: BlockNumber,
    data: BlockBuf,
    txn_id: TxnId,
    commit_seq: CommitSeq,
    /// Internal dirty-tracker sequence number at the time this candidate was captured.
    seq: u64,
}

/// Ordered tracking of dirty blocks with deterministic age semantics.
#[derive(Debug, Default)]
struct DirtyTracker {
    next_seq: u64,
    by_block: HashMap<BlockNumber, DirtyEntry>,
    by_age: BTreeSet<(u64, BlockNumber)>,
    dirty_bytes: usize,
}

impl DirtyTracker {
    fn mark_dirty(
        &mut self,
        block: BlockNumber,
        bytes: usize,
        txn_id: TxnId,
        commit_seq: Option<CommitSeq>,
        state: DirtyState,
    ) {
        if let Some(prev) = self.by_block.remove(&block) {
            let _ = self.by_age.remove(&(prev.seq, block));
            self.dirty_bytes = self.dirty_bytes.saturating_sub(prev.bytes);
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let entry = DirtyEntry {
            seq,
            bytes,
            txn_id,
            commit_seq,
            state,
        };
        self.by_block.insert(block, entry);
        self.by_age.insert((seq, block));
        self.dirty_bytes = self.dirty_bytes.saturating_add(bytes);
    }

    fn clear_dirty(&mut self, block: BlockNumber, seq: u64) {
        if let Some(entry) = self.by_block.get(&block).copied() {
            if entry.seq == seq {
                self.by_block.remove(&block);
                let _ = self.by_age.remove(&(entry.seq, block));
                self.dirty_bytes = self.dirty_bytes.saturating_sub(entry.bytes);
            }
        }
    }

    fn clear_dirty_unconditional(&mut self, block: BlockNumber) {
        if let Some(entry) = self.by_block.remove(&block) {
            let _ = self.by_age.remove(&(entry.seq, block));
            self.dirty_bytes = self.dirty_bytes.saturating_sub(entry.bytes);
        }
    }

    fn is_dirty(&self, block: BlockNumber) -> bool {
        self.by_block.contains_key(&block)
    }

    fn entry(&self, block: BlockNumber) -> Option<DirtyEntry> {
        self.by_block.get(&block).copied()
    }

    fn dirty_count(&self) -> usize {
        self.by_block.len()
    }

    fn dirty_bytes(&self) -> usize {
        self.dirty_bytes
    }

    fn oldest_dirty_age_ticks(&self) -> Option<u64> {
        self.by_age
            .iter()
            .next()
            .map(|(oldest_seq, _)| self.next_seq.saturating_sub(*oldest_seq))
    }

    fn dirty_blocks_oldest_first(&self) -> Vec<BlockNumber> {
        self.by_age.iter().map(|(_, block)| *block).collect()
    }

    fn state_counts(&self) -> (usize, usize) {
        let mut in_flight = 0_usize;
        let mut committed = 0_usize;
        for entry in self.by_block.values() {
            match entry.state {
                DirtyState::InFlight => in_flight += 1,
                DirtyState::Committed => committed += 1,
            }
        }
        (in_flight, committed)
    }

    fn flushable_count(&self) -> usize {
        let (_, committed) = self.state_counts();
        committed
    }
}

#[cfg(feature = "s3fifo")]
const S3_FAST_HIT_MAX_SLOTS: usize = 4096;

#[cfg(feature = "s3fifo")]
const S3_THREAD_FAST_HIT_SLOTS: usize = 256;

#[cfg(feature = "s3fifo")]
static S3_FAST_CACHE_IDS: AtomicU64 = AtomicU64::new(1);

#[cfg(feature = "s3fifo")]
thread_local! {
    static S3_THREAD_FAST_RESIDENTS: RefCell<S3ThreadFastResidentSlab> =
        RefCell::new(S3ThreadFastResidentSlab::new());
}

#[cfg(feature = "s3fifo")]
fn next_s3_fast_cache_id() -> u64 {
    S3_FAST_CACHE_IDS.fetch_add(1, Ordering::Relaxed)
}

#[cfg(feature = "s3fifo")]
#[derive(Debug)]
struct S3AccessHandle {
    count: AtomicU8,
    valid: AtomicBool,
}

#[cfg(feature = "s3fifo")]
impl S3AccessHandle {
    fn new(count: u8) -> Arc<Self> {
        Arc::new(Self {
            count: AtomicU8::new(count),
            valid: AtomicBool::new(true),
        })
    }

    fn load_count(&self) -> u8 {
        self.count.load(Ordering::Relaxed)
    }

    fn store_count(&self, count: u8) {
        self.count.store(count, Ordering::Relaxed);
    }

    fn increment_count(&self) -> u8 {
        let mut current = self.count.load(Ordering::Relaxed);
        loop {
            if current == u8::MAX {
                return current;
            }
            let next = current.saturating_add(1);
            match self.count.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
    }

    fn invalidate(&self) {
        self.valid.store(false, Ordering::Release);
    }

    fn is_valid(&self) -> bool {
        self.valid.load(Ordering::Acquire)
    }
}

#[cfg(feature = "s3fifo")]
#[derive(Debug, Clone)]
struct S3FastResident {
    data: BlockBuf,
    access: Arc<S3AccessHandle>,
}

#[cfg(feature = "s3fifo")]
#[derive(Debug, Clone)]
struct S3ThreadFastResident {
    cache_id: u64,
    block: BlockNumber,
    epoch: u64,
    data: BlockBuf,
    access: Arc<S3AccessHandle>,
}

#[cfg(feature = "s3fifo")]
#[derive(Debug)]
struct S3ThreadFastResidentSlab {
    slots: Vec<Option<S3ThreadFastResident>>,
}

#[cfg(feature = "s3fifo")]
impl S3ThreadFastResidentSlab {
    fn new() -> Self {
        Self {
            slots: vec![None; S3_THREAD_FAST_HIT_SLOTS],
        }
    }

    fn slot_index(block: BlockNumber) -> usize {
        let mask = u64::try_from(S3_THREAD_FAST_HIT_SLOTS - 1).unwrap_or(u64::MAX);
        usize::try_from(block.0 & mask).unwrap_or(0)
    }

    fn get_valid(
        &self,
        cache_id: u64,
        block: BlockNumber,
        epoch: u64,
    ) -> Option<(BlockBuf, Arc<S3AccessHandle>)> {
        let slot = Self::slot_index(block);
        self.slots[slot].as_ref().and_then(|entry| {
            (entry.cache_id == cache_id
                && entry.block == block
                && entry.epoch == epoch
                && entry.access.is_valid())
            .then(|| (entry.data.clone_ref(), Arc::clone(&entry.access)))
        })
    }

    fn insert(&mut self, cache_id: u64, block: BlockNumber, epoch: u64, resident: S3FastResident) {
        let slot = Self::slot_index(block);
        self.slots[slot] = Some(S3ThreadFastResident {
            cache_id,
            block,
            epoch,
            data: resident.data,
            access: resident.access,
        });
    }
}

#[cfg(feature = "s3fifo")]
#[derive(Debug)]
struct S3FastResidentTable {
    slots: Vec<RwLock<Option<(BlockNumber, S3FastResident)>>>,
    slot_mask: u64,
}

#[cfg(feature = "s3fifo")]
impl S3FastResidentTable {
    fn for_capacity(capacity_blocks: usize) -> Self {
        let target_slots = capacity_blocks
            .saturating_mul(2)
            .clamp(1, S3_FAST_HIT_MAX_SLOTS);
        let slot_count = target_slots
            .checked_next_power_of_two()
            .unwrap_or(S3_FAST_HIT_MAX_SLOTS)
            .min(S3_FAST_HIT_MAX_SLOTS);
        Self::new(slot_count)
    }

    fn new(slot_count: usize) -> Self {
        let slot_count = slot_count.max(1).next_power_of_two();
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            slots.push(RwLock::new(None));
        }
        let slot_mask = u64::try_from(slot_count - 1).unwrap_or(u64::MAX);
        Self { slots, slot_mask }
    }

    fn slot_index(&self, block: BlockNumber) -> usize {
        usize::try_from(block.0 & self.slot_mask).unwrap_or(0)
    }

    fn get_valid(&self, block: BlockNumber) -> Option<S3FastResident> {
        let slot = &self.slots[self.slot_index(block)];
        let guard = slot.read();
        let entry = guard.as_ref().and_then(|(resident_block, entry)| {
            (*resident_block == block && entry.access.is_valid()).then(|| entry.clone())
        });
        drop(guard);
        entry
    }

    fn insert(&self, block: BlockNumber, entry: S3FastResident) {
        let slot = &self.slots[self.slot_index(block)];
        *slot.write() = Some((block, entry));
    }

    fn remove(&self, block: BlockNumber) {
        let slot = &self.slots[self.slot_index(block)];
        let mut guard = slot.write();
        if let Some((resident_block, entry)) = guard.take() {
            if resident_block == block {
                entry.access.invalidate();
            } else {
                *guard = Some((resident_block, entry));
            }
        }
    }
}

#[cfg(feature = "s3fifo")]
#[repr(align(64))]
#[derive(Debug)]
struct S3FastHitStripe {
    hits: AtomicU64,
}

#[cfg(feature = "s3fifo")]
impl S3FastHitStripe {
    fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
        }
    }
}

#[cfg(feature = "s3fifo")]
#[derive(Debug)]
struct S3FastHitCounter {
    stripes: Vec<S3FastHitStripe>,
    stripe_mask: u64,
}

#[cfg(feature = "s3fifo")]
impl S3FastHitCounter {
    fn for_capacity(capacity_blocks: usize) -> Self {
        let target_stripes = capacity_blocks
            .saturating_mul(2)
            .clamp(1, S3_FAST_HIT_MAX_SLOTS);
        let stripe_count = target_stripes
            .checked_next_power_of_two()
            .unwrap_or(S3_FAST_HIT_MAX_SLOTS)
            .min(S3_FAST_HIT_MAX_SLOTS);
        Self::new(stripe_count)
    }

    fn new(stripe_count: usize) -> Self {
        let stripe_count = stripe_count.max(1).next_power_of_two();
        let mut stripes = Vec::with_capacity(stripe_count);
        for _ in 0..stripe_count {
            stripes.push(S3FastHitStripe::new());
        }
        let stripe_mask = u64::try_from(stripe_count - 1).unwrap_or(u64::MAX);
        Self {
            stripes,
            stripe_mask,
        }
    }

    fn stripe_index(&self, block: BlockNumber) -> usize {
        usize::try_from(block.0 & self.stripe_mask).unwrap_or(0)
    }

    fn increment(&self, block: BlockNumber) {
        self.stripes[self.stripe_index(block)]
            .hits
            .fetch_add(1, Ordering::Relaxed);
    }

    fn total(&self, ordering: Ordering) -> u64 {
        self.stripes.iter().fold(0_u64, |total, stripe| {
            total.saturating_add(stripe.hits.load(ordering))
        })
    }
}

#[cfg(feature = "s3fifo")]
#[derive(Debug)]
struct S3FastMutationGuard<'a> {
    active: &'a AtomicUsize,
    epoch: &'a AtomicU64,
}

#[cfg(feature = "s3fifo")]
impl Drop for S3FastMutationGuard<'_> {
    fn drop(&mut self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.active.fetch_sub(1, Ordering::Release);
    }
}

#[derive(Debug)]
struct ArcState {
    /// Active target capacity in blocks (may be reduced under pressure).
    capacity: usize,
    /// Nominal maximum capacity configured at cache creation.
    max_capacity: usize,
    /// Last applied memory pressure level.
    pressure_level: MemoryPressure,
    /// Target size for the T1 list.
    #[cfg(not(feature = "s3fifo"))]
    p: usize,
    t1: VecDeque<BlockNumber>,
    t2: VecDeque<BlockNumber>,
    b1: VecDeque<GhostQueueEntry>,
    b2: VecDeque<GhostQueueEntry>,
    #[cfg(feature = "s3fifo")]
    b1_live_len: usize,
    #[cfg(feature = "s3fifo")]
    b2_live_len: usize,
    #[cfg(feature = "s3fifo")]
    ghost_generations: HashMap<BlockNumber, u64>,
    #[cfg(feature = "s3fifo")]
    next_ghost_generation: u64,
    loc: HashMap<BlockNumber, ArcList>,
    resident: HashMap<BlockNumber, BlockBuf>,
    #[cfg(not(feature = "s3fifo"))]
    resident_recency: HashMap<BlockNumber, ResidentRecency>,
    #[cfg(not(feature = "s3fifo"))]
    clean_t1: BTreeSet<CleanResidentEntry>,
    #[cfg(not(feature = "s3fifo"))]
    clean_t2: BTreeSet<CleanResidentEntry>,
    #[cfg(not(feature = "s3fifo"))]
    next_recency: u64,
    /// Ordered dirty block tracking for write-back and durability accounting.
    dirty: DirtyTracker,
    /// Dirty payloads queued for retry after a failed flush attempt.
    pending_flush: Vec<FlushCandidate>,
    /// Staged, not-yet-committed transactional payloads.
    staged_txn_writes: HashMap<TxnId, HashMap<BlockNumber, Vec<u8>>>,
    /// Reverse map for staged payload ownership checks.
    staged_block_owner: HashMap<BlockNumber, TxnId>,
    /// Monotonic hit counter (resident data found).
    hits: u64,
    /// Monotonic miss counter (device read required).
    misses: u64,
    /// Monotonic eviction counter (resident block displaced).
    evictions: u64,
    /// Monotonic dirty flush counter (dirty blocks written during sync/retry paths).
    dirty_flushes: u64,
    /// Monotonic B1 ghost hit counter (re-admissions from T1 ghost list).
    b1_ghost_hits: u64,
    /// Monotonic B2 ghost hit counter (re-admissions from T2 ghost list).
    b2_ghost_hits: u64,
    #[cfg(feature = "s3fifo")]
    small_capacity: usize,
    #[cfg(feature = "s3fifo")]
    main_capacity: usize,
    #[cfg(feature = "s3fifo")]
    ghost_capacity: usize,
    #[cfg(feature = "s3fifo")]
    last_read_miss: Option<BlockNumber>,
    #[cfg(feature = "s3fifo")]
    sequential_read_miss_streak: u8,
    #[cfg(feature = "s3fifo")]
    access_count: HashMap<BlockNumber, Arc<S3AccessHandle>>,
    #[cfg(feature = "s3fifo")]
    fast_invalidations: Vec<BlockNumber>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PressureEvictionBatch {
    evicted_blocks: usize,
    evicted_bytes: usize,
}

impl ArcState {
    #[cfg(feature = "s3fifo")]
    fn s3_capacity_split(capacity: usize) -> (usize, usize, usize) {
        let (small_capacity, main_capacity) = if capacity <= 1 {
            (1, 0)
        } else if capacity <= 4 {
            // Tiny caches need relaxed split targets; otherwise S3-FIFO
            // under-fills and violates generic cache warm-up expectations.
            (capacity, capacity)
        } else {
            let small = (capacity / 10).max(1).min(capacity - 1);
            let main = capacity.saturating_sub(small);
            (small, main)
        };
        let ghost_capacity = capacity.max(1);
        (small_capacity, main_capacity, ghost_capacity)
    }

    fn new(capacity: usize) -> Self {
        #[cfg(feature = "s3fifo")]
        let (small_capacity, main_capacity, ghost_capacity) = Self::s3_capacity_split(capacity);
        Self {
            capacity,
            max_capacity: capacity,
            pressure_level: MemoryPressure::None,
            #[cfg(not(feature = "s3fifo"))]
            p: 0,
            t1: VecDeque::new(),
            t2: VecDeque::new(),
            b1: VecDeque::new(),
            b2: VecDeque::new(),
            #[cfg(feature = "s3fifo")]
            b1_live_len: 0,
            #[cfg(feature = "s3fifo")]
            b2_live_len: 0,
            #[cfg(feature = "s3fifo")]
            ghost_generations: HashMap::new(),
            #[cfg(feature = "s3fifo")]
            next_ghost_generation: 1,
            loc: HashMap::new(),
            resident: HashMap::new(),
            #[cfg(not(feature = "s3fifo"))]
            resident_recency: HashMap::new(),
            #[cfg(not(feature = "s3fifo"))]
            clean_t1: BTreeSet::new(),
            #[cfg(not(feature = "s3fifo"))]
            clean_t2: BTreeSet::new(),
            #[cfg(not(feature = "s3fifo"))]
            next_recency: 0,
            dirty: DirtyTracker::default(),
            pending_flush: Vec::new(),
            staged_txn_writes: HashMap::new(),
            staged_block_owner: HashMap::new(),
            hits: 0,
            misses: 0,
            evictions: 0,
            dirty_flushes: 0,
            b1_ghost_hits: 0,
            b2_ghost_hits: 0,
            #[cfg(feature = "s3fifo")]
            small_capacity,
            #[cfg(feature = "s3fifo")]
            main_capacity,
            #[cfg(feature = "s3fifo")]
            ghost_capacity,
            #[cfg(feature = "s3fifo")]
            last_read_miss: None,
            #[cfg(feature = "s3fifo")]
            sequential_read_miss_streak: 0,
            #[cfg(feature = "s3fifo")]
            access_count: HashMap::new(),
            #[cfg(feature = "s3fifo")]
            fast_invalidations: Vec::new(),
        }
    }

    fn increment_counter(counter: &mut u64) {
        *counter = counter.saturating_add(1);
    }

    fn add_usize_to_counter(counter: &mut u64, delta: usize) {
        let delta = u64::try_from(delta).unwrap_or(u64::MAX);
        *counter = counter.saturating_add(delta);
    }

    #[cfg(not(feature = "s3fifo"))]
    fn next_clean_recency(&mut self) -> u64 {
        let recency = self.next_recency;
        self.next_recency = self.next_recency.saturating_add(1);
        recency
    }

    #[cfg(not(feature = "s3fifo"))]
    fn remove_clean_entry(&mut self, recency: ResidentRecency) {
        match recency.list {
            ArcList::T1 => {
                let _ = self.clean_t1.remove(&recency.entry);
            }
            ArcList::T2 => {
                let _ = self.clean_t2.remove(&recency.entry);
            }
            ArcList::B1 | ArcList::B2 => {}
        }
    }

    #[cfg(not(feature = "s3fifo"))]
    fn insert_clean_entry(&mut self, recency: ResidentRecency) {
        if self.is_dirty(recency.entry.block) {
            return;
        }
        match recency.list {
            ArcList::T1 => {
                self.clean_t1.insert(recency.entry);
            }
            ArcList::T2 => {
                self.clean_t2.insert(recency.entry);
            }
            ArcList::B1 | ArcList::B2 => {}
        }
    }

    #[cfg(not(feature = "s3fifo"))]
    fn remove_resident_recency(&mut self, block: BlockNumber) {
        if let Some(recency) = self.resident_recency.remove(&block) {
            self.remove_clean_entry(recency);
        }
    }

    #[cfg(not(feature = "s3fifo"))]
    fn track_resident_recency(&mut self, block: BlockNumber, list: ArcList) {
        self.remove_resident_recency(block);
        let recency = ResidentRecency {
            list,
            entry: CleanResidentEntry {
                recency: self.next_clean_recency(),
                block,
            },
        };
        self.resident_recency.insert(block, recency);
        self.insert_clean_entry(recency);
    }

    #[cfg(not(feature = "s3fifo"))]
    fn remove_clean_resident(&mut self, block: BlockNumber) {
        if let Some(recency) = self.resident_recency.get(&block).copied() {
            self.remove_clean_entry(recency);
        }
    }

    #[cfg(not(feature = "s3fifo"))]
    fn refresh_clean_resident(&mut self, block: BlockNumber) {
        if let Some(recency) = self.resident_recency.get(&block).copied() {
            self.insert_clean_entry(recency);
        }
    }

    #[cfg(not(feature = "s3fifo"))]
    fn oldest_clean_resident(&self, list: ArcList) -> Option<BlockNumber> {
        match list {
            ArcList::T1 => self.clean_t1.first().map(|entry| entry.block),
            ArcList::T2 => self.clean_t2.first().map(|entry| entry.block),
            ArcList::B1 | ArcList::B2 => None,
        }
    }

    #[cfg(feature = "s3fifo")]
    fn s3_access_count(&self, key: BlockNumber) -> u8 {
        self.access_count
            .get(&key)
            .map_or(0, |handle| handle.load_count())
    }

    #[cfg(feature = "s3fifo")]
    fn increment_s3_access_count(&mut self, key: BlockNumber) -> u8 {
        if let Some(handle) = self.access_count.get(&key) {
            return handle.increment_count();
        }
        let _ = self.access_count.insert(key, S3AccessHandle::new(1));
        1
    }

    #[cfg(feature = "s3fifo")]
    fn take_fast_invalidations(&mut self) -> Vec<BlockNumber> {
        std::mem::take(&mut self.fast_invalidations)
    }

    fn resident_len(&self) -> usize {
        self.t1.len() + self.t2.len()
    }

    fn b1_len(&self) -> usize {
        #[cfg(feature = "s3fifo")]
        {
            self.b1_live_len
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            self.b1.len()
        }
    }

    fn b2_len(&self) -> usize {
        #[cfg(feature = "s3fifo")]
        {
            self.b2_live_len
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            self.b2.len()
        }
    }

    #[cfg(not(feature = "s3fifo"))]
    fn total_len(&self) -> usize {
        self.t1.len() + self.t2.len() + self.b1.len() + self.b2.len()
    }

    fn snapshot_metrics(&self) -> CacheMetrics {
        CacheMetrics {
            hits: self.hits,
            misses: self.misses,
            evictions: self.evictions,
            dirty_flushes: self.dirty_flushes,
            t1_len: self.t1.len(),
            t2_len: self.t2.len(),
            b1_len: self.b1_len(),
            b2_len: self.b2_len(),
            resident: self.resident_len(),
            dirty_blocks: self.dirty.dirty_count(),
            dirty_bytes: self.dirty.dirty_bytes(),
            writeback_queue_depth: self.dirty.flushable_count(),
            oldest_dirty_age_ticks: self.dirty.oldest_dirty_age_ticks(),
            capacity: self.capacity,
            p: {
                #[cfg(feature = "s3fifo")]
                {
                    0
                }
                #[cfg(not(feature = "s3fifo"))]
                {
                    self.p
                }
            },
            b1_ghost_hits: self.b1_ghost_hits,
            b2_ghost_hits: self.b2_ghost_hits,
        }
    }

    fn pressure_report(&self) -> CachePressureReport {
        let total_accesses = self.hits.saturating_add(self.misses);
        let eviction_rate = if total_accesses == 0 {
            0.0
        } else {
            self.evictions as f64 / total_accesses as f64
        };
        CachePressureReport {
            current_size: self.resident_len(),
            target_size: self.capacity,
            dirty_count: self.dirty.dirty_count(),
            eviction_rate,
        }
    }

    fn set_pressure_level(&mut self, pressure: MemoryPressure) {
        self.pressure_level = pressure;
        let target = pressure.target_capacity(self.max_capacity);
        self.set_target_capacity(target);
    }

    fn restore_target_capacity(&mut self) {
        self.set_target_capacity(self.max_capacity);
    }

    fn set_target_capacity(&mut self, target: usize) {
        self.capacity = target.clamp(1, self.max_capacity);
    }

    fn trim_to_capacity(&mut self) -> PressureEvictionBatch {
        let mut batch = PressureEvictionBatch::default();
        // Single O(N) forward pass over t1 (ghost B1) then t2 (ghost B2): evict
        // clean blocks in FIFO order until back under capacity. The previous loop
        // re-scanned past the dirty prefix on every eviction — `next_pressure_victim`
        // and `remove_from_list` are each O(N) and ran per evicted block, so a long
        // dirty front made trimming O(N^2). Draining each queue once keeps non-evicted
        // (dirty / not-yet-reached) blocks in their original relative order, so the
        // resulting queues, ghost pushes, and batch totals are byte-identical to the
        // per-victim loop. `evict_resident` only fails on dirty blocks, which are
        // skipped here, so the dirty-race break below is unreachable but preserved.
        let mut resident = self.resident_len();
        for (queue_is_t1, ghost) in [(true, ArcList::B1), (false, ArcList::B2)] {
            if resident <= self.capacity {
                break;
            }
            let queue = std::mem::take(if queue_is_t1 {
                &mut self.t1
            } else {
                &mut self.t2
            });
            let mut kept = VecDeque::with_capacity(queue.len());
            let mut drain = queue.into_iter();
            for victim in drain.by_ref() {
                if resident <= self.capacity {
                    kept.push_back(victim);
                    break;
                }
                if self.is_dirty(victim) {
                    kept.push_back(victim);
                    continue;
                }
                let freed_bytes = self.resident.get(&victim).map_or(0, BlockBuf::len);
                if self.evict_resident(victim) {
                    self.push_ghost(victim, ghost);
                    self.evictions = self.evictions.saturating_add(1);
                    batch.evicted_blocks = batch.evicted_blocks.saturating_add(1);
                    batch.evicted_bytes = batch.evicted_bytes.saturating_add(freed_bytes);
                    resident -= 1;
                } else {
                    // Unreachable (victim is clean); mirror the original dirty-race
                    // tolerance: re-queue and stop shrinking until flush catches up.
                    kept.push_back(victim);
                    self.loc.insert(
                        victim,
                        if queue_is_t1 {
                            ArcList::T1
                        } else {
                            ArcList::T2
                        },
                    );
                    kept.extend(drain);
                    if queue_is_t1 {
                        self.t1 = kept;
                    } else {
                        self.t2 = kept;
                    }
                    self.trim_ghosts_to(self.capacity);
                    return batch;
                }
            }
            kept.extend(drain);
            if queue_is_t1 {
                self.t1 = kept;
            } else {
                self.t2 = kept;
            }
        }
        self.trim_ghosts_to(self.capacity);
        batch
    }

    fn remove_from_list(list: &mut VecDeque<BlockNumber>, key: BlockNumber) -> bool {
        if let Some(pos) = list.iter().position(|k| *k == key) {
            let _ = list.remove(pos);
            return true;
        }
        false
    }

    #[cfg(feature = "s3fifo")]
    fn live_ghost_entry(&self, entry: S3GhostEntry, list: ArcList) -> bool {
        matches!(self.loc.get(&entry.key), Some(current) if *current == list)
            && self
                .ghost_generations
                .get(&entry.key)
                .is_some_and(|generation| *generation == entry.generation)
    }

    #[cfg(feature = "s3fifo")]
    fn should_compact_ghost_queue(physical_len: usize, live_len: usize, capacity: usize) -> bool {
        let stale_len = physical_len.saturating_sub(live_len);
        stale_len > capacity / 2 && physical_len > live_len.saturating_mul(2)
    }

    #[cfg(feature = "s3fifo")]
    fn compact_b1_ghosts(&mut self) {
        let old = std::mem::take(&mut self.b1);
        let mut compact = VecDeque::with_capacity(self.b1_live_len);
        let mut live_len = 0_usize;
        for entry in old {
            if self.live_ghost_entry(entry, ArcList::B1) {
                compact.push_back(entry);
                live_len = live_len.saturating_add(1);
            }
        }
        self.b1 = compact;
        self.b1_live_len = live_len;
    }

    #[cfg(feature = "s3fifo")]
    fn compact_b2_ghosts(&mut self) {
        let old = std::mem::take(&mut self.b2);
        let mut compact = VecDeque::with_capacity(self.b2_live_len);
        let mut live_len = 0_usize;
        for entry in old {
            if self.live_ghost_entry(entry, ArcList::B2) {
                compact.push_back(entry);
                live_len = live_len.saturating_add(1);
            }
        }
        self.b2 = compact;
        self.b2_live_len = live_len;
    }

    #[cfg(feature = "s3fifo")]
    fn compact_ghosts_if_sparse(&mut self, list: ArcList) {
        match list {
            ArcList::B1
                if Self::should_compact_ghost_queue(
                    self.b1.len(),
                    self.b1_live_len,
                    self.ghost_capacity,
                ) =>
            {
                self.compact_b1_ghosts();
            }
            ArcList::B2
                if Self::should_compact_ghost_queue(
                    self.b2.len(),
                    self.b2_live_len,
                    self.ghost_capacity,
                ) =>
            {
                self.compact_b2_ghosts();
            }
            ArcList::T1 | ArcList::T2 | ArcList::B1 | ArcList::B2 => {}
        }
    }

    #[cfg(feature = "s3fifo")]
    fn next_ghost_entry(&mut self, key: BlockNumber) -> S3GhostEntry {
        let generation = self.next_ghost_generation;
        self.next_ghost_generation = self.next_ghost_generation.saturating_add(1);
        let _ = self.ghost_generations.insert(key, generation);
        S3GhostEntry { key, generation }
    }

    #[cfg(all(feature = "s3fifo", test))]
    fn b1_live_keys(&self) -> impl Iterator<Item = BlockNumber> + '_ {
        self.b1
            .iter()
            .copied()
            .filter(|entry| self.live_ghost_entry(*entry, ArcList::B1))
            .map(|entry| entry.key)
    }

    #[cfg(all(feature = "s3fifo", test))]
    fn b2_live_keys(&self) -> impl Iterator<Item = BlockNumber> + '_ {
        self.b2
            .iter()
            .copied()
            .filter(|entry| self.live_ghost_entry(*entry, ArcList::B2))
            .map(|entry| entry.key)
    }

    #[cfg(all(feature = "s3fifo", test))]
    fn b1_front_live(&self) -> Option<BlockNumber> {
        self.b1_live_keys().next()
    }

    #[cfg(all(feature = "s3fifo", test))]
    fn b1_contains_live(&self, key: BlockNumber) -> bool {
        self.b1_live_keys().any(|entry| entry == key)
    }

    fn push_ghost(&mut self, key: BlockNumber, list: ArcList) {
        match list {
            ArcList::B1 => {
                #[cfg(feature = "s3fifo")]
                {
                    let _ = self.remove_live_ghost(key);
                    let entry = self.next_ghost_entry(key);
                    self.b1.push_back(entry);
                    self.b1_live_len = self.b1_live_len.saturating_add(1);
                }
                #[cfg(not(feature = "s3fifo"))]
                {
                    self.b1.push_back(key);
                }
                self.loc.insert(key, ArcList::B1);
            }
            ArcList::B2 => {
                #[cfg(feature = "s3fifo")]
                {
                    let _ = self.remove_live_ghost(key);
                    let entry = self.next_ghost_entry(key);
                    self.b2.push_back(entry);
                    self.b2_live_len = self.b2_live_len.saturating_add(1);
                }
                #[cfg(not(feature = "s3fifo"))]
                {
                    self.b2.push_back(key);
                }
                self.loc.insert(key, ArcList::B2);
            }
            ArcList::T1 | ArcList::T2 => {}
        }
    }

    #[cfg(feature = "s3fifo")]
    fn remove_live_ghost(&mut self, key: BlockNumber) -> bool {
        match self.loc.get(&key).copied() {
            Some(ArcList::B1) => {
                self.b1_live_len = self.b1_live_len.saturating_sub(1);
                let _ = self.ghost_generations.remove(&key);
                let _ = self.loc.remove(&key);
                self.compact_ghosts_if_sparse(ArcList::B1);
                true
            }
            Some(ArcList::B2) => {
                self.b2_live_len = self.b2_live_len.saturating_sub(1);
                let _ = self.ghost_generations.remove(&key);
                let _ = self.loc.remove(&key);
                self.compact_ghosts_if_sparse(ArcList::B2);
                true
            }
            Some(ArcList::T1 | ArcList::T2) | None => false,
        }
    }

    fn pop_b1_front(&mut self) -> Option<BlockNumber> {
        #[cfg(feature = "s3fifo")]
        {
            while let Some(victim) = self.b1.pop_front() {
                if self.live_ghost_entry(victim, ArcList::B1) {
                    self.b1_live_len = self.b1_live_len.saturating_sub(1);
                    let _ = self.ghost_generations.remove(&victim.key);
                    let _ = self.loc.remove(&victim.key);
                    return Some(victim.key);
                }
            }
            self.b1_live_len = 0;
            None
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            self.b1.pop_front().inspect(|victim| {
                let _ = self.loc.remove(victim);
            })
        }
    }

    fn pop_b2_front(&mut self) -> Option<BlockNumber> {
        #[cfg(feature = "s3fifo")]
        {
            while let Some(victim) = self.b2.pop_front() {
                if self.live_ghost_entry(victim, ArcList::B2) {
                    self.b2_live_len = self.b2_live_len.saturating_sub(1);
                    let _ = self.ghost_generations.remove(&victim.key);
                    let _ = self.loc.remove(&victim.key);
                    return Some(victim.key);
                }
            }
            self.b2_live_len = 0;
            None
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            self.b2.pop_front().inspect(|victim| {
                let _ = self.loc.remove(victim);
            })
        }
    }

    fn trim_ghosts_to(&mut self, capacity: usize) {
        while self.b1_len() > capacity {
            let _ = self.pop_b1_front();
        }
        while self.b2_len() > capacity {
            let _ = self.pop_b2_front();
        }
    }

    fn remove_ghost_block(&mut self, key: BlockNumber) -> bool {
        #[cfg(feature = "s3fifo")]
        {
            self.remove_live_ghost(key)
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            let removed = Self::remove_from_list(&mut self.b1, key)
                | Self::remove_from_list(&mut self.b2, key);
            if removed {
                let _ = self.loc.remove(&key);
            }
            removed
        }
    }

    fn evict_resident(&mut self, victim: BlockNumber) -> bool {
        if self.is_dirty(victim) {
            let metrics = self.snapshot_metrics();
            warn!(
                event = "dirty_evict_attempt",
                block = victim.0,
                dirty_blocks = metrics.dirty_blocks,
                dirty_bytes = metrics.dirty_bytes,
                dirty_ratio = metrics.dirty_ratio(),
                oldest_dirty_age_ticks = metrics.oldest_dirty_age_ticks.unwrap_or(0),
                "dirty block cannot be evicted before flush"
            );
            return false;
        }
        #[cfg(not(feature = "s3fifo"))]
        self.remove_resident_recency(victim);
        let _ = self.resident.remove(&victim);
        #[cfg(feature = "s3fifo")]
        {
            if let Some(handle) = self.access_count.remove(&victim) {
                handle.invalidate();
                self.fast_invalidations.push(victim);
            }
        }
        self.clear_dirty_unconditional(victim);
        trace!(event = "cache_evict_clean", block = victim.0);
        true
    }

    #[cfg(not(feature = "s3fifo"))]
    fn touch_mru(&mut self, key: BlockNumber) {
        let Some(list) = self.loc.get(&key).copied() else {
            return;
        };

        match list {
            ArcList::T1 => {
                let _ = Self::remove_from_list(&mut self.t1, key);
                self.t2.push_back(key);
                self.loc.insert(key, ArcList::T2);
                self.track_resident_recency(key, ArcList::T2);
            }
            ArcList::T2 => {
                let _ = Self::remove_from_list(&mut self.t2, key);
                self.t2.push_back(key);
                self.track_resident_recency(key, ArcList::T2);
            }
            ArcList::B1 | ArcList::B2 => {}
        }
    }

    #[cfg(not(feature = "s3fifo"))]
    fn replace(&mut self, incoming: BlockNumber) {
        // `replace()` is only meaningful when the resident set is full.
        // Guard against accidental calls during warm-up, which would cause
        // premature eviction and underutilize the cache.
        if self.resident_len() < self.capacity {
            return;
        }

        let t1_len = self.t1.len();
        let target_t1 = t1_len >= 1
            && (t1_len > self.p
                || (matches!(self.loc.get(&incoming), Some(ArcList::B2)) && t1_len == self.p));

        let mut victim = None;
        let mut from_t1 = target_t1;

        if from_t1 {
            if let Some(block) = self.oldest_clean_resident(ArcList::T1) {
                if Self::remove_from_list(&mut self.t1, block) {
                    victim = Some(block);
                }
            } else if let Some(block) = self.oldest_clean_resident(ArcList::T2)
                && Self::remove_from_list(&mut self.t2, block)
            {
                victim = Some(block);
                from_t1 = false;
            }
        } else {
            if let Some(block) = self.oldest_clean_resident(ArcList::T2) {
                if Self::remove_from_list(&mut self.t2, block) {
                    victim = Some(block);
                }
            } else if let Some(block) = self.oldest_clean_resident(ArcList::T1)
                && Self::remove_from_list(&mut self.t1, block)
            {
                victim = Some(block);
                from_t1 = true;
            }
        }

        if let Some(victim) = victim {
            if self.evict_resident(victim) {
                if from_t1 {
                    self.loc.insert(victim, ArcList::B1);
                    self.b1.push_back(victim);
                } else {
                    self.loc.insert(victim, ArcList::B2);
                    self.b2.push_back(victim);
                }
                Self::increment_counter(&mut self.evictions);
            } else if from_t1 {
                self.t1.push_back(victim);
                self.loc.insert(victim, ArcList::T1);
            } else {
                self.t2.push_back(victim);
                self.loc.insert(victim, ArcList::T2);
            }
        }

        while self.b1.len() > self.capacity {
            if let Some(victim) = self.b1.pop_front() {
                let _ = self.loc.remove(&victim);
            }
        }
        while self.b2.len() > self.capacity {
            if let Some(victim) = self.b2.pop_front() {
                let _ = self.loc.remove(&victim);
            }
        }
    }

    fn on_hit(&mut self, key: BlockNumber) {
        Self::increment_counter(&mut self.hits);
        #[cfg(feature = "s3fifo")]
        {
            self.s3_on_hit(key);
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            self.touch_mru(key);
        }
    }

    fn on_miss_or_ghost_hit(&mut self, key: BlockNumber) {
        Self::increment_counter(&mut self.misses);
        #[cfg(feature = "s3fifo")]
        {
            self.s3_on_miss_or_ghost_hit(key);
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            // Defensive: callers use `resident.contains_key()` to decide hit vs miss.
            // If we ever see a "miss" for a resident key, treat it as a hit to avoid
            // duplicating list entries.
            if matches!(self.loc.get(&key), Some(ArcList::T1 | ArcList::T2)) {
                debug_assert!(
                    false,
                    "ARC invariant violated: loc says resident but resident map is missing"
                );
                self.on_hit(key);
                return;
            }

            if matches!(self.loc.get(&key), Some(ArcList::B1)) {
                Self::increment_counter(&mut self.b1_ghost_hits);
                let b1_len = self.b1.len().max(1);
                let b2_len = self.b2.len().max(1);
                let delta = (b2_len / b1_len).max(1);
                self.p = (self.p + delta).min(self.capacity);
                let _ = Self::remove_from_list(&mut self.b1, key);
                self.replace(key);
                self.t2.push_back(key);
                self.loc.insert(key, ArcList::T2);
                self.track_resident_recency(key, ArcList::T2);
                return;
            }

            if matches!(self.loc.get(&key), Some(ArcList::B2)) {
                Self::increment_counter(&mut self.b2_ghost_hits);
                let b1_len = self.b1.len().max(1);
                let b2_len = self.b2.len().max(1);
                let delta = (b1_len / b2_len).max(1);
                self.p = self.p.saturating_sub(delta);
                let _ = Self::remove_from_list(&mut self.b2, key);
                self.replace(key);
                self.t2.push_back(key);
                self.loc.insert(key, ArcList::T2);
                self.track_resident_recency(key, ArcList::T2);
                return;
            }

            // Not present in any list.
            let l1_len = self.t1.len() + self.b1.len();
            let total_len = self.total_len();
            if l1_len == self.capacity {
                if self.t1.len() < self.capacity {
                    let _ = self.b1.pop_front().and_then(|v| self.loc.remove(&v));
                    self.replace(key);
                } else if let Some(victim) = self.t1.pop_front() {
                    if self.evict_resident(victim) {
                        let _ = self.loc.remove(&victim);
                        Self::increment_counter(&mut self.evictions);
                    } else {
                        self.t1.push_front(victim);
                        self.loc.insert(victim, ArcList::T1);
                    }
                }
            } else if l1_len < self.capacity && total_len >= self.capacity {
                if total_len >= self.capacity.saturating_mul(2) {
                    let _ = self.b2.pop_front().and_then(|v| self.loc.remove(&v));
                }
                self.replace(key);
            }

            self.t1.push_back(key);
            self.loc.insert(key, ArcList::T1);
            self.track_resident_recency(key, ArcList::T1);
        }
    }

    #[cfg(feature = "s3fifo")]
    fn on_read_miss_or_scan_bypass(&mut self, key: BlockNumber) -> bool {
        Self::increment_counter(&mut self.misses);

        let is_sequential = self
            .last_read_miss
            .is_some_and(|previous| previous.0.wrapping_add(1) == key.0);
        self.last_read_miss = Some(key);
        if is_sequential {
            self.sequential_read_miss_streak = self.sequential_read_miss_streak.saturating_add(1);
        } else {
            self.sequential_read_miss_streak = 0;
        }

        let has_cache_history = self.loc.contains_key(&key);
        let bypass = self.sequential_read_miss_streak >= 2 && !has_cache_history;
        if bypass {
            self.push_ghost(key, ArcList::B1);
            self.trim_ghosts_to(self.ghost_capacity);
            trace!(
                target: "ffs::block::s3fifo",
                event = "admission_decision",
                block = key.0,
                reason = "sequential_scan_ghost_only",
                sequential_read_miss_streak = self.sequential_read_miss_streak,
                small_len = self.t1.len(),
                main_len = self.t2.len(),
                ghost_len = self.b1_len()
            );
            self.s3_emit_summary_if_due();
            true
        } else {
            self.s3_on_miss_or_ghost_hit(key);
            false
        }
    }

    #[cfg(not(feature = "s3fifo"))]
    fn on_read_miss_or_scan_bypass(&mut self, key: BlockNumber) -> bool {
        self.on_miss_or_ghost_hit(key);
        false
    }

    #[cfg(feature = "s3fifo")]
    fn s3_on_hit(&mut self, key: BlockNumber) {
        let list = self.loc.get(&key).copied();
        match list {
            Some(ArcList::T1) => {
                // Keep large-cache hit path O(1): defer T1->T2 promotion until
                // queue rebalance when the small queue overflows.
                if self.small_capacity <= 32 {
                    let _ = Self::remove_from_list(&mut self.t1, key);
                    self.t2.push_back(key);
                    self.loc.insert(key, ArcList::T2);
                }
            }
            Some(ArcList::T2) => {}
            Some(ArcList::B1 | ArcList::B2) => {
                warn!(
                    target: "ffs::block::s3fifo",
                    event = "invariant_recovery",
                    block = key.0,
                    queue = "resident",
                    detail = "hit observed for ghost location; repairing to resident queue"
                );
                let _ = self.remove_live_ghost(key);
                let _ = Self::remove_from_list(&mut self.t1, key);
                let _ = Self::remove_from_list(&mut self.t2, key);
                self.t1.push_back(key);
                self.loc.insert(key, ArcList::T1);
            }
            None => {
                warn!(
                    target: "ffs::block::s3fifo",
                    event = "invariant_recovery",
                    block = key.0,
                    queue = "resident",
                    detail = "hit observed without location metadata; repairing to resident queue"
                );
                let _ = Self::remove_from_list(&mut self.t1, key);
                let _ = Self::remove_from_list(&mut self.t2, key);
                let _ = self.remove_live_ghost(key);
                self.t1.push_back(key);
                self.loc.insert(key, ArcList::T1);
            }
        }
        let access_count = self.increment_s3_access_count(key);
        trace!(
            target: "ffs::block::s3fifo",
            event = "queue_transition",
            block = key.0,
            from_queue = "resident",
            to_queue = "resident",
            access_count,
            small_len = self.t1.len(),
            main_len = self.t2.len(),
            ghost_len = self.b1_len()
        );
        self.s3_emit_summary_if_due();
    }

    #[cfg(feature = "s3fifo")]
    fn s3_on_miss_or_ghost_hit(&mut self, key: BlockNumber) {
        // Defensive: callers use `resident.contains_key()` to decide hit vs miss.
        // If we ever see a "miss" for a resident key, we have stale queue metadata.
        // Repair metadata and continue through miss admission.
        if matches!(self.loc.get(&key), Some(ArcList::T1 | ArcList::T2)) {
            warn!(
                target: "ffs::block::s3fifo",
                event = "invariant_recovery",
                block = key.0,
                queue = "resident",
                detail = "miss observed for resident metadata without payload; dropping stale resident metadata"
            );
            let _ = Self::remove_from_list(&mut self.t1, key);
            let _ = Self::remove_from_list(&mut self.t2, key);
            let _ = self.loc.remove(&key);
            if let Some(handle) = self.access_count.remove(&key) {
                handle.invalidate();
                self.fast_invalidations.push(key);
            }
        }

        let ghost_hit = matches!(self.loc.get(&key), Some(ArcList::B1 | ArcList::B2));
        if ghost_hit {
            let _ = self.remove_live_ghost(key);
            self.loc.insert(key, ArcList::T2);
            self.t2.push_back(key);
            let _ = self.access_count.insert(key, S3AccessHandle::new(1));
            debug!(
                target: "ffs::block::s3fifo",
                event = "admission_decision",
                block = key.0,
                reason = "ghost_hit_readmit_main",
                policy_state = "s3fifo",
                capacity_state = %format!(
                    "small={}/{},main={}/{},ghost={}/{}",
                    self.t1.len(),
                    self.small_capacity,
                    self.t2.len(),
                    self.main_capacity,
                    self.b1_len(),
                    self.ghost_capacity
                )
            );
            trace!(
                target: "ffs::block::s3fifo",
                event = "queue_transition",
                block = key.0,
                from_queue = "ghost",
                to_queue = "main",
                access_count = 1_u8,
                small_len = self.t1.len(),
                main_len = self.t2.len(),
                ghost_len = self.b1_len()
            );
        } else {
            self.loc.insert(key, ArcList::T1);
            self.t1.push_back(key);
            let _ = self.access_count.insert(key, S3AccessHandle::new(0));
            debug!(
                target: "ffs::block::s3fifo",
                event = "admission_decision",
                block = key.0,
                reason = "new_admit_small",
                policy_state = "s3fifo",
                capacity_state = %format!(
                    "small={}/{},main={}/{},ghost={}/{}",
                    self.t1.len(),
                    self.small_capacity,
                    self.t2.len(),
                    self.main_capacity,
                    self.b1_len(),
                    self.ghost_capacity
                )
            );
            trace!(
                target: "ffs::block::s3fifo",
                event = "queue_transition",
                block = key.0,
                from_queue = "none",
                to_queue = "small",
                access_count = 0_u8,
                small_len = self.t1.len(),
                main_len = self.t2.len(),
                ghost_len = self.b1_len()
            );
        }

        self.s3_rebalance_queues(Some(key));
        self.s3_emit_summary_if_due();
    }

    #[cfg(feature = "s3fifo")]
    #[allow(clippy::too_many_lines)]
    fn s3_rebalance_queues(&mut self, block_hint: Option<BlockNumber>) {
        let pending_admission = block_hint.filter(|block| !self.resident.contains_key(block));

        let mut t1_attempts = self.t1.len().saturating_mul(2).max(1);
        while self.t1.len() > self.small_capacity && t1_attempts > 0 {
            t1_attempts -= 1;
            let Some(victim) = self.t1.pop_front() else {
                break;
            };
            if Some(victim) == pending_admission {
                self.t1.push_back(victim);
                continue;
            }
            if self.is_dirty(victim) {
                self.t1.push_back(victim);
                continue;
            }
            let access_count = self.s3_access_count(victim);
            if access_count > 0 {
                self.loc.insert(victim, ArcList::T2);
                self.t2.push_back(victim);
                trace!(
                    target: "ffs::block::s3fifo",
                    event = "queue_transition",
                    block = victim.0,
                    from_queue = "small",
                    to_queue = "main",
                    access_count,
                    small_len = self.t1.len(),
                    main_len = self.t2.len(),
                    ghost_len = self.b1_len()
                );
            } else if self.evict_resident(victim) {
                self.push_ghost(victim, ArcList::B1);
                self.evictions = self.evictions.saturating_add(1);
                trace!(
                    target: "ffs::block::s3fifo",
                    event = "victim_selection",
                    block = victim.0,
                    from_queue = "small",
                    to_queue = "ghost",
                    access_count,
                    small_len = self.t1.len(),
                    main_len = self.t2.len(),
                    ghost_len = self.b1_len()
                );
            } else {
                self.t1.push_back(victim);
                self.loc.insert(victim, ArcList::T1);
            }
        }

        let mut t2_attempts = self.t2.len().max(1);
        while self.t2.len() > self.main_capacity && t2_attempts > 0 {
            t2_attempts -= 1;
            let Some(victim) = self.t2.pop_front() else {
                break;
            };
            if Some(victim) == pending_admission {
                self.t2.push_back(victim);
                continue;
            }
            if self.is_dirty(victim) {
                self.t2.push_back(victim);
                continue;
            }
            let access_count = self.s3_access_count(victim);
            if access_count > 0 {
                let next_count = access_count.saturating_sub(1);
                if let Some(handle) = self.access_count.get(&victim) {
                    handle.store_count(next_count);
                }
                self.t2.push_back(victim);
                trace!(
                    target: "ffs::block::s3fifo",
                    event = "second_chance_rotation",
                    block = victim.0,
                    from_queue = "main",
                    to_queue = "main",
                    access_count = next_count,
                    small_len = self.t1.len(),
                    main_len = self.t2.len(),
                    ghost_len = self.b1_len()
                );
                continue;
            }

            if self.evict_resident(victim) {
                self.push_ghost(victim, ArcList::B1);
                self.evictions = self.evictions.saturating_add(1);
                trace!(
                    target: "ffs::block::s3fifo",
                    event = "victim_selection",
                    block = victim.0,
                    from_queue = "main",
                    to_queue = "ghost",
                    access_count,
                    small_len = self.t1.len(),
                    main_len = self.t2.len(),
                    ghost_len = self.b1_len()
                );
            } else {
                self.t2.push_back(victim);
                self.loc.insert(victim, ArcList::T2);
            }
        }

        while self.b1_len() > self.ghost_capacity {
            let overflow_by = self.b1_len().saturating_sub(self.ghost_capacity);
            if let Some(victim) = self.pop_b1_front() {
                warn!(
                    target: "ffs::block::s3fifo",
                    event = "ghost_overflow_recovery",
                    block = victim.0,
                    queue = "ghost",
                    overflow_by,
                    "ghost queue exceeded capacity and oldest key was dropped"
                );
            }
        }

        // If second-chance rotation still left us above target, force clean evictions.
        let mut emergency_attempts = self.t1.len().saturating_add(self.t2.len());
        while self.resident_len() > self.capacity && emergency_attempts > 0 {
            emergency_attempts -= 1;
            let t1_pos = self.t1.iter().position(|candidate| {
                Some(*candidate) != pending_admission && !self.is_dirty(*candidate)
            });
            let (victim, from_t1) = if let Some(pos) = t1_pos {
                (self.t1.remove(pos), true)
            } else {
                let t2_pos = self.t2.iter().position(|candidate| {
                    Some(*candidate) != pending_admission && !self.is_dirty(*candidate)
                });
                (t2_pos.and_then(|pos| self.t2.remove(pos)), false)
            };
            let Some(victim) = victim else {
                break;
            };
            if self.evict_resident(victim) {
                self.push_ghost(victim, ArcList::B1);
                self.evictions = self.evictions.saturating_add(1);
                trace!(
                    target: "ffs::block::s3fifo",
                    event = "pressure_fallback_evict",
                    block = victim.0,
                    from_queue = if from_t1 { "small" } else { "main" },
                    to_queue = "ghost",
                    small_len = self.t1.len(),
                    main_len = self.t2.len(),
                    ghost_len = self.b1_len()
                );
            } else if from_t1 {
                self.t1.push_back(victim);
                self.loc.insert(victim, ArcList::T1);
            } else {
                self.t2.push_back(victim);
                self.loc.insert(victim, ArcList::T2);
            }
        }

        if self.resident_len() > self.capacity {
            let repaired_entries = self.s3_reconcile_resident_queues(pending_admission);
            if repaired_entries > 0 {
                warn!(
                    target: "ffs::block::s3fifo",
                    event = "invariant_recovery",
                    repaired_entries,
                    detail = "dropped stale or duplicate resident queue metadata"
                );
            }

            let has_clean_candidate = self
                .t1
                .iter()
                .chain(self.t2.iter())
                .copied()
                .any(|candidate| Some(candidate) != pending_admission && !self.is_dirty(candidate));
            if !has_clean_candidate {
                debug!(
                    target: "ffs::block::s3fifo",
                    event = "overflow_tolerated_dirty",
                    resident = self.resident_len(),
                    capacity = self.capacity
                );
                return;
            }

            // Last-resort forced clean eviction. Keep process alive while preserving data.
            while self.resident_len() > self.capacity {
                let Some(victim) =
                    self.t1
                        .iter()
                        .chain(self.t2.iter())
                        .copied()
                        .find(|candidate| {
                            Some(*candidate) != pending_admission && !self.is_dirty(*candidate)
                        })
                else {
                    break;
                };
                let from_t1 = Self::remove_from_list(&mut self.t1, victim);
                if !from_t1 {
                    let _ = Self::remove_from_list(&mut self.t2, victim);
                }
                if self.evict_resident(victim) {
                    self.push_ghost(victim, ArcList::B1);
                    self.evictions = self.evictions.saturating_add(1);
                } else if from_t1 {
                    self.t1.push_back(victim);
                    self.loc.insert(victim, ArcList::T1);
                    break;
                } else {
                    self.t2.push_back(victim);
                    self.loc.insert(victim, ArcList::T2);
                    break;
                }
            }

            if self.resident_len() > self.capacity {
                let block = block_hint.map_or(0_u64, |b| b.0);
                error!(
                    target: "ffs::block::s3fifo",
                    event = "invariant_violation",
                    block,
                    queue = "resident",
                    detail = "resident set exceeded configured capacity after all recoveries"
                );
            }
        }
    }

    #[cfg(feature = "s3fifo")]
    fn s3_reconcile_resident_queues(&mut self, pending_admission: Option<BlockNumber>) -> usize {
        let before = self.t1.len().saturating_add(self.t2.len());
        let mut resident_keys: HashSet<BlockNumber> = self.resident.keys().copied().collect();
        if let Some(block) = pending_admission {
            resident_keys.insert(block);
        }
        let mut seen = HashSet::with_capacity(resident_keys.len());

        self.t1
            .retain(|candidate| resident_keys.contains(candidate) && seen.insert(*candidate));
        self.t2
            .retain(|candidate| resident_keys.contains(candidate) && seen.insert(*candidate));
        let stale_access_keys: Vec<BlockNumber> = self
            .access_count
            .keys()
            .copied()
            .filter(|candidate| !resident_keys.contains(candidate))
            .collect();
        for key in stale_access_keys {
            if let Some(handle) = self.access_count.remove(&key) {
                handle.invalidate();
                self.fast_invalidations.push(key);
            }
        }

        let queue_loc_keys: Vec<BlockNumber> = self
            .loc
            .iter()
            .filter_map(|(key, list)| matches!(list, ArcList::T1 | ArcList::T2).then_some(*key))
            .collect();
        for key in queue_loc_keys {
            let _ = self.loc.remove(&key);
        }
        for &key in &self.t1 {
            self.loc.insert(key, ArcList::T1);
        }
        for &key in &self.t2 {
            self.loc.insert(key, ArcList::T2);
        }

        before.saturating_sub(self.resident_len())
    }

    #[cfg(feature = "s3fifo")]
    fn s3_emit_summary_if_due(&self) {
        let accesses = self.hits.saturating_add(self.misses);
        if accesses == 0 || accesses % 1024 != 0 {
            return;
        }
        info!(
            target: "ffs::block::s3fifo",
            event = "cache_summary",
            hits = self.hits,
            misses = self.misses,
            evictions = self.evictions,
            ghost_hits = self.b1_len(),
            occupancy = self.resident_len(),
            mode = "s3fifo"
        );
    }

    /// Mark a block as dirty (written but not yet flushed to disk).
    fn mark_dirty(
        &mut self,
        block: BlockNumber,
        bytes: usize,
        txn_id: TxnId,
        commit_seq: Option<CommitSeq>,
        state: DirtyState,
    ) {
        self.dirty
            .mark_dirty(block, bytes, txn_id, commit_seq, state);
        #[cfg(not(feature = "s3fifo"))]
        self.remove_clean_resident(block);
    }

    /// Clear the dirty flag for a block (after flushing to disk).
    fn clear_dirty(&mut self, block: BlockNumber, seq: u64) {
        self.dirty.clear_dirty(block, seq);
        #[cfg(not(feature = "s3fifo"))]
        self.refresh_clean_resident(block);
    }

    /// Clear the dirty flag for a block unconditionally.
    fn clear_dirty_unconditional(&mut self, block: BlockNumber) {
        self.dirty.clear_dirty_unconditional(block);
        #[cfg(not(feature = "s3fifo"))]
        self.refresh_clean_resident(block);
    }

    /// Check if a block is dirty.
    fn is_dirty(&self, block: BlockNumber) -> bool {
        self.dirty.is_dirty(block)
    }

    /// Return list of dirty blocks that need flushing.
    fn dirty_blocks(&self) -> Vec<BlockNumber> {
        self.dirty.dirty_blocks_oldest_first()
    }

    fn stage_txn_write(&mut self, txn_id: TxnId, block: BlockNumber, data: &[u8]) -> Result<()> {
        if let Some(owner) = self.staged_block_owner.get(&block).copied()
            && owner != txn_id
        {
            return Err(FfsError::Format(format!(
                "block {} already staged by txn {}",
                block.0, owner.0
            )));
        }

        let payload = data.to_vec();
        self.staged_txn_writes
            .entry(txn_id)
            .or_default()
            .insert(block, payload);
        self.staged_block_owner.insert(block, txn_id);
        self.mark_dirty(block, data.len(), txn_id, None, DirtyState::InFlight);
        trace!(
            event = "mvcc_dirty_stage",
            txn_id = txn_id.0,
            block = block.0,
            commit_seq_opt = 0_u64,
            state = "in_flight"
        );
        Ok(())
    }

    fn take_staged_txn(&mut self, txn_id: TxnId) -> HashMap<BlockNumber, Vec<u8>> {
        let staged = self.staged_txn_writes.remove(&txn_id).unwrap_or_default();
        for block in staged.keys() {
            let _ = self.staged_block_owner.remove(block);
        }
        staged
    }

    fn is_current_flush_candidate(&self, candidate: &FlushCandidate) -> bool {
        self.dirty.entry(candidate.block).is_some_and(|entry| {
            entry.seq == candidate.seq
                && entry.txn_id == candidate.txn_id
                && entry.commit_seq == Some(candidate.commit_seq)
                && entry.is_flushable()
        })
    }

    fn take_pending_flush(&mut self) -> Vec<FlushCandidate> {
        let pending = std::mem::take(&mut self.pending_flush);
        let pending_count = pending.len();
        let mut current = Vec::with_capacity(pending_count);
        for candidate in pending {
            if self.is_current_flush_candidate(&candidate) {
                current.push(candidate);
            } else {
                warn!(
                    event = "stale_pending_flush_dropped",
                    block = candidate.block.0,
                    txn_id = candidate.txn_id.0,
                    commit_seq = candidate.commit_seq.0,
                    dirty_seq = candidate.seq
                );
            }
        }
        current
    }

    fn take_dirty_and_pending_flushes(&mut self) -> Vec<FlushCandidate> {
        let mut flushes = self.take_pending_flush();
        let requested_blocks = self.dirty.dirty_count();
        let (in_flight_blocks, _) = self.dirty.state_counts();
        let mut queued = HashSet::with_capacity(flushes.len());
        for candidate in &flushes {
            queued.insert(candidate.block);
        }

        for block in self.dirty_blocks() {
            // DirtyTracker yields each block once. `queued` only needs to
            // exclude candidates already recovered from pending_flush.
            if !queued.is_empty() && queued.contains(&block) {
                continue;
            }
            let Some(entry) = self.dirty.entry(block) else {
                continue;
            };
            if !entry.is_flushable() {
                warn!(
                    event = "mvcc_flush_skipped_uncommitted",
                    txn_id = entry.txn_id.0,
                    block = block.0,
                    state = "in_flight"
                );
                continue;
            }
            let Some(commit_seq) = entry.commit_seq else {
                continue;
            };
            if let Some(data) = self.resident.get(&block).cloned() {
                trace!(
                    event = "mvcc_flush_candidate",
                    block = block.0,
                    commit_seq = commit_seq.0,
                    flushable = true
                );
                flushes.push(FlushCandidate {
                    block,
                    data,
                    txn_id: entry.txn_id,
                    commit_seq,
                    seq: entry.seq,
                });
            }
        }

        debug!(
            event = "mvcc_flush_batch_filter",
            requested_blocks,
            eligible_blocks = flushes.len(),
            in_flight_blocks,
            aborted_blocks = 0_usize
        );
        flushes
    }

    fn take_dirty_and_pending_flushes_limited(&mut self, limit: usize) -> Vec<FlushCandidate> {
        if limit == 0 {
            return Vec::new();
        }

        let pending = self.take_pending_flush();
        let requested_blocks = self.dirty.dirty_count();
        let (in_flight_blocks, _) = self.dirty.state_counts();
        let mut flushes = Vec::with_capacity(limit.min(pending.len()));
        let mut overflow_pending = Vec::new();

        for item in pending {
            if flushes.len() < limit {
                flushes.push(item);
            } else {
                overflow_pending.push(item);
            }
        }

        if !overflow_pending.is_empty() {
            self.pending_flush.extend(overflow_pending);
        }

        let mut queued = HashSet::with_capacity(flushes.len());
        for candidate in &flushes {
            queued.insert(candidate.block);
        }

        for block in self.dirty_blocks() {
            if flushes.len() >= limit {
                break;
            }
            // DirtyTracker yields each block once. `queued` only needs to
            // exclude candidates already recovered from pending_flush.
            if !queued.is_empty() && queued.contains(&block) {
                continue;
            }
            let Some(entry) = self.dirty.entry(block) else {
                continue;
            };
            if !entry.is_flushable() {
                warn!(
                    event = "mvcc_flush_skipped_uncommitted",
                    txn_id = entry.txn_id.0,
                    block = block.0,
                    state = "in_flight"
                );
                continue;
            }
            let Some(commit_seq) = entry.commit_seq else {
                continue;
            };
            if let Some(data) = self.resident.get(&block).cloned() {
                trace!(
                    event = "mvcc_flush_candidate",
                    block = block.0,
                    commit_seq = commit_seq.0,
                    flushable = true
                );
                flushes.push(FlushCandidate {
                    block,
                    data,
                    txn_id: entry.txn_id,
                    commit_seq,
                    seq: entry.seq,
                });
            }
        }

        debug!(
            event = "mvcc_flush_batch_filter",
            requested_blocks,
            eligible_blocks = flushes.len(),
            in_flight_blocks,
            aborted_blocks = 0_usize
        );

        flushes
    }
}

/// ARC-cached wrapper around a [`BlockDevice`].
///
/// Current behavior:
/// - read caching of whole blocks
/// - default write-through (writes update cache and the underlying device immediately)
/// - optional write-back mode via [`ArcCache::new_with_policy`]
///
/// # Concurrency design
///
/// **Locking strategy:** A single `parking_lot::Mutex<ArcState>` protects all
/// cache metadata (T1/T2/B1/B2 lists, resident map, counters). A sharded
/// [`PageLockTable`] coalesces concurrent cold reads for the same block so
/// worker bursts do not stampede the underlying device. This is sufficient
/// because:
///
/// 1. The lock is **never held during I/O**.  `read_block` drops the lock
///    before issuing a device read and re-acquires it afterwards.
///    `write_block` writes through to the device first, then acquires the lock
///    only to update metadata.
/// 2. `parking_lot::Mutex` is non-poisoning and uses adaptive spinning, so
///    contention under typical FUSE workloads (many concurrent reads, few
///    writes) remains low.
///
/// **High-core sharding:** [`ShardedArcCache`] shards resident metadata by
/// `BlockNumber` into N independent `Mutex<ArcState>` segments for workloads
/// that show metadata lock contention under heavy parallel read bursts. This
/// type remains the single-policy default for smaller deployments and for
/// callers that need one global adaptive replacement policy.
///
/// See [`DeferredArcCache`] for an integrated write-back + background flush variant.
#[derive(Debug)]
pub struct ArcCache<D: BlockDevice> {
    inner: D,
    state: Mutex<ArcState>,
    page_locks: PageLockTable,
    write_policy: ArcWritePolicy,
    mvcc_flush_lifecycle: Arc<dyn MvccFlushLifecycle>,
    repair_flush_lifecycle: Arc<dyn RepairFlushLifecycle>,
    #[cfg(feature = "s3fifo")]
    s3_fast_residents: S3FastResidentTable,
    #[cfg(feature = "s3fifo")]
    s3_fast_hits: S3FastHitCounter,
    #[cfg(feature = "s3fifo")]
    s3_fast_hits_enabled: bool,
    #[cfg(feature = "s3fifo")]
    s3_fast_cache_id: u64,
    #[cfg(feature = "s3fifo")]
    s3_fast_mutation_active: AtomicUsize,
    #[cfg(feature = "s3fifo")]
    s3_fast_mutation_epoch: AtomicU64,
}

/// Write policy for [`ArcCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcWritePolicy {
    /// Always write to the underlying device immediately.
    WriteThrough,
    /// Keep writes in cache until sync; dirty blocks cannot be evicted.
    WriteBack,
}

/// Maximum default shard count selected by [`ShardedArcCache::for_host_parallelism`].
pub const MAX_HOST_PARALLEL_CACHE_SHARDS: usize = 64;

/// Block-number-sharded wrapper around [`ArcCache`] for high-core read bursts.
///
/// Each shard owns an independent [`ArcCache`] and metadata lock. A block is
/// routed by `block % shard_count`, so any given block has exactly one cache
/// owner while unrelated hot blocks can be served by different locks. The
/// policy tradeoff is deliberate: replacement is shard-local instead of global,
/// buying lower contention for 64+ core swarms without weakening write-back
/// durability, dirty tracking, or same-block miss coalescing within a shard.
#[derive(Debug)]
pub struct ShardedArcCache<D: BlockDevice> {
    inner: Arc<D>,
    shards: Vec<ArcCache<Arc<D>>>,
    shard_mask: Option<u64>,
}

impl<D: BlockDevice> ShardedArcCache<D> {
    /// Create a write-through sharded cache with an explicit shard count.
    pub fn new(inner: D, capacity_blocks: usize, shard_count: usize) -> Result<Self> {
        Self::new_with_policy(
            inner,
            capacity_blocks,
            shard_count,
            ArcWritePolicy::WriteThrough,
        )
    }

    /// Create a sharded cache sized to the current host's hardware parallelism.
    pub fn for_host_parallelism(inner: D, capacity_blocks: usize) -> Result<Self> {
        let host_threads = thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        let shard_count = host_threads
            .clamp(1, MAX_HOST_PARALLEL_CACHE_SHARDS)
            .min(capacity_blocks.max(1));
        Self::new(inner, capacity_blocks, shard_count)
    }

    /// Create a sharded cache with the requested write policy.
    pub fn new_with_policy(
        inner: D,
        capacity_blocks: usize,
        shard_count: usize,
        write_policy: ArcWritePolicy,
    ) -> Result<Self> {
        if capacity_blocks == 0 {
            return Err(FfsError::Format(
                "ShardedArcCache capacity_blocks must be > 0".to_owned(),
            ));
        }
        if shard_count == 0 {
            return Err(FfsError::Format(
                "ShardedArcCache shard_count must be > 0".to_owned(),
            ));
        }

        let shard_count = shard_count.min(capacity_blocks);
        let base_capacity = capacity_blocks / shard_count;
        let remainder = capacity_blocks % shard_count;
        let inner = Arc::new(inner);
        let mut shards = Vec::with_capacity(shard_count);

        for shard_index in 0..shard_count {
            let shard_capacity = base_capacity + usize::from(shard_index < remainder);
            shards.push(ArcCache::new_with_policy(
                Arc::clone(&inner),
                shard_capacity,
                write_policy,
            )?);
        }

        let shard_mask = shard_count
            .is_power_of_two()
            .then_some(u64::try_from(shard_count - 1).unwrap_or(u64::MAX));

        Ok(Self {
            inner,
            shards,
            shard_mask,
        })
    }

    /// Return the underlying block device shared by all shards.
    #[must_use]
    pub fn inner(&self) -> &Arc<D> {
        &self.inner
    }

    /// Number of independently locked cache shards.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Deterministic owner shard for `block`.
    #[must_use]
    pub fn shard_index_for(&self, block: BlockNumber) -> usize {
        if let Some(mask) = self.shard_mask {
            return usize::try_from(block.0 & mask).unwrap_or(0);
        }
        let shard_count = u64::try_from(self.shards.len()).unwrap_or(u64::MAX);
        usize::try_from(block.0 % shard_count).unwrap_or(0)
    }

    fn shard_for(&self, block: BlockNumber) -> &ArcCache<Arc<D>> {
        &self.shards[self.shard_index_for(block)]
    }

    /// Per-shard metric snapshots for diagnosing imbalance.
    #[must_use]
    pub fn shard_metrics(&self) -> Vec<CacheMetrics> {
        self.shards.iter().map(ArcCache::metrics).collect()
    }

    /// Aggregate metric snapshot across all shards.
    #[must_use]
    pub fn metrics(&self) -> CacheMetrics {
        CacheMetrics::aggregate(self.shard_metrics())
    }

    /// Export aggregate cache metrics using the runtime/e2e JSON field names.
    #[must_use]
    pub fn runtime_metrics(&self) -> CacheRuntimeMetricsSnapshot {
        self.metrics().runtime_metrics_snapshot()
    }
}

/// Default dirty-ratio threshold where aggressive flush is preferred.
pub const DIRTY_HIGH_WATERMARK: f64 = 0.80;
/// Default dirty-ratio threshold where new writes are backpressured.
pub const DIRTY_CRITICAL_WATERMARK: f64 = 0.95;

/// Runtime configuration for background dirty flushing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlushDaemonConfig {
    /// Sleep interval between flush cycles.
    pub interval: Duration,
    /// Maximum number of dirty blocks to flush per non-aggressive cycle.
    pub batch_size: usize,
    /// Poll quota threshold below which flush batches are reduced.
    pub budget_poll_quota_threshold: u32,
    /// Reduced batch size used when budget pressure is active.
    pub reduced_batch_size: usize,
    /// Yield duration when budget pressure is active.
    pub budget_yield_sleep: Duration,
    /// Dirty ratio threshold that triggers aggressive full flush.
    pub high_watermark: f64,
    /// Dirty ratio threshold that blocks writes until flushed below high watermark.
    pub critical_watermark: f64,
}

impl Default for FlushDaemonConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            batch_size: 256,
            budget_poll_quota_threshold: 256,
            reduced_batch_size: 64,
            budget_yield_sleep: Duration::from_millis(10),
            high_watermark: DIRTY_HIGH_WATERMARK,
            critical_watermark: DIRTY_CRITICAL_WATERMARK,
        }
    }
}

impl FlushDaemonConfig {
    fn validate(self) -> Result<Self> {
        if self.interval.is_zero() {
            return Err(FfsError::Format(
                "flush daemon interval must be > 0".to_owned(),
            ));
        }
        if self.batch_size == 0 {
            return Err(FfsError::Format(
                "flush daemon batch_size must be > 0".to_owned(),
            ));
        }
        if self.reduced_batch_size == 0 {
            return Err(FfsError::Format(
                "flush daemon reduced_batch_size must be > 0".to_owned(),
            ));
        }
        if !(0.0..=1.0).contains(&self.high_watermark)
            || !(0.0..=1.0).contains(&self.critical_watermark)
            || self.high_watermark >= self.critical_watermark
        {
            return Err(FfsError::Format(
                "flush daemon watermarks must satisfy 0<=high<critical<=1".to_owned(),
            ));
        }
        Ok(self)
    }
}

/// Handle for a running background flush daemon.
#[derive(Debug)]
pub struct FlushDaemon {
    stop: Arc<FlushDaemonStop>,
    join: Option<JoinHandle<()>>,
}

impl FlushDaemon {
    /// Request shutdown and block until the daemon exits.
    pub fn shutdown(mut self) {
        self.stop.request_stop();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for FlushDaemon {
    fn drop(&mut self) {
        self.stop.request_stop();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct FlushDaemonStop {
    stopped: Mutex<bool>,
    condvar: Condvar,
}

impl std::fmt::Debug for FlushDaemonStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlushDaemonStop").finish_non_exhaustive()
    }
}

impl FlushDaemonStop {
    fn new() -> Self {
        Self {
            stopped: Mutex::new(false),
            condvar: Condvar::new(),
        }
    }

    fn request_stop(&self) {
        *self.stopped.lock() = true;
        self.condvar.notify_all();
    }

    fn wait_interval_or_stopped(&self, interval: Duration) -> bool {
        let mut stopped = self.stopped.lock();
        if *stopped {
            return true;
        }
        self.condvar.wait_for(&mut stopped, interval);
        *stopped
    }
}

/// Write-back [`ArcCache`] with an integrated background [`FlushDaemon`].
///
/// Combines a write-back ARC cache with a background flush daemon that
/// periodically writes dirty blocks to the underlying device.  When the
/// `DeferredArcCache` is dropped, the daemon is stopped and a final flush
/// is performed before the cache is released.
///
/// # Example
///
/// ```text
/// let deferred = DeferredArcCache::new(device, 1024, FlushDaemonConfig::default())?;
/// deferred.write_block(&cx, BlockNumber(0), &data)?; // deferred to cache
/// // daemon flushes dirty blocks in background …
/// drop(deferred); // final flush + shutdown
/// ```
pub struct DeferredArcCache<D: BlockDevice + 'static> {
    /// Dropped first — joins the daemon thread (which does a final flush).
    daemon: FlushDaemon,
    /// Dropped second — the underlying cache (kept alive by daemon's Arc clone
    /// until the daemon thread exits in `FlushDaemon::drop`).
    cache: Arc<ArcCache<D>>,
}

impl<D: BlockDevice + 'static> DeferredArcCache<D> {
    /// Create a write-back cache with a background flush daemon.
    pub fn new(inner: D, capacity_blocks: usize, config: FlushDaemonConfig) -> Result<Self> {
        let cache = Arc::new(ArcCache::new_with_policy(
            inner,
            capacity_blocks,
            ArcWritePolicy::WriteBack,
        )?);
        let daemon = cache.start_flush_daemon(config)?;
        Ok(Self { daemon, cache })
    }

    /// Access the underlying [`ArcCache`].
    #[must_use]
    pub fn cache(&self) -> &Arc<ArcCache<D>> {
        &self.cache
    }

    /// Shut down the daemon and perform a final flush, consuming the wrapper.
    ///
    /// Returns the inner `Arc<ArcCache<D>>` for continued (non-deferred) use.
    #[must_use]
    pub fn shutdown(self) -> Arc<ArcCache<D>> {
        let Self { daemon, cache } = self;
        daemon.shutdown();
        cache
    }
}

impl<D: BlockDevice + 'static> std::ops::Deref for DeferredArcCache<D> {
    type Target = ArcCache<D>;
    fn deref(&self) -> &Self::Target {
        &self.cache
    }
}

impl<D: BlockDevice + 'static> BlockDevice for DeferredArcCache<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        self.cache.read_block(cx, block)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        self.cache.write_block(cx, block, data)
    }

    fn block_size(&self) -> u32 {
        self.cache.block_size()
    }

    fn block_count(&self) -> u64 {
        self.cache.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.cache.sync(cx)
    }
}

impl<D: BlockDevice + std::fmt::Debug + 'static> std::fmt::Debug for DeferredArcCache<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeferredArcCache")
            .field("cache", &self.cache)
            .field("daemon", &self.daemon)
            .finish()
    }
}

impl<D: BlockDevice> ArcCache<D> {
    pub fn new(inner: D, capacity_blocks: usize) -> Result<Self> {
        Self::new_with_policy(inner, capacity_blocks, ArcWritePolicy::WriteThrough)
    }

    pub fn new_with_policy(
        inner: D,
        capacity_blocks: usize,
        write_policy: ArcWritePolicy,
    ) -> Result<Self> {
        Self::new_with_policy_and_lifecycles(
            inner,
            capacity_blocks,
            write_policy,
            Arc::new(NoopMvccFlushLifecycle),
            Arc::new(NoopRepairFlushLifecycle),
        )
    }

    pub fn new_with_policy_and_mvcc_lifecycle(
        inner: D,
        capacity_blocks: usize,
        write_policy: ArcWritePolicy,
        mvcc_flush_lifecycle: Arc<dyn MvccFlushLifecycle>,
    ) -> Result<Self> {
        Self::new_with_policy_and_lifecycles(
            inner,
            capacity_blocks,
            write_policy,
            mvcc_flush_lifecycle,
            Arc::new(NoopRepairFlushLifecycle),
        )
    }

    pub fn new_with_policy_and_repair_lifecycle(
        inner: D,
        capacity_blocks: usize,
        write_policy: ArcWritePolicy,
        repair_flush_lifecycle: Arc<dyn RepairFlushLifecycle>,
    ) -> Result<Self> {
        Self::new_with_policy_and_lifecycles(
            inner,
            capacity_blocks,
            write_policy,
            Arc::new(NoopMvccFlushLifecycle),
            repair_flush_lifecycle,
        )
    }

    pub fn new_with_policy_and_lifecycles(
        inner: D,
        capacity_blocks: usize,
        write_policy: ArcWritePolicy,
        mvcc_flush_lifecycle: Arc<dyn MvccFlushLifecycle>,
        repair_flush_lifecycle: Arc<dyn RepairFlushLifecycle>,
    ) -> Result<Self> {
        if capacity_blocks == 0 {
            return Err(FfsError::Format(
                "ArcCache capacity_blocks must be > 0".to_owned(),
            ));
        }
        #[cfg(feature = "s3fifo")]
        let s3_fast_hits_enabled = ArcState::s3_capacity_split(capacity_blocks).0 > 32;
        let cache = Self {
            inner,
            state: Mutex::new(ArcState::new(capacity_blocks)),
            page_locks: PageLockTable::for_host_parallelism(),
            write_policy,
            mvcc_flush_lifecycle,
            repair_flush_lifecycle,
            #[cfg(feature = "s3fifo")]
            s3_fast_residents: S3FastResidentTable::for_capacity(capacity_blocks),
            #[cfg(feature = "s3fifo")]
            s3_fast_hits: S3FastHitCounter::for_capacity(capacity_blocks),
            #[cfg(feature = "s3fifo")]
            s3_fast_hits_enabled,
            #[cfg(feature = "s3fifo")]
            s3_fast_cache_id: next_s3_fast_cache_id(),
            #[cfg(feature = "s3fifo")]
            s3_fast_mutation_active: AtomicUsize::new(0),
            #[cfg(feature = "s3fifo")]
            s3_fast_mutation_epoch: AtomicU64::new(0),
        };
        #[cfg(feature = "s3fifo")]
        info!(
            target: "ffs::block::s3fifo",
            event = "cache_mode_selected",
            mode = "s3fifo",
            capacity = capacity_blocks
        );
        #[cfg(not(feature = "s3fifo"))]
        info!(
            event = "cache_mode_selected",
            mode = "arc",
            capacity = capacity_blocks
        );
        Ok(cache)
    }

    #[must_use]
    pub fn inner(&self) -> &D {
        &self.inner
    }

    /// Take a snapshot of current cache metrics.
    ///
    /// Acquires the state lock briefly to read counters and list sizes.
    /// The returned [`CacheMetrics`] is a frozen point-in-time snapshot.
    #[must_use]
    pub fn metrics(&self) -> CacheMetrics {
        #[cfg(feature = "s3fifo")]
        {
            let mut metrics = self.state.lock().snapshot_metrics();
            metrics.hits = metrics
                .hits
                .saturating_add(self.s3_fast_hits.total(Ordering::Relaxed));
            metrics
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            self.state.lock().snapshot_metrics()
        }
    }

    /// Export cache metrics using the runtime/e2e JSON field names.
    #[must_use]
    pub fn runtime_metrics(&self) -> CacheRuntimeMetricsSnapshot {
        self.metrics().runtime_metrics_snapshot()
    }

    #[must_use]
    pub fn write_policy(&self) -> ArcWritePolicy {
        self.write_policy
    }

    #[cfg(feature = "s3fifo")]
    fn s3_fast_hit(&self, block: BlockNumber) -> Option<BlockBuf> {
        if !self.s3_fast_hits_enabled {
            return None;
        }
        let epoch = self.s3_fast_mutation_epoch.load(Ordering::Acquire);
        if self.s3_fast_mutation_active.load(Ordering::Acquire) != 0 {
            return None;
        }
        if let Some(buf) = self.s3_thread_fast_hit(block, epoch) {
            return Some(buf);
        }
        let entry = self.s3_fast_residents.get_valid(block)?;
        if self.s3_fast_mutation_active.load(Ordering::Acquire) != 0
            || self.s3_fast_mutation_epoch.load(Ordering::Acquire) != epoch
            || !entry.access.is_valid()
        {
            return None;
        }
        entry.access.increment_count();
        self.s3_fast_hits.increment(block);
        let data = entry.data.clone_ref();
        self.store_s3_thread_fast_hit(block, epoch, entry);
        Some(data)
    }

    #[cfg(feature = "s3fifo")]
    fn s3_thread_fast_hit(&self, block: BlockNumber, epoch: u64) -> Option<BlockBuf> {
        let (data, access) = S3_THREAD_FAST_RESIDENTS.with(|residents| {
            residents
                .borrow()
                .get_valid(self.s3_fast_cache_id, block, epoch)
        })?;
        if self.s3_fast_mutation_active.load(Ordering::Acquire) != 0
            || self.s3_fast_mutation_epoch.load(Ordering::Acquire) != epoch
            || !access.is_valid()
        {
            return None;
        }
        access.increment_count();
        self.s3_fast_hits.increment(block);
        Some(data)
    }

    #[cfg(feature = "s3fifo")]
    fn store_s3_thread_fast_hit(&self, block: BlockNumber, epoch: u64, resident: S3FastResident) {
        S3_THREAD_FAST_RESIDENTS.with(|residents| {
            residents
                .borrow_mut()
                .insert(self.s3_fast_cache_id, block, epoch, resident);
        });
    }

    #[cfg(feature = "s3fifo")]
    fn begin_s3_fast_mutation(&self) -> S3FastMutationGuard<'_> {
        self.s3_fast_mutation_active.fetch_add(1, Ordering::AcqRel);
        self.s3_fast_mutation_epoch.fetch_add(1, Ordering::AcqRel);
        S3FastMutationGuard {
            active: &self.s3_fast_mutation_active,
            epoch: &self.s3_fast_mutation_epoch,
        }
    }

    #[cfg(feature = "s3fifo")]
    fn s3_fast_entry_for(
        &self,
        state: &ArcState,
        block: BlockNumber,
        data: &BlockBuf,
    ) -> Option<S3FastResident> {
        if !self.s3_fast_hits_enabled {
            return None;
        }
        let access = state.access_count.get(&block)?;
        access.is_valid().then(|| S3FastResident {
            data: data.clone_ref(),
            access: Arc::clone(access),
        })
    }

    #[cfg(feature = "s3fifo")]
    fn apply_s3_fast_resident_updates(
        &self,
        invalidations: Vec<BlockNumber>,
        insert: Option<(BlockNumber, S3FastResident)>,
    ) {
        for block in invalidations {
            self.s3_fast_residents.remove(block);
        }
        if let Some((block, entry)) = insert {
            self.s3_fast_residents.insert(block, entry);
        }
    }

    /// Apply a memory-pressure signal and adjust cache target size.
    ///
    /// This reduces (or restores) the active target capacity and evicts clean
    /// cold entries when possible. Dirty entries are never evicted.
    #[must_use]
    pub fn memory_pressure_callback(&self, pressure: MemoryPressure) -> CachePressureReport {
        #[cfg(feature = "s3fifo")]
        let mutation_guard = self.begin_s3_fast_mutation();
        let (old_pressure, old_target, new_target, batch, report, fast_invalidations) = {
            let mut guard = self.state.lock();
            let old_pressure = guard.pressure_level;
            let old_target = guard.capacity;
            guard.set_pressure_level(pressure);
            let batch = guard.trim_to_capacity();
            (
                old_pressure,
                old_target,
                guard.capacity,
                batch,
                guard.pressure_report(),
                {
                    #[cfg(feature = "s3fifo")]
                    {
                        guard.take_fast_invalidations()
                    }
                    #[cfg(not(feature = "s3fifo"))]
                    {
                        Vec::<BlockNumber>::new()
                    }
                },
            )
        };
        #[cfg(feature = "s3fifo")]
        self.apply_s3_fast_resident_updates(fast_invalidations, None);
        #[cfg(feature = "s3fifo")]
        drop(mutation_guard);
        #[cfg(not(feature = "s3fifo"))]
        let _ = fast_invalidations;

        if old_pressure != pressure {
            info!(
                event = "cache_pressure_level_change",
                old_level = ?old_pressure,
                new_level = ?pressure
            );
        }
        if old_target != new_target {
            debug!(event = "cache_target_size_change", old_target, new_target);
        }
        if batch.evicted_blocks > 0 {
            debug!(
                event = "cache_pressure_evict_batch",
                evicted_blocks = batch.evicted_blocks,
                evicted_bytes = batch.evicted_bytes
            );
        }
        report
    }

    /// Restore cache target size to the configured nominal capacity.
    #[must_use]
    pub fn restore_target_size(&self) -> CachePressureReport {
        #[cfg(feature = "s3fifo")]
        let mutation_guard = self.begin_s3_fast_mutation();
        let (old_level, old_target, new_target, batch, report, fast_invalidations) = {
            let mut guard = self.state.lock();
            let old_level = guard.pressure_level;
            let old_target = guard.capacity;
            guard.pressure_level = MemoryPressure::None;
            guard.restore_target_capacity();
            let batch = guard.trim_to_capacity();
            (
                old_level,
                old_target,
                guard.capacity,
                batch,
                guard.pressure_report(),
                {
                    #[cfg(feature = "s3fifo")]
                    {
                        guard.take_fast_invalidations()
                    }
                    #[cfg(not(feature = "s3fifo"))]
                    {
                        Vec::<BlockNumber>::new()
                    }
                },
            )
        };
        #[cfg(feature = "s3fifo")]
        self.apply_s3_fast_resident_updates(fast_invalidations, None);
        #[cfg(feature = "s3fifo")]
        drop(mutation_guard);
        #[cfg(not(feature = "s3fifo"))]
        let _ = fast_invalidations;
        if old_level != MemoryPressure::None {
            info!(
                event = "cache_pressure_level_change",
                old_level = ?old_level,
                new_level = ?MemoryPressure::None
            );
        }
        if old_target != new_target {
            debug!(event = "cache_target_size_change", old_target, new_target);
        }
        if batch.evicted_blocks > 0 {
            debug!(
                event = "cache_pressure_evict_batch",
                evicted_blocks = batch.evicted_blocks,
                evicted_bytes = batch.evicted_bytes
            );
        }
        report
    }

    /// Current cache pressure snapshot.
    #[must_use]
    pub fn pressure_report(&self) -> CachePressureReport {
        self.state.lock().pressure_report()
    }

    fn dirty_state_counts(&self) -> (usize, usize) {
        self.state.lock().dirty.state_counts()
    }

    fn committed_dirty_ratio(&self) -> f64 {
        let guard = self.state.lock();
        let (_, committed_blocks) = guard.dirty.state_counts();
        if guard.capacity == 0 {
            0.0
        } else {
            committed_blocks as f64 / guard.capacity as f64
        }
    }

    /// Stage a transactional write that is not yet visible/flushable.
    ///
    /// The payload is tracked as in-flight dirty state and only becomes
    /// cache-visible + flushable after [`Self::commit_staged_txn`].
    pub fn stage_txn_write(
        &self,
        cx: &Cx,
        txn_id: TxnId,
        block: BlockNumber,
        data: &[u8],
    ) -> Result<()> {
        cx_checkpoint(cx)?;
        let expected = usize::try_from(self.block_size())
            .map_err(|_| FfsError::Format("block_size does not fit usize".to_owned()))?;
        if data.len() != expected {
            return Err(FfsError::Format(format!(
                "stage_txn_write data size mismatch: got={} expected={expected}",
                data.len()
            )));
        }

        let mut guard = self.state.lock();
        guard.stage_txn_write(txn_id, block, data)
    }

    /// Commit all staged writes for `txn_id` and mark them flushable.
    ///
    /// Returns the number of blocks transitioned from in-flight to committed.
    pub fn commit_staged_txn(
        &self,
        cx: &Cx,
        txn_id: TxnId,
        commit_seq: CommitSeq,
    ) -> Result<usize> {
        cx_checkpoint(cx)?;
        let staged = {
            let mut guard = self.state.lock();
            guard.take_staged_txn(txn_id)
        };
        if staged.is_empty() {
            return Ok(0);
        }

        let mut enforce_backpressure = false;
        let mut committed_blocks = 0_usize;
        let mut guard = self.state.lock();
        for (block, data) in staged {
            let payload = BlockBuf::new(data);
            let payload_len = payload.len();
            if guard.resident.contains_key(&block) {
                guard.resident.insert(block, payload);
                guard.on_hit(block);
            } else {
                guard.on_miss_or_ghost_hit(block);
                guard.resident.insert(block, payload);
            }
            guard.mark_dirty(
                block,
                payload_len,
                txn_id,
                Some(commit_seq),
                DirtyState::Committed,
            );
            trace!(
                event = "mvcc_dirty_stage",
                txn_id = txn_id.0,
                block = block.0,
                commit_seq_opt = commit_seq.0,
                state = "committed"
            );
            committed_blocks += 1;
        }

        if matches!(self.write_policy, ArcWritePolicy::WriteBack) {
            let (_, committed_blocks_now) = guard.dirty.state_counts();
            let dirty_ratio = if guard.capacity == 0 {
                0.0
            } else {
                committed_blocks_now as f64 / guard.capacity as f64
            };
            if dirty_ratio > DIRTY_CRITICAL_WATERMARK {
                enforce_backpressure = true;
                warn!(
                    event = "flush_backpressure_critical",
                    txn_id = txn_id.0,
                    dirty_ratio,
                    critical_watermark = DIRTY_CRITICAL_WATERMARK
                );
                warn!(
                    event = "backpressure_activated",
                    source = "commit_staged_txn",
                    level = "critical",
                    txn_id = txn_id.0,
                    dirty_ratio,
                    threshold = DIRTY_CRITICAL_WATERMARK
                );
            } else if dirty_ratio > DIRTY_HIGH_WATERMARK {
                warn!(
                    event = "flush_backpressure_high",
                    txn_id = txn_id.0,
                    dirty_ratio,
                    high_watermark = DIRTY_HIGH_WATERMARK
                );
                warn!(
                    event = "backpressure_activated",
                    source = "commit_staged_txn",
                    level = "high",
                    txn_id = txn_id.0,
                    dirty_ratio,
                    threshold = DIRTY_HIGH_WATERMARK
                );
            }
        }

        let pending_flush = guard.take_pending_flush();
        drop(guard);
        self.flush_pending_evictions(cx, pending_flush)?;

        if enforce_backpressure {
            loop {
                let dirty_ratio = self.committed_dirty_ratio();
                if dirty_ratio <= DIRTY_HIGH_WATERMARK {
                    break;
                }
                self.flush_dirty(cx)?;
            }
        }

        Ok(committed_blocks)
    }

    /// Abort all staged writes for `txn_id`, discarding in-flight dirty state.
    ///
    /// Returns the number of discarded staged blocks.
    #[must_use]
    pub fn abort_staged_txn(&self, txn_id: TxnId) -> usize {
        let discarded_block_ids = {
            let mut guard = self.state.lock();
            let staged = guard.take_staged_txn(txn_id);
            let mut discarded = Vec::new();
            for block in staged.keys() {
                let is_same_txn_inflight = guard.dirty.entry(*block).is_some_and(|entry| {
                    entry.txn_id == txn_id && matches!(entry.state, DirtyState::InFlight)
                });
                if is_same_txn_inflight {
                    guard.clear_dirty_unconditional(*block);
                    discarded.push(block.0);
                }
            }
            drop(guard);
            discarded
        };
        let discarded_blocks = discarded_block_ids.len();
        if discarded_blocks > 0 {
            warn!(
                event = "mvcc_discard_aborted_dirty",
                txn_id = txn_id.0,
                discarded_blocks
            );
            for block_id in discarded_block_ids {
                warn!(
                    event = "dirty_block_discarded",
                    block_id,
                    txn_id = txn_id.0,
                    reason = "abort"
                );
            }
        }
        discarded_blocks
    }

    /// Spawn a background thread that periodically flushes dirty blocks.
    ///
    /// The daemon flushes oldest dirty blocks first using `batch_size`, unless
    /// dirty ratio exceeds `high_watermark`, in which case it flushes all dirty
    /// blocks aggressively. On shutdown it performs a final full flush.
    pub fn start_flush_daemon(self: &Arc<Self>, config: FlushDaemonConfig) -> Result<FlushDaemon>
    where
        D: 'static,
    {
        let config = config.validate()?;
        let stop = Arc::new(FlushDaemonStop::new());
        let cache = Arc::clone(self);
        let stop_signal = Arc::clone(&stop);

        let join = thread::Builder::new()
            .name("ffs-flush-daemon".to_owned())
            .spawn(move || {
                // Daemon uses a long-lived context for periodic background work.
                let cx = Cx::for_testing();
                let mut cycle_seq = 0_u64;
                let mut daemon_throttled = false;

                loop {
                    if stop_signal.wait_interval_or_stopped(config.interval) {
                        break;
                    }
                    cycle_seq = cycle_seq.saturating_add(1);
                    cache.run_flush_daemon_cycle(&cx, &config, cycle_seq, &mut daemon_throttled);
                }

                if let Err(err) = cache.flush_dirty(&cx) {
                    error!(
                        event = "flush_shutdown_failed",
                        error = %err,
                        remaining_dirty_blocks = cache.dirty_count()
                    );
                }
            })
            .map_err(FfsError::from)?;

        Ok(FlushDaemon {
            stop,
            join: Some(join),
        })
    }

    fn run_flush_daemon_cycle(
        &self,
        cx: &Cx,
        config: &FlushDaemonConfig,
        cycle_seq: u64,
        daemon_throttled: &mut bool,
    ) {
        let metrics = self.metrics();
        let dirty_ratio = metrics.dirty_ratio();
        let (in_flight_blocks, committed_blocks) = self.dirty_state_counts();
        let committed_dirty_ratio = if metrics.capacity == 0 {
            0.0
        } else {
            committed_blocks as f64 / metrics.capacity as f64
        };
        trace!(
            event = "flush_daemon_tick",
            cycle_seq,
            dirty_blocks = metrics.dirty_blocks,
            in_flight_blocks,
            committed_blocks,
            dirty_bytes = metrics.dirty_bytes,
            dirty_ratio,
            committed_dirty_ratio,
            oldest_dirty_age_ticks = metrics.oldest_dirty_age_ticks.unwrap_or(0)
        );

        if committed_blocks == 0 {
            Self::maybe_log_daemon_resumed(daemon_throttled, cx.budget().poll_quota);
            trace!(
                event = "flush_daemon_sleep",
                cycle_seq,
                interval_ms = config.interval.as_millis()
            );
            return;
        }

        let batch_size = Self::effective_flush_batch_size(cx, config, daemon_throttled);
        let flush_res = self.flush_cycle_batch(
            cx,
            config,
            cycle_seq,
            committed_dirty_ratio,
            committed_blocks,
            batch_size,
        );

        if let Err(err) = flush_res {
            error!(
                event = "flush_batch_failed",
                cycle_seq,
                error = %err,
                attempted_blocks = metrics.dirty_blocks,
                attempted_bytes = metrics.dirty_bytes
            );
        }

        trace!(
            event = "flush_daemon_sleep",
            cycle_seq,
            interval_ms = config.interval.as_millis()
        );
    }

    fn maybe_log_daemon_resumed(daemon_throttled: &mut bool, new_budget: u32) {
        if *daemon_throttled {
            debug!(
                event = "daemon_resumed",
                daemon_name = "flush_daemon",
                new_budget
            );
            *daemon_throttled = false;
        }
    }

    fn effective_flush_batch_size(
        cx: &Cx,
        config: &FlushDaemonConfig,
        daemon_throttled: &mut bool,
    ) -> usize {
        let budget = cx.budget();
        let budget_pressure =
            budget.is_exhausted() || budget.poll_quota <= config.budget_poll_quota_threshold;
        if budget_pressure {
            let reduced = config.reduced_batch_size.min(config.batch_size).max(1);
            if reduced < config.batch_size {
                debug!(
                    event = "batch_size_reduced",
                    daemon_name = "flush_daemon",
                    original_size = config.batch_size,
                    reduced_size = reduced,
                    pressure_level = "budget"
                );
            }
            debug!(
                event = "daemon_throttled",
                daemon_name = "flush_daemon",
                budget_remaining = budget.poll_quota,
                yield_duration_ms = config.budget_yield_sleep.as_millis(),
                pressure_level = "budget"
            );
            *daemon_throttled = true;
            sleep_for_flush_budget_yield(cx, config.budget_yield_sleep);
            reduced
        } else {
            Self::maybe_log_daemon_resumed(daemon_throttled, budget.poll_quota);
            config.batch_size
        }
    }

    fn flush_cycle_batch(
        &self,
        cx: &Cx,
        config: &FlushDaemonConfig,
        cycle_seq: u64,
        committed_dirty_ratio: f64,
        committed_blocks: usize,
        batch_size: usize,
    ) -> Result<usize> {
        if committed_dirty_ratio > config.high_watermark {
            if committed_dirty_ratio > config.critical_watermark {
                warn!(
                    event = "flush_backpressure_critical",
                    cycle_seq,
                    dirty_ratio = committed_dirty_ratio,
                    critical_watermark = config.critical_watermark
                );
                warn!(
                    event = "backpressure_activated",
                    source = "flush_daemon",
                    level = "critical",
                    cycle_seq,
                    dirty_ratio = committed_dirty_ratio,
                    threshold = config.critical_watermark
                );
            } else {
                warn!(
                    event = "flush_backpressure_high",
                    cycle_seq,
                    dirty_ratio = committed_dirty_ratio,
                    high_watermark = config.high_watermark
                );
                warn!(
                    event = "backpressure_activated",
                    source = "flush_daemon",
                    level = "high",
                    cycle_seq,
                    dirty_ratio = committed_dirty_ratio,
                    threshold = config.high_watermark
                );
            }
            self.flush_dirty(cx).map(|()| committed_blocks)
        } else {
            self.flush_dirty_batch(cx, batch_size)
        }
    }

    fn flush_blocks(&self, cx: &Cx, flushes: &[FlushCandidate]) -> Result<()> {
        let lifecycle = Arc::clone(&self.mvcc_flush_lifecycle);
        for candidate in flushes {
            cx_checkpoint(cx)?;
            let pin = match lifecycle.pin_for_flush(candidate.block, candidate.commit_seq) {
                Ok(pin) => pin,
                Err(err) => {
                    error!(
                        event = "mvcc_flush_pin_conflict",
                        block = candidate.block.0,
                        commit_seq = candidate.commit_seq.0,
                        error = %err
                    );
                    return Err(err);
                }
            };
            self.inner
                .write_block(cx, candidate.block, candidate.data.as_slice())?;
            if let Err(err) = lifecycle.mark_persisted(candidate.block, candidate.commit_seq) {
                error!(
                    event = "mvcc_flush_commit_state_update_failed",
                    txn_id = candidate.txn_id.0,
                    block = candidate.block.0,
                    commit_seq = candidate.commit_seq.0,
                    error = %err
                );
                return Err(err);
            }
            drop(pin);
        }
        Ok(())
    }

    fn notify_repair_flush(&self, cx: &Cx, flushes: &[FlushCandidate]) -> Result<()> {
        if flushes.is_empty() {
            return Ok(());
        }

        let blocks: Vec<BlockNumber> = flushes.iter().map(|candidate| candidate.block).collect();
        // block_preview feeds only the debug! record below; skip the (up to
        // 16-element) allocation + collect when the refresh debug target is
        // disabled (the default). `blocks` itself is still needed for
        // on_flush_committed, so only the preview is guarded.
        let block_preview: Vec<u64> = if tracing::enabled!(target: "ffs::repair::refresh", tracing::Level::DEBUG)
        {
            blocks.iter().take(16).map(|block| block.0).collect()
        } else {
            Vec::new()
        };
        debug!(
            target: "ffs::repair::refresh",
            event = "flush_triggers_refresh",
            block_count = blocks.len(),
            block_ids = ?block_preview,
            truncated = blocks.len() > block_preview.len()
        );
        self.repair_flush_lifecycle.on_flush_committed(cx, &blocks)
    }

    fn restore_pending_flush_candidates(&self, flushes: Vec<FlushCandidate>) {
        let attempted = flushes.len();
        let mut stale = Vec::new();
        let restored = {
            let mut guard = self.state.lock();
            let mut restored = 0_usize;
            for candidate in flushes {
                if guard.is_current_flush_candidate(&candidate) {
                    guard.pending_flush.push(candidate);
                    restored = restored.saturating_add(1);
                } else {
                    stale.push((
                        candidate.block.0,
                        candidate.txn_id.0,
                        candidate.commit_seq.0,
                        candidate.seq,
                    ));
                }
            }
            drop(guard);
            restored
        };
        for (block, txn_id, commit_seq, dirty_seq) in stale {
            warn!(
                event = "stale_pending_flush_not_restored",
                block, txn_id, commit_seq, dirty_seq
            );
        }
        if restored < attempted {
            debug!(
                event = "pending_flush_restore_filtered",
                attempted,
                restored,
                dropped = attempted.saturating_sub(restored)
            );
        }
    }

    fn flush_pending_evictions(&self, cx: &Cx, pending_flush: Vec<FlushCandidate>) -> Result<()> {
        if pending_flush.is_empty() {
            return Ok(());
        }

        debug!(
            event = "pending_flush_batch_start",
            blocks = pending_flush.len(),
            "flushing pending dirty evictions"
        );

        if let Err(err) = self.flush_blocks(cx, &pending_flush) {
            // Restore the pending queue on failure so callers can retry.
            self.restore_pending_flush_candidates(pending_flush);
            error!(event = "pending_flush_batch_failed", error = %err);
            return Err(err);
        }

        if let Err(err) = self.notify_repair_flush(cx, &pending_flush) {
            // Blocks were already written to device by flush_blocks above.
            // Do NOT restore them as dirty — just log the repair notification
            // failure and continue. The blocks are persisted; only the repair
            // system missed the notification.
            error!(event = "pending_flush_batch_repair_notify_failed", error = %err);
        }

        let mut guard = self.state.lock();
        for candidate in &pending_flush {
            guard.clear_dirty(candidate.block, candidate.seq);
        }
        ArcState::add_usize_to_counter(&mut guard.dirty_flushes, pending_flush.len());
        info!(
            event = "pending_flush_batch_complete",
            blocks = pending_flush.len(),
            dirty_flushes = guard.dirty_flushes
        );
        drop(guard);
        Ok(())
    }
}

impl<D: BlockDevice> BlockDevice for ArcCache<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        cx_checkpoint(cx)?;
        #[cfg(feature = "s3fifo")]
        if let Some(buf) = self.s3_fast_hit(block) {
            return Ok(buf);
        }
        {
            let mut guard = self.state.lock();
            if let Some(buf) = guard.resident.get(&block).cloned() {
                guard.on_hit(block);
                #[cfg(feature = "s3fifo")]
                let fast_invalidations = guard.take_fast_invalidations();
                drop(guard);
                #[cfg(feature = "s3fifo")]
                self.apply_s3_fast_resident_updates(fast_invalidations, None);
                return Ok(buf);
            }
        }

        let _page_lock = self.page_locks.acquire(block);
        {
            let mut guard = self.state.lock();
            if let Some(buf) = guard.resident.get(&block).cloned() {
                guard.on_hit(block);
                #[cfg(feature = "s3fifo")]
                let fast_invalidations = guard.take_fast_invalidations();
                drop(guard);
                #[cfg(feature = "s3fifo")]
                self.apply_s3_fast_resident_updates(fast_invalidations, None);
                return Ok(buf);
            }
        }

        let buf = self.inner.read_block(cx, block)?;

        #[cfg(feature = "s3fifo")]
        let mutation_guard = self.begin_s3_fast_mutation();
        let mut guard = self.state.lock();
        // Re-check: another thread may have populated this block while we
        // were reading from the device (TOCTOU race).  If so, treat as a hit
        // and return the data already in the cache (it might be newer).
        #[cfg(feature = "s3fifo")]
        let mut fast_insert = None;
        let final_buf = if let Some(existing) = guard.resident.get(&block).cloned() {
            guard.on_hit(block);
            #[cfg(feature = "s3fifo")]
            {
                fast_insert = self
                    .s3_fast_entry_for(&guard, block, &existing)
                    .map(|entry| (block, entry));
            }
            existing
        } else {
            let bypass_cache = guard.on_read_miss_or_scan_bypass(block);
            if !bypass_cache {
                guard.resident.insert(block, buf.clone_ref());
                #[cfg(feature = "s3fifo")]
                {
                    fast_insert = self
                        .s3_fast_entry_for(&guard, block, &buf)
                        .map(|entry| (block, entry));
                }
            }
            buf
        };
        let pending_flush = guard.take_pending_flush();
        #[cfg(feature = "s3fifo")]
        let fast_invalidations = guard.take_fast_invalidations();
        drop(guard);
        #[cfg(feature = "s3fifo")]
        self.apply_s3_fast_resident_updates(fast_invalidations, fast_insert);
        #[cfg(feature = "s3fifo")]
        drop(mutation_guard);
        self.flush_pending_evictions(cx, pending_flush)?;
        Ok(final_buf)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        if matches!(self.write_policy, ArcWritePolicy::WriteThrough) {
            self.inner.write_block(cx, block, data)?;
        } else {
            cx_checkpoint(cx)?;
        }

        let mut enforce_backpressure = false;
        #[cfg(feature = "s3fifo")]
        let mutation_guard = self.begin_s3_fast_mutation();
        let mut guard = self.state.lock();
        let payload = BlockBuf::new(data.to_vec());
        if guard.resident.contains_key(&block) {
            // Block already cached — just update data and touch for recency.
            guard.resident.insert(block, payload.clone_ref());
            guard.on_hit(block);
        } else {
            guard.on_miss_or_ghost_hit(block);
            guard.resident.insert(block, payload.clone_ref());
        }
        #[cfg(feature = "s3fifo")]
        let fast_insert = self
            .s3_fast_entry_for(&guard, block, &payload)
            .map(|entry| (block, entry));

        if matches!(self.write_policy, ArcWritePolicy::WriteBack) {
            guard.mark_dirty(
                block,
                data.len(),
                TxnId(0),
                Some(CommitSeq(0)),
                DirtyState::Committed,
            );
            trace!(
                event = "mvcc_dirty_stage",
                txn_id = 0_u64,
                block = block.0,
                commit_seq_opt = 0_u64,
                state = "committed"
            );
        } else {
            guard.clear_dirty_unconditional(block);
        }

        let metrics = guard.snapshot_metrics();
        trace!(
            event = "cache_write",
            block = block.0,
            bytes = data.len(),
            write_policy = ?self.write_policy,
            dirty_blocks = metrics.dirty_blocks,
            dirty_bytes = metrics.dirty_bytes,
            dirty_ratio = metrics.dirty_ratio(),
            oldest_dirty_age_ticks = metrics.oldest_dirty_age_ticks.unwrap_or(0)
        );

        if matches!(self.write_policy, ArcWritePolicy::WriteBack) {
            let (_, committed_blocks) = guard.dirty.state_counts();
            let dirty_ratio = if guard.capacity == 0 {
                0.0
            } else {
                committed_blocks as f64 / guard.capacity as f64
            };
            if dirty_ratio > DIRTY_CRITICAL_WATERMARK {
                enforce_backpressure = true;
                warn!(
                    event = "flush_backpressure_critical",
                    block = block.0,
                    dirty_ratio,
                    critical_watermark = DIRTY_CRITICAL_WATERMARK
                );
            } else if dirty_ratio > DIRTY_HIGH_WATERMARK {
                warn!(
                    event = "flush_backpressure_high",
                    block = block.0,
                    dirty_ratio,
                    high_watermark = DIRTY_HIGH_WATERMARK
                );
            }
        }

        let pending_flush = guard.take_pending_flush();
        #[cfg(feature = "s3fifo")]
        let fast_invalidations = guard.take_fast_invalidations();
        drop(guard);
        #[cfg(feature = "s3fifo")]
        self.apply_s3_fast_resident_updates(fast_invalidations, fast_insert);
        #[cfg(feature = "s3fifo")]
        drop(mutation_guard);
        self.flush_pending_evictions(cx, pending_flush)?;

        if enforce_backpressure {
            // Block writers by synchronously draining until we're back under high watermark.
            loop {
                let dirty_ratio = self.committed_dirty_ratio();
                if dirty_ratio <= DIRTY_HIGH_WATERMARK {
                    break;
                }
                self.flush_dirty(cx)?;
            }
        }

        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        // Flush any deferred dirty blocks before syncing the underlying device.
        self.flush_dirty(cx)?;
        self.inner.sync(cx)
    }
}

impl<D: BlockDevice> BlockDevice for ShardedArcCache<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        self.shard_for(block).read_block(cx, block)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        self.shard_for(block).write_block(cx, block, data)
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        for shard in &self.shards {
            shard.flush_dirty(cx)?;
        }
        self.inner.sync(cx)
    }
}

impl<D: BlockDevice> BlockCache for ShardedArcCache<D> {
    fn mark_clean(&self, block: BlockNumber) {
        self.shard_for(block).mark_clean(block);
    }

    fn dirty_blocks_oldest_first(&self) -> Vec<BlockNumber> {
        let mut dirty = Vec::new();
        for shard in &self.shards {
            dirty.extend(shard.dirty_blocks_oldest_first());
        }
        dirty
    }

    fn evict(&self, block: BlockNumber) {
        self.shard_for(block).evict(block);
    }
}

impl<D: BlockDevice> BlockCache for ArcCache<D> {
    fn mark_clean(&self, block: BlockNumber) {
        let mut guard = self.state.lock();
        guard.clear_dirty_unconditional(block);
        let metrics = guard.snapshot_metrics();
        drop(guard);
        trace!(
            event = "mark_clean",
            block = block.0,
            dirty_blocks = metrics.dirty_blocks,
            dirty_bytes = metrics.dirty_bytes
        );
    }

    fn dirty_blocks_oldest_first(&self) -> Vec<BlockNumber> {
        self.state.lock().dirty_blocks()
    }

    fn evict(&self, block: BlockNumber) {
        let mut guard = self.state.lock();
        if guard.is_dirty(block) {
            let metrics = guard.snapshot_metrics();
            warn!(
                event = "dirty_evict_attempt",
                block = block.0,
                dirty_blocks = metrics.dirty_blocks,
                dirty_bytes = metrics.dirty_bytes,
                dirty_ratio = metrics.dirty_ratio(),
                oldest_dirty_age_ticks = metrics.oldest_dirty_age_ticks.unwrap_or(0),
                "dirty block cannot be evicted before flush"
            );
            return;
        }

        #[cfg(feature = "s3fifo")]
        let mutation_guard = {
            let target_present = guard.t1.contains(&block)
                || guard.t2.contains(&block)
                || guard.resident.contains_key(&block)
                || matches!(guard.loc.get(&block), Some(ArcList::B1 | ArcList::B2));
            // The state mutex is already held when mutation becomes visible. A
            // fast reader that completed its epoch/active validation before this
            // point linearizes before eviction. Once active is incremented, fast
            // readers fall back to the state mutex and can only observe the
            // post-eviction state after this critical section releases it.
            target_present.then(|| self.begin_s3_fast_mutation())
        };

        let mut removed = false;
        #[cfg(not(feature = "s3fifo"))]
        guard.remove_resident_recency(block);
        removed |= ArcState::remove_from_list(&mut guard.t1, block);
        removed |= ArcState::remove_from_list(&mut guard.t2, block);
        removed |= guard.remove_ghost_block(block);
        removed |= guard.resident.remove(&block).is_some();
        #[cfg(feature = "s3fifo")]
        if removed {
            if let Some(handle) = guard.access_count.remove(&block) {
                handle.invalidate();
            }
            guard.fast_invalidations.push(block);
        }
        guard.clear_dirty_unconditional(block);
        let _ = guard.loc.remove(&block);

        let evicted = if removed {
            ArcState::increment_counter(&mut guard.evictions);
            true
        } else {
            false
        };
        #[cfg(feature = "s3fifo")]
        let fast_invalidations = if mutation_guard.is_some() {
            guard.take_fast_invalidations()
        } else {
            Vec::new()
        };
        drop(guard);
        #[cfg(feature = "s3fifo")]
        if let Some(mutation_guard) = mutation_guard {
            self.apply_s3_fast_resident_updates(fast_invalidations, None);
            // Dropping last advances the epoch and re-enables the fast path;
            // thread-local entries from before eviction can no longer match.
            drop(mutation_guard);
        }

        if evicted {
            trace!(event = "cache_evict_clean", block = block.0);
        }
    }
}

impl<D: BlockDevice> ArcCache<D> {
    /// Flush at most `max_blocks` dirty blocks in oldest-first order.
    ///
    /// Returns the number of blocks flushed in this batch.
    pub fn flush_dirty_batch(&self, cx: &Cx, max_blocks: usize) -> Result<usize> {
        cx_checkpoint(cx)?;
        if max_blocks == 0 {
            return Ok(0);
        }

        let (flushes, pre_metrics) = {
            let mut guard = self.state.lock();
            let metrics = guard.snapshot_metrics();
            let flushes = guard.take_dirty_and_pending_flushes_limited(max_blocks);
            drop(guard);
            (flushes, metrics)
        };

        if flushes.is_empty() {
            return Ok(0);
        }

        let flush_bytes: usize = flushes.iter().map(|candidate| candidate.data.len()).sum();
        let min_commit_seq = flushes.iter().map(|candidate| candidate.commit_seq.0).min();
        let max_commit_seq = flushes.iter().map(|candidate| candidate.commit_seq.0).max();
        debug!(
            event = "flush_batch_start",
            batch_len = flushes.len(),
            oldest_block = flushes.first().map_or(0, |candidate| candidate.block.0),
            oldest_dirty_age_ticks = pre_metrics.oldest_dirty_age_ticks.unwrap_or(0),
            policy = ?self.write_policy,
            attempted_bytes = flush_bytes
        );

        let started = Instant::now();
        if let Err(err) = self.flush_blocks(cx, &flushes) {
            let attempted_blocks = flushes.len();
            self.restore_pending_flush_candidates(flushes);
            error!(
                event = "flush_batch_failed",
                error = %err,
                attempted_blocks,
                duration_ms = started.elapsed().as_millis(),
                attempted_bytes = flush_bytes
            );
            return Err(err);
        }

        if let Err(err) = self.notify_repair_flush(cx, &flushes) {
            // Blocks were already written to device by flush_blocks above.
            // Do NOT restore them as dirty — the write is durable. Only
            // the repair notification was lost; log and continue.
            error!(
                event = "flush_batch_repair_notify_failed",
                error = %err,
                attempted_blocks = flushes.len(),
                duration_ms = started.elapsed().as_millis(),
                attempted_bytes = flush_bytes
            );
        }

        let mut guard = self.state.lock();
        for candidate in &flushes {
            guard.clear_dirty(candidate.block, candidate.seq);
        }
        ArcState::add_usize_to_counter(&mut guard.dirty_flushes, flushes.len());
        let metrics = guard.snapshot_metrics();
        drop(guard);
        info!(
            event = "mvcc_flush_commit_batch",
            flushed_blocks = flushes.len(),
            min_commit_seq = min_commit_seq.unwrap_or(0),
            max_commit_seq = max_commit_seq.unwrap_or(0),
            duration_ms = started.elapsed().as_millis()
        );
        info!(
            event = "flush_batch_complete",
            flushed_blocks = flushes.len(),
            flushed_bytes = flush_bytes,
            duration_ms = started.elapsed().as_millis(),
            remaining_dirty_blocks = metrics.dirty_blocks,
            remaining_dirty_ratio = metrics.dirty_ratio()
        );
        info!(
            event = "flush_batch",
            blocks_flushed = flushes.len(),
            bytes_written = flush_bytes,
            flush_duration_us = started.elapsed().as_micros()
        );

        Ok(flushes.len())
    }

    /// Flush all dirty blocks to the underlying device.
    ///
    /// Write-through mode should normally have zero dirty blocks; write-back
    /// mode accumulates dirty blocks until this method (or a future daemon)
    /// flushes them durably.
    ///
    /// Returns Ok(()) if all dirty blocks were successfully flushed.
    pub fn flush_dirty(&self, cx: &Cx) -> Result<()> {
        cx_checkpoint(cx)?;

        // Collect all dirty payloads (resident + evicted pending) under lock.
        let flushes = {
            let mut guard = self.state.lock();
            guard.take_dirty_and_pending_flushes()
        };

        if flushes.is_empty() {
            return Ok(());
        }

        let flush_bytes: usize = flushes.iter().map(|candidate| candidate.data.len()).sum();
        let min_commit_seq = flushes.iter().map(|candidate| candidate.commit_seq.0).min();
        let max_commit_seq = flushes.iter().map(|candidate| candidate.commit_seq.0).max();
        debug!(
            event = "flush_dirty_start",
            blocks = flushes.len(),
            bytes = flush_bytes
        );

        let started = Instant::now();
        if let Err(err) = self.flush_blocks(cx, &flushes) {
            // Restore flush state on failure so retry logic can recover.
            self.restore_pending_flush_candidates(flushes);
            error!(
                event = "flush_dirty_failed",
                error = %err,
                duration_ms = started.elapsed().as_millis()
            );
            return Err(err);
        }

        if let Err(err) = self.notify_repair_flush(cx, &flushes) {
            // Blocks already persisted by flush_blocks. Only repair
            // notification was lost — log and continue.
            error!(
                event = "flush_dirty_repair_notify_failed",
                error = %err,
                duration_ms = started.elapsed().as_millis()
            );
        }

        let mut guard = self.state.lock();
        for candidate in &flushes {
            guard.clear_dirty(candidate.block, candidate.seq);
        }
        ArcState::add_usize_to_counter(&mut guard.dirty_flushes, flushes.len());
        let metrics = guard.snapshot_metrics();
        info!(
            event = "mvcc_flush_commit_batch",
            flushed_blocks = flushes.len(),
            min_commit_seq = min_commit_seq.unwrap_or(0),
            max_commit_seq = max_commit_seq.unwrap_or(0),
            duration_ms = started.elapsed().as_millis()
        );
        info!(
            event = "flush_dirty_complete",
            blocks = flushes.len(),
            bytes = flush_bytes,
            duration_ms = started.elapsed().as_millis(),
            dirty_flushes = guard.dirty_flushes,
            remaining_dirty_blocks = metrics.dirty_blocks,
            remaining_dirty_bytes = metrics.dirty_bytes,
            remaining_dirty_ratio = metrics.dirty_ratio()
        );
        info!(
            event = "flush_batch",
            blocks_flushed = flushes.len(),
            bytes_written = flush_bytes,
            flush_duration_us = started.elapsed().as_micros()
        );

        Ok(())
    }

    /// Return the number of currently dirty blocks.
    #[must_use]
    pub fn dirty_count(&self) -> usize {
        self.state.lock().dirty.dirty_count()
    }

    /// Return dirty blocks in oldest-first order.
    #[must_use]
    pub fn dirty_blocks_oldest_first(&self) -> Vec<BlockNumber> {
        self.state.lock().dirty_blocks()
    }
}
