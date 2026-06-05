//! Bw-Tree mapping-table + delta-chain core.
//!
//! This module provides a safe (no-`unsafe`) foundation for Bw-Tree style
//! append-only delta chains:
//! - mapping table indirection (`PageId -> head delta`)
//! - CAS-style head replacement with retry loops
//! - delta traversal/materialization for lookup
//! - crossbeam-epoch deferred reclamation for replaced delta heads
//!
//! Note: this crate forbids `unsafe`, so this implementation uses `Arc` for
//! delta ownership and crossbeam-epoch for deferred reclamation handoff.

use crossbeam_epoch as epoch;
use ffs_error::{FfsError, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error as IoError, ErrorKind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{debug, trace, warn};

const MAX_CAS_RETRIES: usize = 1_024;
const MAX_CHAIN_DEPTH: usize = 16_384;
/// Hard ceiling for chain-walk loops. The consolidation logic keeps real
/// chains far below `MAX_CHAIN_DEPTH`; this is a runaway-loop guard, not a
/// correctness limit. The grace headroom over `MAX_CHAIN_DEPTH` accommodates
/// brief overshoots when several threads race to append before any of them
/// hits the pre-consolidation trigger — a 16385-node chain (`MAX_CHAIN_DEPTH`
/// deltas plus the base) would previously be rejected as `Corruption` even
/// when its base node was perfectly valid.
const MAX_CHAIN_WALK: usize = MAX_CHAIN_DEPTH * 2;
const DEFAULT_CONSOLIDATION_THRESHOLD: usize = 16;
const DEFAULT_MESSAGE_BUFFER_CAPACITY: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BwKey(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BwValue(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PageId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageDelta {
    Insert {
        key: BwKey,
        value: BwValue,
        next: Arc<Self>,
    },
    Delete {
        key: BwKey,
        next: Arc<Self>,
    },
    Split {
        separator: BwKey,
        new_sibling: PageId,
        next: Arc<Self>,
    },
    Merge {
        removed_sibling: PageId,
        next: Arc<Self>,
    },
    MessageBuffer {
        messages: BTreeMap<BwKey, BufferedMutation>,
        next: Arc<Self>,
    },
    AppendRun {
        entries: Arc<Vec<(BwKey, BwValue)>>,
        next: Arc<Self>,
    },
    Base {
        entries: BTreeMap<BwKey, BwValue>,
    },
}

impl PageDelta {
    #[must_use]
    pub fn empty_base() -> Arc<Self> {
        Arc::new(Self::Base {
            entries: BTreeMap::new(),
        })
    }
}

/// Iterative `Drop` for the `next: Arc<Self>` chain.
///
/// `PageDelta` forms a singly-linked list via `Arc<Self>`, so the default
/// recursive `Drop` walks the chain through nested stack frames and overflows
/// the thread stack on any chain that approaches `MAX_CHAIN_DEPTH`. Ordinarily
/// pre-consolidation would keep chains short, but `defer_reclaim` hands the
/// *old* head (potentially tens of thousands of nodes) to crossbeam-epoch for
/// deferred drop right after a consolidation CAS — and that drop eventually
/// runs on a worker thread with the default 2 MiB stack, where ~16 KiB-deep
/// recursion explodes.
///
/// The standard trick: extract `next` and walk the chain in a loop, only
/// touching uniquely-owned arcs. Shared arcs bail out and let the remaining
/// owners drive their own (shorter, by definition) drop chain.
impl Drop for PageDelta {
    fn drop(&mut self) {
        let mut head = match self {
            Self::Insert { next, .. }
            | Self::Delete { next, .. }
            | Self::Split { next, .. }
            | Self::Merge { next, .. }
            | Self::MessageBuffer { next, .. }
            | Self::AppendRun { next, .. } => std::mem::replace(next, Self::empty_base()),
            Self::Base { .. } => return,
        };
        // `self`'s default field-drops still run after this method returns,
        // but `next` now holds an empty base, so its Drop terminates in O(1).

        loop {
            match Arc::try_unwrap(head) {
                Ok(mut node) => {
                    let next_arc = match &mut node {
                        Self::Insert { next, .. }
                        | Self::Delete { next, .. }
                        | Self::Split { next, .. }
                        | Self::Merge { next, .. }
                        | Self::MessageBuffer { next, .. }
                        | Self::AppendRun { next, .. } => {
                            std::mem::replace(next, Self::empty_base())
                        }
                        Self::Base { .. } => return,
                    };
                    // `node` is dropped at the end of this arm; recursing
                    // back into our Drop impl picks up the empty base via
                    // the `Base` short-circuit above, so the recursion is
                    // bounded by one frame.
                    head = next_arc;
                }
                Err(_shared) => {
                    // Some other Arc clone is keeping the rest of the chain
                    // alive; let that owner walk it.
                    return;
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PageSnapshot {
    pub epoch: u64,
    pub head: Arc<PageDelta>,
    pub chain_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaMutation {
    Insert {
        key: BwKey,
        value: BwValue,
    },
    Delete {
        key: BwKey,
    },
    Split {
        separator: BwKey,
        new_sibling: PageId,
    },
    Merge {
        removed_sibling: PageId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferedMutation {
    Insert(BwValue),
    Delete,
}

enum MessageBufferAppend {
    Buffered {
        new_head: Arc<PageDelta>,
        new_chain_len: usize,
    },
    FlushRequired,
}

#[derive(Debug)]
struct PageHead {
    delta: Arc<PageDelta>,
    chain_len: usize,
}

impl PageHead {
    fn empty() -> Self {
        Self {
            delta: PageDelta::empty_base(),
            chain_len: 1,
        }
    }

    fn new(delta: Arc<PageDelta>, chain_len: usize) -> Self {
        Self { delta, chain_len }
    }
}

#[derive(Debug)]
struct MappingEntry {
    head: RwLock<PageHead>,
    epoch: AtomicU64,
}

impl MappingEntry {
    fn new() -> Self {
        Self {
            head: RwLock::new(PageHead::empty()),
            epoch: AtomicU64::new(0),
        }
    }
}

#[derive(Debug)]
pub struct MappingTable {
    pages: Vec<MappingEntry>,
    next_page_id: AtomicU64,
}

impl MappingTable {
    #[must_use]
    pub fn with_capacity(page_capacity: usize) -> Self {
        let pages = (0..page_capacity).map(|_| MappingEntry::new()).collect();
        Self {
            pages,
            next_page_id: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn page_capacity(&self) -> usize {
        self.pages.len()
    }

    pub fn allocate_page(&self) -> Result<PageId> {
        let capacity = u64::try_from(self.pages.len()).map_err(|_| FfsError::NoSpace)?;
        let mut page_raw = self.next_page_id.load(Ordering::Acquire);
        loop {
            if page_raw >= capacity {
                return Err(FfsError::NoSpace);
            }
            let next_page = page_raw.checked_add(1).ok_or(FfsError::NoSpace)?;
            match self.next_page_id.compare_exchange_weak(
                page_raw,
                next_page,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => page_raw = observed,
            }
        }
        debug!(
            target: "ffs::bwtree",
            event = "bw_page_alloc",
            page_id = page_raw,
            capacity = self.pages.len()
        );
        Ok(PageId(page_raw))
    }

    pub fn get_page(&self, page_id: PageId) -> Result<PageSnapshot> {
        let entry = self.entry(page_id)?;
        let epoch = entry.epoch.load(Ordering::Acquire);
        let head_guard = read_lock(&entry.head);
        Ok(PageSnapshot {
            epoch,
            head: Arc::clone(&head_guard.delta),
            chain_len: head_guard.chain_len,
        })
    }

    pub fn cas_page(
        &self,
        page_id: PageId,
        expected_epoch: u64,
        new_head: Arc<PageDelta>,
        new_chain_len: usize,
    ) -> Result<bool> {
        let entry = self.entry(page_id)?;
        trace!(
            target: "ffs::bwtree",
            event = "bw_cas_attempt",
            page_id = page_id.0,
            expected_epoch
        );
        let mut head_guard = write_lock(&entry.head);
        match entry.epoch.compare_exchange(
            expected_epoch,
            expected_epoch.wrapping_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                debug_assert_eq!(chain_length(&new_head), new_chain_len);
                let old_head = Arc::clone(&head_guard.delta);
                *head_guard = PageHead::new(new_head, new_chain_len);
                defer_reclaim(old_head);
                debug!(
                    target: "ffs::bwtree",
                    event = "bw_cas_commit",
                    page_id = page_id.0,
                    new_epoch = expected_epoch.wrapping_add(1)
                );
                Ok(true)
            }
            Err(observed_epoch) => {
                drop(head_guard);
                trace!(
                    target: "ffs::bwtree",
                    event = "bw_cas_retry",
                    page_id = page_id.0,
                    expected_epoch,
                    observed_epoch
                );
                Ok(false)
            }
        }
    }

    pub fn append_delta(&self, page_id: PageId, mutation: DeltaMutation) -> Result<usize> {
        for attempt in 1..=MAX_CAS_RETRIES {
            let snapshot = self.get_page(page_id)?;
            let _guard = epoch::pin();

            match message_buffer_append(mutation, &snapshot) {
                Some(MessageBufferAppend::Buffered {
                    new_head,
                    new_chain_len,
                }) => {
                    if self.cas_page(page_id, snapshot.epoch, new_head, new_chain_len)? {
                        return Ok(attempt);
                    }
                    continue;
                }
                Some(MessageBufferAppend::FlushRequired) => {
                    let (new_head, new_chain_len) =
                        append_run_or_materialized_base(&snapshot)?;
                    if self.cas_page(page_id, snapshot.epoch, new_head, new_chain_len)? {
                        debug!(
                            target: "ffs::bwtree",
                            event = "bw_append_message_buffer_flush",
                            page_id = page_id.0,
                            capacity = DEFAULT_MESSAGE_BUFFER_CAPACITY
                        );
                    }
                    continue;
                }
                None => {}
            }

            let chain_len = snapshot.chain_len;
            if chain_len > DEFAULT_CONSOLIDATION_THRESHOLD {
                let (state, _) = materialize_from_head(&snapshot.head)?;
                let new_base = Arc::new(PageDelta::Base { entries: state });
                if self.cas_page(page_id, snapshot.epoch, new_base, 1)? {
                    debug!(
                        target: "ffs::bwtree",
                        event = "bw_append_preconsolidate",
                        page_id = page_id.0,
                        chain_len
                    );
                }
                continue;
            }

            let new_head = Arc::new(mutation.to_delta(snapshot.head));
            if self.cas_page(page_id, snapshot.epoch, new_head, snapshot.chain_len + 1)? {
                return Ok(attempt);
            }
        }
        warn!(
            target: "ffs::bwtree",
            event = "bw_cas_retry_exhausted",
            page_id = page_id.0,
            max_retries = MAX_CAS_RETRIES
        );
        Err(FfsError::Io(IoError::other(
            "bw-tree CAS retries exhausted without progress",
        )))
    }

    pub fn insert(&self, page_id: PageId, key: BwKey, value: BwValue) -> Result<usize> {
        self.append_delta(page_id, DeltaMutation::Insert { key, value })
    }

    pub fn delete(&self, page_id: PageId, key: BwKey) -> Result<usize> {
        self.append_delta(page_id, DeltaMutation::Delete { key })
    }

    pub fn append_split_delta(
        &self,
        page_id: PageId,
        separator: BwKey,
        new_sibling: PageId,
    ) -> Result<usize> {
        self.append_delta(
            page_id,
            DeltaMutation::Split {
                separator,
                new_sibling,
            },
        )
    }

    pub fn append_merge_delta(&self, page_id: PageId, removed_sibling: PageId) -> Result<usize> {
        self.append_delta(page_id, DeltaMutation::Merge { removed_sibling })
    }

    pub fn lookup(&self, page_id: PageId, key: BwKey) -> Result<Option<BwValue>> {
        let snapshot = self.get_page(page_id)?;
        let (value, chain_len) = lookup_from_head(&snapshot.head, key)?;
        debug!(
            target: "ffs::bwtree",
            event = "bw_lookup_chain_stats",
            page_id = page_id.0,
            chain_len,
            epoch = snapshot.epoch
        );
        Ok(value)
    }

    pub fn materialize_page(&self, page_id: PageId) -> Result<BTreeMap<BwKey, BwValue>> {
        let snapshot = self.get_page(page_id)?;
        let (state, chain_len) = materialize_from_head(&snapshot.head)?;
        debug!(
            target: "ffs::bwtree",
            event = "bw_lookup_chain_stats",
            page_id = page_id.0,
            chain_len,
            epoch = snapshot.epoch
        );
        Ok(state)
    }

    pub fn range_scan(
        &self,
        page_id: PageId,
        start: BwKey,
        count: usize,
    ) -> Result<Vec<(BwKey, BwValue)>> {
        let snapshot = self.get_page(page_id)?;
        let (rows, chain_len) = range_scan_from_head(&snapshot.head, start, count)?;
        debug!(
            target: "ffs::bwtree",
            event = "bw_lookup_chain_stats",
            page_id = page_id.0,
            chain_len,
            epoch = snapshot.epoch
        );
        Ok(rows)
    }

    /// Consolidate a page's delta chain into a fresh base page.
    ///
    /// Materializes the current chain, creates a new `PageDelta::Base`,
    /// and atomically replaces the old chain via CAS. If the CAS fails
    /// (concurrent modification), retries up to `max_retries` times.
    ///
    /// Returns `Ok(result)` with consolidation statistics, or `Err` if
    /// retries are exhausted or the page is not found.
    pub fn consolidate_page(
        &self,
        page_id: PageId,
        config: &ConsolidationConfig,
    ) -> Result<ConsolidationResult> {
        for attempt in 1..=config.max_retries {
            let snapshot = self.get_page(page_id)?;
            let chain_len_before = snapshot.chain_len;

            if chain_len_before <= 1 {
                // Already a base page (or single delta on base); nothing to do.
                // Reporting entries_count here as a hard-coded zero misleads
                // operator dashboards and metrics consumers, so read the
                // actual count from the base node when one is present.
                let entries_count = match snapshot.head.as_ref() {
                    PageDelta::Base { entries } => entries.len(),
                    _ => 0,
                };
                trace!(
                    target: "ffs::bwtree",
                    event = "bw_consolidate_skip",
                    page_id = page_id.0,
                    chain_len = chain_len_before,
                    entries_count,
                    reason = "already_base"
                );
                return Ok(ConsolidationResult {
                    chain_len_before,
                    chain_len_after: chain_len_before,
                    entries_count,
                    cas_attempts: 0,
                });
            }

            let _guard = epoch::pin();
            let (state, _) = materialize_from_head(&snapshot.head)?;
            let entries_count = state.len();
            let new_base = Arc::new(PageDelta::Base { entries: state });

            if self.cas_page(page_id, snapshot.epoch, new_base, 1)? {
                debug!(
                    target: "ffs::bwtree",
                    event = "bw_consolidate_done",
                    page_id = page_id.0,
                    chain_len_before,
                    chain_len_after = 1,
                    entries_count,
                    cas_attempts = attempt
                );
                return Ok(ConsolidationResult {
                    chain_len_before,
                    chain_len_after: 1,
                    entries_count,
                    cas_attempts: attempt,
                });
            }

            trace!(
                target: "ffs::bwtree",
                event = "bw_consolidate_cas_retry",
                page_id = page_id.0,
                attempt
            );
        }

        warn!(
            target: "ffs::bwtree",
            event = "bw_consolidate_retry_exhausted",
            page_id = page_id.0,
            max_retries = config.max_retries
        );
        Err(FfsError::Io(IoError::new(
            ErrorKind::WouldBlock,
            "bw-tree consolidation CAS retries exhausted",
        )))
    }

    /// Scan all allocated pages and return page IDs whose delta chain
    /// length exceeds `threshold`.
    pub fn scan_for_consolidation(&self, threshold: usize) -> Vec<PageId> {
        let allocated = self.next_page_id.load(Ordering::Acquire);
        let mut candidates = Vec::new();
        for raw_id in 0..allocated {
            let page_id = PageId(raw_id);
            if let Ok(snapshot) = self.get_page(page_id) {
                if snapshot.chain_len > threshold {
                    candidates.push(page_id);
                }
            }
        }
        candidates
    }

    /// Consolidate all pages whose chain length exceeds the configured
    /// threshold. Returns the number of pages successfully consolidated.
    ///
    /// Per-page failures (e.g., CAS retry exhaustion under heavy concurrent
    /// load) are logged at warn level and skipped; the contract is "best
    /// effort, return how many succeeded" — failing one transient page must
    /// not throw away the work already done on the preceding pages.
    pub fn consolidate_all(&self, config: &ConsolidationConfig) -> Result<usize> {
        let candidates = self.scan_for_consolidation(config.chain_threshold);
        let mut consolidated = 0;
        let mut skipped = 0;
        for page_id in candidates {
            match self.consolidate_page(page_id, config) {
                Ok(_) => consolidated += 1,
                Err(FfsError::Io(err)) if err.kind() == ErrorKind::WouldBlock => {
                    skipped += 1;
                    warn!(
                        target: "ffs::bwtree",
                        event = "bw_consolidate_all_skip",
                        page_id = page_id.0,
                        error = %err,
                    );
                }
                Err(err) => return Err(err),
            }
        }
        debug!(
            target: "ffs::bwtree",
            event = "bw_consolidate_all_done",
            consolidated,
            skipped,
            threshold = config.chain_threshold
        );
        Ok(consolidated)
    }

    fn entry(&self, page_id: PageId) -> Result<&MappingEntry> {
        let page_index = usize::try_from(page_id.0).map_err(|_| page_not_found(page_id))?;
        let allocated = self.next_page_id.load(Ordering::Acquire);
        if page_id.0 >= allocated {
            return Err(page_not_found(page_id));
        }
        self.pages
            .get(page_index)
            .ok_or_else(|| page_not_found(page_id))
    }
}

/// Configuration for delta chain consolidation.
#[derive(Debug, Clone)]
pub struct ConsolidationConfig {
    /// Consolidate when chain length exceeds this value.
    pub chain_threshold: usize,
    /// Maximum CAS retry attempts per consolidation.
    pub max_retries: usize,
}

impl Default for ConsolidationConfig {
    fn default() -> Self {
        Self {
            chain_threshold: DEFAULT_CONSOLIDATION_THRESHOLD,
            max_retries: MAX_CAS_RETRIES,
        }
    }
}

/// Result of a page consolidation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsolidationResult {
    /// Delta chain length before consolidation.
    pub chain_len_before: usize,
    /// Delta chain length after consolidation (always 1 on success).
    pub chain_len_after: usize,
    /// Number of key-value entries in the consolidated base page.
    pub entries_count: usize,
    /// Number of CAS attempts needed.
    pub cas_attempts: usize,
}

/// Count the number of delta nodes in a chain (including the base page).
///
/// Walks at most `MAX_CHAIN_WALK` nodes and returns that limit if no base
/// is reached — a defensive cap, not a correctness claim. Healthy chains
/// stay well under `MAX_CHAIN_DEPTH`; the headroom over that threshold lets
/// brief overshoots (concurrent appenders all observing `chain_len <
/// MAX_CHAIN_DEPTH` before any of them consolidates) report an accurate
/// count instead of being silently truncated.
#[must_use]
pub fn chain_length(head: &Arc<PageDelta>) -> usize {
    let mut cursor = Arc::clone(head);
    let mut len = 0_usize;
    loop {
        len += 1;
        if len > MAX_CHAIN_WALK {
            return len;
        }
        match cursor.as_ref() {
            PageDelta::Base { .. } => return len,
            PageDelta::Insert { next, .. }
            | PageDelta::Delete { next, .. }
            | PageDelta::Split { next, .. }
            | PageDelta::Merge { next, .. }
            | PageDelta::MessageBuffer { next, .. }
            | PageDelta::AppendRun { next, .. } => {
                cursor = Arc::clone(next);
            }
        }
    }
}

impl DeltaMutation {
    fn to_delta(self, next: Arc<PageDelta>) -> PageDelta {
        match self {
            Self::Insert { key, value } => PageDelta::Insert { key, value, next },
            Self::Delete { key } => PageDelta::Delete { key, next },
            Self::Split {
                separator,
                new_sibling,
            } => PageDelta::Split {
                separator,
                new_sibling,
                next,
            },
            Self::Merge { removed_sibling } => PageDelta::Merge {
                removed_sibling,
                next,
            },
        }
    }
}

fn message_buffer_append(
    mutation: DeltaMutation,
    snapshot: &PageSnapshot,
) -> Option<MessageBufferAppend> {
    let buffered = BufferedMutation::from_delta(mutation)?;
    match snapshot.head.as_ref() {
        PageDelta::MessageBuffer { messages, next } => {
            let grows = !messages.contains_key(&buffered.key);
            if grows && messages.len() >= DEFAULT_MESSAGE_BUFFER_CAPACITY {
                return Some(MessageBufferAppend::FlushRequired);
            }
            let mut new_messages = messages.clone();
            new_messages.insert(buffered.key, buffered.mutation);
            Some(MessageBufferAppend::Buffered {
                new_head: Arc::new(PageDelta::MessageBuffer {
                    messages: new_messages,
                    next: Arc::clone(next),
                }),
                new_chain_len: snapshot.chain_len,
            })
        }
        _ if snapshot.chain_len <= DEFAULT_CONSOLIDATION_THRESHOLD => {
            let mut messages = BTreeMap::new();
            messages.insert(buffered.key, buffered.mutation);
            Some(MessageBufferAppend::Buffered {
                new_head: Arc::new(PageDelta::MessageBuffer {
                    messages,
                    next: Arc::clone(&snapshot.head),
                }),
                new_chain_len: snapshot.chain_len + 1,
            })
        }
        _ => None,
    }
}

fn append_run_or_materialized_base(snapshot: &PageSnapshot) -> Result<(Arc<PageDelta>, usize)> {
    if let Some(new_head) = append_run_from_message_buffer(&snapshot.head) {
        return Ok((new_head, snapshot.chain_len));
    }

    let (state, _) = materialize_from_head(&snapshot.head)?;
    Ok((Arc::new(PageDelta::Base { entries: state }), 1))
}

fn append_run_from_message_buffer(head: &Arc<PageDelta>) -> Option<Arc<PageDelta>> {
    let PageDelta::MessageBuffer { messages, next } = head.as_ref() else {
        return None;
    };
    let max_key = append_only_max_key(next.as_ref())?;
    let entries = buffered_insert_run_above(messages, max_key)?;
    Some(Arc::new(PageDelta::AppendRun {
        entries: Arc::new(entries),
        next: Arc::clone(next),
    }))
}

fn append_only_max_key(head: &PageDelta) -> Option<Option<BwKey>> {
    match head {
        PageDelta::Base { entries } => Some(entries.keys().next_back().copied()),
        PageDelta::AppendRun { entries, next } => entries
            .last()
            .map(|&(key, _)| Some(key))
            .or_else(|| append_only_max_key(next.as_ref())),
        PageDelta::Insert { .. }
        | PageDelta::Delete { .. }
        | PageDelta::Split { .. }
        | PageDelta::Merge { .. }
        | PageDelta::MessageBuffer { .. } => None,
    }
}

fn buffered_insert_run_above(
    messages: &BTreeMap<BwKey, BufferedMutation>,
    max_key: Option<BwKey>,
) -> Option<Vec<(BwKey, BwValue)>> {
    if messages.is_empty() {
        return None;
    }

    let mut entries = Vec::with_capacity(messages.len());
    for (&key, &message) in messages {
        if max_key.is_some_and(|bound| key <= bound) {
            return None;
        }
        let BufferedMutation::Insert(value) = message else {
            return None;
        };
        entries.push((key, value));
    }
    Some(entries)
}

struct BufferedMutationEntry {
    key: BwKey,
    mutation: BufferedMutation,
}

impl BufferedMutation {
    fn from_delta(mutation: DeltaMutation) -> Option<BufferedMutationEntry> {
        match mutation {
            DeltaMutation::Insert { key, value } => Some(BufferedMutationEntry {
                key,
                mutation: Self::Insert(value),
            }),
            DeltaMutation::Delete { key } => Some(BufferedMutationEntry {
                key,
                mutation: Self::Delete,
            }),
            DeltaMutation::Split { .. } | DeltaMutation::Merge { .. } => None,
        }
    }
}

fn page_not_found(page_id: PageId) -> FfsError {
    FfsError::NotFound(format!("bw-tree page {} is not allocated", page_id.0))
}

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaterializeOp {
    Insert { key: BwKey, value: BwValue },
    Delete { key: BwKey },
    Split { separator: BwKey },
}

fn materialize_from_head(head: &Arc<PageDelta>) -> Result<(BTreeMap<BwKey, BwValue>, usize)> {
    let mut ops: Vec<MaterializeOp> = Vec::new();
    let mut cursor = Arc::clone(head);
    let mut chain_len = 0_usize;

    loop {
        chain_len = chain_len.saturating_add(1);
        if chain_len > MAX_CHAIN_WALK {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "bw-tree delta chain exceeded walk limit ({MAX_CHAIN_WALK}) without base page"
                ),
            });
        }

        match cursor.as_ref() {
            PageDelta::Base { entries } => {
                let mut state = entries.clone();
                for op in ops.iter().rev().copied() {
                    apply_op(&mut state, op);
                }
                return Ok((state, chain_len));
            }
            PageDelta::Insert { key, value, next } => {
                ops.push(MaterializeOp::Insert {
                    key: *key,
                    value: *value,
                });
                cursor = Arc::clone(next);
            }
            PageDelta::Delete { key, next } => {
                ops.push(MaterializeOp::Delete { key: *key });
                cursor = Arc::clone(next);
            }
            PageDelta::Split {
                separator, next, ..
            } => {
                ops.push(MaterializeOp::Split {
                    separator: *separator,
                });
                cursor = Arc::clone(next);
            }
            PageDelta::Merge { next, .. } => {
                cursor = Arc::clone(next);
            }
            PageDelta::MessageBuffer { messages, next } => {
                push_buffered_ops(&mut ops, messages);
                cursor = Arc::clone(next);
            }
            PageDelta::AppendRun { entries, next } => {
                push_append_run_ops(&mut ops, entries);
                cursor = Arc::clone(next);
            }
        }
    }
}

fn range_scan_from_head(
    head: &Arc<PageDelta>,
    start: BwKey,
    count: usize,
) -> Result<(Vec<(BwKey, BwValue)>, usize)> {
    let mut ops: Vec<MaterializeOp> = Vec::new();
    let mut cursor = Arc::clone(head);
    let mut chain_len = 0_usize;

    loop {
        chain_len = chain_len.saturating_add(1);
        if chain_len > MAX_CHAIN_WALK {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "bw-tree delta chain exceeded walk limit ({MAX_CHAIN_WALK}) without base page"
                ),
            });
        }

        match cursor.as_ref() {
            PageDelta::Base { entries } => {
                let rows = bounded_range_from_base(entries, &ops, start, count);
                return Ok((rows, chain_len));
            }
            PageDelta::Insert { key, value, next } => {
                ops.push(MaterializeOp::Insert {
                    key: *key,
                    value: *value,
                });
                cursor = Arc::clone(next);
            }
            PageDelta::Delete { key, next } => {
                ops.push(MaterializeOp::Delete { key: *key });
                cursor = Arc::clone(next);
            }
            PageDelta::Split {
                separator, next, ..
            } => {
                ops.push(MaterializeOp::Split {
                    separator: *separator,
                });
                cursor = Arc::clone(next);
            }
            PageDelta::Merge { next, .. } => {
                cursor = Arc::clone(next);
            }
            PageDelta::MessageBuffer { messages, next } => {
                push_buffered_ops(&mut ops, messages);
                cursor = Arc::clone(next);
            }
            PageDelta::AppendRun { entries, next } => {
                push_append_run_ops(&mut ops, entries);
                cursor = Arc::clone(next);
            }
        }
    }
}

fn bounded_range_from_base(
    entries: &BTreeMap<BwKey, BwValue>,
    ops: &[MaterializeOp],
    start: BwKey,
    count: usize,
) -> Vec<(BwKey, BwValue)> {
    if count == 0 {
        return Vec::new();
    }

    let mut delta_values = BTreeMap::new();
    let mut shadowed_keys = BTreeSet::new();
    let mut base_upper_bound: Option<BwKey> = None;

    for op in ops {
        match *op {
            MaterializeOp::Insert { key, value } => {
                if key >= start
                    && !shadowed_keys.contains(&key)
                    && key_before_bound(key, base_upper_bound)
                {
                    delta_values.insert(key, value);
                }
                shadowed_keys.insert(key);
            }
            MaterializeOp::Delete { key } => {
                shadowed_keys.insert(key);
            }
            MaterializeOp::Split { separator } => {
                base_upper_bound =
                    Some(base_upper_bound.map_or(separator, |bound| bound.min(separator)));
            }
        }
    }

    let mut rows = Vec::with_capacity(count);
    let mut base_iter = entries.range(start..).peekable();
    let mut delta_iter = delta_values.iter().peekable();

    while rows.len() < count {
        let next_base = base_iter
            .peek()
            .map(|&(&key, &value)| (key, value))
            .filter(|&(key, _)| key_before_bound(key, base_upper_bound));
        let next_delta = delta_iter.peek().map(|&(&key, &value)| (key, value));

        match (next_base, next_delta) {
            (Some((base_key, base_value)), Some((delta_key, delta_value))) => {
                match base_key.cmp(&delta_key) {
                    std::cmp::Ordering::Less => {
                        base_iter.next();
                        if !shadowed_keys.contains(&base_key) {
                            rows.push((base_key, base_value));
                        }
                    }
                    std::cmp::Ordering::Greater => {
                        delta_iter.next();
                        rows.push((delta_key, delta_value));
                    }
                    std::cmp::Ordering::Equal => {
                        base_iter.next();
                        delta_iter.next();
                        rows.push((delta_key, delta_value));
                    }
                }
            }
            (Some((base_key, base_value)), None) => {
                base_iter.next();
                if !shadowed_keys.contains(&base_key) {
                    rows.push((base_key, base_value));
                }
            }
            (None, Some((delta_key, delta_value))) => {
                delta_iter.next();
                rows.push((delta_key, delta_value));
            }
            (None, None) => break,
        }
    }

    rows
}

fn key_before_bound(key: BwKey, bound: Option<BwKey>) -> bool {
    bound.is_none_or(|bound| key < bound)
}

fn lookup_from_head(head: &Arc<PageDelta>, key: BwKey) -> Result<(Option<BwValue>, usize)> {
    let mut cursor = head.as_ref();
    let mut chain_len = 0_usize;

    loop {
        chain_len = chain_len.saturating_add(1);
        if chain_len > MAX_CHAIN_WALK {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "bw-tree delta chain exceeded walk limit ({MAX_CHAIN_WALK}) without base page"
                ),
            });
        }

        match cursor {
            PageDelta::Base { entries } => return Ok((entries.get(&key).copied(), chain_len)),
            PageDelta::Insert {
                key: delta_key,
                value,
                next,
            } => {
                if *delta_key == key {
                    return Ok((Some(*value), chain_len));
                }
                cursor = next.as_ref();
            }
            PageDelta::Delete {
                key: delta_key,
                next,
            } => {
                if *delta_key == key {
                    return Ok((None, chain_len));
                }
                cursor = next.as_ref();
            }
            PageDelta::Split {
                separator, next, ..
            } => {
                if key >= *separator {
                    return Ok((None, chain_len));
                }
                cursor = next.as_ref();
            }
            PageDelta::Merge { next, .. } => {
                cursor = next.as_ref();
            }
            PageDelta::MessageBuffer { messages, next } => {
                if let Some(message) = messages.get(&key) {
                    return Ok((
                        match *message {
                            BufferedMutation::Insert(value) => Some(value),
                            BufferedMutation::Delete => None,
                        },
                        chain_len,
                    ));
                }
                cursor = next.as_ref();
            }
            PageDelta::AppendRun { entries, next } => {
                match entries.binary_search_by_key(&key, |(entry_key, _)| *entry_key) {
                    Ok(index) => return Ok((Some(entries[index].1), chain_len)),
                    Err(_) => cursor = next.as_ref(),
                }
            }
        }
    }
}

fn push_buffered_ops(ops: &mut Vec<MaterializeOp>, messages: &BTreeMap<BwKey, BufferedMutation>) {
    for (&key, &message) in messages {
        match message {
            BufferedMutation::Insert(value) => ops.push(MaterializeOp::Insert { key, value }),
            BufferedMutation::Delete => ops.push(MaterializeOp::Delete { key }),
        }
    }
}

fn push_append_run_ops(ops: &mut Vec<MaterializeOp>, entries: &[(BwKey, BwValue)]) {
    for &(key, value) in entries {
        ops.push(MaterializeOp::Insert { key, value });
    }
}

fn apply_op(state: &mut BTreeMap<BwKey, BwValue>, op: MaterializeOp) {
    match op {
        MaterializeOp::Insert { key, value } => {
            state.insert(key, value);
        }
        MaterializeOp::Delete { key } => {
            state.remove(&key);
        }
        MaterializeOp::Split { separator } => {
            let keys_to_remove: Vec<_> = state.range(separator..).map(|(k, _)| *k).collect();
            for k in keys_to_remove {
                state.remove(&k);
            }
        }
    }
}

fn defer_reclaim(delta: Arc<PageDelta>) {
    let guard = epoch::pin();
    guard.defer(move || drop(delta));
}

#[cfg(test)]
mod tests {
    use super::{
        BwKey, BwValue, ConsolidationConfig, DEFAULT_CONSOLIDATION_THRESHOLD,
        DEFAULT_MESSAGE_BUFFER_CAPACITY, DeltaMutation, FfsError, MAX_CAS_RETRIES, MAX_CHAIN_DEPTH,
        MAX_CHAIN_WALK, MappingTable, PageDelta, PageHead, PageId, chain_length,
        materialize_from_head, range_scan_from_head, write_lock,
    };
    use std::collections::BTreeMap;
    use std::sync::{Arc, Barrier, atomic::Ordering};

    fn start_test_thread<F>(f: F) -> std::thread::JoinHandle<()>
    where
        F: FnOnce() + Send + 'static,
    {
        std::thread::Builder::new()
            .spawn(f)
            .expect("spawn test thread")
    }

    fn append_delta_without_preconsolidation_for_test(
        table: &MappingTable,
        page: PageId,
        mutation: DeltaMutation,
    ) {
        for _ in 0..MAX_CAS_RETRIES {
            let snapshot = table.get_page(page).expect("snapshot");
            let new_head = Arc::new(match mutation {
                DeltaMutation::Insert { key, value } => PageDelta::Insert {
                    key,
                    value,
                    next: snapshot.head,
                },
                DeltaMutation::Delete { key } => PageDelta::Delete {
                    key,
                    next: snapshot.head,
                },
                DeltaMutation::Split {
                    separator,
                    new_sibling,
                } => PageDelta::Split {
                    separator,
                    new_sibling,
                    next: snapshot.head,
                },
                DeltaMutation::Merge { removed_sibling } => PageDelta::Merge {
                    removed_sibling,
                    next: snapshot.head,
                },
            });
            if table
                .cas_page(page, snapshot.epoch, new_head, snapshot.chain_len + 1)
                .expect("legacy cas")
            {
                return;
            }
        }
        panic!("legacy no-preconsolidation append exhausted CAS retries");
    }

    fn insert_without_preconsolidation_for_test(
        table: &MappingTable,
        page: PageId,
        key: BwKey,
        value: BwValue,
    ) {
        append_delta_without_preconsolidation_for_test(
            table,
            page,
            DeltaMutation::Insert { key, value },
        );
    }

    fn delete_without_preconsolidation_for_test(table: &MappingTable, page: PageId, key: BwKey) {
        append_delta_without_preconsolidation_for_test(table, page, DeltaMutation::Delete { key });
    }

    fn append_delta_without_message_buffer_for_test(
        table: &MappingTable,
        page: PageId,
        mutation: DeltaMutation,
    ) {
        let cfg = ConsolidationConfig::default();
        for _ in 0..MAX_CAS_RETRIES {
            let snapshot = table.get_page(page).expect("snapshot");
            if snapshot.chain_len > cfg.chain_threshold {
                table
                    .consolidate_page(page, &cfg)
                    .expect("legacy preconsolidate");
                continue;
            }
            let new_head = Arc::new(match mutation {
                DeltaMutation::Insert { key, value } => PageDelta::Insert {
                    key,
                    value,
                    next: snapshot.head,
                },
                DeltaMutation::Delete { key } => PageDelta::Delete {
                    key,
                    next: snapshot.head,
                },
                DeltaMutation::Split {
                    separator,
                    new_sibling,
                } => PageDelta::Split {
                    separator,
                    new_sibling,
                    next: snapshot.head,
                },
                DeltaMutation::Merge { removed_sibling } => PageDelta::Merge {
                    removed_sibling,
                    next: snapshot.head,
                },
            });
            if table
                .cas_page(page, snapshot.epoch, new_head, snapshot.chain_len + 1)
                .expect("legacy cas")
            {
                return;
            }
        }
        panic!("legacy individual preconsolidation append exhausted CAS retries");
    }

    fn insert_without_message_buffer_for_test(
        table: &MappingTable,
        page: PageId,
        key: BwKey,
        value: BwValue,
    ) {
        append_delta_without_message_buffer_for_test(
            table,
            page,
            DeltaMutation::Insert { key, value },
        );
    }

    fn delete_without_message_buffer_for_test(table: &MappingTable, page: PageId, key: BwKey) {
        append_delta_without_message_buffer_for_test(table, page, DeltaMutation::Delete { key });
    }

    #[test]
    fn single_thread_insert_delete_lookup_round_trip() {
        let table = MappingTable::with_capacity(4);
        let page = table
            .allocate_page()
            .expect("page allocation should succeed");

        assert_eq!(
            table
                .lookup(page, BwKey(10))
                .expect("lookup should succeed"),
            None
        );

        table
            .insert(page, BwKey(10), BwValue(111))
            .expect("insert key=10 should succeed");
        table
            .insert(page, BwKey(20), BwValue(222))
            .expect("insert key=20 should succeed");
        assert_eq!(
            table
                .lookup(page, BwKey(10))
                .expect("lookup should succeed"),
            Some(BwValue(111))
        );
        assert_eq!(
            table
                .lookup(page, BwKey(20))
                .expect("lookup should succeed"),
            Some(BwValue(222))
        );

        table
            .delete(page, BwKey(10))
            .expect("delete key=10 should succeed");
        assert_eq!(
            table
                .lookup(page, BwKey(10))
                .expect("lookup should succeed"),
            None
        );
        assert_eq!(
            table
                .lookup(page, BwKey(20))
                .expect("lookup should succeed"),
            Some(BwValue(222))
        );
    }

    #[test]
    fn delta_chain_materialization_merges_newest_state() {
        let table = MappingTable::with_capacity(2);
        let page = table
            .allocate_page()
            .expect("page allocation should succeed");

        table
            .insert(page, BwKey(5), BwValue(1))
            .expect("insert should succeed");
        table
            .insert(page, BwKey(5), BwValue(2))
            .expect("overwrite should succeed");
        table
            .insert(page, BwKey(9), BwValue(9))
            .expect("insert key=9 should succeed");
        table
            .append_split_delta(page, BwKey(7), PageId(1))
            .expect("split delta should succeed");
        table
            .delete(page, BwKey(9))
            .expect("delete key=9 should succeed");
        table
            .append_merge_delta(page, PageId(1))
            .expect("merge delta should succeed");

        let state = table
            .materialize_page(page)
            .expect("materialize should succeed");
        assert_eq!(state.get(&BwKey(5)).copied(), Some(BwValue(2)));
        assert!(!state.contains_key(&BwKey(9)));
    }

    #[test]
    fn concurrent_cas_append_preserves_all_updates() {
        let table = Arc::new(MappingTable::with_capacity(1));
        let page = table
            .allocate_page()
            .expect("page allocation should succeed");

        let workers = 4_u64;
        let keys_per_worker = 64_u64;
        let barrier = Arc::new(Barrier::new(usize::try_from(workers).unwrap_or(4)));
        let mut handles = Vec::new();

        for worker in 0..workers {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(start_test_thread(move || {
                barrier.wait();
                for slot in 0..keys_per_worker {
                    let key = BwKey(worker * 1_000 + slot);
                    let value = BwValue(key.0 + 10);
                    table
                        .insert(page, key, value)
                        .expect("concurrent insert should succeed");
                }
            }));
        }

        for handle in handles {
            handle.join().expect("worker should not panic");
        }

        let state = table
            .materialize_page(page)
            .expect("materialize should succeed");
        assert_eq!(
            u64::try_from(state.len()).expect("len conversion should succeed"),
            workers * keys_per_worker
        );

        for worker in 0..workers {
            for slot in 0..keys_per_worker {
                let key = BwKey(worker * 1_000 + slot);
                assert_eq!(state.get(&key).copied(), Some(BwValue(key.0 + 10)));
            }
        }
    }

    // ── Consolidation tests ─────────────────────────────────────────

    fn default_config() -> ConsolidationConfig {
        ConsolidationConfig {
            chain_threshold: 4,
            max_retries: 64,
        }
    }

    fn assert_cached_chain_len_matches(table: &MappingTable, page: PageId) -> usize {
        let snapshot = table.get_page(page).expect("snapshot");
        let computed = chain_length(&snapshot.head);
        assert_eq!(snapshot.chain_len, computed);
        computed
    }

    #[test]
    fn chain_length_of_empty_base_is_one() {
        let base = PageDelta::empty_base();
        assert_eq!(chain_length(&base), 1);
    }

    #[test]
    fn chain_length_grows_with_deltas() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");
        for i in 0..10 {
            insert_without_preconsolidation_for_test(&table, page, BwKey(i), BwValue(i));
        }
        assert_eq!(assert_cached_chain_len_matches(&table, page), 11); // 10 inserts + 1 base
    }

    #[test]
    fn consolidate_reduces_chain_to_one() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        for i in 0..20 {
            insert_without_preconsolidation_for_test(&table, page, BwKey(i), BwValue(i * 10));
        }
        assert_eq!(assert_cached_chain_len_matches(&table, page), 21);

        let config = default_config();
        let result = table.consolidate_page(page, &config).expect("consolidate");
        assert_eq!(result.chain_len_before, 21);
        assert_eq!(result.chain_len_after, 1);
        assert_eq!(result.entries_count, 20);
        assert!(result.cas_attempts >= 1);

        assert_eq!(assert_cached_chain_len_matches(&table, page), 1);
    }

    #[test]
    fn consolidate_preserves_all_data() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        // Build a chain with inserts, overwrites, and deletes
        for i in 0..50 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }
        // Overwrite even keys
        for i in (0..50).step_by(2) {
            table
                .insert(page, BwKey(i), BwValue(i + 1000))
                .expect("overwrite");
        }
        // Delete keys divisible by 5
        for i in (0..50).step_by(5) {
            table.delete(page, BwKey(i)).expect("delete");
        }

        let state_before = table.materialize_page(page).expect("materialize");

        let config = default_config();
        table.consolidate_page(page, &config).expect("consolidate");

        let state_after = table.materialize_page(page).expect("materialize");
        assert_eq!(state_before, state_after);
    }

    #[test]
    fn consolidate_skips_already_base_page() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        let config = default_config();
        let result = table.consolidate_page(page, &config).expect("consolidate");
        assert_eq!(result.chain_len_before, 1);
        assert_eq!(result.chain_len_after, 1);
        assert_eq!(result.cas_attempts, 0);
    }

    #[test]
    fn scan_for_consolidation_finds_long_chains() {
        let table = MappingTable::with_capacity(4);
        let p0 = table.allocate_page().expect("alloc");
        let p1 = table.allocate_page().expect("alloc");
        let _p2 = table.allocate_page().expect("alloc");

        // p0: 3 deltas (below threshold of 4)
        for i in 0..3 {
            insert_without_preconsolidation_for_test(&table, p0, BwKey(i), BwValue(i));
        }
        // p1: 10 deltas (above threshold)
        for i in 0..10 {
            insert_without_preconsolidation_for_test(&table, p1, BwKey(i), BwValue(i));
        }
        // p2: 1 delta (base only, below threshold)

        let candidates = table.scan_for_consolidation(4);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], p1);
    }

    #[test]
    fn consolidate_all_consolidates_only_long_chains() {
        let table = MappingTable::with_capacity(4);
        let p0 = table.allocate_page().expect("alloc");
        let p1 = table.allocate_page().expect("alloc");
        let p2 = table.allocate_page().expect("alloc");

        for i in 0..2 {
            insert_without_preconsolidation_for_test(&table, p0, BwKey(i), BwValue(i));
        }
        for i in 0..10 {
            insert_without_preconsolidation_for_test(&table, p1, BwKey(i), BwValue(i));
        }
        for i in 0..8 {
            insert_without_preconsolidation_for_test(&table, p2, BwKey(i), BwValue(i));
        }

        let config = ConsolidationConfig {
            chain_threshold: 5,
            max_retries: 64,
        };
        let count = table.consolidate_all(&config).expect("consolidate_all");
        assert_eq!(count, 2); // p1 and p2

        // p0 should still have chain length > 1
        assert_eq!(assert_cached_chain_len_matches(&table, p0), 3);

        // p1 and p2 should be consolidated
        assert_eq!(assert_cached_chain_len_matches(&table, p1), 1);
        assert_eq!(assert_cached_chain_len_matches(&table, p2), 1);
    }

    #[test]
    fn concurrent_consolidation_and_inserts_preserve_data() {
        let table = Arc::new(MappingTable::with_capacity(1));
        let page = table.allocate_page().expect("alloc");

        // Seed with some initial data
        for i in 0..20 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }

        let barrier = Arc::new(Barrier::new(3)); // 1 consolidator + 2 inserters
        let mut handles = Vec::new();

        // Consolidator thread
        {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(start_test_thread(move || {
                barrier.wait();
                let config = ConsolidationConfig {
                    chain_threshold: 1,
                    max_retries: 256,
                };
                for _ in 0..5 {
                    let _ = table.consolidate_page(page, &config);
                }
            }));
        }

        // Inserter threads
        for worker in 0..2_u64 {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(start_test_thread(move || {
                barrier.wait();
                let base = 1000 + worker * 100;
                for i in 0..50 {
                    table
                        .insert(page, BwKey(base + i), BwValue(base + i + 10))
                        .expect("insert");
                }
            }));
        }

        for h in handles {
            // ubs:ignore - loops over handles
            h.join().expect("thread should not panic");
        }

        // Verify all initial and inserted data is present
        let state = table.materialize_page(page).expect("materialize");
        for i in 0..20 {
            assert_eq!(
                state.get(&BwKey(i)).copied(),
                Some(BwValue(i)),
                "initial key {i} should be present"
            );
        }
        for worker in 0..2_u64 {
            let base = 1000 + worker * 100;
            for i in 0..50 {
                assert_eq!(
                    state.get(&BwKey(base + i)).copied(),
                    Some(BwValue(base + i + 10)),
                    "worker {worker} key {} should be present",
                    base + i
                );
            }
        }
        assert_cached_chain_len_matches(&table, page);
    }

    #[test]
    fn consolidation_result_fields_are_correct() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        insert_without_preconsolidation_for_test(&table, page, BwKey(1), BwValue(10));
        insert_without_preconsolidation_for_test(&table, page, BwKey(2), BwValue(20));
        delete_without_preconsolidation_for_test(&table, page, BwKey(1));

        let config = default_config();
        let result = table.consolidate_page(page, &config).expect("consolidate");

        // Chain was: delete -> insert(2) -> insert(1) -> base = 4 nodes
        assert_eq!(result.chain_len_before, 4);
        assert_eq!(result.chain_len_after, 1);
        // After materialization: only key 2 remains
        assert_eq!(result.entries_count, 1);
        assert_eq!(result.cas_attempts, 1);
    }

    #[test]
    fn consolidation_with_split_and_merge_deltas() {
        let table = MappingTable::with_capacity(4);
        let page = table.allocate_page().expect("alloc");
        let sibling = table.allocate_page().expect("alloc sibling");

        table.insert(page, BwKey(10), BwValue(100)).expect("insert");
        table.insert(page, BwKey(20), BwValue(200)).expect("insert");
        table
            .append_split_delta(page, BwKey(15), sibling)
            .expect("split");
        table.insert(page, BwKey(30), BwValue(300)).expect("insert");
        table.append_merge_delta(page, sibling).expect("merge");
        table.insert(page, BwKey(40), BwValue(400)).expect("insert");

        let state_before = table.materialize_page(page).expect("materialize");

        let config = default_config();
        table.consolidate_page(page, &config).expect("consolidate");

        let state_after = table.materialize_page(page).expect("materialize");
        assert_eq!(state_before, state_after);

        let snap = table.get_page(page).expect("get");
        assert_eq!(chain_length(&snap.head), 1);
    }

    #[test]
    fn repeated_consolidation_is_idempotent() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        for i in 0..10 {
            table
                .insert(page, BwKey(i), BwValue(i * 2))
                .expect("insert");
        }

        let config = default_config();
        table.consolidate_page(page, &config).expect("first");
        let state1 = table.materialize_page(page).expect("mat1");

        table.consolidate_page(page, &config).expect("second");
        let state2 = table.materialize_page(page).expect("mat2");

        assert_eq!(state1, state2);
    }

    #[test]
    fn inserts_after_consolidation_build_new_chain() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        for i in 0..10 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }

        let config = default_config();
        table.consolidate_page(page, &config).expect("consolidate");
        assert_eq!(assert_cached_chain_len_matches(&table, page), 1);

        // New inserts build on consolidated base
        for i in 10..15 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }
        assert_eq!(assert_cached_chain_len_matches(&table, page), 2);

        // All data still accessible
        for i in 0..15 {
            assert_eq!(
                table.lookup(page, BwKey(i)).expect("lookup"),
                Some(BwValue(i))
            );
        }
    }

    #[test]
    fn append_structural_delta_at_default_threshold_preconsolidates_before_appending() {
        let table = MappingTable::with_capacity(2);
        let page = table.allocate_page().expect("alloc");
        let sibling = table.allocate_page().expect("sibling alloc");

        for i in 0..u64::try_from(DEFAULT_CONSOLIDATION_THRESHOLD).expect("threshold fits") {
            insert_without_preconsolidation_for_test(&table, page, BwKey(i), BwValue(i));
        }

        assert_eq!(
            assert_cached_chain_len_matches(&table, page),
            DEFAULT_CONSOLIDATION_THRESHOLD + 1
        );

        table
            .append_split_delta(page, BwKey(u64::MAX), sibling)
            .expect("append structural delta after preconsolidation");

        let state = table.materialize_page(page).expect("materialize");
        assert_eq!(state.len(), DEFAULT_CONSOLIDATION_THRESHOLD);

        assert_eq!(assert_cached_chain_len_matches(&table, page), 2);
    }

    #[test]
    fn append_preconsolidation_matches_deferred_golden_report() {
        let old_table = MappingTable::with_capacity(1);
        let old_page = old_table.allocate_page().expect("old alloc");
        let new_table = MappingTable::with_capacity(1);
        let new_page = new_table.allocate_page().expect("new alloc");

        for key in 0..32_u64 {
            insert_without_preconsolidation_for_test(
                &old_table,
                old_page,
                BwKey(key),
                BwValue(key * 10),
            );
            new_table
                .insert(new_page, BwKey(key), BwValue(key * 10))
                .expect("new seed insert");
        }

        let cfg = ConsolidationConfig::default();
        old_table
            .consolidate_page(old_page, &cfg)
            .expect("old consolidate");
        new_table
            .consolidate_page(new_page, &cfg)
            .expect("new consolidate");

        for step in 0..96_u64 {
            let key = BwKey((step * 37 + 11) % 64);
            match step % 4 {
                0 => {
                    let value = BwValue(10_000 + step);
                    insert_without_preconsolidation_for_test(&old_table, old_page, key, value);
                    new_table.insert(new_page, key, value).expect("new insert");
                }
                1 => {
                    delete_without_preconsolidation_for_test(&old_table, old_page, key);
                    new_table.delete(new_page, key).expect("new delete");
                }
                2 => {
                    let value = BwValue(20_000 + step);
                    insert_without_preconsolidation_for_test(&old_table, old_page, key, value);
                    new_table.insert(new_page, key, value).expect("new insert");
                }
                _ => {
                    if key.0 % 3 == 0 {
                        delete_without_preconsolidation_for_test(&old_table, old_page, key);
                        new_table.delete(new_page, key).expect("new delete");
                    } else {
                        let value = BwValue(30_000 + step);
                        insert_without_preconsolidation_for_test(&old_table, old_page, key, value);
                        new_table.insert(new_page, key, value).expect("new insert");
                    }
                }
            }
        }

        let old_state = old_table
            .materialize_page(old_page)
            .expect("old materialize");
        let new_state = new_table
            .materialize_page(new_page)
            .expect("new materialize");
        assert_eq!(old_state, new_state);

        let old_chain_len = assert_cached_chain_len_matches(&old_table, old_page);
        let new_chain_len = assert_cached_chain_len_matches(&new_table, new_page);
        assert!(old_chain_len > DEFAULT_CONSOLIDATION_THRESHOLD);
        assert!(new_chain_len <= DEFAULT_CONSOLIDATION_THRESHOLD + 1);

        println!("BWTREE_PRECONSOLIDATE_GOLDEN\told_chain_len\t{old_chain_len}");
        println!("BWTREE_PRECONSOLIDATE_GOLDEN\tnew_chain_len\t{new_chain_len}");
        println!(
            "BWTREE_PRECONSOLIDATE_GOLDEN\tstate_len\t{}",
            new_state.len()
        );

        for key in [0_u64, 1, 2, 3, 5, 8, 13, 21, 34, 55, 63] {
            let key = BwKey(key);
            let old_lookup = old_table.lookup(old_page, key).expect("old lookup");
            let new_lookup = new_table.lookup(new_page, key).expect("new lookup");
            assert_eq!(old_lookup, new_lookup);
            println!(
                "BWTREE_PRECONSOLIDATE_GOLDEN\tlookup\t{}\t{}",
                key.0,
                new_lookup.map_or_else(|| "None".to_owned(), |value| value.0.to_string())
            );
        }

        let old_range = old_table
            .range_scan(old_page, BwKey(7), 12)
            .expect("old range");
        let new_range = new_table
            .range_scan(new_page, BwKey(7), 12)
            .expect("new range");
        assert_eq!(old_range, new_range);
        for (key, value) in new_range {
            println!(
                "BWTREE_PRECONSOLIDATE_GOLDEN\trange\t{}\t{}",
                key.0, value.0
            );
        }
    }

    struct MessageBufferGoldenTables {
        old_table: MappingTable,
        old_page: PageId,
        old_sibling: PageId,
        new_table: MappingTable,
        new_page: PageId,
        new_sibling: PageId,
    }

    fn seed_message_buffer_golden_tables() -> MessageBufferGoldenTables {
        let old_table = MappingTable::with_capacity(2);
        let old_page = old_table.allocate_page().expect("old alloc");
        let old_sibling = old_table.allocate_page().expect("old sibling");
        let new_table = MappingTable::with_capacity(2);
        let new_page = new_table.allocate_page().expect("new alloc");
        let new_sibling = new_table.allocate_page().expect("new sibling");

        for key in 0..96_u64 {
            insert_without_message_buffer_for_test(
                &old_table,
                old_page,
                BwKey(key),
                BwValue(key * 10),
            );
            new_table
                .insert(new_page, BwKey(key), BwValue(key * 10))
                .expect("new seed insert");
        }

        let cfg = ConsolidationConfig::default();
        old_table
            .consolidate_page(old_page, &cfg)
            .expect("old consolidate");
        new_table
            .consolidate_page(new_page, &cfg)
            .expect("new consolidate");

        MessageBufferGoldenTables {
            old_table,
            old_page,
            old_sibling,
            new_table,
            new_page,
            new_sibling,
        }
    }

    fn apply_message_buffer_split_probe(tables: &MessageBufferGoldenTables) {
        insert_without_message_buffer_for_test(
            &tables.old_table,
            tables.old_page,
            BwKey(300),
            BwValue(30_000),
        );
        tables
            .new_table
            .insert(tables.new_page, BwKey(300), BwValue(30_000))
            .expect("new pre-split insert");
        append_delta_without_message_buffer_for_test(
            &tables.old_table,
            tables.old_page,
            DeltaMutation::Split {
                separator: BwKey(256),
                new_sibling: tables.old_sibling,
            },
        );
        tables
            .new_table
            .append_split_delta(tables.new_page, BwKey(256), tables.new_sibling)
            .expect("new split");
        insert_without_message_buffer_for_test(
            &tables.old_table,
            tables.old_page,
            BwKey(300),
            BwValue(30_001),
        );
        tables
            .new_table
            .insert(tables.new_page, BwKey(300), BwValue(30_001))
            .expect("new post-split insert");
    }

    fn apply_message_buffer_golden_workload(tables: &MessageBufferGoldenTables) {
        for step in 0..384_u64 {
            let key = BwKey((step * 109 + 17) % 512);
            match step % 6 {
                0 | 2 => {
                    let value = BwValue(40_000 + step);
                    insert_without_message_buffer_for_test(
                        &tables.old_table,
                        tables.old_page,
                        key,
                        value,
                    );
                    tables
                        .new_table
                        .insert(tables.new_page, key, value)
                        .expect("new insert");
                }
                1 => {
                    delete_without_message_buffer_for_test(&tables.old_table, tables.old_page, key);
                    tables
                        .new_table
                        .delete(tables.new_page, key)
                        .expect("new delete");
                }
                3 => {
                    let value = BwValue(50_000 + step);
                    insert_without_message_buffer_for_test(
                        &tables.old_table,
                        tables.old_page,
                        key,
                        value,
                    );
                    tables
                        .new_table
                        .insert(tables.new_page, key, value)
                        .expect("new insert");
                }
                4 => {
                    if key.0 % 4 == 0 {
                        delete_without_message_buffer_for_test(
                            &tables.old_table,
                            tables.old_page,
                            key,
                        );
                        tables
                            .new_table
                            .delete(tables.new_page, key)
                            .expect("new delete");
                    } else {
                        let value = BwValue(60_000 + step);
                        insert_without_message_buffer_for_test(
                            &tables.old_table,
                            tables.old_page,
                            key,
                            value,
                        );
                        tables
                            .new_table
                            .insert(tables.new_page, key, value)
                            .expect("new insert");
                    }
                }
                _ => {
                    let value = BwValue(70_000 + step);
                    insert_without_message_buffer_for_test(
                        &tables.old_table,
                        tables.old_page,
                        key,
                        value,
                    );
                    tables
                        .new_table
                        .insert(tables.new_page, key, value)
                        .expect("new insert");
                }
            }
        }
    }

    fn assert_message_buffer_golden_report(tables: &MessageBufferGoldenTables) {
        let old_state = tables
            .old_table
            .materialize_page(tables.old_page)
            .expect("old materialize");
        let new_state = tables
            .new_table
            .materialize_page(tables.new_page)
            .expect("new materialize");
        assert_eq!(old_state, new_state);

        let old_chain_len = assert_cached_chain_len_matches(&tables.old_table, tables.old_page);
        let new_chain_len = assert_cached_chain_len_matches(&tables.new_table, tables.new_page);
        assert!(old_chain_len <= DEFAULT_CONSOLIDATION_THRESHOLD + 1);
        assert!(new_chain_len <= DEFAULT_MESSAGE_BUFFER_CAPACITY + 2);

        println!("BWTREE_MESSAGE_BUFFER_GOLDEN\told_chain_len\t{old_chain_len}");
        println!("BWTREE_MESSAGE_BUFFER_GOLDEN\tnew_chain_len\t{new_chain_len}");
        println!(
            "BWTREE_MESSAGE_BUFFER_GOLDEN\tstate_len\t{}",
            new_state.len()
        );

        for key in [0_u64, 7, 17, 31, 63, 96, 127, 191, 255, 383, 511] {
            let key = BwKey(key);
            let old_lookup = tables
                .old_table
                .lookup(tables.old_page, key)
                .expect("old lookup");
            let new_lookup = tables
                .new_table
                .lookup(tables.new_page, key)
                .expect("new lookup");
            assert_eq!(old_lookup, new_lookup);
            println!(
                "BWTREE_MESSAGE_BUFFER_GOLDEN\tlookup\t{}\t{}",
                key.0,
                new_lookup.map_or_else(|| "None".to_owned(), |value| value.0.to_string())
            );
        }

        let old_range = tables
            .old_table
            .range_scan(tables.old_page, BwKey(89), 16)
            .expect("old range");
        let new_range = tables
            .new_table
            .range_scan(tables.new_page, BwKey(89), 16)
            .expect("new range");
        assert_eq!(old_range, new_range);
        for (key, value) in new_range {
            println!(
                "BWTREE_MESSAGE_BUFFER_GOLDEN\trange\t{}\t{}",
                key.0, value.0
            );
        }
    }

    #[test]
    fn message_buffer_matches_individual_preconsolidation_golden_report() {
        let tables = seed_message_buffer_golden_tables();
        apply_message_buffer_split_probe(&tables);
        apply_message_buffer_golden_workload(&tables);
        assert_message_buffer_golden_report(&tables);
    }

    // ── Comprehensive unit tests (bd-1mdk.3) ─────────────────────

    #[test]
    fn crud_1000_keys_insert_lookup_delete() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        // Insert 1000 keys
        for i in 0..1000_u64 {
            table
                .insert(page, BwKey(i), BwValue(i * 3))
                .expect("insert");
        }

        // Verify all 1000 lookups
        for i in 0..1000_u64 {
            assert_eq!(
                table.lookup(page, BwKey(i)).expect("lookup"),
                Some(BwValue(i * 3)),
                "key {i} mismatch"
            );
        }

        // Delete even keys
        for i in (0..1000_u64).step_by(2) {
            table.delete(page, BwKey(i)).expect("delete");
        }

        // Verify: even keys gone, odd keys present
        for i in 0..1000_u64 {
            let result = table.lookup(page, BwKey(i)).expect("lookup");
            if i % 2 == 0 {
                assert_eq!(result, None, "deleted key {i} should be absent");
            } else {
                assert_eq!(
                    result,
                    Some(BwValue(i * 3)),
                    "odd key {i} should still exist"
                );
            }
        }

        let state = table.materialize_page(page).expect("materialize");
        assert_eq!(state.len(), 500);
    }

    #[test]
    fn duplicate_insert_uses_latest_value() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        for round in 0..5_u64 {
            for i in 0..100_u64 {
                table
                    .insert(page, BwKey(i), BwValue(round * 1000 + i))
                    .expect("insert");
            }
        }

        // Only the last round's values should be visible
        for i in 0..100_u64 {
            assert_eq!(
                table.lookup(page, BwKey(i)).expect("lookup"),
                Some(BwValue(4000 + i)),
                "key {i} should reflect round 4"
            );
        }
    }

    #[test]
    fn materialized_page_is_sorted_by_key() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        // Insert in reverse order
        for i in (0..50_u64).rev() {
            table
                .insert(page, BwKey(i * 7), BwValue(i))
                .expect("insert");
        }

        let state = table.materialize_page(page).expect("materialize");
        let keys: Vec<u64> = state.keys().map(|k| k.0).collect();
        for pair in keys.windows(2) {
            assert!(
                pair[0] < pair[1],
                "keys should be sorted: {} < {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn range_scan_returns_sorted_bounded_entries_from_start_key() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        for i in (0..10_u64).rev() {
            table
                .insert(page, BwKey(i * 10), BwValue(i))
                .expect("insert");
        }

        let rows = table
            .range_scan(page, BwKey(25), 4)
            .expect("range scan should succeed");
        assert_eq!(
            rows,
            vec![
                (BwKey(30), BwValue(3)),
                (BwKey(40), BwValue(4)),
                (BwKey(50), BwValue(5)),
                (BwKey(60), BwValue(6)),
            ]
        );
    }

    #[test]
    fn range_scan_filters_deletes_and_split_removed_tail() {
        let table = MappingTable::with_capacity(2);
        let page = table.allocate_page().expect("alloc");
        let sibling = table.allocate_page().expect("alloc sibling");

        for i in 0..10_u64 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }
        table.delete(page, BwKey(4)).expect("delete");
        table
            .append_split_delta(page, BwKey(7), sibling)
            .expect("split");

        let rows = table
            .range_scan(page, BwKey(3), 10)
            .expect("range scan should succeed");
        assert_eq!(
            rows,
            vec![
                (BwKey(3), BwValue(3)),
                (BwKey(5), BwValue(5)),
                (BwKey(6), BwValue(6)),
            ]
        );
    }

    #[test]
    fn range_scan_matches_materialized_range_with_shadowing_deltas() {
        let table = MappingTable::with_capacity(2);
        let page = table.allocate_page().expect("alloc");
        let sibling = table.allocate_page().expect("alloc sibling");

        for i in 0..12_u64 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }
        table
            .consolidate_page(page, &default_config())
            .expect("consolidate");

        table.insert(page, BwKey(9), BwValue(90)).expect("insert");
        table
            .append_split_delta(page, BwKey(8), sibling)
            .expect("split");
        table
            .insert(page, BwKey(8), BwValue(800))
            .expect("insert after split");
        table.delete(page, BwKey(3)).expect("delete");
        table
            .insert(page, BwKey(5), BwValue(500))
            .expect("shadow base");

        let materialized = table.materialize_page(page).expect("materialize");
        let expected: Vec<_> = materialized
            .range(BwKey(2)..)
            .take(10)
            .map(|(&key, &value)| (key, value))
            .collect();

        assert_eq!(
            table
                .range_scan(page, BwKey(2), 10)
                .expect("range scan should succeed"),
            expected
        );
    }

    #[test]
    fn range_scan_zero_count_returns_empty_after_page_validation() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        table.insert(page, BwKey(1), BwValue(1)).expect("insert");

        assert_eq!(
            table
                .range_scan(page, BwKey(0), 0)
                .expect("range scan should succeed"),
            Vec::<(BwKey, BwValue)>::new()
        );
        assert!(matches!(
            table.range_scan(PageId(99), BwKey(0), 0),
            Err(FfsError::NotFound(_))
        ));
    }

    #[test]
    fn concurrent_insert_lookup_no_corrupt_state() {
        let table = Arc::new(MappingTable::with_capacity(1));
        let page = table.allocate_page().expect("alloc");

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();

        // 4 writer threads, each inserting unique key ranges
        for worker in 0..4_u64 {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(start_test_thread(move || {
                barrier.wait();
                let base = worker * 1000;
                for i in 0..500 {
                    table
                        .insert(page, BwKey(base + i), BwValue(base + i + 10))
                        .expect("insert");
                }
            }));
        }

        // 4 reader threads doing lookups continuously
        for _ in 0..4 {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(start_test_thread(move || {
                barrier.wait();
                // Readers must never see corrupt state
                for probe in 0..2000 {
                    let _ = table.lookup(page, BwKey(probe));
                }
            }));
        }

        for h in handles {
            h.join().expect("no panics");
        }

        // After all writers done: verify all 2000 keys present
        let state = table.materialize_page(page).expect("materialize");
        assert_eq!(state.len(), 2000);
        for worker in 0..4_u64 {
            let base = worker * 1000;
            for i in 0..500 {
                assert_eq!(
                    state.get(&BwKey(base + i)).copied(),
                    Some(BwValue(base + i + 10))
                );
            }
        }
    }

    #[test]
    fn concurrent_insert_delete_non_overlapping_ranges() {
        let table = Arc::new(MappingTable::with_capacity(1));
        let page = table.allocate_page().expect("alloc");

        // Pre-populate range 0..500 that will be deleted
        for i in 0..500_u64 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }

        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();

        // Thread 1: insert range 1000..1500
        {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(start_test_thread(move || {
                barrier.wait();
                for i in 1000..1500_u64 {
                    table
                        .insert(page, BwKey(i), BwValue(i + 10))
                        .expect("insert");
                }
            }));
        }

        // Thread 2: delete range 0..500
        {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(start_test_thread(move || {
                barrier.wait();
                for i in 0..500_u64 {
                    table.delete(page, BwKey(i)).expect("delete");
                }
            }));
        }

        for h in handles {
            h.join().expect("no panics");
        }

        let state = table.materialize_page(page).expect("materialize");
        // All 0..500 should be deleted
        for i in 0..500_u64 {
            assert!(!state.contains_key(&BwKey(i)), "key {i} should be deleted");
        }
        // All 1000..1500 should be present
        for i in 1000..1500_u64 {
            assert_eq!(
                state.get(&BwKey(i)).copied(),
                Some(BwValue(i + 10)),
                "key {i} should be present"
            );
        }
    }

    #[test]
    fn concurrent_insert_delete_overlapping_keys() {
        let table = Arc::new(MappingTable::with_capacity(1));
        let page = table.allocate_page().expect("alloc");

        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();

        // Thread 1: repeatedly insert keys 0..100
        {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(start_test_thread(move || {
                barrier.wait();
                for round in 0..10_u64 {
                    for i in 0..100 {
                        table
                            .insert(page, BwKey(i), BwValue(round * 100 + i))
                            .expect("insert");
                    }
                }
            }));
        }

        // Thread 2: repeatedly delete keys 0..100
        {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(start_test_thread(move || {
                barrier.wait();
                for _ in 0..5 {
                    for i in 0..100_u64 {
                        let _ = table.delete(page, BwKey(i));
                    }
                }
            }));
        }

        for h in handles {
            h.join().expect("no panics");
        }

        // After both threads: we can't predict exact state,
        // but materialization must not panic or produce corrupt results.
        let state = table.materialize_page(page).expect("materialize");
        // All present keys must have valid values
        for (key, value) in &state {
            assert!(key.0 < 100, "unexpected key {}", key.0);
            assert!(value.0 < 1000, "unexpected value {}", value.0);
        }
    }

    #[test]
    fn empty_page_operations() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        // Lookup on empty page returns None
        assert_eq!(table.lookup(page, BwKey(0)).expect("lookup"), None);
        assert_eq!(table.lookup(page, BwKey(u64::MAX)).expect("lookup"), None);

        // Delete on empty page succeeds (no-op)
        table.delete(page, BwKey(42)).expect("delete");

        // Materialize empty page returns empty map
        let state = table.materialize_page(page).expect("materialize");
        assert!(state.is_empty());
    }

    #[test]
    fn single_element_all_operations() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        table.insert(page, BwKey(42), BwValue(99)).expect("insert");
        assert_eq!(
            table.lookup(page, BwKey(42)).expect("lookup"),
            Some(BwValue(99))
        );

        let state = table.materialize_page(page).expect("materialize");
        assert_eq!(state.len(), 1);

        table.delete(page, BwKey(42)).expect("delete");
        assert_eq!(table.lookup(page, BwKey(42)).expect("lookup"), None);

        let state = table.materialize_page(page).expect("materialize");
        assert!(state.is_empty());
    }

    #[test]
    fn unallocated_page_returns_not_found() {
        let table = MappingTable::with_capacity(4);
        // No pages allocated yet
        let result = table.lookup(PageId(0), BwKey(0));
        assert!(result.is_err());
    }

    #[test]
    fn page_allocation_exhaustion() {
        let table = MappingTable::with_capacity(2);
        table.allocate_page().expect("first alloc");
        table.allocate_page().expect("second alloc");
        let result = table.allocate_page();
        assert!(result.is_err(), "should fail when capacity exhausted");
        assert_eq!(table.next_page_id.load(Ordering::Acquire), 2);
    }

    #[test]
    fn page_allocation_numeric_limit_does_not_wrap_to_existing_page() {
        let table = MappingTable::with_capacity(1);
        table.next_page_id.store(u64::MAX, Ordering::Release);

        let err = table
            .allocate_page()
            .expect_err("numeric limit must not wrap to page 0");

        assert!(matches!(err, FfsError::NoSpace));
        assert_eq!(table.next_page_id.load(Ordering::Acquire), u64::MAX);
    }

    #[test]
    fn consolidation_after_all_keys_deleted_produces_empty_base() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        for i in 0..20_u64 {
            table.insert(page, BwKey(i), BwValue(i)).expect("insert");
        }
        for i in 0..20_u64 {
            table.delete(page, BwKey(i)).expect("delete");
        }

        let config = default_config();
        let result = table.consolidate_page(page, &config).expect("consolidate");
        assert_eq!(result.entries_count, 0);
        assert_eq!(result.chain_len_after, 1);

        let state = table.materialize_page(page).expect("materialize");
        assert!(state.is_empty());
    }

    #[test]
    fn consolidation_triggered_by_threshold_scan() {
        let table = MappingTable::with_capacity(2);
        let p0 = table.allocate_page().expect("alloc");
        let p1 = table.allocate_page().expect("alloc");

        // p0: exactly at threshold (should not be consolidated)
        for i in 0..4_u64 {
            insert_without_preconsolidation_for_test(&table, p0, BwKey(i), BwValue(i));
        }
        // p1: above threshold
        for i in 0..20_u64 {
            insert_without_preconsolidation_for_test(&table, p1, BwKey(i), BwValue(i));
        }

        let config = ConsolidationConfig {
            chain_threshold: 5,
            max_retries: 64,
        };
        let count = table.consolidate_all(&config).expect("consolidate_all");
        assert_eq!(count, 1); // only p1

        // p0 chain unchanged
        let snap0 = table.get_page(p0).expect("get");
        assert_eq!(chain_length(&snap0.head), 5); // 4 inserts + base

        // p1 consolidated
        let snap1 = table.get_page(p1).expect("get");
        assert_eq!(chain_length(&snap1.head), 1);
    }

    #[test]
    fn multiple_pages_independent_state() {
        let table = MappingTable::with_capacity(4);
        let pages: Vec<PageId> = (0..4)
            .map(|_| table.allocate_page().expect("alloc"))
            .collect();

        // Insert different data into each page
        for (idx, &page) in pages.iter().enumerate() {
            let base = (idx as u64) * 100;
            for i in 0..10_u64 {
                table
                    .insert(page, BwKey(base + i), BwValue(base + i))
                    .expect("insert");
            }
        }

        // Verify each page has only its own data
        for (idx, &page) in pages.iter().enumerate() {
            let state = table.materialize_page(page).expect("materialize");
            assert_eq!(state.len(), 10);
            let base = (idx as u64) * 100;
            for i in 0..10_u64 {
                assert_eq!(
                    state.get(&BwKey(base + i)).copied(),
                    Some(BwValue(base + i))
                );
            }
            // Should not have other pages' data
            for other_idx in 0..4 {
                if other_idx != idx {
                    let other_base = (other_idx as u64) * 100;
                    assert!(!state.contains_key(&BwKey(other_base)));
                }
            }
        }
    }

    #[test]
    fn consolidation_stress_interleaved() {
        let table = Arc::new(MappingTable::with_capacity(4));
        let pages: Vec<PageId> = (0..4)
            .map(|_| table.allocate_page().expect("alloc"))
            .collect();

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();

        // 4 inserter threads (one per page)
        for (idx, &page) in pages.iter().enumerate() {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(start_test_thread(move || {
                barrier.wait();
                let base = (idx as u64) * 1000;
                for i in 0..100 {
                    table
                        .insert(page, BwKey(base + i), BwValue(base + i))
                        .expect("insert");
                }
            }));
        }

        // 4 consolidator threads (one per page)
        for &page in &pages {
            let table = Arc::clone(&table);
            let barrier = Arc::clone(&barrier);
            handles.push(start_test_thread(move || {
                barrier.wait();
                let config = ConsolidationConfig {
                    chain_threshold: 1,
                    max_retries: 512,
                };
                for _ in 0..10 {
                    let _ = table.consolidate_page(page, &config);
                    std::thread::yield_now();
                }
            }));
        }

        for h in handles {
            // ubs:ignore - loops over handles
            h.join().expect("thread should not panic");
        }

        // Verify all data is intact
        for (idx, &page) in pages.iter().enumerate() {
            let state = table.materialize_page(page).expect("materialize");
            let base = (idx as u64) * 1000;
            assert_eq!(state.len(), 100);
            for i in 0..100 {
                assert_eq!(
                    state.get(&BwKey(base + i)).copied(),
                    Some(BwValue(base + i))
                );
            }
        }
    }

    #[test]
    fn page_capacity_returns_configured_value() {
        let table = MappingTable::with_capacity(42);
        assert_eq!(table.page_capacity(), 42);
    }

    #[test]
    fn split_delta_partitions_data_in_materialization() {
        let table = MappingTable::with_capacity(4);
        let page = table.allocate_page().expect("alloc");
        let sibling = table.allocate_page().expect("alloc sibling");

        // Insert keys 1..10 on the main page.
        for i in 1..=10 {
            table
                .insert(page, BwKey(i), BwValue(i * 100))
                .expect("insert");
        }

        // Split at key 6: keys >= 6 conceptually move to sibling.
        table
            .append_split_delta(page, BwKey(6), sibling)
            .expect("split");

        // The main page materializes only keys < separator.
        let main_state = table.materialize_page(page).expect("materialize main");
        for i in 1..6 {
            assert_eq!(main_state.get(&BwKey(i)).copied(), Some(BwValue(i * 100)));
        }
        for i in 6..=10 {
            assert!(
                !main_state.contains_key(&BwKey(i)),
                "key {i} should be split away from main page"
            );
        }
        for i in 1..=10 {
            assert_eq!(
                table.lookup(page, BwKey(i)).expect("lookup after split"),
                main_state.get(&BwKey(i)).copied(),
                "lookup should match materialized split state for key {i}"
            );
        }

        table
            .insert(page, BwKey(7), BwValue(7000))
            .expect("newer insert after split");
        table
            .delete(page, BwKey(5))
            .expect("newer delete after split");

        let shadowed_state = table
            .materialize_page(page)
            .expect("materialize shadowed split state");
        for i in 1..=10 {
            assert_eq!(
                table
                    .lookup(page, BwKey(i))
                    .expect("lookup after split shadowing"),
                shadowed_state.get(&BwKey(i)).copied(),
                "lookup should match materialized split-shadow state for key {i}"
            );
        }
    }

    #[test]
    fn direct_lookup_matches_materialized_state_for_golden_trace() {
        let table = MappingTable::with_capacity(4);
        let page = table.allocate_page().expect("alloc");
        let sibling = table.allocate_page().expect("alloc sibling");

        for i in 1..=12 {
            table
                .insert(page, BwKey(i), BwValue(i * 100))
                .expect("seed insert");
        }
        table
            .insert(page, BwKey(3), BwValue(3333))
            .expect("overwrite before split");
        table
            .insert(page, BwKey(9), BwValue(9999))
            .expect("overwrite split-tail key before split");
        table.delete(page, BwKey(2)).expect("delete before split");
        table
            .append_split_delta(page, BwKey(8), sibling)
            .expect("split");
        table
            .insert(page, BwKey(9), BwValue(9000))
            .expect("newer insert shadows split");
        table
            .delete(page, BwKey(6))
            .expect("newer delete shadows base");
        table.append_merge_delta(page, sibling).expect("merge");
        table
            .insert(page, BwKey(7), BwValue(7000))
            .expect("newer insert under split separator");
        table
            .delete(page, BwKey(9))
            .expect("newer delete shadows post-split insert");

        let materialized = table.materialize_page(page).expect("materialize");
        for key in 0..=13 {
            let lookup = table.lookup(page, BwKey(key)).expect("lookup");
            let expected = materialized.get(&BwKey(key)).copied();
            assert_eq!(
                lookup, expected,
                "direct lookup should match materialized state for key {key}"
            );
            let rendered = lookup.map_or_else(|| String::from("-"), |value| value.0.to_string());
            println!("BWTREE_GOLDEN\t{key}\t{rendered}");
        }
    }

    #[test]
    fn bwtree_lookup_golden_report() {
        let table = MappingTable::with_capacity(4);
        let page = table.allocate_page().expect("alloc");
        let sibling = table.allocate_page().expect("alloc sibling");

        for (key, value) in [(1, 10), (2, 20), (3, 30), (4, 40), (5, 50)] {
            table
                .insert(page, BwKey(key), BwValue(value))
                .expect("insert");
        }
        table.delete(page, BwKey(2)).expect("delete");
        table
            .append_split_delta(page, BwKey(4), sibling)
            .expect("split");
        table
            .insert(page, BwKey(5), BwValue(500))
            .expect("newer insert");

        let materialized = table.materialize_page(page).expect("materialize");
        for key in [1, 2, 3, 4, 5, 6] {
            let key = BwKey(key);
            let lookup = table.lookup(page, key).expect("lookup");
            let expected = materialized.get(&key).copied();
            assert_eq!(lookup, expected);
            println!(
                "BWTREE_LOOKUP_GOLDEN\t{}\t{}",
                key.0,
                lookup.map_or_else(|| "None".to_owned(), |value| value.0.to_string())
            );
        }
    }

    #[test]
    fn merge_delta_records_sibling_removal() {
        let table = MappingTable::with_capacity(4);
        let page = table.allocate_page().expect("alloc");
        let sibling = table.allocate_page().expect("alloc sibling");

        // Insert data, split, then merge.
        for i in 1..=5 {
            insert_without_preconsolidation_for_test(&table, page, BwKey(i), BwValue(i));
        }
        table
            .append_split_delta(page, BwKey(4), sibling)
            .expect("split");
        table.append_merge_delta(page, sibling).expect("merge");

        // After merge, the split-away keys are removed (Bw-tree merge is
        // a structural delta, the actual data reabsorption requires reading
        // the sibling page). Only keys below the separator remain.
        let state = table
            .materialize_page(page)
            .expect("materialize after merge");
        // Keys 1..3 should still be present.
        for i in 1..=3 {
            assert_eq!(state.get(&BwKey(i)).copied(), Some(BwValue(i)));
        }
        // Merge delta appended successfully (chain length grew).
        let snap = table.get_page(page).expect("get page");
        // chain: merge -> split -> inserts(5) -> base = 8
        assert!(chain_length(&snap.head) >= 7);
    }

    #[test]
    fn lookup_returns_none_for_deleted_key() {
        let table = MappingTable::with_capacity(2);
        let page = table.allocate_page().expect("alloc");

        table.insert(page, BwKey(42), BwValue(100)).expect("insert");
        assert_eq!(
            table.lookup(page, BwKey(42)).expect("lookup"),
            Some(BwValue(100))
        );

        table.delete(page, BwKey(42)).expect("delete");
        assert_eq!(
            table.lookup(page, BwKey(42)).expect("lookup after delete"),
            None
        );
    }

    #[test]
    fn lookup_returns_none_for_nonexistent_key() {
        let table = MappingTable::with_capacity(2);
        let page = table.allocate_page().expect("alloc");
        assert_eq!(
            table.lookup(page, BwKey(999)).expect("lookup nonexistent"),
            None
        );
    }

    #[test]
    fn consolidation_config_custom_threshold() {
        let table = Arc::new(MappingTable::with_capacity(2));
        let page = table.allocate_page().expect("alloc");

        // Insert enough to build a long chain.
        for i in 0..20 {
            insert_without_preconsolidation_for_test(&table, page, BwKey(i), BwValue(i));
        }

        // With high threshold, no pages should need consolidation.
        let to_consolidate = table.scan_for_consolidation(100);
        assert!(to_consolidate.is_empty());

        // With low threshold, the page should need consolidation.
        let to_consolidate = table.scan_for_consolidation(5);
        assert!(!to_consolidate.is_empty());
        assert!(to_consolidate.contains(&page));
    }

    #[test]
    fn chain_length_fn_counts_correctly() {
        let base = PageDelta::empty_base();
        assert_eq!(chain_length(&base), 1);

        let with_insert = Arc::new(PageDelta::Insert {
            key: BwKey(1),
            value: BwValue(1),
            next: base,
        });
        assert_eq!(chain_length(&with_insert), 2);

        let with_delete = Arc::new(PageDelta::Delete {
            key: BwKey(1),
            next: with_insert,
        });
        assert_eq!(chain_length(&with_delete), 3);
    }

    #[test]
    fn delete_nonexistent_key_is_harmless() {
        let table = MappingTable::with_capacity(2);
        let page = table.allocate_page().expect("alloc");

        table.insert(page, BwKey(1), BwValue(1)).expect("insert");
        // Deleting a key that doesn't exist should succeed (delta is appended).
        table.delete(page, BwKey(999)).expect("delete nonexistent");

        // Original key should still be there.
        assert_eq!(
            table.lookup(page, BwKey(1)).expect("lookup"),
            Some(BwValue(1))
        );
    }

    // ── Multi-pass audit regressions ───────────────────────────────────

    /// `consolidate_page` previously reported `entries_count = 0` whenever it
    /// took the "already consolidated" early-return path, which made the
    /// metric useless for any healthy consolidated page. Read the actual
    /// count from the `Base` node instead.
    #[test]
    fn consolidate_page_reports_actual_entries_count_when_already_base() {
        let table = MappingTable::with_capacity(2);
        let page = table.allocate_page().expect("alloc");

        // Force consolidation so the chain is exactly one Base with a known
        // number of entries.
        for k in 0..7_u64 {
            table.insert(page, BwKey(k), BwValue(k)).expect("insert");
        }
        let cfg = ConsolidationConfig::default();
        let first = table.consolidate_page(page, &cfg).expect("consolidate");
        assert_eq!(first.entries_count, 7);
        assert_eq!(first.chain_len_after, 1);

        // Second call observes chain_len_before <= 1 and takes the no-op
        // path. Before the fix, entries_count would be 0; after it must
        // reflect the seven entries actually present in the base.
        let again = table
            .consolidate_page(page, &cfg)
            .expect("consolidate no-op");
        assert!(again.chain_len_before <= 1);
        assert_eq!(again.cas_attempts, 0);
        assert_eq!(
            again.entries_count, 7,
            "no-op consolidation must report the real entry count, not 0"
        );
    }

    /// `consolidate_all` previously aborted on the first per-page failure,
    /// dropping the count of pages it had already finished. This test
    /// drives a successful run; the regression is documented by the
    /// invariant that on success it returns the count rather than 0.
    #[test]
    fn consolidate_all_returns_count_of_successful_pages() {
        let table = MappingTable::with_capacity(8);

        // Build several pages with chains long enough to qualify for
        // consolidation under the default threshold.
        let cfg = ConsolidationConfig {
            chain_threshold: 1,
            max_retries: MAX_CAS_RETRIES,
        };
        let mut pages = Vec::new();
        for _ in 0..4 {
            let p = table.allocate_page().expect("alloc");
            for k in 0..(cfg.chain_threshold + 2) {
                let key = BwKey(u64::try_from(k).expect("fits"));
                table.insert(p, key, BwValue(0)).expect("insert");
            }
            pages.push(p);
        }

        // Sanity: scan finds every qualifying page exactly once.
        let candidates = table.scan_for_consolidation(cfg.chain_threshold);
        for p in &pages {
            assert!(candidates.contains(p));
        }

        let consolidated = table.consolidate_all(&cfg).expect("consolidate_all");
        assert_eq!(consolidated, pages.len());

        // Each page now has chain length 1.
        for p in pages {
            let snap = table.get_page(p).expect("snapshot");
            assert_eq!(chain_length(&snap.head), 1);
        }
    }

    /// Transient CAS retry exhaustion is safe for `consolidate_all` to skip,
    /// but structural corruption must still reach the caller. The broad
    /// catch-all skip path would previously convert this malformed chain into
    /// `Ok(0)`.
    #[test]
    fn consolidate_all_propagates_corrupt_chain() {
        let table = MappingTable::with_capacity(1);
        let page = table.allocate_page().expect("alloc");

        let mut head = PageDelta::empty_base();
        for k in 0..MAX_CHAIN_WALK {
            let key = BwKey(u64::try_from(k).expect("fits"));
            head = Arc::new(PageDelta::Insert {
                key,
                value: BwValue(key.0),
                next: head,
            });
        }

        let entry = table.entry(page).expect("entry");
        *write_lock(&entry.head) = PageHead::new(head, MAX_CHAIN_WALK + 1);

        let cfg = ConsolidationConfig {
            chain_threshold: 1,
            max_retries: 64,
        };
        let err = table
            .consolidate_all(&cfg)
            .expect_err("corrupt chain must not be skipped");
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    /// `chain_length` and `materialize_from_head` previously rejected any
    /// chain longer than `MAX_CHAIN_DEPTH`. In practice, multiple appenders
    /// racing past the pre-consolidation check can briefly leave a chain at
    /// `MAX_CHAIN_DEPTH + k`; rejecting it as `Corruption` is a false
    /// positive. The walk limit now sits at `MAX_CHAIN_WALK` (2× the depth
    /// trigger) to absorb that race.
    #[test]
    fn materialize_from_head_tolerates_chain_overshoot() {
        // Build a chain of MAX_CHAIN_DEPTH + 1 nodes (one more than the
        // pre-consolidation trigger): MAX_CHAIN_DEPTH Insert deltas on a
        // base with one entry. This shape is what a brief race produces
        // before a thread reaches the consolidation branch.
        let mut head: Arc<PageDelta> = Arc::new(PageDelta::Base {
            entries: BTreeMap::from([(BwKey(0), BwValue(0))]),
        });
        for k in 1..=MAX_CHAIN_DEPTH {
            head = Arc::new(PageDelta::Insert {
                key: BwKey(u64::try_from(k).expect("fits")),
                value: BwValue(u64::try_from(k).expect("fits")),
                next: head,
            });
        }
        // Chain depth: 1 base + MAX_CHAIN_DEPTH deltas = MAX_CHAIN_DEPTH + 1
        // nodes total.
        assert_eq!(chain_length(&head), MAX_CHAIN_DEPTH + 1);

        let (state, observed_len) =
            materialize_from_head(&head).expect("overshoot must materialize cleanly");
        assert_eq!(observed_len, MAX_CHAIN_DEPTH + 1);
        // Every key from 0 through MAX_CHAIN_DEPTH must be present.
        assert_eq!(state.len(), MAX_CHAIN_DEPTH + 1);
        assert_eq!(state.get(&BwKey(0)).copied(), Some(BwValue(0)));
        let last = u64::try_from(MAX_CHAIN_DEPTH).expect("fits");
        assert_eq!(state.get(&BwKey(last)).copied(), Some(BwValue(last)));
    }

    // ── Property-based tests (proptest) ────────────────────────────────

    use proptest::prelude::*;

    /// Op stream over a single page: each op either inserts a key/value or
    /// deletes a key. Keys are bounded so multiple ops legitimately collide.
    #[derive(Debug, Clone)]
    enum BwOp {
        Insert(u64, u64),
        Delete(u64),
    }

    fn bw_op_strat() -> impl Strategy<Value = BwOp> {
        prop_oneof![
            (0_u64..32, any::<u64>()).prop_map(|(k, v)| BwOp::Insert(k, v)),
            (0_u64..32).prop_map(BwOp::Delete),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Metamorphic relation: `materialize_page` after a sequence of
        /// inserts and deletes must equal the canonical BTreeMap state
        /// produced by replaying the same ops on a model. This pins the
        /// chain-walk + delta-fold logic in `materialize_from_head`
        /// against the trivial reference implementation: a regression
        /// that re-orders deltas, drops a delete, or applies an insert
        /// twice would diverge from the model on the first such op.
        #[test]
        fn proptest_materialize_matches_btreemap_model(
            ops in proptest::collection::vec(bw_op_strat(), 0..64),
        ) {
            let table = MappingTable::with_capacity(1);
            let page = table.allocate_page().expect("alloc");

            let mut model: BTreeMap<BwKey, BwValue> = BTreeMap::new();
            for op in &ops {
                match *op {
                    BwOp::Insert(k, v) => {
                        let key = BwKey(k);
                        let value = BwValue(v);
                        table.insert(page, key, value).expect("insert");
                        model.insert(key, value);
                    }
                    BwOp::Delete(k) => {
                        let key = BwKey(k);
                        table.delete(page, key).expect("delete");
                        model.remove(&key);
                    }
                }
            }

            let materialized = table.materialize_page(page).expect("materialize");
            prop_assert_eq!(
                materialized, model,
                "materialize_page must match the model BTreeMap after {} ops",
                ops.len()
            );

            // Lookup must agree with materialize for every key in the union
            // of model.keys() and the ops' targeted keys.
            let mut probed_keys: std::collections::BTreeSet<u64> =
                ops.iter()
                    .map(|op| match *op {
                        BwOp::Insert(k, _) | BwOp::Delete(k) => k,
                    })
                    .collect();
            probed_keys.insert(33);  // a key never touched
            for k in probed_keys {
                let key = BwKey(k);
                let expected = table
                    .materialize_page(page)
                    .expect("materialize")
                    .get(&key)
                    .copied();
                let actual = table.lookup(page, key).expect("lookup");
                prop_assert_eq!(
                    actual, expected,
                    "lookup({}) diverges from materialize-then-lookup",
                    k
                );
            }
        }

        /// Metamorphic relation: `consolidate_page` is idempotent — once a
        /// page has been consolidated to chain_len=1, calling it again
        /// must not change observable state (chain_len stays 1, entries
        /// are preserved, cas_attempts is 0).
        #[test]
        fn proptest_consolidate_page_is_idempotent(
            ops in proptest::collection::vec(bw_op_strat(), 1..32),
        ) {
            let table = MappingTable::with_capacity(1);
            let page = table.allocate_page().expect("alloc");

            for op in &ops {
                match *op {
                    BwOp::Insert(k, v) => {
                        table.insert(page, BwKey(k), BwValue(v)).expect("insert");
                    }
                    BwOp::Delete(k) => {
                        table.delete(page, BwKey(k)).expect("delete");
                    }
                }
            }

            let cfg = ConsolidationConfig {
                chain_threshold: 0,
                max_retries: 4,
            };

            let first = table.consolidate_page(page, &cfg).expect("first consolidate");
            let after_first = table.materialize_page(page).expect("materialize");

            let second = table.consolidate_page(page, &cfg).expect("second consolidate");
            let after_second = table.materialize_page(page).expect("materialize");

            prop_assert_eq!(after_first, after_second,
                "consolidate-twice must preserve materialized state");

            // After the first consolidation chain_len drops to 1; the
            // second call sees chain_len_before == 1 and skips work.
            prop_assert_eq!(first.chain_len_after, 1);
            prop_assert_eq!(second.chain_len_before, 1);
            prop_assert_eq!(second.chain_len_after, 1);
            prop_assert_eq!(second.cas_attempts, 0,
                "second consolidate must not perform any CAS attempts");
        }
    }

    /// Same-binary A/B for bd-xmh5g.15: run the mixed bench workload
    /// (50% lookup / 30% insert / 10% delete / 10% range_scan, PREPOPULATE
    /// 10_000, 5_000 ops) twice in ONE process over an IDENTICAL seeded op
    /// sequence — once with `range_scan` materializing the whole page (the old
    /// path) and once with the bounded delta replay. Only the scan
    /// implementation differs; both runs share the worker and binary, so the
    /// relative comparison is machine-independent. This is the rigorous proof
    /// the cross-worker criterion figures (bogus 2.31x / 4.75s) could not give.
    /// The scan-row checksums must match (isomorphism on workload-generated
    /// states). Prints the speedup with `--nocapture`.
    #[test]
    fn bd_xmh5g_15_range_scan_same_binary_ab() {
        const PREPOPULATE: u64 = 10_000;
        const OPS: u64 = 5_000;
        const REPS: usize = 5;
        const SCAN_COUNT: usize = 10;

        fn xorshift64(s: &mut u64) -> u64 {
            let mut x = *s;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *s = x;
            x
        }

        // Old path: materialize the full page, then range(start..).take(count).
        fn scan_materialize(
            table: &MappingTable,
            page: PageId,
            start: BwKey,
        ) -> Vec<(BwKey, BwValue)> {
            let snap = table.get_page(page).expect("get_page");
            let (state, _) = materialize_from_head(&snap.head).expect("materialize");
            state
                .range(start..)
                .take(SCAN_COUNT)
                .map(|(&k, &v)| (k, v))
                .collect()
        }
        // New path: bounded delta replay (the committed range_scan body).
        fn scan_bounded(table: &MappingTable, page: PageId, start: BwKey) -> Vec<(BwKey, BwValue)> {
            let snap = table.get_page(page).expect("get_page");
            range_scan_from_head(&snap.head, start, SCAN_COUNT)
                .expect("bounded range scan")
                .0
        }

        // Replay the identical workload with the chosen scan path; return
        // (elapsed, checksum-of-scan-rows). A fresh table + fixed seed make the
        // mutation stream — and therefore the chain state at every scan —
        // identical across both variants.
        let run = |use_bounded: bool| -> (std::time::Duration, u64) {
            let table = MappingTable::with_capacity(16);
            let page = table.allocate_page().expect("alloc");
            for i in 0..PREPOPULATE {
                table.insert(page, BwKey(i), BwValue(i)).expect("insert");
            }
            let cfg = ConsolidationConfig::default();
            let _ = table.consolidate_page(page, &cfg);

            let mut rng = 0x9E37_79B9_7F4A_7C15_u64;
            let mut checksum = 0_u64;
            let begin = std::time::Instant::now();
            for _ in 0..OPS {
                let op = xorshift64(&mut rng) % 100;
                let key = xorshift64(&mut rng) % (PREPOPULATE * 2);
                if op < 50 {
                    let _ = table.lookup(page, BwKey(key));
                } else if op < 80 {
                    let _ = table.insert(page, BwKey(key), BwValue(key + 1));
                } else if op < 90 {
                    let _ = table.delete(page, BwKey(key));
                } else {
                    let rows = if use_bounded {
                        scan_bounded(&table, page, BwKey(key))
                    } else {
                        scan_materialize(&table, page, BwKey(key))
                    };
                    for (k, _) in &rows {
                        checksum = checksum.wrapping_add(k.0);
                    }
                }
            }
            (begin.elapsed(), checksum)
        };

        let mut best_mat = std::time::Duration::MAX;
        let mut best_bnd = std::time::Duration::MAX;
        let mut cks_mat = 0_u64;
        let mut cks_bnd = 0_u64;
        for _ in 0..REPS {
            let (d, c) = run(false);
            best_mat = best_mat.min(d);
            cks_mat = c;
            let (d, c) = run(true);
            best_bnd = best_bnd.min(d);
            cks_bnd = c;
        }

        assert_eq!(
            cks_mat, cks_bnd,
            "bounded range_scan must return identical rows to materialize \
             across the whole workload (isomorphism)"
        );

        let speedup = best_mat.as_secs_f64() / best_bnd.as_secs_f64();
        eprintln!(
            "bd-xmh5g.15 same-binary A/B (mixed, 1 thread): materialize={best_mat:?} \
             bounded={best_bnd:?} speedup={speedup:.3}x checksum={cks_bnd}"
        );
    }
}
