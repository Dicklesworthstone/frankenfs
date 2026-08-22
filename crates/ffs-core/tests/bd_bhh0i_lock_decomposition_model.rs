#![forbid(unsafe_code)]

//! Bounded Loom model for the proposed bd-bhh0i allocation-lock decomposition.
//!
//! This is deliberately model-only: it does not wire the decomposition into
//! `OpenFs`. The abstraction mirrors the accepted lean eager-commit protocol:
//!
//! ```text
//! outer allocator R
//!   -> allocation groups (sorted)
//!   -> MVCC shards (sorted)
//!   -> contention metrics
//!   -> assign sequence and install every version
//!   -> drop every shard
//!   -> publish the contiguous ready prefix while groups remain held
//!   -> optional active-snapshot -> shard prune
//!   -> update group counters and release groups
//! ```
//!
//! The `completed_prefix.store(Release)` in the publication gate is the modeled
//! linearization point. A snapshot reader Acquire-loads that prefix and filters
//! installed versions by it, so installed-but-unpublished versions stay hidden.
//! A Loom-synchronized ghost history records every invocation and response. The
//! commit-sequence order must respect every non-overlap edge in that history and
//! replay against a sequential bitmap allocator. Each group effect has an
//! explicit MVCC-shard mapping, and every installed payload must equal that
//! group's sequential prefix, rather than inferring linearizability from final
//! counters alone.
//!
//! The proof is split to keep each state space finite and exhaustive: five fixed
//! writer configurations cover the allocator lock graph; publication visibility
//! has one fixed installed sequence, one installer, and one reader; pruning has
//! one writer plus one reader. Exhaustiveness is over modeled schedules for those
//! enumerated configurations, not over every possible two-group operation. These
//! are separate bounded claims, not a proof of their arbitrary composition. They
//! cover the default sharded, no-JBD2 bitmap-allocation primitive only. They do
//! not prove whole-create atomicity, crash consistency, starvation freedom, the
//! single-store/JBD2 path, or compensation after an installed write.

use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::sync::{Arc, Condvar, Mutex, RwLock};
use loom::thread;
use std::collections::BTreeSet;

const GROUP_COUNT: usize = 2;
const WRITER_COUNT: usize = 2;
const GROUP_CAPACITY: usize = 2;
const MAX_GROUPS_PER_OPERATION: usize = 2;

#[derive(Clone, Copy, Debug)]
struct OperationSpec {
    requested_groups: [usize; MAX_GROUPS_PER_OPERATION],
    group_count: usize,
    requested_shards: [usize; MAX_GROUPS_PER_OPERATION],
    shard_payload_groups: [usize; MAX_GROUPS_PER_OPERATION],
    shard_count: usize,
    fail_before_install: bool,
}

impl OperationSpec {
    const fn one(group: usize) -> Self {
        Self {
            requested_groups: [group, group],
            group_count: 1,
            requested_shards: [group, group],
            shard_payload_groups: [group, group],
            shard_count: 1,
            fail_before_install: false,
        }
    }

    const fn two(first: usize, second: usize) -> Self {
        Self {
            requested_groups: [first, second],
            group_count: 2,
            requested_shards: [first, second],
            shard_payload_groups: [first, second],
            shard_count: 2,
            fail_before_install: false,
        }
    }

    const fn mapped(
        requested_groups: [usize; MAX_GROUPS_PER_OPERATION],
        group_count: usize,
        requested_shards: [usize; MAX_GROUPS_PER_OPERATION],
        shard_payload_groups: [usize; MAX_GROUPS_PER_OPERATION],
        shard_count: usize,
    ) -> Self {
        Self {
            requested_groups,
            group_count,
            requested_shards,
            shard_payload_groups,
            shard_count,
            fail_before_install: false,
        }
    }

    const fn failing(group: usize) -> Self {
        Self {
            fail_before_install: true,
            ..Self::one(group)
        }
    }

    fn sorted_groups(self) -> [usize; MAX_GROUPS_PER_OPERATION] {
        Self::sorted_unique(self.requested_groups, self.group_count)
    }

    fn sorted_shard_writes(self) -> [(usize, usize); MAX_GROUPS_PER_OPERATION] {
        let mut writes = std::array::from_fn(|index| {
            (
                self.requested_shards[index],
                self.shard_payload_groups[index],
            )
        });
        if self.shard_count == 2 && writes[0].0 > writes[1].0 {
            writes.swap(0, 1);
        }
        assert!((1..=MAX_GROUPS_PER_OPERATION).contains(&self.shard_count));
        assert!(
            writes[..self.shard_count]
                .iter()
                .all(|(shard, payload_group)| {
                    *shard < GROUP_COUNT && self.touches(*payload_group)
                })
        );
        if self.shard_count == 2 {
            assert_ne!(writes[0].0, writes[1].0, "MVCC shard locks are unique");
        }
        for group in self.sorted_groups()[..self.group_count].iter().copied() {
            assert!(
                writes[..self.shard_count]
                    .iter()
                    .any(|(_, payload_group)| *payload_group == group),
                "every group effect maps to at least one MVCC shard"
            );
        }
        writes
    }

    fn sorted_unique(
        mut indices: [usize; MAX_GROUPS_PER_OPERATION],
        count: usize,
    ) -> [usize; MAX_GROUPS_PER_OPERATION] {
        if count == 2 && indices[0] > indices[1] {
            indices.swap(0, 1);
        }
        assert!((1..=MAX_GROUPS_PER_OPERATION).contains(&count));
        assert!(indices[..count].iter().all(|index| *index < GROUP_COUNT));
        if count == 2 {
            assert_ne!(indices[0], indices[1], "multi-lock sets are unique");
        }
        indices
    }

    fn touches(self, group: usize) -> bool {
        let groups = self.sorted_groups();
        groups[..self.group_count].contains(&group)
    }

    fn touches_shard(self, shard: usize) -> bool {
        self.sorted_shard_writes()[..self.shard_count]
            .iter()
            .any(|(candidate, _)| *candidate == shard)
    }

    fn writes_payload_to_shard(self, shard: usize, payload_group: usize) -> bool {
        self.sorted_shard_writes()[..self.shard_count].contains(&(shard, payload_group))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Version {
    sequence: usize,
    worker: usize,
    payload_group: usize,
    bitmap: [bool; GROUP_CAPACITY],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CommitResult {
    sequence: usize,
    worker: usize,
    allocated_bits: [Option<usize>; GROUP_COUNT],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplayState {
    bitmaps: [[bool; GROUP_CAPACITY]; GROUP_COUNT],
    cursors: [usize; GROUP_COUNT],
}

#[derive(Debug)]
struct GroupState {
    bitmap: [bool; GROUP_CAPACITY],
    free: usize,
    cursor: usize,
}

impl Default for GroupState {
    fn default() -> Self {
        Self {
            bitmap: [false; GROUP_CAPACITY],
            free: GROUP_CAPACITY,
            cursor: 0,
        }
    }
}

impl GroupState {
    fn next_free(&self) -> Option<usize> {
        (0..GROUP_CAPACITY)
            .map(|offset| (self.cursor + offset) % GROUP_CAPACITY)
            .find(|bit| !self.bitmap[*bit])
    }

    fn install(&mut self, bit: usize, bitmap: [bool; GROUP_CAPACITY]) {
        assert!(!self.bitmap[bit], "an allocator bit is never reused");
        assert!(bitmap[bit], "the installed bitmap contains the allocation");
        self.bitmap = bitmap;
        self.free = self
            .free
            .checked_sub(1)
            .expect("free count cannot underflow");
        self.cursor = (bit + 1) % GROUP_CAPACITY;
        assert_eq!(
            self.free + self.bitmap.into_iter().filter(|set| *set).count(),
            GROUP_CAPACITY,
            "free count and bitmap population are conserved"
        );
    }
}

#[derive(Debug, Default)]
struct ShardState {
    versions: Vec<Version>,
}

#[derive(Debug, Default)]
struct MetricsState {
    committed_by_worker: [bool; WRITER_COUNT],
}

#[derive(Debug, Default)]
struct ActiveSnapshotState {
    high: Option<usize>,
}

#[derive(Debug, Default)]
struct HistoryState {
    clock: usize,
    invocation: [usize; WRITER_COUNT],
    response: [usize; WRITER_COUNT],
}

impl HistoryState {
    fn record_invocation(&mut self, worker: usize) {
        assert_eq!(self.invocation[worker], 0, "one invocation per worker");
        self.clock += 1;
        self.invocation[worker] = self.clock;
    }

    fn record_response(&mut self, worker: usize) {
        assert_ne!(self.invocation[worker], 0, "response follows invocation");
        assert_eq!(self.response[worker], 0, "one response per worker");
        self.clock += 1;
        self.response[worker] = self.clock;
    }
}

#[derive(Debug)]
struct PublicationState {
    completed_shadow: usize,
    ready: BTreeSet<usize>,
    worker_by_sequence: [Option<usize>; WRITER_COUNT],
}

impl Default for PublicationState {
    fn default() -> Self {
        Self {
            completed_shadow: 0,
            ready: BTreeSet::new(),
            worker_by_sequence: [None; WRITER_COUNT],
        }
    }
}

#[derive(Debug)]
struct PublicationGate {
    completed_prefix: AtomicUsize,
    state: Mutex<PublicationState>,
    ready: Condvar,
}

impl PublicationGate {
    fn new() -> Self {
        Self::with_completed(0)
    }

    fn with_completed(completed: usize) -> Self {
        let state = PublicationState {
            completed_shadow: completed,
            ..PublicationState::default()
        };
        Self {
            completed_prefix: AtomicUsize::new(completed),
            state: Mutex::new(state),
            ready: Condvar::new(),
        }
    }

    fn with_sequence_two_installed_and_ready() -> Self {
        let mut state = PublicationState::default();
        assert!(state.ready.insert(2));
        state.worker_by_sequence[1] = Some(1);
        Self {
            completed_prefix: AtomicUsize::new(0),
            state: Mutex::new(state),
            ready: Condvar::new(),
        }
    }

    fn completed(&self) -> usize {
        self.completed_prefix.load(Ordering::Acquire)
    }

    fn publish(&self, sequence: usize, worker: usize) {
        let mut state = self.state.lock().expect("publication state lock");
        assert!(state.ready.insert(sequence), "sequence becomes ready once");
        assert!(
            state.worker_by_sequence[sequence - 1]
                .replace(worker)
                .is_none(),
            "sequence is installed once"
        );

        loop {
            let mut advanced = false;
            loop {
                let next = state.completed_shadow.saturating_add(1);
                if !state.ready.remove(&next) {
                    break;
                }
                // All versions are installed and their shard guards were dropped
                // before this Release store. This is the linearization point.
                state.completed_shadow = next;
                self.completed_prefix.store(next, Ordering::Release);
                advanced = true;
            }
            if advanced {
                self.ready.notify_all();
            }
            if state.completed_shadow >= sequence {
                return;
            }
            state = self
                .ready
                .wait(state)
                .expect("publication wait reacquires its mutex");
        }
    }
}

#[derive(Debug)]
struct DecompositionModel {
    outer_allocator: RwLock<()>,
    groups: [Mutex<GroupState>; GROUP_COUNT],
    // Writer-side production `RwLock<W>` behavior is abstracted as a Mutex;
    // visibility/read-lock interaction is modeled separately below.
    shards: [Mutex<ShardState>; GROUP_COUNT],
    contention_metrics: Mutex<MetricsState>,
    next_commit: AtomicUsize,
    publication: PublicationGate,
    // Ghost-only instrumentation. This lock is never held with a modeled
    // production lock and gives invocation/response events a total observer
    // order without asserting a production synchronization edge.
    history: Mutex<HistoryState>,
}

impl DecompositionModel {
    fn new() -> Self {
        Self {
            outer_allocator: RwLock::new(()),
            groups: std::array::from_fn(|_| Mutex::new(GroupState::default())),
            shards: std::array::from_fn(|_| Mutex::new(ShardState::default())),
            contention_metrics: Mutex::new(MetricsState::default()),
            next_commit: AtomicUsize::new(1),
            publication: PublicationGate::new(),
            history: Mutex::new(HistoryState::default()),
        }
    }

    fn commit(&self, worker: usize, spec: OperationSpec) -> Option<CommitResult> {
        self.history
            .lock()
            .expect("record invocation")
            .record_invocation(worker);

        let outer = self.outer_allocator.read().expect("outer allocator read");
        let groups = spec.sorted_groups();
        let mut group_guards = Vec::with_capacity(spec.group_count);
        for &group in &groups[..spec.group_count] {
            group_guards.push((
                group,
                self.groups[group].lock().expect("allocation group lock"),
            ));
        }

        let mut allocated_bits = [None; GROUP_COUNT];
        let mut prepared_bitmaps = [[false; GROUP_CAPACITY]; GROUP_COUNT];
        for (group, state) in &group_guards {
            let bit = state.next_free().expect("bounded model has capacity");
            let mut bitmap = state.bitmap;
            bitmap[bit] = true;
            allocated_bits[*group] = Some(bit);
            prepared_bitmaps[*group] = bitmap;
        }

        let shard_writes = spec.sorted_shard_writes();
        let mut shard_guards = Vec::with_capacity(spec.shard_count);
        for &(shard, payload_group) in &shard_writes[..spec.shard_count] {
            shard_guards.push((
                shard,
                payload_group,
                self.shards[shard].lock().expect("MVCC shard write lock"),
            ));
        }
        if spec.fail_before_install {
            drop(shard_guards);
            drop(group_guards);
            drop(outer);
            self.history
                .lock()
                .expect("record failed response")
                .record_response(worker);
            return None;
        }

        // Production preflight records metrics while shard guards are held, then
        // drops the metrics guard before assigning and installing a sequence.
        {
            let mut metrics = self
                .contention_metrics
                .lock()
                .expect("contention metrics write lock");
            assert!(!metrics.committed_by_worker[worker]);
            metrics.committed_by_worker[worker] = true;
        }

        let sequence = self.next_commit.fetch_add(1, Ordering::AcqRel);
        assert!((1..=WRITER_COUNT).contains(&sequence));

        for (shard_index, payload_group, shard) in &mut shard_guards {
            if let Some(previous) = shard.versions.last() {
                assert!(previous.sequence < sequence, "per-shard versions ascend");
            }
            shard.versions.push(Version {
                sequence,
                worker,
                payload_group: *payload_group,
                bitmap: prepared_bitmaps[*payload_group],
            });
            assert!(*shard_index < GROUP_COUNT);
        }

        drop(shard_guards);
        // The group guards are used below and therefore remain live across this
        // wait; every shard guard was explicitly dropped above it.
        self.publication.publish(sequence, worker);

        for (group, state) in &mut group_guards {
            state.install(
                allocated_bits[*group].expect("prepared allocation bit"),
                prepared_bitmaps[*group],
            );
        }
        drop(group_guards);
        drop(outer);

        let result = CommitResult {
            sequence,
            worker,
            allocated_bits,
        };
        self.history
            .lock()
            .expect("record successful response")
            .record_response(worker);
        Some(result)
    }
}

fn replay(
    specs: [OperationSpec; WRITER_COUNT],
    results: [Option<CommitResult>; WRITER_COUNT],
    high: usize,
) -> ReplayState {
    let mut successful: Vec<CommitResult> = results.into_iter().flatten().collect();
    successful.sort_unstable_by_key(|result| result.sequence);
    let mut bitmaps = [[false; GROUP_CAPACITY]; GROUP_COUNT];
    let mut cursors = [0_usize; GROUP_COUNT];
    for result in successful {
        if result.sequence > high {
            break;
        }
        let spec = specs[result.worker];
        for group in 0..GROUP_COUNT {
            if !spec.touches(group) {
                assert_eq!(result.allocated_bits[group], None);
                continue;
            }
            let expected_bit = (0..GROUP_CAPACITY)
                .map(|offset| (cursors[group] + offset) % GROUP_CAPACITY)
                .find(|bit| !bitmaps[group][*bit])
                .expect("sequential replay has capacity");
            assert_eq!(result.allocated_bits[group], Some(expected_bit));
            assert!(!bitmaps[group][expected_bit], "replay rejects duplicates");
            bitmaps[group][expected_bit] = true;
            cursors[group] = (expected_bit + 1) % GROUP_CAPACITY;
        }
    }
    ReplayState { bitmaps, cursors }
}

fn verify_execution(
    model: &DecompositionModel,
    specs: [OperationSpec; WRITER_COUNT],
    results: [Option<CommitResult>; WRITER_COUNT],
) {
    let successful_count = results.iter().flatten().count();
    let mut successful: Vec<CommitResult> = results.into_iter().flatten().collect();
    successful.sort_unstable_by_key(|result| result.sequence);
    for (index, result) in successful.iter().enumerate() {
        assert_eq!(result.sequence, index + 1, "commit prefix has no gap");
    }

    assert_eq!(model.publication.completed(), successful_count);
    assert_eq!(
        model.next_commit.load(Ordering::Acquire),
        successful_count + 1
    );
    let publication = model
        .publication
        .state
        .lock()
        .expect("inspect publication state");
    assert!(publication.ready.is_empty());
    for result in &successful {
        assert_eq!(
            publication.worker_by_sequence[result.sequence - 1],
            Some(result.worker)
        );
    }
    drop(publication);

    let expected_final = replay(specs, results, successful_count);
    for (group, (expected_bitmap, expected_cursor)) in expected_final
        .bitmaps
        .into_iter()
        .zip(expected_final.cursors)
        .enumerate()
    {
        let state = model.groups[group].lock().expect("inspect group state");
        assert_eq!(state.bitmap, expected_bitmap);
        assert_eq!(
            state.cursor, expected_cursor,
            "allocator cursor matches the sequential replay"
        );
        assert_eq!(
            state.free + state.bitmap.into_iter().filter(|set| *set).count(),
            GROUP_CAPACITY
        );
    }

    for shard_index in 0..GROUP_COUNT {
        let shard = model.shards[shard_index]
            .lock()
            .expect("inspect shard state");
        for version in &shard.versions {
            assert!(
                version.sequence <= successful_count,
                "only assigned sequences install versions"
            );
            assert!(
                specs[version.worker].writes_payload_to_shard(shard_index, version.payload_group)
            );
            assert_eq!(
                version.bitmap,
                replay(specs, results, version.sequence).bitmaps[version.payload_group],
                "each installed shard payload matches its sequential group effect"
            );
        }
        for worker in 0..WRITER_COUNT {
            let expected =
                usize::from(results[worker].is_some() && specs[worker].touches_shard(shard_index));
            assert_eq!(
                shard
                    .versions
                    .iter()
                    .filter(|version| version.worker == worker)
                    .count(),
                expected,
                "each successful writer installs once in every requested shard"
            );
        }
    }

    let metrics = model
        .contention_metrics
        .lock()
        .expect("inspect contention metrics");
    for (worker, result) in results.iter().enumerate() {
        assert_eq!(metrics.committed_by_worker[worker], result.is_some());
    }
    drop(metrics);

    let history = model.history.lock().expect("inspect ghost history");
    for worker in 0..WRITER_COUNT {
        assert_ne!(history.invocation[worker], 0);
        assert!(history.invocation[worker] < history.response[worker]);
    }
    for earlier in &successful {
        for later in &successful {
            if history.response[earlier.worker] < history.invocation[later.worker] {
                assert!(
                    earlier.sequence < later.sequence,
                    "commit order preserves every response-before-invocation edge"
                );
            }
        }
    }
}

fn check_model(specs: [OperationSpec; WRITER_COUNT]) {
    let mut builder = loom::model::Builder::new();
    builder.max_threads = 3;
    builder.max_branches = 1_000;
    builder.max_permutations = None;
    builder.max_duration = None;
    builder.preemption_bound = None;
    builder.check(move || {
        let model = Arc::new(DecompositionModel::new());
        let left = Arc::clone(&model);
        let left_thread = thread::spawn(move || left.commit(0, specs[0]));
        let right = Arc::clone(&model);
        let right_thread = thread::spawn(move || right.commit(1, specs[1]));

        let results = [
            left_thread.join().expect("left writer completes"),
            right_thread.join().expect("right writer completes"),
        ];
        verify_execution(&model, specs, results);
    });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SnapshotObservation {
    high: usize,
    visible_bitmaps: [[bool; GROUP_CAPACITY]; GROUP_COUNT],
}

#[derive(Debug)]
struct VisibilityModel {
    shards: [RwLock<ShardState>; GROUP_COUNT],
    publication: PublicationGate,
}

impl VisibilityModel {
    fn new() -> Self {
        Self {
            // Sequence 2 is fully installed but only ready, leaving a deliberate
            // gap at sequence 1. Readers must still observe prefix 0.
            shards: std::array::from_fn(|group| {
                RwLock::new(ShardState {
                    versions: vec![Version {
                        sequence: 2,
                        worker: 1,
                        payload_group: group,
                        bitmap: [true, true],
                    }],
                })
            }),
            publication: PublicationGate::with_sequence_two_installed_and_ready(),
        }
    }

    fn install_and_publish(&self, worker: usize, sequence: usize) {
        assert_eq!(worker, 0);
        assert_eq!(sequence, 1);
        let bitmap = [true, false];
        let mut shards = Vec::with_capacity(GROUP_COUNT);
        for (group, shard) in self.shards.iter().enumerate() {
            shards.push((group, shard.write().expect("visibility shard write lock")));
        }
        for (group, shard) in &mut shards {
            shard.versions.push(Version {
                sequence,
                worker,
                payload_group: *group,
                bitmap,
            });
            assert!(*group < GROUP_COUNT);
        }
        drop(shards);
        // The allocator lock-order model checks these preconditions separately;
        // this smaller projection isolates ready-prefix visibility.
        self.publication.publish(sequence, worker);
    }

    fn observe(&self) -> SnapshotObservation {
        let high = self.publication.completed();
        let mut visible_bitmaps = [[false; GROUP_CAPACITY]; GROUP_COUNT];
        for (group, visible) in visible_bitmaps.iter_mut().enumerate() {
            let shard = self.shards[group]
                .read()
                .expect("visibility shard read lock");
            if let Some(version) = shard
                .versions
                .iter()
                .filter(|version| version.sequence <= high)
                .max_by_key(|version| version.sequence)
            {
                *visible = version.bitmap;
            }
        }
        SnapshotObservation {
            high,
            visible_bitmaps,
        }
    }
}

fn expected_visible(high: usize) -> [[bool; GROUP_CAPACITY]; GROUP_COUNT] {
    assert!(high <= 2, "bounded publication prefix exceeds two");
    let bitmap = match high {
        0 => [false, false],
        1 => [true, false],
        _ => [true, true],
    };
    [bitmap; GROUP_COUNT]
}

#[derive(Debug)]
struct PruneModel {
    group: Mutex<()>,
    shards: [RwLock<ShardState>; GROUP_COUNT],
    active_snapshots: RwLock<ActiveSnapshotState>,
    publication: PublicationGate,
}

impl PruneModel {
    fn new() -> Self {
        Self {
            group: Mutex::new(()),
            shards: std::array::from_fn(|group| {
                RwLock::new(ShardState {
                    versions: vec![Version {
                        sequence: 1,
                        worker: 0,
                        payload_group: group,
                        bitmap: [true, false],
                    }],
                })
            }),
            active_snapshots: RwLock::new(ActiveSnapshotState::default()),
            publication: PublicationGate::with_completed(1),
        }
    }

    fn commit_then_prune(&self) {
        let group = self.group.lock().expect("allocation group lock");
        let mut shards = Vec::with_capacity(GROUP_COUNT);
        for shard in &self.shards {
            shards.push(shard.write().expect("commit shard write lock"));
        }
        for (payload_group, shard) in shards.iter_mut().enumerate() {
            shard.versions.push(Version {
                sequence: 2,
                worker: 1,
                payload_group,
                bitmap: [true, true],
            });
        }
        drop(shards);
        self.publication.publish(2, 1);

        // Actual `FsMvccBlockDevice::write_block` may prune after commit while
        // the future allocation-group guard still encloses the call. The rank is
        // group -> active_snapshots -> shards, with shards acquired in order.
        let active = self
            .active_snapshots
            .write()
            .expect("active snapshot write lock");
        let watermark = active.high.unwrap_or_else(|| self.publication.completed());
        for shard in &self.shards {
            let mut shard = shard.write().expect("prune shard write lock");
            let newest_visible = shard
                .versions
                .iter()
                .enumerate()
                .filter(|(_, version)| version.sequence <= watermark)
                .max_by_key(|(_, version)| version.sequence)
                .map(|(index, _)| index);
            if let Some(newest_visible) = newest_visible {
                let mut index = 0;
                shard.versions.retain(|version| {
                    let keep = index == newest_visible || version.sequence > watermark;
                    index += 1;
                    keep
                });
            }
        }
        drop(active);
        drop(group);
    }

    fn observe_registered(&self) -> SnapshotObservation {
        let high = {
            let mut active = self
                .active_snapshots
                .write()
                .expect("active snapshot write lock");
            let high = self.publication.completed();
            assert!(active.high.replace(high).is_none());
            drop(active);
            high
        };
        thread::yield_now();
        let mut visible_bitmaps = [[false; GROUP_CAPACITY]; GROUP_COUNT];
        for (group, visible) in visible_bitmaps.iter_mut().enumerate() {
            let shard = self.shards[group].read().expect("snapshot shard read lock");
            *visible = shard
                .versions
                .iter()
                .filter(|version| version.sequence <= high)
                .max_by_key(|version| version.sequence)
                .expect("registered snapshot version survives pruning")
                .bitmap;
        }
        self.active_snapshots
            .write()
            .expect("active snapshot write lock")
            .high = None;
        SnapshotObservation {
            high,
            visible_bitmaps,
        }
    }
}

#[test]
fn disjoint_group_commits_are_deadlock_free_and_linearizable() {
    check_model([OperationSpec::one(0), OperationSpec::one(1)]);
}

#[test]
fn same_group_commits_serialize_and_replay_linearly() {
    check_model([OperationSpec::one(0), OperationSpec::one(0)]);
}

#[test]
fn opposing_multi_group_requests_normalize_to_one_lock_order() {
    check_model([OperationSpec::two(1, 0), OperationSpec::two(0, 1)]);
}

#[test]
fn disjoint_groups_with_cross_mapped_shards_normalize_both_lock_orders() {
    check_model([
        OperationSpec::mapped([0, 0], 1, [1, 0], [0, 0], 2),
        OperationSpec::mapped([1, 1], 1, [0, 1], [1, 1], 2),
    ]);
}

#[test]
fn failure_before_install_leaves_no_allocator_or_mvcc_effect() {
    check_model([OperationSpec::failing(0), OperationSpec::one(0)]);
}

#[test]
fn installed_unpublished_versions_are_hidden_until_the_prefix_is_complete() {
    let mut builder = loom::model::Builder::new();
    builder.max_threads = 3;
    builder.max_branches = 1_000;
    builder.max_permutations = None;
    builder.max_duration = None;
    builder.preemption_bound = None;
    builder.check(|| {
        let model = Arc::new(VisibilityModel::new());
        let first = Arc::clone(&model);
        let first_thread = thread::spawn(move || first.install_and_publish(0, 1));
        let reader = Arc::clone(&model);
        let reader_thread = thread::spawn(move || reader.observe());

        first_thread.join().expect("sequence-one writer completes");
        let observation = reader_thread.join().expect("snapshot reader completes");
        assert_eq!(
            observation.visible_bitmaps,
            expected_visible(observation.high)
        );
        assert_eq!(model.publication.completed(), 2);
        for shard in &model.shards {
            let shard = shard.read().expect("inspect visibility shard");
            assert_eq!(shard.versions.len(), 2);
            assert!(shard.versions.iter().any(|version| version.sequence == 1));
            assert!(shard.versions.iter().any(|version| version.sequence == 2));
            drop(shard);
        }
    });
}

#[test]
fn post_publication_prune_preserves_registered_snapshot_visibility() {
    let mut builder = loom::model::Builder::new();
    builder.max_threads = 3;
    builder.max_branches = 1_000;
    builder.max_permutations = None;
    builder.max_duration = None;
    builder.preemption_bound = None;
    builder.check(|| {
        let model = Arc::new(PruneModel::new());
        let writer = Arc::clone(&model);
        let writer_thread = thread::spawn(move || writer.commit_then_prune());
        let reader = Arc::clone(&model);
        let reader_thread = thread::spawn(move || reader.observe_registered());

        writer_thread.join().expect("writer and prune complete");
        let observation = reader_thread.join().expect("registered reader completes");
        assert_eq!(
            observation.visible_bitmaps,
            expected_visible(observation.high)
        );
        assert_eq!(model.publication.completed(), 2);
    });
}
