#[derive(Debug, Clone)]
pub struct MvccStore {
    pub(crate) next_txn: u64,
    pub(crate) next_commit: u64,
    pub(crate) versions: FxHashMap<BlockNumber, Vec<BlockVersion>>,
    pub(crate) physical_versions: FxHashMap<BlockNumber, Vec<PhysicalBlockVersion>>,
    /// Active snapshots: each entry is a `CommitSeq` from which a reader is
    /// still potentially reading.  The set uses a `BTreeMap` so that the
    /// minimum (oldest active snapshot) can be obtained in O(log n).
    ///
    /// Callers **must** pair every `register_snapshot` with a corresponding
    /// `release_snapshot` to avoid preventing GC indefinitely.
    ///
    /// NOTE: For new code, prefer using [`SnapshotRegistry`] + [`SnapshotHandle`]
    /// which provide thread-safe RAII lifecycle management decoupled from the
    /// version store lock.  These inline methods are retained for backward
    /// compatibility and for use in single-threaded / test contexts.
    active_snapshots: BTreeMap<CommitSeq, u64>,
    /// Device-references whose snapshot was force-aged-out by chain-pressure
    /// relief (`force_advance_oldest_snapshot`) while still held by a live
    /// inline reader. Each such forced advance consumes one ref that no real
    /// `release_snapshot` will provide via `active_snapshots`; recording it
    /// here lets the eventual reader Drop release succeed instead of tripping
    /// the unregistered-release invariant, while genuine double-frees (absent
    /// from both maps) still return `false`.
    force_advanced_releases: BTreeMap<CommitSeq, u64>,
    /// Recent committed transactions retained for SSI antidependency
    /// checking.  Pruned by `prune_ssi_log`.
    pub(crate) ssi_log: Vec<CommittedTxnRecord>,
    /// Version chain compression policy.
    compression_policy: CompressionPolicy,
    /// Epoch-based reclaimer for retired logical block versions.
    ebr_reclaimer: EbrVersionReclaimer,
    /// Optional append-only evidence sink for transaction decisions.
    evidence_sink: Option<MvccEvidenceSink>,
    /// Whether the most recent GC batch was throttled by budget pressure.
    gc_throttled: bool,
    /// Total number of aborted transactions since store creation.
    aborted_transactions: u64,
    /// Total number of SSI conflicts observed since store creation.
    ssi_conflicts: u64,
    /// Conflict resolution policy (Strict / SafeMerge / Adaptive).
    conflict_policy: ConflictPolicy,
    /// Configuration for the adaptive expected-loss decision model.
    adaptive_config: AdaptivePolicyConfig,
    /// Runtime contention metrics tracked via EMA.
    contention_metrics: ContentionMetrics,
    /// JSON-exportable runtime counters/histograms for observability.
    runtime_metrics: MvccRuntimeMetricsState,
}

impl Default for MvccStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MvccStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_txn: 1,
            next_commit: 1,
            versions: FxHashMap::default(),
            physical_versions: FxHashMap::default(),
            active_snapshots: BTreeMap::new(),
            force_advanced_releases: BTreeMap::new(),
            ssi_log: Vec::new(),
            compression_policy: CompressionPolicy::default(),
            ebr_reclaimer: EbrVersionReclaimer::default(),
            evidence_sink: None,
            gc_throttled: false,
            aborted_transactions: 0,
            ssi_conflicts: 0,
            conflict_policy: ConflictPolicy::default(),
            adaptive_config: AdaptivePolicyConfig::default(),
            contention_metrics: ContentionMetrics::default(),
            runtime_metrics: MvccRuntimeMetricsState::default(),
        }
    }

    /// Create a store with a custom compression policy.
    #[must_use]
    pub fn with_compression_policy(policy: CompressionPolicy) -> Self {
        Self {
            compression_policy: policy,
            ..Self::new()
        }
    }

    /// Set the conflict resolution policy.
    pub fn set_conflict_policy(&mut self, policy: ConflictPolicy) {
        self.conflict_policy = policy;
    }

    /// Set the adaptive policy configuration.
    pub fn set_adaptive_config(&mut self, config: AdaptivePolicyConfig) {
        self.adaptive_config = config;
    }

    /// Returns the current conflict policy.
    #[must_use]
    pub fn conflict_policy(&self) -> ConflictPolicy {
        self.conflict_policy
    }

    /// Returns the current contention metrics.
    #[must_use]
    pub fn contention_metrics(&self) -> &ContentionMetrics {
        &self.contention_metrics
    }

    /// Returns the adaptive policy configuration.
    #[must_use]
    pub fn adaptive_config(&self) -> &AdaptivePolicyConfig {
        &self.adaptive_config
    }

    /// The effective policy for the next commit: resolves `Adaptive` to a
    /// concrete `Strict` or `SafeMerge` based on current contention metrics.
    #[must_use]
    pub fn effective_policy(&self) -> ConflictPolicy {
        match self.conflict_policy {
            ConflictPolicy::Adaptive => {
                self.contention_metrics.select_policy(&self.adaptive_config)
            }
            other => other,
        }
    }

    /// Enable append-only evidence recording to a JSONL ledger path.
    ///
    /// Evidence events are best-effort: MVCC commit/abort semantics are never
    /// blocked by ledger I/O errors.
    ///
    /// # Errors
    ///
    /// Returns an error if the ledger file cannot be opened for append.
    pub fn enable_evidence_ledger(&mut self, path: impl AsRef<Path>) -> FfsResult<()> {
        self.evidence_sink = Some(MvccEvidenceSink::open(path.as_ref())?);
        Ok(())
    }

    /// Disable evidence recording.
    pub fn disable_evidence_ledger(&mut self) {
        self.evidence_sink = None;
    }

    /// Returns the current compression policy.
    #[must_use]
    pub fn compression_policy(&self) -> &CompressionPolicy {
        &self.compression_policy
    }

    /// Compute compression statistics across all version chains.
    #[must_use]
    pub fn compression_stats(&self) -> CompressionStats {
        let mut stats = CompressionStats::default();
        for versions in self.versions.values() {
            for (idx, version) in versions.iter().enumerate() {
                match &version.data {
                    VersionData::Full(bytes) => {
                        stats.full_versions += 1;
                        stats.bytes_stored += bytes.len();
                    }
                    VersionData::Zstd(bytes) | VersionData::Brotli(bytes) => {
                        stats.full_versions += 1;
                        stats.bytes_stored += bytes.len();
                    }
                    VersionData::Identical => {
                        stats.identical_versions += 1;
                        // Estimate bytes saved: use the resolved data size
                        if let Some(bytes) =
                            compression::resolve_data_with(versions, idx, |v| &v.data)
                        {
                            stats.bytes_saved += bytes.len();
                        }
                    }
                }
            }
        }
        stats
    }

    /// Epoch-based retirement/reclamation counters for logical block versions.
    #[must_use]
    pub fn ebr_stats(&self) -> EbrVersionStats {
        self.ebr_reclaimer.stats()
    }

    /// Best-effort collection pass for deferred version reclamation.
    pub fn ebr_collect(&self) {
        self.ebr_reclaimer.collect();
    }

    /// Run one budget-aware MVCC GC batch.
    ///
    /// Returns `Some(watermark)` when pruning/collection ran, or `None` when
    /// the batch was skipped due to tight budget.
    pub fn run_gc_batch(&mut self, cx: &Cx, config: GcBackpressureConfig) -> Option<CommitSeq> {
        let budget = cx.budget();
        let budget_remaining = budget.poll_quota;
        let budget_throttled = budget.is_exhausted() || budget_remaining <= config.min_poll_quota;
        if budget_throttled {
            debug!(
                target: "ffs::mvcc::gc",
                daemon_name = "mvcc_gc",
                budget_remaining,
                yield_duration_ms = config.throttle_sleep.as_millis(),
                "daemon_throttled"
            );
            self.gc_throttled = true;
            sleep_for_gc_throttle(cx, config.throttle_sleep);
            return None;
        }

        if self.gc_throttled {
            debug!(
                target: "ffs::mvcc::gc",
                daemon_name = "mvcc_gc",
                new_budget = budget_remaining,
                "daemon_resumed"
            );
            self.gc_throttled = false;
        }

        let watermark = self.prune_safe();
        let collected = self
            .ebr_reclaimer
            .collect_with_budget(cx, config.min_poll_quota);
        if !collected && self.ebr_reclaimer.stats().pending_versions() > 0 {
            debug!(
                target: "ffs::mvcc::gc",
                daemon_name = "mvcc_gc",
                budget_remaining = cx.budget().poll_quota,
                yield_duration_ms = config.throttle_sleep.as_millis(),
                "daemon_throttled"
            );
            self.gc_throttled = true;
            sleep_for_gc_throttle(cx, config.throttle_sleep);
        }
        Some(watermark)
    }

    /// Chain-length monitoring snapshot for logical block versions.
    #[must_use]
    pub fn block_version_stats(&self) -> BlockVersionStats {
        let tracked_blocks = self.versions.len();
        let max_chain_length = self.versions.values().map(Vec::len).max().unwrap_or(0);
        let chain_cap = self.compression_policy.max_chain_length;
        let critical_chain_length = chain_cap.map(Self::critical_chain_len);

        let mut chains_over_cap = 0_usize;
        let mut chains_over_critical = 0_usize;
        if let Some(cap) = chain_cap {
            let critical = Self::critical_chain_len(cap);
            for chain in self.versions.values() {
                chains_over_cap += usize::from(chain.len() > cap);
                chains_over_critical += usize::from(chain.len() >= critical);
            }
        }

        BlockVersionStats {
            tracked_blocks,
            max_chain_length,
            chains_over_cap,
            chains_over_critical,
            chain_cap,
            critical_chain_length,
        }
    }

    /// Monotonic transaction outcome counters since store creation.
    #[must_use]
    pub fn transaction_outcome_stats(&self) -> TransactionOutcomeStats {
        TransactionOutcomeStats {
            aborted_transactions: self.aborted_transactions,
            ssi_conflicts: self.ssi_conflicts,
        }
    }

    /// JSON-friendly runtime metrics export for MVCC health/performance.
    #[must_use]
    pub fn runtime_metrics(&self) -> MvccRuntimeMetricsSnapshot {
        self.runtime_metrics.snapshot(
            self.active_snapshot_count(),
            self.block_version_stats().max_chain_length,
        )
    }

    fn critical_chain_len(max_len: usize) -> usize {
        let cap = max_len.max(1);
        cap.saturating_mul(4).max(cap.saturating_add(1))
    }

    #[must_use]
    pub fn current_snapshot(&self) -> Snapshot {
        let high = self.next_commit.saturating_sub(1);
        Snapshot {
            high: CommitSeq(high),
        }
    }

    pub fn begin(&mut self) -> Transaction {
        let txn = Transaction {
            id: TxnId(self.next_txn),
            snapshot: self.current_snapshot(),
            staged_writes: StagedWrites::new(),
            reads: BTreeMap::new(),
            cow_writes: BTreeMap::new(),
            cow_orphans: BTreeSet::new(),
        };
        self.next_txn = self.next_txn.saturating_add(1);
        txn
    }

    /// Explicitly abort a transaction and emit an evidence entry.
    ///
    /// Aborting is a metadata operation: no versions are installed and staged
    /// writes are dropped when `txn` goes out of scope.
    pub fn abort(&mut self, txn: Transaction, reason: TxnAbortReason, detail: Option<String>) {
        let txn_id = txn.id().0;
        let read_set_size = txn.read_set().len();
        let write_set_size = txn.pending_writes();
        drop(txn);
        self.emit_txn_aborted(TxnAbortedDetail {
            txn_id,
            reason,
            detail,
            read_set_size,
            write_set_size,
        });
    }

    /// Explicitly abort a transaction and free any physical blocks allocated for it.
    pub fn abort_with_cow_allocator(
        &mut self,
        txn: Transaction,
        reason: TxnAbortReason,
        detail: Option<String>,
        allocator: &dyn CowAllocator,
        cx: &Cx,
    ) {
        for intent in txn.cow_writes.values() {
            allocator.defer_free(intent.new_physical, CommitSeq(0));
        }
        for orphan in &txn.cow_orphans {
            allocator.defer_free(*orphan, CommitSeq(0));
        }
        let _ = self.gc_cow_blocks(allocator, cx);
        self.abort(txn, reason, detail);
    }

    pub fn commit(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        let started = Instant::now();
        let txn_id = txn.id().0;
        let read_set_size = txn.read_set().len();
        let write_set_size = txn.pending_writes();
        self.runtime_metrics.record_commit_attempt();
        match self.commit_fcw_internal(txn) {
            Ok((commit_seq, _)) => {
                self.emit_transaction_commit(txn_id, commit_seq, write_set_size, started);
                Ok(commit_seq)
            }
            Err((error, _txn)) => {
                self.record_commit_abort(txn_id, read_set_size, write_set_size, &error);
                Err(error)
            }
        }
    }

    pub fn commit_with_cow_allocator(
        &mut self,
        txn: Transaction,
        allocator: &dyn CowAllocator,
        cx: &Cx,
    ) -> Result<CommitSeq, CommitError> {
        let started = Instant::now();
        let txn_id = txn.id().0;
        let read_set_size = txn.read_set().len();
        let write_set_size = txn.pending_writes();
        self.runtime_metrics.record_commit_attempt();
        match self.commit_fcw_internal(txn) {
            Ok((commit_seq, deferred)) => {
                for block in deferred {
                    trace!(block = block.0, commit_seq = commit_seq.0, "cow_defer_free");
                    allocator.defer_free(block, commit_seq);
                }
                let _ = self.gc_cow_blocks(allocator, cx);
                self.emit_transaction_commit(txn_id, commit_seq, write_set_size, started);
                Ok(commit_seq)
            }
            Err((error, txn)) => {
                for intent in txn.cow_writes.values() {
                    allocator.defer_free(intent.new_physical, CommitSeq(0));
                }
                for orphan in txn.cow_orphans {
                    allocator.defer_free(orphan, CommitSeq(0));
                }
                let _ = self.gc_cow_blocks(allocator, cx);
                self.record_commit_abort(txn_id, read_set_size, write_set_size, &error);
                Err(error)
            }
        }
    }

    /// Validate FCW + chain-pressure constraints without making versions visible.
    ///
    /// Callers should hold the same `MvccStore` write lock between this preflight
    /// and a subsequent [`Self::commit_fcw_prechecked`] call.
    pub fn preflight_commit_fcw(&mut self, txn: &Transaction) -> Result<(), CommitError> {
        self.preflight_fcw(txn)
    }

    /// Commit a transaction that has already passed FCW preflight checks.
    ///
    /// This avoids a second conflict check when an external durability phase
    /// (for example, journal I/O) must run between validation and visibility.
    ///
    /// # Errors
    ///
    /// Returns `CommitError` if the commit sequence is exhausted or if the
    /// prechecked commit fails while installing versions.
    pub fn commit_fcw_prechecked(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        let started = Instant::now();
        let txn_id = txn.id().0;
        let read_set_size = txn.read_set().len();
        let write_set_size = txn.pending_writes();
        self.runtime_metrics.record_commit_attempt();
        match self.apply_fcw_commit(txn) {
            Ok((commit_seq, deferred)) => {
                debug_assert!(
                    deferred.is_empty(),
                    "commit_fcw_prechecked silently drops deferred COW frees"
                );
                self.emit_transaction_commit(txn_id, commit_seq, write_set_size, started);
                Ok(commit_seq)
            }
            Err((error, _txn)) => {
                self.record_commit_abort(txn_id, read_set_size, write_set_size, &error);
                Err(error)
            }
        }
    }

    pub fn resolved_writes_for_commit(
        &self,
        txn: &Transaction,
    ) -> Result<Vec<(BlockNumber, Vec<u8>)>, CommitError> {
        txn.write_set()
            .keys()
            .copied()
            .map(|block| {
                self.resolved_write_bytes(txn, block)
                    .map(|bytes| (block, bytes))
            })
            .collect()
    }

    /// Commit with Serializable Snapshot Isolation (SSI) enforcement.
    ///
    /// This extends FCW with rw-antidependency tracking. A transaction aborts
    /// only when it is the pivot of a two-edge dangerous structure:
    ///
    /// 1. A concurrent transaction read a block this transaction writes.
    /// 2. This transaction read a block that a concurrent transaction wrote
    ///    after this transaction's snapshot.
    ///
    /// A single rw-antidependency edge remains serializable by itself and does
    /// not trigger an SSI abort. Read-only transactions never trigger SSI
    /// aborts.
    pub fn commit_ssi(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        let started = Instant::now();
        let txn_id = txn.id().0;
        let read_set_size = txn.read_set().len();
        let write_set_size = txn.pending_writes();
        self.runtime_metrics.record_commit_attempt();
        match self.commit_ssi_internal(txn) {
            Ok((commit_seq, deferred)) => {
                debug_assert!(
                    deferred.is_empty(),
                    "commit_ssi silently drops deferred COW frees"
                );
                self.emit_transaction_commit(txn_id, commit_seq, write_set_size, started);
                Ok(commit_seq)
            }
            Err((error, _txn)) => {
                self.record_commit_abort(txn_id, read_set_size, write_set_size, &error);
                Err(error)
            }
        }
    }

    pub fn commit_ssi_with_cow_allocator(
        &mut self,
        txn: Transaction,
        allocator: &dyn CowAllocator,
        cx: &Cx,
    ) -> Result<CommitSeq, CommitError> {
        let started = Instant::now();
        let txn_id = txn.id().0;
        let read_set_size = txn.read_set().len();
        let write_set_size = txn.pending_writes();
        self.runtime_metrics.record_commit_attempt();
        match self.commit_ssi_internal(txn) {
            Ok((commit_seq, deferred)) => {
                for block in deferred {
                    trace!(block = block.0, commit_seq = commit_seq.0, "cow_defer_free");
                    allocator.defer_free(block, commit_seq);
                }
                let _ = self.gc_cow_blocks(allocator, cx);
                self.emit_transaction_commit(txn_id, commit_seq, write_set_size, started);
                Ok(commit_seq)
            }
            Err((error, txn)) => {
                for intent in txn.cow_writes.values() {
                    allocator.defer_free(intent.new_physical, CommitSeq(0));
                }
                for orphan in txn.cow_orphans {
                    allocator.defer_free(orphan, CommitSeq(0));
                }
                let _ = self.gc_cow_blocks(allocator, cx);
                self.record_commit_abort(txn_id, read_set_size, write_set_size, &error);
                Err(error)
            }
        }
    }

    fn record_commit_abort(
        &mut self,
        txn_id: u64,
        read_set_size: usize,
        write_set_size: usize,
        error: &CommitError,
    ) {
        self.runtime_metrics.record_commit_abort(error);
        match error {
            CommitError::Conflict { .. } => self.emit_txn_aborted(TxnAbortedDetail {
                txn_id,
                reason: TxnAbortReason::FcwConflict,
                detail: Some(error.to_string()),
                read_set_size,
                write_set_size,
            }),
            CommitError::SsiConflict { concurrent_txn, .. } => {
                self.emit_txn_aborted(TxnAbortedDetail {
                    txn_id,
                    reason: TxnAbortReason::SsiCycle,
                    detail: Some(error.to_string()),
                    read_set_size,
                    write_set_size,
                });
                self.emit_serialization_conflict(
                    txn_id,
                    Some(concurrent_txn.0),
                    "two_edge_rw_antidependency_cycle",
                );
            }
            CommitError::ChainBackpressure { .. } => self.emit_txn_aborted(TxnAbortedDetail {
                txn_id,
                reason: TxnAbortReason::Timeout,
                detail: Some(error.to_string()),
                read_set_size,
                write_set_size,
            }),
            CommitError::DurabilityFailure { .. } => self.emit_txn_aborted(TxnAbortedDetail {
                txn_id,
                reason: TxnAbortReason::DurabilityFailure,
                detail: Some(error.to_string()),
                read_set_size,
                write_set_size,
            }),
        }
    }

    fn emit_transaction_commit(
        &mut self,
        txn_id: u64,
        commit_seq: CommitSeq,
        write_set_size: usize,
        started: Instant,
    ) {
        let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.runtime_metrics.record_commit_success(duration_us);
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::transaction_commit(TransactionCommitDetail {
                txn_id,
                commit_seq: commit_seq.0,
                write_set_size,
                duration_us,
            }),
            txn_id,
        );
    }

    fn emit_txn_aborted(&mut self, detail: TxnAbortedDetail) {
        self.aborted_transactions = self.aborted_transactions.saturating_add(1);
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        let txn_id = detail.txn_id;
        sink.append(&EvidenceRecord::txn_aborted(detail), txn_id);
    }

    fn emit_serialization_conflict(
        &mut self,
        txn_id: u64,
        conflicting_txn: Option<u64>,
        conflict_type: &str,
    ) {
        self.ssi_conflicts = self.ssi_conflicts.saturating_add(1);
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::serialization_conflict(SerializationConflictDetail {
                txn_id,
                conflicting_txn,
                conflict_type: conflict_type.to_owned(),
            }),
            txn_id,
        );
    }

    // ── Merge evidence emission helpers ────────────────────────────────────

    fn emit_merge_proof_checked(
        &self,
        txn_id: u64,
        block_id: u64,
        proof_variant: &str,
        valid: bool,
        rejection_reason: Option<&str>,
    ) {
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::merge_proof_checked(MergeProofCheckedDetail {
                txn_id,
                block_id,
                proof_variant: proof_variant.to_owned(),
                valid,
                rejection_reason: rejection_reason.map(str::to_owned),
            }),
            txn_id,
        );
    }

    fn emit_merge_applied(
        &self,
        txn_id: u64,
        merged_block_count: usize,
        combined_write_set_bytes: usize,
        proof_variant: &str,
    ) {
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::merge_applied(MergeAppliedDetail {
                txn_id,
                merged_block_count,
                combined_write_set_bytes,
                proof_variant: proof_variant.to_owned(),
            }),
            txn_id,
        );
    }

    fn emit_merge_rejected(&self, txn_id: u64, block_id: u64, proof_variant: &str, reason: &str) {
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::merge_rejected(MergeRejectedDetail {
                txn_id,
                block_id,
                proof_variant: proof_variant.to_owned(),
                reason: reason.to_owned(),
            }),
            txn_id,
        );
    }

    fn maybe_emit_policy_switch(&self, prev_effective: ConflictPolicy) {
        let new_effective = self.effective_policy();
        if prev_effective == new_effective {
            return;
        }
        let loss_strict = self
            .contention_metrics
            .expected_loss_strict(&self.adaptive_config);
        let loss_merge = self
            .contention_metrics
            .expected_loss_safe_merge(&self.adaptive_config);
        // Positive delta = the new policy is cheaper than the old one.
        let loss_old = match prev_effective {
            ConflictPolicy::Strict => loss_strict,
            _ => loss_merge,
        };
        let loss_new = match new_effective {
            ConflictPolicy::Strict => loss_strict,
            _ => loss_merge,
        };
        let delta = loss_old - loss_new;

        info!(
            target: "ffs::mvcc::merge",
            event = "mvcc_policy_switched",
            from_policy = ?prev_effective,
            to_policy = ?new_effective,
            expected_loss_delta = delta,
            trigger = "contention_rate_change",
        );
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::policy_switched(PolicySwitchedDetail {
                from_policy: format!("{prev_effective:?}"),
                to_policy: format!("{new_effective:?}"),
                expected_loss_delta: delta,
                trigger_reason: "contention_rate_change".to_owned(),
            }),
            0,
        );
    }

    fn emit_contention_sample(&self) {
        let m = &self.contention_metrics;
        let effective = self.effective_policy();
        info!(
            target: "ffs::mvcc::merge",
            event = "mvcc_contention_sample",
            conflict_rate = m.conflict_rate,
            merge_success_rate = m.merge_success_rate,
            abort_rate = m.abort_rate,
            total_commits = m.total_commits,
            total_conflicts = m.total_conflicts,
            total_merges = m.total_merges,
            total_aborts = m.total_aborts,
            effective_policy = ?effective,
        );
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::contention_sample(ContentionSampleDetail {
                conflict_rate: m.conflict_rate,
                merge_success_rate: m.merge_success_rate,
                abort_rate: m.abort_rate,
                total_commits: m.total_commits,
                total_conflicts: m.total_conflicts,
                total_merges: m.total_merges,
                total_aborts: m.total_aborts,
                effective_policy: format!("{effective:?}"),
            }),
            0,
        );
    }

    #[allow(clippy::result_large_err)]
    fn commit_fcw_internal(
        &mut self,
        txn: Transaction,
    ) -> Result<(CommitSeq, Vec<BlockNumber>), (CommitError, Transaction)> {
        if let Err(error) = self.preflight_fcw(&txn) {
            return Err((error, txn));
        }
        self.apply_fcw_commit(txn)
    }

    fn version_bytes_at(
        &self,
        block: BlockNumber,
        visible_high: CommitSeq,
    ) -> Option<std::borrow::Cow<'_, [u8]>> {
        // Conflict-merge only reads these bytes (`merge_bytes(&base, &latest, ..)`),
        // so return a borrow for the common uncompressed `Full` version instead of
        // cloning it into a fresh Vec; compressed versions still own their
        // decompressed bytes. Byte-identical; `&Cow` deref-coerces to `&[u8]`.
        self.versions.get(&block).and_then(|versions| {
            let idx = newest_visible_index(versions, visible_high)?;
            compression::resolve_data_with(versions, idx, |v| &v.data)
        })
    }

    fn resolved_write_bytes(
        &self,
        txn: &Transaction,
        block: BlockNumber,
    ) -> Result<Vec<u8>, CommitError> {
        self.resolved_write_bytes_with_policy(txn, block, self.effective_policy())
    }

    fn resolved_write_bytes_with_policy(
        &self,
        txn: &Transaction,
        block: BlockNumber,
        effective: ConflictPolicy,
    ) -> Result<Vec<u8>, CommitError> {
        let staged = txn
            .staged_write(block)
            .ok_or_else(|| CommitError::DurabilityFailure {
                detail: format!("write_set keys must have staged bytes: {block:?}"),
            })?;
        let observed = self.latest_commit_seq(block);
        if observed <= txn.snapshot.high {
            return Ok(staged.to_vec());
        }
        if effective == ConflictPolicy::Strict {
            return Err(CommitError::Conflict {
                block,
                snapshot: txn.snapshot.high,
                observed,
            });
        }

        let proof = txn.merge_proof(block).cloned().unwrap_or_default();
        let base = self
            .version_bytes_at(block, txn.snapshot.high)
            .or_else(|| txn.staged_base(block).map(std::borrow::Cow::Borrowed))
            .unwrap_or_default();
        let latest = self.version_bytes_at(block, observed).unwrap_or_default();
        proof
            .merge_bytes(&base, &latest, staged)
            .ok_or(CommitError::Conflict {
                block,
                snapshot: txn.snapshot.high,
                observed,
            })
    }

    /// Preflight validity check mirroring [`Self::resolved_write_bytes_with_policy`]
    /// but returning only a yes/no answer, WITHOUT building the merged block.
    /// The FCW preflight discards the merged bytes (it merely gates the commit);
    /// the install path (`resolved_write_bytes`) rebuilds them. Skipping the
    /// merged-output allocation here removes one block-sized alloc + copy per
    /// conflicting block on the contended commit path. Equivalent to
    /// `resolved_write_bytes_with_policy(..).is_ok()` by construction
    /// (`merge_valid == merge_bytes(..).is_some()`).
    fn resolved_write_valid_with_policy(
        &self,
        txn: &Transaction,
        block: BlockNumber,
        effective: ConflictPolicy,
    ) -> Result<(), CommitError> {
        let staged = txn
            .staged_write(block)
            .ok_or_else(|| CommitError::DurabilityFailure {
                detail: format!("write_set keys must have staged bytes: {block:?}"),
            })?;
        let observed = self.latest_commit_seq(block);
        if observed <= txn.snapshot.high {
            return Ok(());
        }
        if effective == ConflictPolicy::Strict {
            return Err(CommitError::Conflict {
                block,
                snapshot: txn.snapshot.high,
                observed,
            });
        }

        let proof = txn.merge_proof(block).cloned().unwrap_or_default();
        let base = self
            .version_bytes_at(block, txn.snapshot.high)
            .or_else(|| txn.staged_base(block).map(std::borrow::Cow::Borrowed))
            .unwrap_or_default();
        let latest = self.version_bytes_at(block, observed).unwrap_or_default();
        if proof.merge_valid(&base, &latest, staged) {
            Ok(())
        } else {
            Err(CommitError::Conflict {
                block,
                snapshot: txn.snapshot.high,
                observed,
            })
        }
    }

    /// Extract the short variant name from a `MergeProof`'s debug representation.
    fn merge_proof_variant_name(proof: &MergeProof) -> String {
        merge_proof_variant_name(proof).to_owned()
    }

    /// Handle a single block-level conflict during FCW preflight.
    ///
    /// Returns `Ok((variant, bytes_len))` if the conflict was resolved via
    /// merge, `Err` if the commit should be aborted.
    fn preflight_resolve_block_conflict(
        &self,
        txn: &Transaction,
        block: BlockNumber,
        latest: CommitSeq,
        effective: ConflictPolicy,
    ) -> Result<(String, usize), CommitError> {
        let proof = txn.merge_proof(block).cloned().unwrap_or_default();
        let variant = Self::merge_proof_variant_name(&proof);

        if effective == ConflictPolicy::Strict {
            self.emit_merge_check_and_reject(
                txn.id.0,
                block.0,
                &variant,
                "strict_policy_rejects_all_merges",
                "strict_fcw_conflict",
            );
            return Err(CommitError::Conflict {
                block,
                snapshot: txn.snapshot.high,
                observed: latest,
            });
        }

        if self
            .resolved_write_valid_with_policy(txn, block, effective)
            .is_ok()
        {
            let bytes_len = txn.staged_write(block).map_or(0, <[u8]>::len);
            info!(
                target: "ffs::mvcc::merge",
                event = "mvcc_merge_proof_checked",
                txn_id = txn.id.0, block = block.0,
                proof_variant = %variant, valid = true,
            );
            self.emit_merge_proof_checked(txn.id.0, block.0, &variant, true, None);
            Ok((variant, bytes_len))
        } else {
            self.emit_merge_check_and_reject(
                txn.id.0,
                block.0,
                &variant,
                "merge_bytes_returned_none",
                "merge_validation_failed",
            );
            Err(CommitError::Conflict {
                block,
                snapshot: txn.snapshot.high,
                observed: latest,
            })
        }
    }

    /// Emit both a merge-proof-checked (invalid) and merge-rejected event.
    fn emit_merge_check_and_reject(
        &self,
        txn_id: u64,
        block_id: u64,
        variant: &str,
        check_reason: &str,
        reject_reason: &str,
    ) {
        info!(
            target: "ffs::mvcc::merge",
            event = "mvcc_merge_proof_checked",
            txn_id, block = block_id,
            proof_variant = %variant, valid = false,
            reason = %check_reason,
        );
        self.emit_merge_proof_checked(txn_id, block_id, variant, false, Some(check_reason));
        info!(
            target: "ffs::mvcc::merge",
            event = "mvcc_merge_rejected",
            txn_id, block = block_id,
            proof_variant = %variant,
            reason = %reject_reason,
        );
        self.emit_merge_rejected(txn_id, block_id, variant, reject_reason);
    }

    fn preflight_fcw(&mut self, txn: &Transaction) -> Result<(), CommitError> {
        validate_transaction_id(txn.id())?;

        let chain_cap = self.compression_policy.max_chain_length;
        let prev_effective = self.effective_policy();
        // Only Adaptive consumes the contention metrics (`effective_policy` reads
        // them to select a strategy; no production caller reads them otherwise).
        // Under a fixed policy (default SafeMerge) the per-commit `record_commit` +
        // `select_policy` (2-3x/commit under Adaptive) + policy-switch/sample
        // emissions are dead CPU — skip them. Sibling of the sharded-store gate
        // (73174f5b). Merge telemetry (`mvcc_merge_applied`) stays ungated since
        // merges also occur under SafeMerge.
        let record_metrics = matches!(self.conflict_policy, ConflictPolicy::Adaptive);
        let mut had_conflict = false;
        let mut merge_succeeded = false;
        let mut merged_block_count: usize = 0;
        let mut combined_write_bytes: usize = 0;
        let mut merge_variants: BTreeSet<String> = BTreeSet::new();

        for &block in txn.write_set().keys() {
            let latest = self.latest_commit_seq(block);
            if latest > txn.snapshot.high {
                had_conflict = true;
                let resolution_started = Instant::now();
                let resolution =
                    self.preflight_resolve_block_conflict(txn, block, latest, prev_effective);
                let resolution_latency_us =
                    u64::try_from(resolution_started.elapsed().as_micros()).unwrap_or(u64::MAX);
                self.runtime_metrics
                    .record_conflict_resolution_latency(resolution_latency_us);
                match resolution {
                    Ok((variant, bytes_len)) => {
                        merge_succeeded = true;
                        merged_block_count += 1;
                        combined_write_bytes += bytes_len;
                        merge_variants.insert(variant);
                    }
                    Err(err) => {
                        if record_metrics {
                            self.contention_metrics.record_commit(
                                self.adaptive_config.ema_alpha,
                                true,
                                false,
                                true,
                            );
                            self.contention_metrics.last_selected =
                                Some(self.contention_metrics.select_policy(&self.adaptive_config));
                            self.maybe_emit_policy_switch(prev_effective);
                        }
                        return Err(err);
                    }
                }
            }
            if let Some(cap) = chain_cap {
                if let Err(err) = self.enforce_chain_pressure(txn.id, block, cap) {
                    // Chain backpressure abort — still record the commit attempt.
                    if record_metrics {
                        self.contention_metrics.record_commit(
                            self.adaptive_config.ema_alpha,
                            had_conflict,
                            merge_succeeded,
                            true,
                        );
                        self.contention_metrics.last_selected =
                            Some(self.contention_metrics.select_policy(&self.adaptive_config));
                    }
                    return Err(err);
                }
            }
        }

        // Record successful preflight (no abort).
        if record_metrics {
            self.contention_metrics.record_commit(
                self.adaptive_config.ema_alpha,
                had_conflict,
                merge_succeeded,
                false,
            );
            // Update hysteresis state so the next select_policy call has a stable incumbent.
            self.contention_metrics.last_selected =
                Some(self.contention_metrics.select_policy(&self.adaptive_config));
        }

        // mvcc_merge_applied — emit after successful merge commit preflight.
        if merged_block_count > 0 {
            let variants_joined: String = merge_variants.into_iter().collect::<Vec<_>>().join("+");
            info!(
                target: "ffs::mvcc::merge",
                event = "mvcc_merge_applied",
                txn_id = txn.id.0,
                merged_block_count,
                combined_write_set_bytes = combined_write_bytes,
                proof_variant = %variants_joined,
            );
            self.emit_merge_applied(
                txn.id.0,
                merged_block_count,
                combined_write_bytes,
                &variants_joined,
            );
        }

        if record_metrics {
            self.maybe_emit_policy_switch(prev_effective);

            // Periodic contention sample (every 100 commits).
            if self.contention_metrics.total_commits % 100 == 0
                && self.contention_metrics.total_commits > 0
            {
                self.emit_contention_sample();
            }
        }

        Ok(())
    }

    fn next_commit_seq(&mut self) -> Result<CommitSeq, CommitError> {
        let current = self.next_commit;
        let Some(next) = current.checked_add(1) else {
            return Err(CommitError::DurabilityFailure {
                detail: format!("commit sequence exhausted at {current}"),
            });
        };
        self.next_commit = next;
        Ok(CommitSeq(current))
    }

    #[allow(clippy::result_large_err)]
    fn apply_fcw_commit(
        &mut self,
        txn: Transaction,
    ) -> Result<(CommitSeq, Vec<BlockNumber>), (CommitError, Transaction)> {
        if let Err(error) = validate_transaction_id(txn.id()) {
            return Err((error, txn));
        }

        // Resolve conflicts before moving staged writes out of the transaction.
        // The common no-conflict path stays borrow-only until the commit is
        // known to succeed, so aborts still return the original transaction
        // while successful commits can move owned staged bytes into storage.
        let snapshot_high = txn.snapshot.high;
        let effective = self.effective_policy();
        let mut merged_writes = BTreeMap::new();
        for (block, staged) in &txn.staged_writes {
            let block = *block;
            let observed = self.latest_commit_seq(block);
            if observed <= snapshot_high {
                continue;
            }
            if effective == ConflictPolicy::Strict {
                return Err((
                    CommitError::Conflict {
                        block,
                        snapshot: snapshot_high,
                        observed,
                    },
                    txn,
                ));
            }

            let base = self
                .version_bytes_at(block, snapshot_high)
                .unwrap_or_default();
            let latest = self.version_bytes_at(block, observed).unwrap_or_default();
            match staged
                .merge_proof
                .merge_bytes(&base, &latest, &staged.bytes)
            {
                Some(merged) => {
                    merged_writes.insert(block, merged);
                }
                None => {
                    return Err((
                        CommitError::Conflict {
                            block,
                            snapshot: snapshot_high,
                            observed,
                        },
                        txn,
                    ));
                }
            }
        }

        let commit_seq = match self.next_commit_seq() {
            Ok(seq) => seq,
            Err(error) => return Err((error, txn)),
        };
        let chain_cap = self.compression_policy.max_chain_length;
        let Transaction {
            id: txn_id,
            staged_writes,
            cow_writes,
            cow_orphans,
            ..
        } = txn;
        let dedup_enabled = self.compression_policy.dedup_identical;
        let store_full = matches!(self.compression_policy.algo, CompressionAlgo::None);

        for (block, staged) in staged_writes {
            let version_bytes = merged_writes.remove(&block).unwrap_or(staged.bytes);
            // Move the owned bytes straight into `Full` for the no-compression
            // store (the prior path re-`to_vec`d them in `compress_data`). Dedup
            // and non-`None` compression keep their existing output.
            let version_data =
                if dedup_enabled && self.is_identical_to_latest(block, &version_bytes) {
                    VersionData::Identical
                } else if store_full {
                    VersionData::full(version_bytes)
                } else {
                    self.compress_data(&version_bytes)
                };

            self.versions.entry(block).or_default().push(BlockVersion {
                block,
                commit_seq,
                writer: txn_id,
                data: version_data,
            });

            if let Some(intent) = cow_writes.get(&block) {
                self.physical_versions
                    .entry(block)
                    .or_default()
                    .push(PhysicalBlockVersion {
                        logical: block,
                        physical: intent.new_physical,
                        commit_seq,
                        writer: txn_id,
                    });
            }

            if let Some(cap) = chain_cap {
                self.enforce_chain_cap(block, cap);
                self.enforce_physical_chain_cap(block, cap);
            }
        }
        debug_assert!(merged_writes.is_empty());

        let deferred = Self::collect_cow_deferred_frees(&cow_writes, cow_orphans);
        Ok((commit_seq, deferred))
    }

    /// Whether `bytes` is byte-identical to the latest committed version of
    /// `block` — the dedup-`Identical` predicate, factored out of `maybe_dedup`
    /// so the commit apply path can test it without re-`to_vec`ing the data.
    fn is_identical_to_latest(&self, block: BlockNumber, bytes: &[u8]) -> bool {
        let Some(versions) = self.versions.get(&block) else {
            return false;
        };
        if versions.is_empty() {
            return false;
        }
        compression::resolve_data_with(versions, versions.len() - 1, |v| &v.data)
            .is_some_and(|existing| existing.as_ref() == bytes)
    }

    #[inline]
    fn merged_writes_after_preflight(
        &self,
        txn: &Transaction,
    ) -> Result<BTreeMap<BlockNumber, Vec<u8>>, CommitError> {
        let snapshot_high = txn.snapshot.high;
        let effective = self.effective_policy();
        let mut merged_writes = BTreeMap::new();
        for (block, staged) in &txn.staged_writes {
            let block = *block;
            let observed = self.latest_commit_seq(block);
            if observed <= snapshot_high {
                continue;
            }
            if effective == ConflictPolicy::Strict {
                return Err(CommitError::Conflict {
                    block,
                    snapshot: snapshot_high,
                    observed,
                });
            }

            let base = self
                .version_bytes_at(block, snapshot_high)
                .unwrap_or_default();
            let latest = self.version_bytes_at(block, observed).unwrap_or_default();
            let Some(merged) = staged
                .merge_proof
                .merge_bytes(&base, &latest, &staged.bytes)
            else {
                return Err(CommitError::Conflict {
                    block,
                    snapshot: snapshot_high,
                    observed,
                });
            };
            merged_writes.insert(block, merged);
        }
        Ok(merged_writes)
    }

    #[allow(clippy::result_large_err)]
    fn commit_ssi_internal(
        &mut self,
        txn: Transaction,
    ) -> Result<(CommitSeq, Vec<BlockNumber>), (CommitError, Transaction)> {
        if let Err(error) = self.preflight_fcw(&txn) {
            return Err((error, txn));
        }

        // Step 2: SSI two-edge rw-antidependency check.
        let checks_performed = match self.validate_ssi_read_set(&txn) {
            Ok(count) => count,
            Err(e) => return Err((e, txn)),
        };

        let mut merged_writes = match self.merged_writes_after_preflight(&txn) {
            Ok(writes) => writes,
            Err(error) => return Err((error, txn)),
        };

        let commit_seq = match self.next_commit_seq() {
            Ok(seq) => seq,
            Err(error) => return Err((error, txn)),
        };

        let Transaction {
            id: txn_id,
            snapshot,
            staged_writes,
            reads,
            cow_writes,
            cow_orphans,
        } = txn;
        let dedup_enabled = self.compression_policy.dedup_identical;
        let store_full = matches!(self.compression_policy.algo, CompressionAlgo::None);
        let write_keys: BTreeSet<BlockNumber> =
            staged_writes.iter().map(|(block, _)| *block).collect();

        for (block, staged) in staged_writes {
            let version_bytes = merged_writes.remove(&block).unwrap_or(staged.bytes);
            let version_data =
                if dedup_enabled && self.is_identical_to_latest(block, &version_bytes) {
                    trace!(
                        block = block.0,
                        bytes_saved = version_bytes.len(),
                        "version_dedup: identical to previous"
                    );
                    VersionData::Identical
                } else if store_full {
                    VersionData::full(version_bytes)
                } else {
                    self.compress_data(&version_bytes)
                };

            self.versions.entry(block).or_default().push(BlockVersion {
                block,
                commit_seq,
                writer: txn_id,
                data: version_data,
            });

            if let Some(intent) = cow_writes.get(&block) {
                self.physical_versions
                    .entry(block)
                    .or_default()
                    .push(PhysicalBlockVersion {
                        logical: block,
                        physical: intent.new_physical,
                        commit_seq,
                        writer: txn_id,
                    });
            }

            if let Some(cap) = self.compression_policy.max_chain_length {
                self.enforce_chain_cap(block, cap);
                self.enforce_physical_chain_cap(block, cap);
            }
        }
        debug_assert!(merged_writes.is_empty());

        let read_set_size = reads.len();
        let write_set_size = write_keys.len();
        self.ssi_log.push(CommittedTxnRecord {
            txn_id,
            commit_seq,
            snapshot,
            write_set: write_keys,
            read_set: reads,
        });

        info!(
            target: "ffs::ssi",
            txn_id = txn_id.0,
            read_set_size,
            write_set_size,
            checks_performed,
            commit_seq = commit_seq.0,
            "ssi_commit_validated"
        );

        let deferred = Self::collect_cow_deferred_frees(&cow_writes, cow_orphans);
        Ok((commit_seq, deferred))
    }

    /// Check if `new_bytes` are identical to the latest version for `block`.
    /// If so, return `VersionData::Identical` (dedup); otherwise `VersionData::Full` or compressed.
    pub(crate) fn maybe_dedup(&self, block: BlockNumber, new_bytes: &[u8]) -> VersionData {
        if let Some(versions) = self.versions.get(&block) {
            if !versions.is_empty() {
                // Resolve the latest version's data (might itself be Identical).
                if let Some(existing) =
                    compression::resolve_data_with(versions, versions.len() - 1, |v| &v.data)
                {
                    if existing.as_ref() == new_bytes {
                        trace!(
                            block = block.0,
                            chain_len = versions.len(),
                            bytes_saved = new_bytes.len(),
                            "version_dedup: identical to previous"
                        );
                        return VersionData::Identical;
                    }
                }
            }
        }
        self.compress_data(new_bytes)
    }

    pub(crate) fn compress_data(&self, new_bytes: &[u8]) -> VersionData {
        match self.compression_policy.algo {
            compression::CompressionAlgo::None => VersionData::full(new_bytes.to_vec()),
            compression::CompressionAlgo::Zstd { level } => {
                if let Ok(compressed) = zstd::encode_all(new_bytes, level)
                    && compressed.len() < new_bytes.len()
                {
                    return VersionData::Zstd(compressed);
                }
                VersionData::full(new_bytes.to_vec())
            }
            compression::CompressionAlgo::Brotli { level } => {
                let mut compressed = Vec::new();
                #[allow(clippy::cast_possible_wrap)]
                let params = brotli::enc::BrotliEncoderParams {
                    quality: level as i32,
                    ..Default::default()
                };
                let mut reader = new_bytes;
                if brotli::BrotliCompress(&mut reader, &mut compressed, &params).is_ok()
                    && compressed.len() < new_bytes.len()
                {
                    return VersionData::Brotli(compressed);
                }
                VersionData::full(new_bytes.to_vec())
            }
        }
    }

    /// Advance the internal transaction and commit counters so the next
    /// allocated IDs are at least `last_commit + 1` and `last_txn + 1`.
    ///
    /// Used during checkpoint / WAL replay to restore counter state.
    pub(crate) fn advance_counters(&mut self, last_commit: u64, last_txn: u64) {
        self.next_commit = self.next_commit.max(last_commit.saturating_add(1));
        self.next_txn = self.next_txn.max(last_txn.saturating_add(1));
    }

    /// Insert pre-built version chains for a block during checkpoint loading.
    pub(crate) fn insert_versions(&mut self, block: BlockNumber, versions: Vec<BlockVersion>) {
        self.versions.entry(block).or_default().extend(versions);
    }

    fn validate_ssi_read_set(&self, txn: &Transaction) -> Result<u64, CommitError> {
        let records = self
            .ssi_log
            .iter()
            .rev()
            .take_while(|record| record.commit_seq > txn.snapshot.high);
        let (checks_performed, dangerous_structure) = detect_ssi_dangerous_structure(txn, records);

        if let Some(dangerous_structure) = dangerous_structure {
            dangerous_structure.emit_logs(txn.id);
            return Err(dangerous_structure.to_commit_error());
        }

        trace!(
            target: "ffs::ssi",
            txn_id = txn.id.0,
            read_set_size = txn.reads.len(),
            write_set_size = txn.staged_writes.len(),
            checks_performed,
            "ssi_two_edge_check_clean"
        );
        Ok(checks_performed)
    }

    fn force_advance_oldest_snapshot(&mut self) -> Option<(CommitSeq, u64)> {
        let oldest = self.active_snapshots.keys().next().copied()?;
        let refs = self.active_snapshots.get_mut(&oldest)?;
        // This consumes one live device-reference without a real Drop: in both
        // branches `active_snapshots` ends up one short of the live inline
        // readers at `oldest`. Record the forced release so the eventual reader
        // Drop's `release_snapshot` succeeds (the invariant is "every register
        // is matched by a release OR a forced advance"), not so a genuine
        // double-free escapes detection.
        *self.force_advanced_releases.entry(oldest).or_insert(0) += 1;
        if *refs > 1 {
            *refs -= 1;
            return Some((oldest, *refs));
        }
        self.active_snapshots.remove(&oldest);
        Some((oldest, 0))
    }

    fn chain_trim_blocked_by_snapshot(&self, block: BlockNumber, watermark: CommitSeq) -> bool {
        self.versions
            .get(&block)
            .is_some_and(|versions| versions.len() > 1 && versions[1].commit_seq > watermark)
    }

    fn enforce_chain_pressure(
        &mut self,
        txn_id: TxnId,
        block: BlockNumber,
        max_len: usize,
    ) -> Result<(), CommitError> {
        let chain_len = self.versions.get(&block).map_or(0, Vec::len);
        if chain_len == 0 {
            return Ok(());
        }
        let max_len = max_len.max(1);
        let critical_len = Self::critical_chain_len(max_len);
        if chain_len < critical_len {
            return Ok(());
        }

        let watermark = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        if !self.chain_trim_blocked_by_snapshot(block, watermark) {
            return Ok(());
        }

        warn!(
            target: "ffs::mvcc::gc",
            block = block.0,
            chain_len,
            cap = max_len,
            critical_len,
            watermark = watermark.0,
            "chain_pressure_snapshot_blocking"
        );

        if let Some((forced_snapshot, remaining_refs)) = self.force_advance_oldest_snapshot() {
            let new_watermark = self
                .watermark()
                .unwrap_or_else(|| self.current_snapshot().high);
            info!(
                target: "ffs::mvcc::gc",
                block = block.0,
                forced_snapshot = forced_snapshot.0,
                remaining_refs,
                new_watermark = new_watermark.0,
                "chain_pressure_force_advance_oldest_snapshot"
            );
            // Same O(tracked_blocks) evidence-only scan as the release_snapshot
            // path — gate on a real `enabled!` check so it never runs when the
            // evidence target is disabled (a lazy field expr is insufficient
            // under the dynamic EnvFilter; see the note in `release_snapshot`).
            // Gated at DEBUG, not INFO: the default `info` filter must NOT pay
            // this per-commit O(tracked_blocks) scan (it was ~46% of delete CPU
            // under the default filter). Enable explicitly with
            // `RUST_LOG=ffs::mvcc::evidence=debug` for the diagnostic.
            if tracing::enabled!(target: "ffs::mvcc::evidence", tracing::Level::DEBUG) {
                debug!(
                    target: "ffs::mvcc::evidence",
                    event = "snapshot_advanced",
                    old_commit_seq = forced_snapshot.0,
                    new_commit_seq = new_watermark.0,
                    versions_eligible = self.versions_eligible_at_watermark(new_watermark),
                    trigger = "chain_pressure"
                );
            }
            if !self.chain_trim_blocked_by_snapshot(block, new_watermark) {
                return Ok(());
            }
        }

        error!(
            target: "ffs::mvcc::gc",
            block = block.0,
            chain_len,
            cap = max_len,
            critical_len,
            watermark = watermark.0,
            "chain_backpressure_reject"
        );
        warn!(
            target: "ffs::mvcc::evidence",
            event = "txn_aborted",
            txn_id = txn_id.0,
            reason = "timeout",
            block = block.0,
            chain_len,
            cap = max_len,
            watermark = watermark.0
        );
        Err(CommitError::ChainBackpressure {
            block,
            chain_len,
            cap: max_len,
            critical_len,
            watermark,
        })
    }

    /// Enforce chain length cap for a block by pruning the oldest versions.
    ///
    /// Pruning is watermark-aware: versions are only dropped when doing so
    /// cannot break visibility for any active snapshot.
    fn enforce_chain_cap(&mut self, block: BlockNumber, max_len: usize) {
        let max_len = max_len.max(1);
        let watermark = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        let retired = self
            .versions
            .get_mut(&block)
            .map_or_else(Vec::new, |versions| {
                let (trimmed, retired_versions) =
                    Self::trim_block_chain_to_cap(versions, max_len, watermark);
                if trimmed > 0 {
                    trace!(
                        block = block.0,
                        watermark = watermark.0,
                        trimmed,
                        remaining = versions.len(),
                        "chain_cap_enforced"
                    );
                } else if versions.len() > max_len {
                    debug!(
                        target: "ffs::mvcc::gc",
                        block = block.0,
                        watermark = watermark.0,
                        cap = max_len,
                        current_len = versions.len(),
                        "chain_cap_pending_snapshot_release"
                    );
                }
                retired_versions
            });
        if !retired.is_empty() {
            self.ebr_reclaimer.retire_versions(retired);
        }
    }

    /// Enforce chain cap for physical versions using the same watermark-safe
    /// rule as logical versions.
    fn enforce_physical_chain_cap(&mut self, block: BlockNumber, max_len: usize) {
        let max_len = max_len.max(1);
        let watermark = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        if let Some(versions) = self.physical_versions.get_mut(&block) {
            let trimmed = Self::trim_physical_chain_to_cap(versions, max_len, watermark);
            if trimmed > 0 {
                trace!(
                    block = block.0,
                    watermark = watermark.0,
                    trimmed,
                    remaining = versions.len(),
                    "physical_chain_cap_enforced"
                );
            }
        }
    }

    fn trim_block_chain_to_cap(
        versions: &mut Vec<BlockVersion>,
        max_len: usize,
        watermark: CommitSeq,
    ) -> (usize, Vec<BlockVersion>) {
        let mut trim = 0_usize;
        while versions.len().saturating_sub(trim) > max_len {
            let next = trim + 1;
            if next >= versions.len() || versions[next].commit_seq > watermark {
                break;
            }
            trim += 1;
        }
        let retired = if trim > 0 {
            Self::make_chain_head_full(versions, trim);
            versions.drain(0..trim).collect()
        } else {
            Vec::new()
        };
        (trim, retired)
    }

    fn trim_physical_chain_to_cap(
        versions: &mut Vec<PhysicalBlockVersion>,
        max_len: usize,
        watermark: CommitSeq,
    ) -> usize {
        let mut trim = 0_usize;
        while versions.len().saturating_sub(trim) > max_len {
            let next = trim + 1;
            if next >= versions.len() || versions[next].commit_seq > watermark {
                break;
            }
            trim += 1;
        }
        if trim > 0 {
            versions.drain(0..trim);
        }
        trim
    }

    fn make_chain_head_full(versions: &mut [BlockVersion], keep_from: usize) {
        if keep_from < versions.len() && versions[keep_from].data.is_identical() {
            if let Some(full_data) =
                compression::resolve_data_with(versions, keep_from, |v| &v.data)
            {
                let full_data = full_data.into_owned();
                versions[keep_from].data = VersionData::full(full_data);
            }
        }
    }

    fn versions_eligible_at_watermark(&self, watermark: CommitSeq) -> u64 {
        self.versions
            .values()
            .map(|versions| {
                if versions.len() <= 1 {
                    return 0_u64;
                }
                let mut trim = 0_usize;
                while trim + 1 < versions.len() && versions[trim + 1].commit_seq <= watermark {
                    trim += 1;
                }
                u64::try_from(trim).unwrap_or(u64::MAX)
            })
            .sum()
    }

    fn collect_cow_deferred_frees(
        cow_writes: &BTreeMap<BlockNumber, CowRewriteIntent>,
        mut cow_orphans: BTreeSet<BlockNumber>,
    ) -> Vec<BlockNumber> {
        for intent in cow_writes.values() {
            if let Some(old_physical) = intent.old_physical
                && old_physical != intent.new_physical
            {
                cow_orphans.insert(old_physical);
            }
        }
        cow_orphans.into_iter().collect()
    }

    /// Prune SSI log entries older than `watermark`.
    ///
    /// Once no active transaction has a snapshot older than `watermark`,
    /// those log entries can no longer participate in antidependency
    /// detection and can be safely removed.
    pub fn prune_ssi_log(&mut self, watermark: CommitSeq) {
        self.ssi_log.retain(|r| r.commit_seq > watermark);
    }

    #[must_use]
    pub fn latest_commit_seq(&self, block: BlockNumber) -> CommitSeq {
        self.versions
            .get(&block)
            .and_then(|v| v.last())
            .map_or(CommitSeq(0), |v| v.commit_seq)
    }

    #[must_use]
    pub fn read_visible(
        &self,
        block: BlockNumber,
        snapshot: Snapshot,
    ) -> Option<std::borrow::Cow<'_, [u8]>> {
        self.versions.get(&block).and_then(|versions| {
            let idx = newest_visible_index(versions, snapshot.high)?;
            compression::resolve_data_with(versions, idx, |v| &v.data)
        })
    }

    #[must_use]
    pub fn read_visible_block_buf(
        &self,
        block: BlockNumber,
        snapshot: Snapshot,
    ) -> Option<BlockBuf> {
        self.versions.get(&block).and_then(|versions| {
            let idx = newest_visible_index(versions, snapshot.high)?;
            compression::resolve_block_buf_with(versions, idx, |v| &v.data)
        })
    }

    #[must_use]
    pub fn read_visible_physical(
        &self,
        logical: BlockNumber,
        snapshot: Snapshot,
    ) -> Option<BlockNumber> {
        if let Some(versions) = self.physical_versions.get(&logical)
            && let Some(idx) =
                newest_visible_index_by(versions, snapshot.high, |version| version.commit_seq)
        {
            return Some(versions[idx].physical);
        }
        self.read_visible(logical, snapshot).map(|_| logical)
    }

    #[must_use]
    pub fn latest_physical_block(&self, logical: BlockNumber) -> Option<BlockNumber> {
        self.read_visible_physical(logical, self.current_snapshot())
    }

    pub fn write_cow(
        &self,
        logical: BlockNumber,
        data: &[u8],
        txn: &mut Transaction,
        allocator: &dyn CowAllocator,
        cx: &Cx,
    ) -> FfsResult<BlockNumber> {
        let committed_old = txn
            .cow_writes
            .get(&logical)
            .and_then(|intent| intent.old_physical)
            .or_else(|| self.read_visible_physical(logical, txn.snapshot));
        let allocation_hint = txn
            .cow_writes
            .get(&logical)
            .map(|intent| intent.new_physical)
            .or(committed_old);
        let new_physical = allocator.alloc_cow(allocation_hint, cx)?;
        trace!(
            txn_id = txn.id.0,
            logical = logical.0,
            old_physical = committed_old.map(|b| b.0),
            new_physical = new_physical.0,
            "cow_allocation"
        );
        txn.stage_cow_rewrite(logical, committed_old, new_physical, data.to_vec());
        Ok(new_physical)
    }

    pub fn gc_cow_blocks(&self, allocator: &dyn CowAllocator, cx: &Cx) -> usize {
        let watermark = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        let freed = allocator.gc_free(watermark, cx);
        debug!(watermark = watermark.0, freed_blocks = freed, "cow_gc");
        freed
    }

    /// Flush all committed block versions to the underlying device.
    ///
    /// For each block that has committed versions in the MVCC store, this
    /// writes the latest version visible at the current snapshot to the
    /// base device.  This materialises in-memory MVCC data to persistent
    /// storage, which is required for write durability (e.g. `fsync`,
    /// unmount).
    ///
    /// Returns the number of blocks flushed.
    pub fn flush_to_device<D: BlockDevice>(&self, cx: &Cx, device: &D) -> FfsResult<usize> {
        self.flush_to_device_after(cx, device, CommitSeq(0))
            .map(|(flushed, _)| flushed)
    }

    /// Flush versions committed after `flushed_through` and return the snapshot
    /// through which the device is durable.
    ///
    /// The caller must serialize calls and advance its watermark only after this
    /// method succeeds. Keeping that cursor at the filesystem/device boundary
    /// lets the public [`Self::flush_to_device`] retain its full-checkpoint
    /// semantics for callers that supply unrelated devices.
    pub fn flush_to_device_after<D: BlockDevice>(
        &self,
        cx: &Cx,
        device: &D,
        flushed_through: CommitSeq,
    ) -> FfsResult<(usize, CommitSeq)> {
        let snapshot = self.current_snapshot();
        if snapshot.high <= flushed_through {
            return Ok((0, snapshot.high));
        }
        let mut flushed = 0usize;

        // `versions` is an FxHashMap (bd-mvccmap: O(1) commit/read entry vs the
        // old BTreeMap's O(log N)), so collect + sort the blocks here to restore
        // ASCENDING order before coalescing — flush is once per sync, so this one
        // O(N log N) sort is amortized over many O(1) per-op commits. Then
        // coalesce maximal runs of contiguous blocks and write each run with a
        // single `write_contiguous_blocks` (one ranged device write) instead of
        // one `write_block` per block. Bytes/locations identical to the scalar
        // path (bd-ryqep), so the on-disk state is unchanged.
        let mut run_start: Option<BlockNumber> = None;
        let mut run_next: u64 = 0; // next block number that would continue the run
        let mut run_buf: Vec<u8> = Vec::new();

        let mut sorted_versions: Vec<(&BlockNumber, &Vec<BlockVersion>)> =
            self.versions.iter().collect();
        sorted_versions.sort_unstable_by_key(|(block, _)| **block);
        for (block, versions) in sorted_versions {
            // Binary-search the newest visible version instead of an O(n) reverse
            // linear scan; identical index for an ascending-ordered chain.
            let Some(idx) = newest_visible_index(versions, snapshot.high) else {
                continue;
            };
            if versions[idx].commit_seq <= flushed_through {
                continue;
            }
            let Some(data) = compression::resolve_data_with(versions, idx, |v| &v.data) else {
                continue;
            };

            let continues_run = run_start.is_some() && block.0 == run_next;
            if !continues_run {
                if let Some(start) = run_start.take() {
                    device.write_contiguous_blocks(cx, start, &run_buf)?;
                    run_buf.clear();
                }
                run_start = Some(*block);
            }
            run_buf.extend_from_slice(&data);
            run_next = block.0.saturating_add(1);
            flushed += 1;
        }
        if let Some(start) = run_start.take() {
            device.write_contiguous_blocks(cx, start, &run_buf)?;
        }

        if flushed > 0 {
            device.sync(cx)?;
            debug!(flushed_blocks = flushed, "mvcc_flush_to_device");
        }
        Ok((flushed, snapshot.high))
    }

    pub fn prune_versions_older_than(&mut self, watermark: CommitSeq) {
        let mut retired_versions = Vec::new();
        let active_snapshot_count = self.active_snapshot_count();
        for (block, versions) in &mut self.versions {
            if versions.len() <= 1 {
                continue;
            }

            let mut keep_from = 0_usize;
            while keep_from + 1 < versions.len() {
                if versions[keep_from + 1].commit_seq <= watermark {
                    keep_from += 1;
                } else {
                    break;
                }
            }

            if keep_from > 0 {
                Self::make_chain_head_full(versions, keep_from);
                retired_versions.extend(versions.drain(0..keep_from));
                let oldest_retained_commit_seq =
                    versions.first().map_or(watermark.0, |v| v.commit_seq.0);
                info!(
                    target: "ffs::mvcc::evidence",
                    event = "version_gc",
                    block_id = block.0,
                    versions_freed = u64::try_from(keep_from).unwrap_or(u64::MAX),
                    oldest_retained_commit_seq
                );
            } else if versions.len() > 1 {
                let next_commit_seq = versions[1].commit_seq;
                if next_commit_seq > watermark {
                    debug!(
                        target: "ffs::mvcc::gc",
                        event = "gc_skip_pinned_version",
                        block_id = block.0,
                        blocked_commit_seq = next_commit_seq.0,
                        epoch_id = watermark.0,
                        pinned_by = "active_snapshot_watermark",
                        active_snapshot_count
                    );
                }
            }
        }
        if !retired_versions.is_empty() {
            self.runtime_metrics
                .record_versions_pruned(retired_versions.len());
            self.ebr_reclaimer.retire_versions(retired_versions);
        }

        for versions in self.physical_versions.values_mut() {
            if versions.len() <= 1 {
                continue;
            }

            let mut keep_from = 0_usize;
            while keep_from + 1 < versions.len() {
                if versions[keep_from + 1].commit_seq <= watermark {
                    keep_from += 1;
                } else {
                    break;
                }
            }

            if keep_from > 0 {
                versions.drain(0..keep_from);
            }
        }
    }

    // ── Watermark / active snapshot tracking ───────────────────────────

    /// Register a snapshot as active.  This prevents `prune_safe` from
    /// removing versions that this snapshot might still need.
    ///
    /// Multiple registrations of the same `CommitSeq` are ref-counted;
    /// each must be paired with a corresponding `release_snapshot`.
    pub fn register_snapshot(&mut self, snapshot: Snapshot) {
        let count = self.active_snapshots.entry(snapshot.high).or_insert(0);
        *count = count.saturating_add(1);
        trace!(
            commit_seq = snapshot.high.0,
            ref_count_after = *count,
            "snapshot_acquire (inline)"
        );
    }

    /// Release a previously registered snapshot.  When the last reference
    /// at a given `CommitSeq` is released, that sequence is no longer
    /// considered active and versions below it become eligible for pruning.
    ///
    /// Returns `true` if the snapshot was still registered, `false` if it
    /// was already fully released (a logic error by the caller, but not
    /// fatal).
    pub fn release_snapshot(&mut self, snapshot: Snapshot) -> bool {
        let old_watermark = self.watermark();
        if let Some(count) = self.active_snapshots.get_mut(&snapshot.high) {
            *count = count.saturating_sub(1);
            let count_after = *count;
            if count_after == 0 {
                self.active_snapshots.remove(&snapshot.high);
                debug!(
                    commit_seq = snapshot.high.0,
                    "snapshot_final_release (inline): ref_count reached 0"
                );
            } else {
                trace!(
                    commit_seq = snapshot.high.0,
                    ref_count_after = count_after,
                    "snapshot_release (inline)"
                );
            }
            if let Some(old_commit_seq) = old_watermark.map(|wm| wm.0) {
                let new_watermark = self
                    .watermark()
                    .unwrap_or_else(|| self.current_snapshot().high);
                // `versions_eligible_at_watermark` is an O(tracked_blocks) scan
                // of every version chain, and it feeds ONLY this evidence log
                // field. It MUST be skipped when the evidence target is
                // disabled. A lazy `info!` field expression is NOT enough: the
                // `fmt`+`EnvFilter` subscriber registers the callsite as
                // `Interest::sometimes`, so tracing evaluates the field then
                // filters at runtime — the full scan still ran on EVERY write
                // commit (71% of write-path self-time; ~5x slower 4 KiB writes).
                // Gate on a real runtime `enabled!` check so the scan only runs
                // when a subscriber will actually record the event. Gated at
                // DEBUG, not INFO: the default `info` filter must NOT pay this
                // per-commit O(tracked_blocks) scan (it dominated write- and
                // delete-commit CPU under the default filter). Enable with
                // `RUST_LOG=ffs::mvcc::evidence=debug` for the diagnostic.
                if new_watermark.0 > old_commit_seq
                    && tracing::enabled!(target: "ffs::mvcc::evidence", tracing::Level::DEBUG)
                {
                    debug!(
                        target: "ffs::mvcc::evidence",
                        event = "snapshot_advanced",
                        old_commit_seq,
                        new_commit_seq = new_watermark.0,
                        versions_eligible = self.versions_eligible_at_watermark(new_watermark),
                        trigger = "release_snapshot"
                    );
                }
            }
            true
        } else if let Some(pending) = self.force_advanced_releases.get_mut(&snapshot.high) {
            // The snapshot was force-aged-out by chain-pressure relief while
            // this reader still held it; this Drop is the expected late
            // release, not a double-free.
            *pending -= 1;
            if *pending == 0 {
                self.force_advanced_releases.remove(&snapshot.high);
            }
            trace!(
                commit_seq = snapshot.high.0,
                "snapshot_release (inline): matched a prior chain-pressure force-advance"
            );
            true
        } else {
            error!(
                commit_seq = snapshot.high.0,
                "ref_count_underflow (inline): release called on unregistered snapshot"
            );
            false
        }
    }

    /// The oldest active snapshot, or `None` if no snapshots are
    /// registered.
    ///
    /// This is the **safe watermark**: pruning versions with
    /// `commit_seq < watermark` will not break any active reader.
    #[must_use]
    pub fn watermark(&self) -> Option<CommitSeq> {
        self.active_snapshots.keys().next().copied()
    }

    /// Number of currently active (registered) snapshots.
    #[must_use]
    pub fn active_snapshot_count(&self) -> usize {
        self.active_snapshots
            .values()
            .fold(0_usize, |total, count| {
                total.saturating_add(usize::try_from(*count).unwrap_or(usize::MAX))
            })
    }

    /// Prune versions that are no longer needed by any active snapshot.
    ///
    /// Equivalent to `prune_versions_older_than(watermark)` where
    /// `watermark` is the oldest active snapshot.  If no snapshots are
    /// registered, prunes up to the current commit sequence (i.e., keeps
    /// only the latest version per block).
    ///
    /// Returns the watermark that was used.
    pub fn prune_safe(&mut self) -> CommitSeq {
        let wm = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        // `version_count()` is an O(tracked_blocks) scan, and it runs TWICE here
        // (before + after) ONLY to compute `freed`/`remaining` for the debug
        // trace below. Same disabled-log O(N) antipattern as the per-commit scan
        // fixed in the write path (b1619f0b): gate both scans behind a real
        // `enabled!` check so they never run when the gc logs are off (a lazy
        // field expr is insufficient under the dynamic EnvFilter). Enabling
        // TRACE implies DEBUG, so the DEBUG check covers both branches. The
        // actual pruning (`prune_versions_older_than`) always runs.
        let log_counts = tracing::enabled!(tracing::Level::DEBUG);
        let old_count = if log_counts { self.version_count() } else { 0 };
        self.prune_versions_older_than(wm);
        if log_counts {
            let new_count = self.version_count();
            let freed = old_count.saturating_sub(new_count);
            if freed > 0 {
                debug!(
                    watermark = wm.0,
                    versions_freed = freed,
                    versions_remaining = new_count,
                    "watermark_advance: pruned old versions"
                );
            } else {
                trace!(
                    watermark = wm.0,
                    versions_count = new_count,
                    "gc_eligible: no versions to prune"
                );
            }
        }
        if !self.active_snapshots.is_empty() {
            trace!(
                active_snapshots = self.active_snapshot_count(),
                oldest_active = ?self.watermark(),
                "gc_blocked: active snapshots prevent full pruning"
            );
        }
        wm
    }

    /// Total number of block versions stored across all blocks.
    #[must_use]
    pub fn version_count(&self) -> usize {
        self.versions.values().map(Vec::len).sum()
    }

    /// Number of distinct blocks that have at least one version.
    #[must_use]
    pub fn block_count_versioned(&self) -> usize {
        self.versions.len()
    }
}
