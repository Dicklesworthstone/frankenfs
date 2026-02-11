# Write-Back Cache + Dirty Tracking Design

**Bead:** bd-hks
**Status:** Design
**Scope:** ffs-block `ArcCache` write-back, FlushDaemon, MVCC integration

## Current State

`ArcCache` is **write-through**: every `write_block()` immediately writes to
the underlying device, then updates the in-memory cache. No dirty tracking
exists. The single `Mutex<ArcState>` is never held during I/O.

```
write_block(block, data)
  -> inner.write_block(block, data)?     // disk I/O outside lock
  -> lock.update_resident(block, data)   // metadata under lock
```

## Design Goals

1. **Defer writes** to reduce I/O for bursty workloads.
2. **Preserve crash safety** via journal-before-data ordering.
3. **Integrate with MVCC** so committed versions are the dirty set.
4. **Keep the single-lock ArcState simple** by tracking dirtiness separately.

## Architecture

### Phase 1: DirtyTracker (standalone, no journal dependency)

Add a `DirtyTracker` to `ArcCache` that records which blocks have been
written but not yet flushed to the underlying device.

```rust
pub struct DirtyTracker {
    dirty: BTreeSet<BlockNumber>,
    max_dirty: usize,
}
```

**Write path changes:**
```
write_block(block, data)
  -> lock { update_resident(block, data); dirty.insert(block); }
  // NO immediate write to inner device
```

**Flush path:**
```
flush_dirty(cx)
  -> lock { snapshot dirty set, clear it }
  -> for each block in snapshot:
       inner.write_block(cx, block, data)?
```

**Eviction constraint:** A dirty block **must not be evicted** from the
ARC cache until it has been flushed. If eviction pressure exceeds capacity
and all eviction candidates are dirty, the cache triggers an inline flush
of the LRU dirty block before eviction.

### Phase 2: FlushDaemon (background, cooperative cancellation)

```rust
pub struct FlushConfig {
    /// Maximum dirty blocks before triggering a flush.
    pub dirty_threshold: usize,
    /// Maximum age of a dirty block before forced flush.
    pub max_dirty_age: Duration,
    /// Polling interval for the flush loop.
    pub poll_interval: Duration,
}
```

The daemon runs in an `asupersync::Region` scope (structured concurrency):
- Polls at `poll_interval`.
- Flushes when `dirty.len() >= dirty_threshold` or oldest dirty block
  exceeds `max_dirty_age`.
- Respects `Cx` cancellation (clean shutdown writes all remaining dirty
  blocks before returning).

### Phase 3: MVCC Integration

In native FrankenFS mode, the MVCC version store IS the journal:

```
write_block(block, data)
  -> MvccStore: stage_write(block, data)  // buffered in Transaction

commit(txn)
  -> MvccStore: append BlockVersion entries  // atomically committed

flush_committed(watermark)
  -> for each version with commit_seq > flush_watermark:
       write version.bytes to base device at version.block
  -> advance flush_watermark
```

**Key insight:** Dirty blocks = versions with `commit_seq > flush_watermark`.
No separate dirty set needed once MVCC integration is complete. The version
store provides both journaling (crash safety) and dirty tracking.

## Ordering Constraints

### Journal-Before-Data (ext4 compat mode)

For JBD2-journaled ext4 writes:
1. Write descriptor block to journal.
2. Write data blocks to journal.
3. Write commit block to journal.
4. Write data blocks to filesystem locations (flush).
5. Mark journal entry as complete.

### COW Journal (native mode)

For MVCC COW writes:
1. `commit()` atomically appends version entries.
2. Persist version chain metadata to durable storage.
3. Write block data to new on-disk locations (COW, never overwrite).
4. Advance flush watermark.
5. GC old versions below watermark.

**Invariant:** No data block is written to its final location until
its version entry (or journal entry) is durably stored.

## Failure Semantics

### fsync

`fsync(fd)` must flush all dirty blocks belonging to that file's inode:
- Collect dirty blocks referenced by the inode's extent tree.
- Write them to the device (or commit the MVCC transaction).
- Return only after durable storage confirms.

### Flush on close

`release(fd)` triggers a flush of that file's dirty blocks if the
kernel sends `FLUSH` flag. This is best-effort; actual durability
requires fsync.

### Cancellation (Cx)

If a flush is cancelled mid-way:
- Already-written blocks are fine (idempotent overwrites or COW).
- Remaining dirty blocks stay in the dirty set.
- The next flush attempt picks them up.
- No data loss because dirty blocks remain in cache until flushed.

### Power loss

- **With journal (Phase 3):** Journal replay recovers uncommitted blocks.
- **With MVCC COW (Phase 3):** Version store has the latest committed state;
  blocks not yet flushed to final locations are recovered from version chain.
- **Without journal (Phase 1):** Dirty unflushed blocks are lost. This phase
  is for development/testing only and is not crash-safe.

## Interaction with ARC Eviction

The ARC replacement algorithm (`replace()`) selects victims from T1 or T2.
With write-back, a victim that is dirty cannot simply be discarded:

1. **Preferred:** Flush the dirty victim before evicting.
2. **Alternative:** Skip the dirty victim and try the next candidate.
3. **Backpressure:** If all candidates are dirty, block the calling thread
   until the FlushDaemon creates headroom.

Option 1 is simplest. The inline flush adds latency to one cache miss but
maintains the ARC invariant that `resident.len() <= capacity`.

## Testing Strategy

1. **Unit:** DirtyTracker insert/flush/eviction-with-dirty.
2. **Integration:** ArcCache write-back mode end-to-end (write, verify not
   on device, flush, verify on device).
3. **Concurrency:** Lab runtime with interleaved writers + flush daemon.
4. **Crash:** Simulated power loss (drop cache without flushing); verify
   journal replay recovers committed data.

## Phasing Summary

| Phase | Scope | Crash-safe? | Journal dependency |
|-------|-------|------------|-------------------|
| 1 | DirtyTracker + inline flush | No | None |
| 2 | FlushDaemon (background) | No | None |
| 3 | MVCC integration + COW journal | Yes | ffs-journal |
