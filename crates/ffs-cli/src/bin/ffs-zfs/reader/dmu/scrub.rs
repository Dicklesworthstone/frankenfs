//! Bounded read-only checksum scrub of one immutable DMU object set.
//!
//! Walk the meta-dnode and every allocated dnode, not ZPL paths. This includes
//! private xattr/ACL objects and SA spills, but not roots referenced from bonus
//! payloads (other datasets, snapshots, ZIL, or pool allocation metadata).
//! Native layout reference: OpenZFS zfs-2.3.0 include/sys/dnode.h.

use super::{
    BlockPointer, CheckedBlock, Cx, DNODE_BLOCK_BYTES, DNODE_BYTES, Dnode, FfsError, MAX_OBJECT,
    Objects, Result, checkpoint, corrupt, parse, unsupported,
};
use serde::Serialize;

const MAX_ISSUES: usize = 128;

/// Work bounds, not retained-memory bounds or native format maxima.
#[derive(Debug, Clone, Copy)]
pub struct ScrubLimits {
    pub pointers: u64,
    pub decoded_bytes: u64,
    pub objects: u64,
}

impl Default for ScrubLimits {
    fn default() -> Self {
        Self {
            pointers: 16_777_216,
            decoded_bytes: 1 << 40,
            objects: 1_048_576,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ScrubIssue {
    pub object: u64,
    /// None means the damaged pointer lies above the native u64 block range.
    pub block: Option<u64>,
    pub level: u8,
    pub category: &'static str,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct ScrubReport {
    pub pool_guid: u64,
    pub view_txg: u64,
    pub root_birth: u64,
    pub objects_examined: u64,
    pub unallocated_slots_inspected: u64,
    pub pointers_examined: u64,
    /// Logical decoded pointer references, not unique physical media blocks.
    pub verified_blocks: u64,
    pub verified_bytes: u64,
    pub decoded_bytes_attempted: u64,
    pub hole_pointers: u64,
    pub errors: u64,
    pub unsupported: u64,
    pub incomplete_subtrees: u64,
    pub limit_reached: Option<&'static str>,
    pub issues: Vec<ScrubIssue>,
    pub omitted_issues: u64,
}

impl ScrubReport {
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.errors == 0
            && self.unsupported == 0
            && self.incomplete_subtrees == 0
            && self.limit_reached.is_none()
    }
}

struct Tree {
    number: u64,
    node: Dnode,
    ceiling: u64,
    dnodes: bool,
}

#[derive(Clone, Copy)]
struct Position {
    block: u128,
    level: u8,
}

struct Walker<'a> {
    view: &'a mut Objects,
    limits: ScrubLimits,
    report: ScrubReport,
}

impl Walker<'_> {
    fn stop(&mut self, reason: &'static str) {
        if self.report.limit_reached.is_none() {
            self.report.limit_reached = Some(reason);
        }
    }

    fn issue(
        &mut self,
        object: u64,
        position: Position,
        error: FfsError,
        descendants_unknown: bool,
    ) -> Result<()> {
        if matches!(error, FfsError::Cancelled) {
            return Err(FfsError::Cancelled);
        }
        let category = match &error {
            FfsError::UnsupportedFeature(_) => {
                self.report.unsupported += 1;
                "unsupported"
            }
            FfsError::Io(_) => {
                self.report.errors += 1;
                "io"
            }
            _ => {
                self.report.errors += 1;
                "corruption"
            }
        };
        if descendants_unknown {
            self.report.incomplete_subtrees += 1;
        }
        if self.report.issues.len() < MAX_ISSUES {
            self.report.issues.push(ScrubIssue {
                object,
                block: u64::try_from(position.block).ok(),
                level: position.level,
                category,
                detail: error.to_string().chars().take(512).collect(),
            });
        } else {
            self.report.omitted_issues += 1;
        }
        Ok(())
    }

    fn charge_pointer(&mut self) -> bool {
        if self.report.pointers_examined == self.limits.pointers {
            self.stop("pointer budget");
            return false;
        }
        self.report.pointers_examined += 1;
        true
    }

    fn charge_bytes(&mut self, bytes: usize) -> bool {
        let bytes = bytes as u64;
        if bytes > self.limits.decoded_bytes - self.report.decoded_bytes_attempted {
            self.stop("decoded-byte budget");
            return false;
        }
        self.report.decoded_bytes_attempted += bytes;
        true
    }

    fn tree(&mut self, cx: &Cx, tree: &Tree) -> Result<()> {
        let level = tree.node.levels() - 1;
        let fanout = (tree.node.indirect_bytes() / 128) as u128;
        let span = fanout.pow(u32::from(level));
        for (slot, bp) in tree.node.pointers().iter().enumerate() {
            if self.report.limit_reached.is_some() {
                break;
            }
            self.visit(
                cx,
                tree,
                bp,
                Position {
                    block: slot as u128 * span,
                    level,
                },
                span,
                tree.ceiling,
            )?;
        }
        if let Some(bp) = tree.node.spill()
            && self.report.limit_reached.is_none()
        {
            checkpoint(cx)?;
            if !self.charge_pointer() {
                return Ok(());
            }
            let position = Position { block: 0, level: 0 };
            if tree.node.bonus_type() != 44 || bp.logical_bytes() > 128 * 1024 {
                return self.issue(
                    tree.number,
                    position,
                    unsupported("scrub only admits SA spills up to 128 KiB"),
                    false,
                );
            }
            if !self.charge_bytes(bp.logical_bytes()) {
                return Ok(());
            }
            match self
                .view
                .checked(cx, bp, 44, 0, bp.logical_bytes(), tree.ceiling)
            {
                Ok(Some(block)) => {
                    self.report.verified_blocks += 1;
                    self.report.verified_bytes += block.bytes.len() as u64;
                }
                Ok(None) => self.issue(
                    tree.number,
                    position,
                    corrupt("allocated SA spill is a hole"),
                    false,
                )?,
                Err(error) => self.issue(tree.number, position, error, false)?,
            }
        }
        Ok(())
    }

    fn visit(
        &mut self,
        cx: &Cx,
        tree: &Tree,
        bp: &BlockPointer,
        position: Position,
        span: u128,
        ceiling: u64,
    ) -> Result<()> {
        checkpoint(cx)?;
        if self.report.limit_reached.is_some() || !self.charge_pointer() {
            return Ok(());
        }
        let descendants = position.level != 0 || tree.dnodes;
        if position.block > u128::from(tree.node.max_block()) && !bp.hole() {
            return self.issue(
                tree.number,
                position,
                corrupt("allocated pointer exceeds dn_maxblkid"),
                descendants,
            );
        }
        let size = if position.level == 0 {
            tree.node.data_bytes()
        } else {
            tree.node.indirect_bytes()
        };
        if !bp.hole() && !self.charge_bytes(size) {
            return Ok(());
        }
        let block = match self.view.checked(
            cx,
            bp,
            tree.node.object_type(),
            position.level,
            size,
            ceiling,
        ) {
            Ok(Some(block)) => block,
            Ok(None) => {
                // A single hole may cover more than u64::MAX logical bytes.
                // Count its pointer without enumerating or allocating zeroes.
                self.report.hole_pointers += 1;
                return Ok(());
            }
            Err(error) => return self.issue(tree.number, position, error, descendants),
        };
        self.report.verified_blocks += 1;
        self.report.verified_bytes += block.bytes.len() as u64;
        if position.level == 0 {
            if tree.dnodes {
                self.dnodes(cx, position.block, &block)?;
            }
            return Ok(());
        }
        let fanout = block.bytes.len() / 128;
        let child_span = span / fanout as u128;
        for (slot, raw) in block.bytes.chunks_exact(128).enumerate() {
            checkpoint(cx)?;
            if self.report.limit_reached.is_some() {
                break;
            }
            let child_position = Position {
                block: position.block + slot as u128 * child_span,
                level: position.level - 1,
            };
            match BlockPointer::parse(raw, block.order) {
                Ok(child) => {
                    self.visit(cx, tree, &child, child_position, child_span, block.birth)?
                }
                Err(error) => {
                    if !self.charge_pointer() {
                        break;
                    }
                    self.issue(
                        tree.number,
                        child_position,
                        parse(&error),
                        child_position.level != 0 || tree.dnodes,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn dnodes(&mut self, cx: &Cx, block_id: u128, block: &CheckedBlock) -> Result<()> {
        let slots_per_block = DNODE_BLOCK_BYTES / DNODE_BYTES;
        let first_object = block_id * slots_per_block as u128;
        let position = Position {
            block: block_id,
            level: 0,
        };
        if first_object + slots_per_block as u128 > u128::from(MAX_OBJECT) {
            return self.issue(
                0,
                position,
                corrupt("meta-dnode exceeds object namespace"),
                true,
            );
        }
        let mut slot = 0;
        while slot < slots_per_block && self.report.limit_reached.is_none() {
            checkpoint(cx)?;
            let at = slot * DNODE_BYTES;
            if block.bytes[at] == 0 {
                self.report.unallocated_slots_inspected += 1;
                slot += 1;
                continue;
            }
            if self.report.objects_examined == self.limits.objects {
                self.stop("object budget");
                break;
            }
            self.report.objects_examined += 1;
            let number = (first_object + slot as u128) as u64;
            let slots = usize::from(block.bytes[at + 12]) + 1;
            if slot + slots > slots_per_block {
                // A damaged size gives no authority to reinterpret interiors.
                self.issue(
                    number,
                    position,
                    corrupt("large dnode crosses its block"),
                    true,
                )?;
                break;
            }
            let end = (slot + slots) * DNODE_BYTES;
            let node = Dnode::parse(&block.bytes[at..end], block.order);
            slot += slots;
            if number == 0 {
                self.issue(
                    0,
                    position,
                    corrupt("reserved object zero is allocated in dnode table"),
                    true,
                )?;
                continue;
            }
            match node {
                Ok(node) => self.tree(
                    cx,
                    &Tree {
                        number,
                        node,
                        ceiling: block.birth,
                        dnodes: false,
                    },
                )?,
                Err(error) => self.issue(number, position, parse(&error), true)?,
            }
        }
        Ok(())
    }
}

impl Objects {
    /// Verify all allocated blocks reachable through this object's meta-dnode.
    /// Use a fresh cache, so ordinary reads before the scrub cannot substitute
    /// for reading the selected immutable backing again. Success is represented
    /// by report.is_clean(), not merely Ok(report). Cancellation is always Err.
    ///
    /// Existing verified-copy recovery is used; not every mirror replica or
    /// RAIDZ parity sector is read. This neither heals nor claims a pool-wide
    /// allocation, ZIL, namespace, or cross-object-set consistency check.
    pub fn scrub(&self, cx: &Cx, limits: ScrubLimits) -> Result<ScrubReport> {
        checkpoint(cx)?;
        if limits.pointers == 0
            || limits.decoded_bytes == 0
            || limits.objects == 0
            || limits.pointers > (1 << 32)
            || limits.objects > (1 << 32)
        {
            return Err(FfsError::Format(
                "scrub requires nonzero budgets and at most 2^32 pointers/objects".into(),
            ));
        }
        let mut view = self.clone_mos();
        let root = Tree {
            number: 0,
            node: view.meta.clone(),
            ceiling: view.root_birth,
            dnodes: true,
        };
        let report = ScrubReport {
            pool_guid: view.pool_guid(),
            view_txg: view.txg,
            root_birth: view.root_birth,
            objects_examined: 0,
            unallocated_slots_inspected: 0,
            pointers_examined: 0,
            verified_blocks: 0,
            verified_bytes: 0,
            decoded_bytes_attempted: 0,
            hole_pointers: 0,
            errors: 0,
            unsupported: 0,
            incomplete_subtrees: 0,
            limit_reached: None,
            issues: Vec::new(),
            omitted_issues: 0,
        };
        let mut walker = Walker {
            view: &mut view,
            limits,
            report,
        };
        walker.tree(cx, &root)?;
        checkpoint(cx)?;
        Ok(walker.report)
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::reader::{DATA_OFFSET, Endian, LABEL_BYTES, Leaf, VdevConfig};
        use ffs_block::ByteDevice;
        use ffs_ondisk::zfs::checksum;
        use ffs_types::ByteOffset;
        use std::collections::VecDeque;
        use std::sync::{Arc, Mutex};

        const LENGTH: usize = 8 * 1024 * 1024;
        const TABLE: u64 = DATA_OFFSET + 0x10000;
        const INDIRECT: u64 = DATA_OFFSET + 0x18000;
        const FIRST: u64 = DATA_OFFSET + 0x1A000;
        const SECOND: u64 = DATA_OFFSET + 0x1B000;
        const SPILL: u64 = DATA_OFFSET + 0x1C000;

        #[derive(Default)]
        struct Storage {
            bytes: Vec<u8>,
            reads: Vec<u64>,
            cancel_at: Option<u64>,
        }
        struct Memory(Arc<Mutex<Storage>>);
        impl ByteDevice for Memory {
            fn len_bytes(&self) -> u64 { LENGTH as u64 }
            fn read_exact_at(&self, _: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
                let mut state = self.0.lock().unwrap();
                state.reads.push(offset.0);
                if state.cancel_at == Some(offset.0) { return Err(FfsError::Cancelled); }
                let at = offset.0 as usize;
                out.copy_from_slice(state.bytes.get(at..at + out.len()).ok_or_else(|| corrupt("test bounds"))?);
                Ok(())
            }
            fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
                panic!("read-only scrub attempted a backing write")
            }
            fn sync(&self, _: &Cx) -> Result<()> { panic!("read-only scrub attempted a flush") }
        }
        fn word16(bytes: &mut [u8], at: usize, value: u16, order: Endian) {
            let raw = match order { Endian::Little => value.to_le_bytes(), Endian::Big => value.to_be_bytes() };
            bytes[at..at + 2].copy_from_slice(&raw);
        }
        fn pointer(raw: &[u8], at: u64, kind: u8, level: u8, birth: u64, order: Endian) -> Vec<u8> {
            let mut words = [0_u64; 16];
            words[0] = raw.len() as u64 / 512;
            words[1] = (at - DATA_OFFSET) / 512;
            words[6] = (raw.len() as u64 / 512 - 1) | ((raw.len() as u64 / 512 - 1) << 16)
                | (2 << 32) | (7 << 40) | (u64::from(kind) << 48) | (u64::from(level) << 56)
                | (u64::from(order == Endian::Little) << 63);
            words[10] = birth;
            words[12..].copy_from_slice(&checksum(raw, 7, order).unwrap());
            words.into_iter().flat_map(|word| order.encode(word)).collect()
        }
        fn node(kind: u8, size: usize, levels: u8, max: u64, order: Endian) -> Vec<u8> {
            let mut raw = vec![0; 512];
            raw[0] = kind; raw[1] = 12; raw[2] = levels; raw[3] = 1; raw[7] = 1;
            word16(&mut raw, 8, (size / 512) as u16, order);
            raw[16..24].copy_from_slice(&order.encode(max));
            raw
        }
        struct Fixture {
            storage: Arc<Mutex<Storage>>,
            table: Vec<u8>,
            order: Endian,
        }
        impl Fixture {
            fn new(order: Endian) -> Self {
                let mut state = Storage { bytes: vec![0; LENGTH], ..Storage::default() };
                let a = vec![0xA5; 512];
                let b = vec![0x5A; 512];
                let spill = vec![0x7E; 512];
                let mut indirect = vec![0; 4096];
                indirect[..128].copy_from_slice(&pointer(&a, FIRST, 19, 0, 20, order));
                indirect[256..384].copy_from_slice(&pointer(&b, SECOND, 19, 0, 20, order));
                let mut data = node(19, 512, 2, 31, order);
                data[64..192].copy_from_slice(&pointer(&indirect, INDIRECT, 19, 1, 30, order));
                let mut large = node(19, 512, 1, 0, order);
                large.resize(1024, 0);
                large[4] = 44; large[7] |= 4; large[12] = 1;
                large[512] = 19; // Interior must not be parsed as a third object.
                large[896..1024].copy_from_slice(&pointer(&spill, SPILL, 44, 0, 30, order));
                let mut table = vec![0; DNODE_BLOCK_BYTES];
                table[512..1024].copy_from_slice(&data);
                table[7 * 512..9 * 512].copy_from_slice(&large);
                for (at, bytes) in [(FIRST, &a), (SECOND, &b), (SPILL, &spill), (INDIRECT, &indirect)] {
                    state.bytes[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
                }
                Self { storage: Arc::new(Mutex::new(state)), table, order }
            }
            fn view(&self) -> Objects {
                self.storage.lock().unwrap().bytes[TABLE as usize..TABLE as usize + self.table.len()]
                    .copy_from_slice(&self.table);
                let mut meta = node(10, DNODE_BLOCK_BYTES, 1, 0, self.order);
                meta[64..192].copy_from_slice(&pointer(&self.table, TABLE, 10, 0, 40, self.order));
                let leaf = Leaf::from_device(&Cx::for_testing(), Box::new(Memory(Arc::clone(&self.storage))), 0, LENGTH as u64).unwrap();
                Objects {
                    pool: leaf.into(),
                    config: VdevConfig {
                        pool_guid: 123, top_guid: 999, version: 5000, txg: 42,
                        ashift: 9, id: 0, allocated_bytes: LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES,
                        read_features: Vec::new(), raidz_members: None,
                    },
                    txg: 43, root_birth: 42, meta: Dnode::parse(&meta, self.order).unwrap(),
                    cache: VecDeque::new(), cached_bytes: 0,
                }
            }
        }
        fn scrub(view: &Objects) -> ScrubReport {
            view.scrub(&Cx::for_testing(), ScrubLimits::default()).unwrap()
        }

        #[test]
        fn scrub_reads_private_objects_and_large_dnode_spills_in_both_orders() {
            for order in [Endian::Little, Endian::Big] {
                let fixture = Fixture::new(order);
                let report = scrub(&fixture.view());
                assert!(report.is_clean(), "{report:?}");
                assert_eq!(report.objects_examined, 2);
                assert_eq!(report.unallocated_slots_inspected, 29);
                assert_eq!(report.verified_blocks, 5);
                assert_eq!(report.verified_bytes, 16_384 + 4096 + 3 * 512);
                assert_eq!(report.hole_pointers, 31);
                let reads = &fixture.storage.lock().unwrap().reads;
                assert_eq!(reads, &[TABLE, INDIRECT, FIRST, SECOND, SPILL]);
            }
        }

        #[test]
        fn scrub_continues_after_bad_data_and_reports_incomplete_metadata() {
            for bad in [FIRST, INDIRECT, TABLE, SPILL] {
                let fixture = Fixture::new(Endian::Little);
                let view = fixture.view();
                fixture.storage.lock().unwrap().bytes[bad as usize] ^= 1;
                let report = scrub(&view);
                assert!(!report.is_clean());
                assert_eq!(report.errors, 1);
                assert_eq!(report.incomplete_subtrees, u64::from(bad == INDIRECT || bad == TABLE));
                let reads = &fixture.storage.lock().unwrap().reads;
                if bad == FIRST { assert!(reads.contains(&SECOND)); }
                if bad != TABLE { assert!(reads.contains(&SPILL)); }
                if bad == INDIRECT { assert!(!reads.contains(&FIRST)); }
            }
        }

        #[test]
        fn scrub_does_not_reuse_a_warm_data_cache() {
            let fixture = Fixture::new(Endian::Little);
            let mut view = fixture.view();
            assert_eq!(view.read(&Cx::for_testing(), 1, 0, 512).unwrap(), vec![0xA5; 512]);
            fixture.storage.lock().unwrap().bytes[FIRST as usize] ^= 1;
            let report = scrub(&view);
            assert_eq!(report.errors, 1);
            assert!(!report.is_clean());
            assert!(fixture.storage.lock().unwrap().reads.iter().filter(|at| **at == FIRST).count() >= 2);
        }

        #[test]
        fn scrub_cancellation_is_not_damage_or_a_successful_partial_report() {
            for at in [TABLE, INDIRECT, FIRST, SPILL] {
                let fixture = Fixture::new(Endian::Little);
                let view = fixture.view();
                fixture.storage.lock().unwrap().cancel_at = Some(at);
                assert!(matches!(view.scrub(&Cx::for_testing(), ScrubLimits::default()), Err(FfsError::Cancelled)));
                assert_eq!(fixture.storage.lock().unwrap().reads.last(), Some(&at));
            }
        }

        #[test]
        fn scrub_budgets_stop_work_and_never_report_clean() {
            let cases = [
                ScrubLimits { pointers: 1, ..ScrubLimits::default() },
                ScrubLimits { decoded_bytes: 16_383, ..ScrubLimits::default() },
                ScrubLimits { objects: 1, ..ScrubLimits::default() },
            ];
            for limits in cases {
                let fixture = Fixture::new(Endian::Little);
                let view = fixture.view();
                let report = view.scrub(&Cx::for_testing(), limits).unwrap();
                assert!(!report.is_clean());
                assert!(report.limit_reached.is_some());
                assert!(report.pointers_examined <= limits.pointers);
                assert!(report.decoded_bytes_attempted <= limits.decoded_bytes);
                assert!(report.objects_examined <= limits.objects);
                if limits.decoded_bytes < 16_384 { assert!(fixture.storage.lock().unwrap().reads.is_empty()); }
            }
        }

        #[test]
        fn scrub_skips_huge_sparse_trees_without_per_logical_block_work() {
            let mut fixture = Fixture::new(Endian::Big);
            let mut sparse = node(19, 512, 8, u64::MAX, fixture.order);
            sparse[1] = 17;
            fixture.table[512..1024].copy_from_slice(&sparse);
            let report = scrub(&fixture.view());
            assert!(report.is_clean(), "{report:?}");
            assert_eq!(report.pointers_examined, 4);
            assert_eq!(fixture.storage.lock().unwrap().reads, [TABLE, SPILL]);
        }

        #[test]
        fn scrub_rejects_cross_block_dnodes_without_parsing_their_interiors() {
            let mut fixture = Fixture::new(Endian::Little);
            fixture.table[7 * 512 + 12] = 250;
            let report = scrub(&fixture.view());
            assert_eq!(report.objects_examined, 2);
            assert_eq!(report.errors, 1);
            assert_eq!(report.incomplete_subtrees, 1);
            assert!(!fixture.storage.lock().unwrap().reads.contains(&SPILL));
        }

        #[test]
        fn scrub_preserves_historical_birth_limits() {
            let fixture = Fixture::new(Endian::Little);
            let mut view = fixture.view();
            view.txg = 39;
            let report = scrub(&view);
            assert_eq!(report.errors, 1);
            assert_eq!(report.incomplete_subtrees, 1);
            assert!(fixture.storage.lock().unwrap().reads.is_empty());
        }

        #[test]
        fn scrub_rejects_allocated_pointers_past_the_native_maximum() {
            let mut fixture = Fixture::new(Endian::Little);
            // The allocated indirect slot 2 must not be silently dropped.
            fixture.table[512 + 16..512 + 24].copy_from_slice(&fixture.order.encode(0));
            let report = scrub(&fixture.view());
            assert_eq!(report.errors, 1);
            assert_eq!(report.issues[0].object, 1);
            assert_eq!(report.issues[0].block, Some(2));
            assert!(!fixture.storage.lock().unwrap().reads.contains(&SECOND));
        }

        #[test]
        fn scrub_retains_unsupported_spill_coverage_and_later_objects() {
            let mut fixture = Fixture::new(Endian::Little);
            fixture.table[7 * 512 + 4] = 17;
            let report = scrub(&fixture.view());
            assert_eq!(report.unsupported, 1);
            assert_eq!(report.errors, 0);
            assert!(!report.is_clean());
            assert_eq!(report.issues[0].category, "unsupported");
            assert!(!fixture.storage.lock().unwrap().reads.contains(&SPILL));
        }

        #[test]
        fn scrub_rejects_empty_work_budgets_without_io() {
            let fixture = Fixture::new(Endian::Little);
            let view = fixture.view();
            assert!(view.scrub(&Cx::for_testing(), ScrubLimits { objects: 0, ..ScrubLimits::default() }).is_err());
            assert!(fixture.storage.lock().unwrap().reads.is_empty());
        }
    }
}
