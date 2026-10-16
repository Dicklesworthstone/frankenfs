//! Constructed log blocks over native mirror/stripe/RAIDZ maps. Not import proof.
use super::*;
use super::super::storage::{ReadState, read_block};
use crate::reader::pool::raidz::NativeMap;
use crate::reader::{Pool, RaidzGroup, RaidzMember};

type MemberBlocks = Vec<Vec<(u64, Vec<u8>)>>;

fn pool(blocks: MemberBlocks, faults: &[Option<u64>], reverse: bool) -> (Pool, Vec<Reads>) {
    let mut leaves = Vec::new();
    let mut reads = Vec::new();
    for (index, blocks) in blocks.into_iter().enumerate() {
        let (source, observed) = leaf(&blocks, faults.get(index).copied().flatten());
        leaves.push(source.leaves()[0].clone());
        reads.push(observed);
    }
    if reverse { leaves.reverse(); }
    (Pool::from_leaves(leaves).unwrap(), reads)
}

fn claimed(first: &[u8], order: Endian) -> Vec<u8> {
    let mut hdr = header(first, order);
    for (at, value) in [(0, 43), (144, 2), (152, 3), (160, 1)] {
        put(&mut hdr, at, value, order);
    }
    hdr
}

#[test]
fn mirror_log_scans_recover_corrupt_or_unreadable_first_member_and_preserve_cancellation() {
    for order in [Endian::Little, Endian::Big] {
        for algorithm in [5, 9] {
            let first = pointer(FIRST, 1, algorithm, 4096, order, order);
            let next = pointer(SECOND, 2, algorithm, 4096, order, order);
            let raw = block(&first, order, &next, &[record(9, 43, 1, 0, b"recovered", order)]);
            for case in 0..3 {
                let damaged = if case == 1 { Vec::new() } else { vec![(FIRST, vec![0; 4096])] };
                let fault = (case == 2).then_some(BASE + DATA_OFFSET + FIRST);
                let (pool, reads) = pool(vec![damaged, vec![(FIRST, raw.clone())]], &[fault, None], false);
                let result = scan(&Cx::for_testing(), &pool, &config(), &claimed(&first, order), order, selection(44));
                if case == 2 {
                    assert!(matches!(result, Err(FfsError::Cancelled)));
                    assert!(reads[1].lock().unwrap().is_empty());
                } else {
                    let log = result.unwrap();
                    assert_eq!(log.termination, Termination::ClaimedBoundary);
                    assert_eq!(log.records[0].raw[192..201], *b"recovered");
                    assert!(log.records[0].pending);
                    assert_eq!(log.physical_work_bytes, 8192);
                    assert_eq!(reads[1].lock().unwrap().len(), 1);
                }
            }
        }
    }
}

#[test]
fn mirror_exhaustion_distinguishes_readable_unverified_tail_from_io_failure() {
    let order = Endian::Little;
    let first = pointer(FIRST, 1, 9, 4096, order, order);
    for missing in [false, true] {
        let other = if missing { Vec::new() } else { vec![(FIRST, vec![0; 4096])] };
        let (pool, _) = pool(vec![vec![(FIRST, vec![0; 4096])], other], &[], false);
        let result = scan(&Cx::for_testing(), &pool, &config(), &header(&first, order), order, selection(42));
        if missing { assert!(matches!(result, Err(FfsError::Io(_)))); }
        else { assert_eq!(result.unwrap().termination, Termination::UnverifiedTail); }
        assert!(scan(&Cx::for_testing(), &pool, &config(), &claimed(&first, order), order, selection(44)).is_err());
    }
}

fn group_config(parity: usize, width: usize, ashift: u8, reverse: bool) -> VdevConfig {
    let mut cfg = config();
    cfg.ashift = ashift;
    let capacity = cfg.allocated_bytes / (1_u64 << ashift) * (1_u64 << ashift);
    if parity != 0 { cfg.allocated_bytes = capacity * width as u64; }
    cfg.raidz_members = Some(RaidzGroup {
        parity,
        members: (0..width).map(|index| RaidzMember {
            supplied_index: if reverse { width - 1 - index } else { index },
            guid: 1001 + index as u64,
            ashift,
            allocated_bytes: if parity == 0 { capacity } else { cfg.allocated_bytes },
        }).collect(),
    });
    cfg
}

#[test]
fn striped_zil_routes_by_vdev_id_not_argument_position() {
    let order = Endian::Big;
    for reverse in [false, true] {
        let mut first = pointer(FIRST, 1, 9, 4096, order, order);
        put(&mut first, 0, (1_u64 << 32) | 8, order);
        let next = pointer(SECOND, 2, 9, 4096, order, order);
        let raw = block(&first, order, &next, &[record(9, 43, 1, 0, b"stripe", order)]);
        let (pool, reads) = pool(vec![vec![(FIRST, vec![0; 4096])], vec![(FIRST, raw)]], &[], reverse);
        let log = scan(&Cx::for_testing(), &pool, &group_config(0, 2, 9, reverse), &claimed(&first, order), order, selection(44)).unwrap();
        assert_eq!(log.records[0].raw[192..198], *b"stripe");
        assert!(reads[0].lock().unwrap().is_empty());
        assert_eq!(reads[1].lock().unwrap().len(), 1);
    }
}

fn encode(map: &NativeMap, raw: &[u8], width: usize) -> MemberBlocks {
    let mut result: MemberBlocks = (0..width).map(|_| Vec::new()).collect();
    let mut padded = raw.to_vec();
    padded.resize(map.aligned_bytes(), 0);
    for column in map.columns().iter().filter(|column| column.data_offset.is_some()) {
        let start = column.data_offset.unwrap();
        result[column.child_id].push((column.offset, padded[start..start + column.bytes].to_vec()));
    }
    // Encode P/Q/R independently in Horner form, not using decoder GF helpers.
    for row in 0..map.parity() {
        let column = &map.columns()[row];
        let mut parity = vec![0_u8; column.bytes];
        for data in map.columns().iter().filter(|column| column.data_offset.is_some()) {
            for (index, value) in parity.iter_mut().enumerate() {
                for _ in 0..row {
                    let doubled = u16::from(*value) * 2;
                    *value = u8::try_from(if doubled >= 256 { doubled ^ 0x11d } else { doubled }).unwrap();
                }
                if index < data.bytes { *value ^= padded[data.data_offset.unwrap() + index]; }
            }
        }
        result[column.child_id].push((column.offset, parity));
    }
    result
}

fn raid_log(parity: usize, order: Endian, algorithm: u8, ashift: u8) -> (Vec<u8>, Vec<u8>, NativeMap, MemberBlocks) {
    let width = parity + 3;
    let map = NativeMap::new(FIRST, 4096, ashift, width, parity).unwrap();
    let mut first = pointer(FIRST, 1, algorithm, 4096, order, order);
    put(&mut first, 0, map.allocated_bytes() / 512, order);
    let next = pointer(SECOND, 2, algorithm, 4096, order, order);
    let raw = block(&first, order, &next, &[record(9, 43, 1, 0, b"RAIDZ log", order)]);
    let members = encode(&map, &raw, width);
    (first, raw, map, members)
}

fn damage(members: &mut MemberBlocks, map: &NativeMap, ordinal: usize) {
    let column = &map.columns()[ordinal];
    let (_, bytes) = members[column.child_id].iter_mut().find(|(offset, _)| *offset == column.offset).unwrap();
    bytes[0] ^= 0x5a;
}

#[test]
fn raidz_zilog_and_zilog2_reconstruct_with_each_parity_level_and_native_orders() {
    for parity in 1..=3 {
        for order in [Endian::Little, Endian::Big] {
            for algorithm in [5, 9] {
                for ashift in [9, 12, 16] {
                    let (first, expected, map, mut members) = raid_log(parity, order, algorithm, ashift);
                    // One corrupt data column and all but the last parity equation.
                    // Q and R must remain useful even when earlier parity is bad.
                    damage(&mut members, &map, parity);
                    for bad in 0..parity - 1 { damage(&mut members, &map, bad); }
                    let (pool, _) = pool(members, &[], true);
                    let pointer = Pointer::parse(&first, order, 3).unwrap().unwrap();
                    let mut state = ReadState::default();
                    let raw = read_block(&Cx::for_testing(), &pool, &group_config(parity, parity + 3, ashift, true), &pointer, &mut state).unwrap().unwrap();
                    assert_eq!(raw, expected);
                    assert!(state.reconstruction_bytes > 4096);
                    assert!(state.physical_bytes >= 4096);
                }
            }
        }
    }
}

#[test]
fn raidz_log_scan_uses_reconstructed_bytes_and_stops_at_claimed_boundary() {
    for parity in 1..=3 {
        let order = Endian::Little;
        let (first, _, map, mut members) = raid_log(parity, order, 9, 9);
        for ordinal in parity..parity * 2 { damage(&mut members, &map, ordinal); }
        let (pool, _) = pool(members, &[], false);
        let log = scan(&Cx::for_testing(), &pool, &group_config(parity, parity + 3, 9, false), &claimed(&first, order), order, selection(44)).unwrap();
        assert_eq!(log.termination, Termination::ClaimedBoundary);
        assert_eq!(log.records[0].raw[192..201], *b"RAIDZ log");
        assert!(log.reconstruction_work_bytes > 4096);
    }
}

#[test]
fn raidz_cancellation_is_terminal_even_when_parity_could_recover() {
    let order = Endian::Little;
    let (first, _, map, members) = raid_log(2, order, 9, 9);
    let data = &map.columns()[2];
    let mut faults = vec![None; 5];
    faults[data.child_id] = Some(BASE + DATA_OFFSET + data.offset);
    let (pool, reads) = pool(members, &faults, false);
    let pointer = Pointer::parse(&first, order, 3).unwrap().unwrap();
    assert!(matches!(read_block(&Cx::for_testing(), &pool, &group_config(2, 5, 9, false), &pointer, &mut ReadState::default()), Err(FfsError::Cancelled)));
    for parity in &map.columns()[..2] {
        assert!(!reads[parity.child_id].lock().unwrap().iter().any(|(offset, _)| *offset == BASE + DATA_OFFSET + parity.offset));
    }
}

#[test]
fn zil_native_allocation_and_physical_work_preflight_precede_every_read() {
    let order = Endian::Little;
    let (first, _, _, members) = raid_log(3, order, 9, 9);
    let (pool, reads) = pool(members, &[], false);
    let cfg = group_config(3, 6, 9, false);
    let mut pointer = Pointer::parse(&first, order, 3).unwrap().unwrap();
    let original = pointer.dvas[0].allocated_bytes;
    pointer.dvas[0].allocated_bytes += 512;
    assert!(read_block(&Cx::for_testing(), &pool, &cfg, &pointer, &mut ReadState::default()).is_err());
    pointer.dvas[0].allocated_bytes = original;
    let mut state = ReadState::default();
    state.physical_bytes = MAX_LOG_BYTES;
    assert!(matches!(read_block(&Cx::for_testing(), &pool, &cfg, &pointer, &mut state), Err(FfsError::UnsupportedFeature(_))));
    assert!(reads.iter().all(|reads| reads.lock().unwrap().is_empty()));
}

#[test]
fn zil_reconstruction_budget_is_not_an_unverified_tail_or_replica_retry() {
    let order = Endian::Little;
    let (first, _, _, members) = raid_log(1, order, 9, 9);
    let (pool, _) = pool(members, &[], false);
    let pointer = Pointer::parse(&first, order, 3).unwrap().unwrap();
    let mut state = ReadState::default();
    state.reconstruction_bytes = usize::MAX;
    assert!(matches!(read_block(&Cx::for_testing(), &pool, &group_config(1, 4, 9, false), &pointer, &mut state), Err(FfsError::UnsupportedFeature(_))));
}

#[test]
fn independent_vdevs_can_reuse_offsets_but_mirror_replicas_cannot_alias() {
    let cx = Cx::for_testing();
    let order = Endian::Little;
    let first = pointer(FIRST, 1, 9, 4096, order, order);
    let mut second = pointer(FIRST, 2, 9, 4096, order, order);
    put(&mut second, 0, (1_u64 << 32) | 8, order);
    let tail = pointer(SECOND, 3, 9, 4096, order, order);
    let a = block(&first, order, &second, &[record(9, 43, 1, 0, b"first", order)]);
    let b = block(&second, order, &tail, &[record(9, 43, 2, 5, b"second", order)]);
    let mut hdr = claimed(&first, order);
    put(&mut hdr, 144, 3, order);
    put(&mut hdr, 160, 2, order);
    let (source, _) = pool(vec![vec![(FIRST, a)], vec![(FIRST, b)]], &[], true);
    let log = scan(&cx, &source, &group_config(0, 2, 9, true), &hdr, order, selection(44)).unwrap();
    assert_eq!(log.verified_blocks, 2);
    assert_eq!(log.records.len(), 2);

    let mut duplicate = first;
    put(&mut duplicate, 16, 8, order);
    put(&mut duplicate, 24, FIRST / 512, order);
    let pointer = Pointer::parse(&duplicate, order, 3).unwrap().unwrap();
    let (source, reads) = pool(vec![Vec::new(), Vec::new()], &[], false);
    assert!(matches!(read_block(&cx, &source, &config(), &pointer, &mut ReadState::default()), Err(FfsError::Corruption { .. })));
    assert!(reads.iter().all(|reads| reads.lock().unwrap().is_empty()));
}

#[test]
fn raidz_io_erasure_recovers_but_unrecoverable_io_does_not_become_a_tail() {
    for parity in 1..=3 {
        let order = Endian::Little;
        for recoverable in [false, true] {
            let (first, expected, map, mut members) = raid_log(parity, order, 9, 9);
            let data = &map.columns()[parity];
            members[data.child_id].retain(|(offset, _)| *offset != data.offset);
            if !recoverable {
                for ordinal in 0..parity { damage(&mut members, &map, ordinal); }
            }
            let (source, _) = pool(members, &[], false);
            let pointer = Pointer::parse(&first, order, 3).unwrap().unwrap();
            let result = read_block(&Cx::for_testing(), &source, &group_config(parity, parity + 3, 9, false), &pointer, &mut ReadState::default());
            if recoverable { assert_eq!(result.unwrap().unwrap(), expected); }
            else { assert!(matches!(result, Err(FfsError::Io(_)))); }
        }
    }
}

#[test]
fn public_recovered_read_retains_multi_member_mos_zpl_and_log_owner() {
    // This is a direct constructed Objects fixture, not native label admission.
    let cx = Cx::for_testing();
    let (mut objects, healthy_reads) = recovery_graph(false);
    let (first, first_reads) = leaf(&[(SECOND, vec![0; 4096])], None);
    objects.pool = Pool::from_leaves(vec![
        first.leaves()[0].clone(),
        objects.pool.leaves()[0].clone(),
    ]).unwrap();
    let recovered = objects.read_with_intent_log(&cx, &[], b"/file", 0, 100, true).unwrap();
    assert_eq!(recovered.bytes, b"abNEWfgh\0\0\0\0!");
    assert_eq!((recovered.file_size, recovered.applied_records), (13, 3));
    assert_eq!(recovered.log.physical_work_bytes, 16_384);
    for reads in [&first_reads, &healthy_reads] {
        assert!(reads.lock().unwrap().iter().any(|(offset, _)| *offset == BASE + DATA_OFFSET + FIRST));
    }
    let mut committed = objects.zpl(&cx, &[]).unwrap();
    assert_eq!(committed.read(&cx, 7, 0, 100).unwrap(), b"abcdefghijklmnop");
}
