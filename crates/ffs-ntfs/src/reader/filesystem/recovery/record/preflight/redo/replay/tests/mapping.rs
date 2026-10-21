use super::*;
use ffs_ondisk::ntfs::decode_mapping_pairs;

const OLD: &[u8] = &[0x11, 4, 100, 0];
const NEW: &[u8] = &[0x11, 2, 70, 0x11, 2, 50, 0];

fn mapped_file() -> Vec<u8> {
    let mut raw = file(42, DATA, b"old");
    // Replace the fixture's resident attribute with independently encoded
    // nonresident DATA. This region does not touch either protected trailer.
    raw[64..144].fill(0);
    raw[64..68].copy_from_slice(&DATA.to_le_bytes());
    raw[68..72].copy_from_slice(&72_u32.to_le_bytes());
    raw[72] = 1;
    raw[78..80].copy_from_slice(&1_u16.to_le_bytes());
    raw[88..96].copy_from_slice(&3_u64.to_le_bytes());
    raw[96..98].copy_from_slice(&64_u16.to_le_bytes());
    for at in [104, 112, 120] {
        raw[at..at + 8].copy_from_slice(&2048_u64.to_le_bytes());
    }
    raw[128..128 + OLD.len()].copy_from_slice(OLD);
    raw[136..140].copy_from_slice(&u32::MAX.to_le_bytes());
    raw[24..28].copy_from_slice(&144_u32.to_le_bytes());
    raw
}

fn change(lsn: u64, redo: &[u8], undo: &[u8]) -> LogRecord {
    let mut record = update(lsn, 64, redo, undo);
    record.summary.redo_op = 9;
    record.summary.undo_op = 9;
    record.data[..2].copy_from_slice(&9_u16.to_le_bytes());
    record.data[2..4].copy_from_slice(&9_u16.to_le_bytes());
    record
}

fn input() -> Input {
    let mut input = Input::new();
    input.records.insert(42, mapped_file());
    input
}

fn mappings(raw: &[u8]) -> Vec<(u64, u64, Option<u64>)> {
    let record = NtfsFileRecord::parse(raw).unwrap();
    let attrs = record.attributes().unwrap();
    let NtfsValue::NonResident(value) = &attrs[0].value else {
        panic!("expected nonresident DATA");
    };
    decode_mapping_pairs(value.mapping_pairs, value.first_vcn, value.last_vcn, 512)
        .unwrap()
        .into_iter()
        .map(|run| (run.vcn, run.clusters, run.lcn))
        .collect()
}

#[test]
fn mapping_redo_uses_the_real_dispatch_and_repeated_redo_is_idempotent() {
    let cx = Cx::for_testing();
    let targets = targets();
    let records = [change(20, NEW, OLD)];
    let plan = build(&cx, &targets, &records).unwrap();
    let mut input = input();
    let before = input.records.clone();
    let staged = execute(&cx, &mut input, &plan, &[], &targets).unwrap();
    assert_eq!(
        mappings(&staged.records[&42]),
        [(0, 2, Some(70)), (2, 2, Some(120))]
    );
    assert_eq!(
        (
            staged.summary.redo,
            staged.summary.undo,
            staged.summary.skipped
        ),
        (1, 0, 0)
    );
    assert_eq!(input.records, before);
    input.records = staged.records;
    let before = input.records.clone();
    let repeated = execute(&cx, &mut input, &plan, &[], &targets).unwrap();
    assert_eq!(repeated.records, before);
    assert_eq!((repeated.summary.redo, repeated.summary.skipped), (0, 1));
}

#[test]
fn mapping_loser_undo_consumes_staged_redo_without_changing_the_backing() {
    let cx = Cx::for_testing();
    let targets = targets();
    let records = [change(20, NEW, OLD)];
    let plan = build(&cx, &targets, &records).unwrap();
    let mut input = input();
    let before = input.records.clone();
    let staged = execute(&cx, &mut input, &plan, &records, &targets).unwrap();
    assert_eq!(mappings(&staged.records[&42]), [(0, 4, Some(100))]);
    assert_eq!((staged.summary.redo, staged.summary.undo), (1, 1));
    assert_eq!(input.reads, 1);
    assert_eq!(input.records, before);
    assert_eq!(u64_at(&staged.records[&42], 8).unwrap(), 20);
}

#[test]
fn replacement_mapping_uses_selected_volume_bounds_not_an_unbounded_decoder() {
    let cx = Cx::for_testing();
    let targets = targets();
    let records = [change(20, &[0x21, 2, 200, 0, 0], OLD)];
    let plan = build(&cx, &targets, &records).unwrap();
    for clusters in [201, 202] {
        let mut input = input();
        input.layout.clusters = clusters;
        let before = input.records.clone();
        let result = execute(&cx, &mut input, &plan, &[], &targets);
        if clusters == 201 {
            assert!(matches!(result, Err(FfsError::Corruption { .. })));
        } else {
            assert_eq!(mappings(&result.unwrap().records[&42]), [(0, 2, Some(200))]);
        }
        assert_eq!(input.reads, 1);
        assert_eq!(input.records, before);
    }
}

#[test]
fn malformed_later_mapping_discards_the_entire_private_replay_stage() {
    let cx = Cx::for_testing();
    let targets = targets();
    let records = [change(20, NEW, OLD), change(30, &[0x11, 1, 0xFA, 0], NEW)];
    let plan = build(&cx, &targets, &records).unwrap();
    let mut input = input();
    let before = input.records.clone();
    assert!(matches!(
        execute(&cx, &mut input, &plan, &[], &targets),
        Err(FfsError::Corruption { .. })
    ));
    assert_eq!(input.records, before);
    assert_eq!(input.reads, 1);
}

#[test]
fn mapping_execution_preserves_target_ownership_and_cancellation_checks() {
    let cx = Cx::for_testing();
    let targets = targets();
    let records = [change(20, NEW, OLD)];
    let plan = build(&cx, &targets, &records).unwrap();
    let mut changed_mapping = input();
    changed_mapping.mapping_delta = 200;
    assert!(execute(&cx, &mut changed_mapping, &plan, &[], &targets).is_err());
    assert_eq!(changed_mapping.reads, 0);
    let mut cancelled = input();
    cancelled.failure = Some(FfsError::Cancelled);
    let before = cancelled.records.clone();
    assert!(matches!(
        execute(&cx, &mut cancelled, &plan, &[], &targets),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(cancelled.records, before);
}
