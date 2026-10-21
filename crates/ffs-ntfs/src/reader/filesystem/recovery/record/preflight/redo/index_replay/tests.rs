use super::super::super::super::TailRecord;
use super::*;
use ffs_error::FfsError;
use std::collections::BTreeSet;

const OWNER: u64 = (7_u64 << 48) | 0x2A;

fn attribute() -> Attribute {
    Attribute {
        reference: OWNER,
        kind: 0xA0,
        index_bytes: 1024,
        opened: 1,
        name: I30.to_vec(),
    }
}

fn entry(name: u16) -> Vec<u8> {
    let mut bytes = vec![0; 88];
    bytes[..8].copy_from_slice(&((7_u64 << 48) | 0x2B).to_le_bytes());
    bytes[8..10].copy_from_slice(&88_u16.to_le_bytes());
    bytes[10..12].copy_from_slice(&68_u16.to_le_bytes());
    bytes[16..24].copy_from_slice(&OWNER.to_le_bytes());
    bytes[80] = 1;
    bytes[81] = 1;
    bytes[82..84].copy_from_slice(&name.to_le_bytes());
    bytes
}

fn block(vbn: u64) -> Vec<u8> {
    let mut raw = vec![0xC1; 1024];
    raw[..168].fill(0);
    raw[..4].copy_from_slice(b"INDX");
    raw[4..6].copy_from_slice(&40_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
    raw[8..16].copy_from_slice(&10_u64.to_le_bytes());
    raw[16..24].copy_from_slice(&vbn.to_le_bytes());
    raw[24..28].copy_from_slice(&40_u32.to_le_bytes());
    raw[28..32].copy_from_slice(&144_u32.to_le_bytes());
    raw[32..36].copy_from_slice(&1000_u32.to_le_bytes());
    raw[64..152].copy_from_slice(&entry(97));
    raw[160..162].copy_from_slice(&16_u16.to_le_bytes());
    raw[164..166].copy_from_slice(&2_u16.to_le_bytes());
    // Independently encode USA; do not use the editor to build its input.
    let token = 0xA5A5_u16.to_le_bytes();
    raw[40..42].copy_from_slice(&token);
    for sector in 1..=2 {
        let end = sector * 512;
        let saved = [raw[end - 2], raw[end - 1]];
        raw[40 + sector * 2..42 + sector * 2].copy_from_slice(&saved);
        raw[end - 2..end].copy_from_slice(&token);
    }
    raw
}

fn record(lsn: u64, redo: u16, undo: u16, at: u16, payload: &[u8], inverse: &[u8]) -> LogRecord {
    let redo_at = 48_usize;
    let undo_at = (redo_at + payload.len()).next_multiple_of(8);
    let mut data = vec![0; undo_at + inverse.len()];
    data[..2].copy_from_slice(&redo.to_le_bytes());
    data[2..4].copy_from_slice(&undo.to_le_bytes());
    data[4..6].copy_from_slice(&u16::try_from(redo_at).unwrap().to_le_bytes());
    data[6..8].copy_from_slice(&u16::try_from(payload.len()).unwrap().to_le_bytes());
    data[8..10].copy_from_slice(&u16::try_from(undo_at).unwrap().to_le_bytes());
    data[10..12].copy_from_slice(&u16::try_from(inverse.len()).unwrap().to_le_bytes());
    data[12..14].copy_from_slice(&24_u16.to_le_bytes());
    data[14..16].copy_from_slice(&2_u16.to_le_bytes());
    data[18..20].copy_from_slice(&at.to_le_bytes());
    data[24..32].copy_from_slice(&2_u64.to_le_bytes());
    data[32..40].copy_from_slice(&102_u64.to_le_bytes());
    data[40..48].copy_from_slice(&50_u64.to_le_bytes());
    data[redo_at..redo_at + payload.len()].copy_from_slice(payload);
    data[undo_at..].copy_from_slice(inverse);
    LogRecord {
        lsn,
        previous: 0,
        undo_next: 0,
        kind: LFS_CLIENT_RECORD,
        summary: TailRecord {
            transaction_id: 24,
            redo_op: redo,
            undo_op: undo,
        },
        data,
    }
}

struct Memory {
    geometry: Geometry,
    shape: Shape,
    blocks: BTreeMap<u64, Vec<u8>>,
    mappings: BTreeMap<u64, u64>,
    free: BTreeSet<(Option<u64>, bool, u64)>,
    opens: usize,
    reads: usize,
    failure: Option<FfsError>,
}

impl Memory {
    fn new() -> Self {
        Self {
            geometry: Geometry {
                cluster_bytes: 512,
                clusters: 1024,
                records: 128,
                boundary: 100,
            },
            shape: Shape {
                block_bytes: 1024,
                vcn_bytes: 512,
                initialized: 4096,
            },
            blocks: BTreeMap::from([(1024, block(2)), (2048, block(4))]),
            mappings: BTreeMap::from([(2, 102), (3, 50), (4, 51), (5, 52)]),
            free: BTreeSet::new(),
            opens: 0,
            reads: 0,
            failure: None,
        }
    }
}

impl Input for Memory {
    fn geometry(&self) -> Geometry {
        self.geometry
    }
    fn open(&mut self, _cx: &Cx, _attribute: &Attribute) -> Result<Shape> {
        self.opens += 1;
        Ok(self.shape)
    }
    fn mapped_lcn(&self, _reference: u64, vcn: u64) -> Result<u64> {
        self.mappings
            .get(&vcn)
            .copied()
            .ok_or_else(|| corrupt(0, "fixture mapping gap"))
    }
    fn allocated(&mut self, _cx: &Cx, reference: Option<u64>, mft: bool, bit: u64) -> Result<bool> {
        Ok(!self.free.contains(&(reference, mft, bit)))
    }
    fn block(&mut self, _cx: &Cx, reference: u64, offset: u64, size: usize) -> Result<Vec<u8>> {
        self.reads += 1;
        assert_eq!(reference, OWNER);
        assert_eq!(size, 1024);
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        self.blocks
            .get(&offset)
            .cloned()
            .ok_or_else(|| corrupt(offset, "fixture block absent"))
    }
}

fn action<'a>(record: &'a LogRecord, attribute: &'a Attribute, undo: bool) -> Action<'a> {
    Action {
        record,
        attribute,
        lcns: vec![102, 50],
        undo,
    }
}

fn names(raw: &[u8]) -> Vec<Vec<u16>> {
    parse_index_block(raw, 2)
        .unwrap()
        .into_iter()
        .filter_map(|entry| entry.key.map(|(_, name)| name.name))
        .collect()
}

#[test]
fn external_entry_insertion_and_empty_payload_loser_deletion_use_native_semantics() {
    let cx = Cx::for_testing();
    let attribute = attribute();
    let update = record(20, 0x0E, 0x0F, 152, &entry(98), &[]);
    let mut source = Memory::new();
    let original = source.blocks.clone();
    let staged = execute(&cx, &mut source, &[action(&update, &attribute, false)]).unwrap();
    assert_eq!(names(&staged.blocks[&(OWNER, 1024)]), [vec![97], vec![98]]);
    assert_eq!(staged.summary.redo, 1);
    assert_eq!(source.blocks, original);
    let staged = execute(
        &cx,
        &mut source,
        &[
            action(&update, &attribute, false),
            action(&update, &attribute, true),
        ],
    )
    .unwrap();
    assert_eq!(names(&staged.blocks[&(OWNER, 1024)]), [vec![97]]);
    assert_eq!((staged.summary.redo, staged.summary.undo), (1, 1));
    assert_eq!(source.blocks, original);
    assert_eq!(
        source.reads, 2,
        "each complete execution loads the block only once"
    );
}

#[test]
fn repeated_redo_is_idempotent_but_still_checks_live_allocation() {
    let cx = Cx::for_testing();
    let attribute = attribute();
    let update = record(20, 0x0E, 0x0F, 152, &entry(98), &[]);
    let mut source = Memory::new();
    let staged = execute(&cx, &mut source, &[action(&update, &attribute, false)]).unwrap();
    source
        .blocks
        .insert(1024, staged.blocks[&(OWNER, 1024)].clone());
    let original = source.blocks.clone();
    let repeated = execute(&cx, &mut source, &[action(&update, &attribute, false)]).unwrap();
    assert_eq!((repeated.summary.redo, repeated.summary.skipped), (0, 1));
    assert_eq!(repeated.blocks[&(OWNER, 1024)], original[&1024]);
    source.free.insert((Some(OWNER), false, 1));
    assert!(execute(&cx, &mut source, &[action(&update, &attribute, false)]).is_err());
    assert_eq!(source.blocks, original);
}

#[test]
fn every_claim_and_all_three_allocation_domains_are_required_before_payload_io() {
    let cx = Cx::for_testing();
    let attribute = attribute();
    let update = record(20, 0x0F, 0x0E, 64, &[], &entry(97));
    for mutation in 0..6 {
        let mut source = Memory::new();
        match mutation {
            0 => {
                source.mappings.insert(3, 51);
            }
            1 => {
                source.free.insert((None, false, 102));
            }
            2 => {
                source.free.insert((None, false, 50));
            }
            3 => {
                source.free.insert((None, true, 42));
            }
            4 => {
                source.free.insert((Some(OWNER), false, 1));
            }
            _ => source.geometry.clusters = 102,
        }
        let original = source.blocks.clone();
        assert!(execute(&cx, &mut source, &[action(&update, &attribute, false)]).is_err());
        assert_eq!(source.reads, 0, "allocation/mapping mutation {mutation}");
        assert_eq!(source.blocks, original);
    }
}

#[test]
fn later_unsupported_opcode_and_forged_stream_identity_fail_before_any_open() {
    let cx = Cx::for_testing();
    let original_attribute = attribute();
    for mutation in 0..6 {
        let first = record(20, 0x0E, 0x0F, 152, &entry(98), &[]);
        let mut later = record(30, 0x0F, 0x0E, 64, &[], &entry(97));
        let mut attribute = original_attribute.clone();
        match mutation {
            0 => {
                later.summary.redo_op = 8;
                later.data[..2].copy_from_slice(&8_u16.to_le_bytes());
            }
            1 => attribute.name = vec![0x24, 0x53, 0x49, 0x49],
            2 => attribute.reference = 42,
            3 => attribute.reference = (7_u64 << 48) | 5,
            4 => attribute.opened = 40,
            _ => later.data[6..8].copy_from_slice(&u16::MAX.to_le_bytes()),
        }
        let mut source = Memory::new();
        assert!(
            execute(
                &cx,
                &mut source,
                &[
                    action(&first, &original_attribute, false),
                    action(&later, &attribute, false),
                ]
            )
            .is_err()
        );
        assert_eq!((source.opens, source.reads), (0, 0));
    }
}

#[test]
fn late_structural_or_parent_failure_discards_all_preceding_private_edits() {
    let cx = Cx::for_testing();
    let attribute = attribute();
    for foreign in [false, true] {
        let first = record(20, 0x0E, 0x0F, 152, &entry(98), &[]);
        let mut payload = entry(99);
        if foreign {
            payload[16..24].copy_from_slice(&(OWNER + 1).to_le_bytes());
        }
        let later = record(
            30,
            0x0E,
            0x0F,
            if foreign { 240 } else { 248 },
            &payload,
            &[],
        );
        let mut source = Memory::new();
        let original = source.blocks.clone();
        assert!(
            execute(
                &cx,
                &mut source,
                &[
                    action(&first, &attribute, false),
                    action(&later, &attribute, false),
                ]
            )
            .is_err()
        );
        assert_eq!(source.blocks, original);
        assert_eq!(source.reads, 1);
    }
}

#[test]
fn torn_wrong_vbn_future_and_unallocated_key_targets_never_return_staged_bytes() {
    let cx = Cx::for_testing();
    let attribute = attribute();
    let update = record(20, 0x0F, 0x0E, 64, &[], &entry(97));
    for mutation in 0..5 {
        let mut source = Memory::new();
        let raw = source.blocks.get_mut(&1024).unwrap();
        match mutation {
            0 => raw[511] ^= 1,
            1 => raw[1023] ^= 1,
            2 => raw[16..24].fill(0),
            3 => raw[8..16].copy_from_slice(&101_u64.to_le_bytes()),
            _ => {
                source.free.insert((None, true, 43));
            }
        }
        let original = source.blocks.clone();
        assert!(execute(&cx, &mut source, &[action(&update, &attribute, false)]).is_err());
        assert_eq!(source.blocks, original);
    }
}

#[test]
fn subcluster_vbns_and_multicluster_transfers_use_the_native_record_displacement() {
    for cluster in [512_u64, 1024, 4096, 8192, 65_536] {
        for block in [512_u32, 1024, 4096, 65_536] {
            let logical = u64::from(block) * 3;
            let displacement = logical % cluster;
            let count = (displacement + u64::from(block)).div_ceil(cluster);
            let mut attribute = attribute();
            attribute.index_bytes = block;
            let mut record = record(20, 0x0F, 0x0E, 64, &[], &entry(97));
            record.data[24..32].copy_from_slice(&(logical / cluster).to_le_bytes());
            record.data[20..22]
                .copy_from_slice(&u16::try_from(displacement / 512).unwrap().to_le_bytes());
            let action = Action {
                record: &record,
                attribute: &attribute,
                lcns: vec![100; count as usize],
                undo: false,
            };
            let geometry = Geometry {
                cluster_bytes: cluster,
                clusters: 1 << 20,
                records: 128,
                boundary: 100,
            };
            let shape = Shape {
                block_bytes: block,
                vcn_bytes: if u64::from(block) < cluster {
                    512
                } else {
                    cluster as u32
                },
                initialized: logical + u64::from(block),
            };
            assert_eq!(location(&action, geometry, shape).unwrap(), logical);
            assert!(
                location(
                    &action,
                    geometry,
                    Shape {
                        initialized: logical,
                        ..shape
                    }
                )
                .is_err()
            );
        }
    }
    // A second sub-cluster buffer is selected by record_off, not attr_off.
    let mut record = record(20, 0x0F, 0x0E, 64, &[], &entry(97));
    record.data[24..32].fill(0);
    record.data[16..18].copy_from_slice(&1024_u16.to_le_bytes());
    let attribute = attribute();
    let action = Action {
        record: &record,
        attribute: &attribute,
        lcns: vec![100],
        undo: false,
    };
    let geometry = Geometry {
        cluster_bytes: 4096,
        ..Memory::new().geometry
    };
    assert_eq!(
        location(&action, geometry, Memory::new().shape).unwrap(),
        1024
    );
}

#[test]
fn cancellation_and_io_errors_preserve_backing_bytes_and_stop_execution() {
    let cx = Cx::for_testing();
    let attribute = attribute();
    let update = record(20, 0x0F, 0x0E, 64, &[], &entry(97));
    for cancelled in [false, true] {
        let mut source = Memory::new();
        source.failure = Some(if cancelled {
            FfsError::Cancelled
        } else {
            FfsError::Io(std::io::Error::other("injected INDX read"))
        });
        let original = source.blocks.clone();
        let result = execute(&cx, &mut source, &[action(&update, &attribute, false)]);
        if cancelled {
            assert!(matches!(result, Err(FfsError::Cancelled)));
        } else {
            assert!(matches!(result, Err(FfsError::Io(_))));
        }
        assert_eq!(source.reads, 1);
        assert_eq!(source.blocks, original);
    }
}

#[test]
fn repeated_or_reordered_lsns_cannot_reorder_redo_and_loser_undo() {
    let cx = Cx::for_testing();
    let attribute = attribute();
    let a = record(20, 0x0E, 0x0F, 152, &entry(98), &[]);
    let b = record(30, 0x0E, 0x0F, 240, &entry(99), &[]);
    for actions in [
        vec![action(&b, &attribute, false), action(&a, &attribute, false)],
        vec![action(&a, &attribute, false), action(&a, &attribute, false)],
        vec![action(&a, &attribute, true), action(&b, &attribute, true)],
        vec![action(&a, &attribute, true), action(&b, &attribute, false)],
    ] {
        let mut source = Memory::new();
        assert!(execute(&cx, &mut source, &actions).is_err());
        assert_eq!((source.opens, source.reads), (0, 0));
    }
}

#[test]
fn self_aliased_physical_clusters_are_not_admitted_as_a_fragmented_buffer() {
    let cx = Cx::for_testing();
    let attribute = attribute();
    let update = record(20, 0x0F, 0x0E, 64, &[], &entry(97));
    let mut source = Memory::new();
    source.mappings.insert(3, 102);
    let action = Action {
        record: &update,
        attribute: &attribute,
        lcns: vec![102, 102],
        undo: false,
    };
    assert!(execute(&cx, &mut source, &[action]).is_err());
    assert_eq!(source.reads, 0);
}

#[test]
fn filename_metadata_and_write_end_have_structural_inverses() {
    let cx = Cx::for_testing();
    let attribute = attribute();
    let mut source = Memory::new();
    let update = record(20, 0x14, 0x14, 64, &[0x5A; 56], &[0; 56]);
    let changed = execute(&cx, &mut source, &[action(&update, &attribute, false)]).unwrap();
    let raw = ffs_ondisk::ntfs::restore_record(&changed.blocks[&(OWNER, 1024)], b"INDX").unwrap();
    assert_eq!(&raw[88..144], &[0x5A; 56]);
    assert_eq!(names(&changed.blocks[&(OWNER, 1024)]), [vec![97]]);
    let restored = execute(
        &cx,
        &mut source,
        &[
            action(&update, &attribute, false),
            action(&update, &attribute, true),
        ],
    )
    .unwrap();
    let raw = ffs_ondisk::ntfs::restore_record(&restored.blocks[&(OWNER, 1024)], b"INDX").unwrap();
    assert_eq!(&raw[88..144], &[0; 56]);
    let mut terminal = vec![0; 16];
    terminal[8..10].copy_from_slice(&16_u16.to_le_bytes());
    terminal[12..14].copy_from_slice(&2_u16.to_le_bytes());
    let mut old = entry(97);
    old.extend_from_slice(&terminal);
    let update = record(20, 0x10, 0x10, 64, &terminal, &old);
    let empty = execute(&cx, &mut source, &[action(&update, &attribute, false)]).unwrap();
    assert_eq!(names(&empty.blocks[&(OWNER, 1024)]), Vec::<Vec<u16>>::new());
    let restored = execute(
        &cx,
        &mut source,
        &[
            action(&update, &attribute, false),
            action(&update, &attribute, true),
        ],
    )
    .unwrap();
    assert_eq!(names(&restored.blocks[&(OWNER, 1024)]), [vec![97]]);
}

#[test]
fn native_child_updates_require_allocated_distinct_nonself_vbns() {
    let cx = Cx::for_testing();
    let attribute = attribute();
    let mut source = Memory::new();
    let raw = source.blocks.get_mut(&1024).unwrap();
    // Convert only pre-trailer fields to a two-child branch, independently of
    // the editor. Children are VBNs 0 and 6, in 512-byte units, not block IDs.
    raw[28..32].copy_from_slice(&160_u32.to_le_bytes());
    raw[36..40].copy_from_slice(&1_u32.to_le_bytes());
    raw[72..74].copy_from_slice(&96_u16.to_le_bytes());
    raw[76..78].copy_from_slice(&1_u16.to_le_bytes());
    raw[152..184].fill(0);
    raw[168..170].copy_from_slice(&24_u16.to_le_bytes());
    raw[172..174].copy_from_slice(&3_u16.to_le_bytes());
    raw[176..184].copy_from_slice(&6_u64.to_le_bytes());
    for child in [4_u64, 2, 3, 6, 8, u64::MAX] {
        let update = record(
            20,
            0x12,
            0x12,
            64,
            &child.to_le_bytes(),
            &0_u64.to_le_bytes(),
        );
        let result = execute(&cx, &mut source, &[action(&update, &attribute, false)]);
        if child == 4 {
            let staged = result.unwrap();
            assert_eq!(
                parse_index_block(&staged.blocks[&(OWNER, 1024)], 2).unwrap()[0].child_vcn,
                Some(4)
            );
            let undo = execute(
                &cx,
                &mut source,
                &[
                    action(&update, &attribute, false),
                    action(&update, &attribute, true),
                ],
            )
            .unwrap();
            assert_eq!(
                parse_index_block(&undo.blocks[&(OWNER, 1024)], 2).unwrap()[0].child_vcn,
                Some(0)
            );
        } else {
            assert!(result.is_err(), "invalid child VBN {child}");
        }
    }
    source.free.insert((Some(OWNER), false, 2));
    let update = record(
        20,
        0x12,
        0x12,
        64,
        &4_u64.to_le_bytes(),
        &0_u64.to_le_bytes(),
    );
    assert!(execute(&cx, &mut source, &[action(&update, &attribute, false)]).is_err());
}
