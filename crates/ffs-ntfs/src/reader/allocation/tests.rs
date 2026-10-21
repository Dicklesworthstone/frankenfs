//! Constructed native records and allocation models, not Windows qualification.

use super::*;
use crate::reader::{ByteDevice, ByteOffset, NtfsFileRecord, DATA, SPARSE, VOLUME_INFORMATION};
use std::sync::{Arc, Mutex};

fn mask(bits: u64, used: impl IntoIterator<Item = u64>) -> Vec<u8> {
    let mut bytes = vec![0; bits.div_ceil(8) as usize];
    for bit in used { bytes[bit as usize / 8] |= 1 << (bit % 8); }
    bytes
}

fn accounting(bits: u64, bitmap: &[u8], claims: &mut [Claim], complete: bool) -> AllocationReport {
    let mut report = AllocationReport { volume_clusters: bits, complete, ..AllocationReport::default() };
    reconcile(&Cx::for_testing(), bitmap, claims, &mut report).unwrap();
    report
}

#[test]
fn sweep_counts_union_cross_links_and_bitmap_discrepancies_without_selecting_an_owner() {
    let mut claims = [
        Claim { first: 2, end: 10, record: 24, attribute: 1 },
        Claim { first: 3, end: 5, record: 25, attribute: 2 },
        Claim { first: 4, end: 8, record: 26, attribute: 3 },
        Claim { first: 8, end: 12, record: 27, attribute: 4 },
    ];
    let report = accounting(16, &mask(16, (2..11).chain([15])), &mut claims, true);
    assert!(!report.is_consistent());
    assert!(report.complete);
    assert_eq!(report.referenced_clusters, 10);
    assert_eq!(report.cross_linked_clusters, 7); // [3,10), not sum of pair overlaps.
    assert_eq!(report.referenced_free_clusters, 1);
    assert_eq!(report.allocated_without_reference, Some(1));
    assert_eq!(report.bitmap_allocated_clusters, 10);
    assert_eq!(report.bitmap_free_clusters, 6);
    assert_eq!(report.issues[0].record, Some(25));
    assert_eq!(report.issues[0].other_record, Some(24));
    assert!(report.issues.iter().any(|issue| issue.category == "referenced_free"
        && issue.first_cluster == Some(11) && issue.clusters == 1));
}

#[test]
fn incomplete_scans_never_label_unseen_clusters_as_unreferenced() {
    let report = accounting(8, &[0xFF], &mut [], false);
    assert_eq!(report.allocated_without_reference, None);
    assert_eq!(report.bitmap_allocated_clusters, 8);
    assert_eq!(report.errors, 0);
    assert!(!report.is_consistent());
}

#[test]
fn allocation_evidence_is_bounded_without_truncating_counts() {
    let mut claims: Vec<_> = (0..300).map(|record| Claim {
        first: 2, end: 6, record, attribute: 0,
    }).collect();
    let report = accounting(8, &[0x3C], &mut claims, true);
    assert_eq!(report.cross_linked_clusters, 4);
    assert_eq!(report.referenced_clusters, 4);
    assert_eq!(report.errors, 299);
    assert_eq!(report.issues.len(), MAX_ISSUES);
    assert_eq!(report.omitted_issues, 299 - MAX_ISSUES as u64);
}

#[test]
fn allocation_sweep_matches_an_independent_per_cluster_oracle() {
    let mut seed = 91_u64;
    let mut random = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        seed >> 32
    };
    for _ in 0..1000 {
        let mut counts = [0_u64; 64];
        let mut claims = Vec::new();
        for record in 0..random() % 24 {
            let first = random() % 64;
            let end = first + 1 + random() % (64 - first);
            for slot in &mut counts[first as usize..end as usize] { *slot += 1; }
            claims.push(Claim { first, end, record, attribute: 0 });
        }
        let used: Vec<_> = (0..64).filter(|_| random() % 3 != 0).collect();
        let bitmap = mask(64, used);
        let report = accounting(64, &bitmap, &mut claims, true);
        assert_eq!(report.referenced_clusters, counts.iter().filter(|&&count| count != 0).count() as u64);
        assert_eq!(report.cross_linked_clusters, counts.iter().filter(|&&count| count > 1).count() as u64);
        assert_eq!(report.referenced_free_clusters, (0..64).filter(|&i| counts[i] != 0 && !bit(&bitmap, i as u64)).count() as u64);
        assert_eq!(report.allocated_without_reference, Some((0..64).filter(|&i| counts[i] == 0 && bit(&bitmap, i as u64)).count() as u64));
    }
}

fn resident(kind: u32, id: u16, value: &[u8]) -> Vec<u8> {
    let length = (24 + value.len()).next_multiple_of(8);
    let mut raw = vec![0; length];
    raw[..4].copy_from_slice(&kind.to_le_bytes());
    raw[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    raw[10..12].copy_from_slice(&24_u16.to_le_bytes());
    raw[14..16].copy_from_slice(&id.to_le_bytes());
    raw[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    raw[20..22].copy_from_slice(&24_u16.to_le_bytes());
    raw[24..24 + value.len()].copy_from_slice(value);
    raw
}

fn mapped(cluster: usize, id: u16, pairs: &[u8], first: u64, count: u64, size: u64, sparse: bool) -> Vec<u8> {
    let start: usize = if sparse { 72 } else { 64 };
    let length = (start + pairs.len()).next_multiple_of(8);
    let mut raw = vec![0; length];
    raw[..4].copy_from_slice(&DATA.to_le_bytes());
    raw[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    raw[8] = 1;
    raw[12..14].copy_from_slice(&(if sparse { SPARSE } else { 0 }).to_le_bytes());
    raw[14..16].copy_from_slice(&id.to_le_bytes());
    raw[16..24].copy_from_slice(&first.to_le_bytes());
    raw[24..32].copy_from_slice(&(first + count - 1).to_le_bytes());
    raw[32..34].copy_from_slice(&(start as u16).to_le_bytes());
    raw[40..48].copy_from_slice(&(size.div_ceil(cluster as u64) * cluster as u64).to_le_bytes());
    raw[48..56].copy_from_slice(&size.to_le_bytes());
    raw[56..64].copy_from_slice(&size.to_le_bytes());
    if sparse {
        raw[34..36].copy_from_slice(&4_u16.to_le_bytes());
        raw[64..72].copy_from_slice(&(cluster as u64).to_le_bytes());
    }
    raw[start..start + pairs.len()].copy_from_slice(pairs);
    raw
}

fn record(number: u32, attrs: &[Vec<u8>], base: u64) -> Vec<u8> {
    let mut raw = vec![0; 1024];
    raw[..4].copy_from_slice(b"FILE");
    raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
    raw[16..18].copy_from_slice(&7_u16.to_le_bytes());
    raw[18..20].copy_from_slice(&1_u16.to_le_bytes());
    raw[20..22].copy_from_slice(&56_u16.to_le_bytes());
    raw[22..24].copy_from_slice(&1_u16.to_le_bytes());
    raw[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    raw[32..40].copy_from_slice(&base.to_le_bytes());
    raw[44..48].copy_from_slice(&number.to_le_bytes());
    let mut at = 56;
    for attr in attrs { raw[at..at + attr.len()].copy_from_slice(attr); at += attr.len(); }
    raw[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    raw[24..28].copy_from_slice(&((at + 8) as u32).to_le_bytes());
    for sector in 1..=2 {
        let saved = [raw[sector * 512 - 2], raw[sector * 512 - 1]];
        raw[48 + sector * 2..50 + sector * 2].copy_from_slice(&saved);
        raw[sector * 512 - 2..sector * 512].copy_from_slice(&0x1357_u16.to_le_bytes());
    }
    raw[48..50].copy_from_slice(&0x1357_u16.to_le_bytes());
    NtfsFileRecord::parse(&raw).unwrap();
    raw
}

const BASE: usize = 1024;
type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

struct Device {
    bytes: Arc<Vec<u8>>,
    reads: Reads,
    fail: Option<(u64, bool)>,
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 { self.bytes.len() as u64 }
    fn read_exact_at(&self, _: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push((offset.0, out.len()));
        if let Some((at, cancel)) = self.fail {
            if at == offset.0 {
                return Err(if cancel { FfsError::Cancelled } else {
                    FfsError::Io(std::io::Error::other("allocation fixture read failure"))
                });
            }
        }
        let at = offset.0 as usize;
        let bytes = self.bytes.get(at..at + out.len()).ok_or_else(|| corrupt(0, "fixture bounds"))?;
        out.copy_from_slice(bytes);
        Ok(())
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("read-only allocation checking wrote its source")
    }
    fn sync(&self, _: &Cx) -> Result<()> { panic!("read-only allocation checking flushed its source") }
}

struct Image { bytes: Vec<u8>, cluster: usize, second: usize }

impl Image {
    fn new(cluster: usize) -> Self {
        let second = if cluster == 512 { 40 } else { 12 };
        let mut image = Self { bytes: vec![0; BASE + 256 * cluster + 512], cluster, second };
        image.bytes[..BASE].fill(0xD1);
        image.bytes[BASE + 256 * cluster..].fill(0xD2);
        let boot = &mut image.bytes[BASE..BASE + 512];
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
        boot[13] = (cluster / 512) as u8;
        boot[21] = 0xF8;
        boot[36] = 0x80;
        boot[38] = 0x80;
        boot[40..48].copy_from_slice(&((256 * cluster / 512 - 1) as u64).to_le_bytes());
        boot[48..56].copy_from_slice(&4_u64.to_le_bytes());
        boot[56..64].copy_from_slice(&128_u64.to_le_bytes());
        boot[64] = 0xF6;
        boot[68] = 0xF4;
        boot[510..512].copy_from_slice(&[0x55, 0xAA]);
        let active = [0, 1, 3, 6, 7, 24, 25, 26, 27];
        let records = mask(32, active);
        let pairs = [0x11, (8192 / cluster) as u8, 4, 0x11,
            (24576 / cluster) as u8, (second - 4) as u8, 0];
        let mft = record(0, &[
            mapped(cluster, 0, &pairs, 0, (32768 / cluster) as u64, 32768, false),
            resident(0xB0, 1, &records),
        ], 0);
        image.put(0, &mft);
        image.bytes[BASE + 128 * cluster..BASE + 128 * cluster + 1024].copy_from_slice(&mft);
        image.put(1, &record(1, &[mapped(cluster, 0,
            &[0x21, (4096 / cluster) as u8, 128, 0, 0], 0, (4096 / cluster) as u64, 4096, false)], 0));
        let mut info = [0; 12]; info[8..10].copy_from_slice(&[3, 1]);
        image.put(3, &record(3, &[resident(VOLUME_INFORMATION, 0, &info)], 0));
        image.put(6, &record(6, &[mapped(cluster, 0, &[0x21, 1, 140, 0, 0], 0, 1, 32, false)], 0));
        image.put(7, &record(7, &[mapped(cluster, 0, &[0x11, 1, 0, 0], 0, 1, cluster as u64, false)], 0));
        // Two FILE records hold consecutive extents of one DATA stream. They
        // are scanned separately, not double-counted through ATTRIBUTE_LIST.
        let mut list = Vec::new();
        for (number, vcn) in [(24_u64, 0_u64), (25, 1)] {
            let mut entry = vec![0; 32];
            entry[..4].copy_from_slice(&DATA.to_le_bytes());
            entry[4..6].copy_from_slice(&32_u16.to_le_bytes());
            entry[7] = 26;
            entry[8..16].copy_from_slice(&vcn.to_le_bytes());
            entry[16..24].copy_from_slice(&((7 << 48) | number).to_le_bytes());
            list.extend(entry);
        }
        image.put(24, &record(24, &[
            mapped(cluster, 0, &[0x21, 1, 180, 0, 0], 0, 1, 2 * cluster as u64, false),
            resident(0x20, 1, &list),
        ], 0));
        image.put(25, &record(25, &[mapped(cluster, 0,
            &[0x21, 1, 170, 0, 0], 1, 1, 0, false)], (7 << 48) | 24));
        image.put(26, &record(26, &[mapped(cluster, 0,
            &[0x01, 2, 0x21, 1, 200, 0, 0x01, 2, 0], 0, 5, 5 * cluster as u64, true)], 0));
        image.put(27, &record(27, &[resident(DATA, 0, b"resident stream")], 0));
        let used = (4..4 + 8192 / cluster).chain(second..second + 24576 / cluster)
            .chain(128..128 + 4096 / cluster).chain([0, 140, 170, 180, 200]);
        let bitmap = mask(255, used.map(|n| n as u64));
        image.bytes[BASE + 140 * cluster..BASE + 140 * cluster + 32].copy_from_slice(&bitmap);
        for lcn in [170, 180, 200] {
            image.bytes[BASE + lcn * cluster..BASE + (lcn + 1) * cluster].fill(0xA5);
        }
        image
    }

    fn offset(&self, number: usize) -> usize {
        BASE + if number < 8 { 4 * self.cluster + number * 1024 }
        else { self.second * self.cluster + (number - 8) * 1024 }
    }
    fn put(&mut self, number: usize, raw: &[u8]) {
        let at = self.offset(number);
        self.bytes[at..at + raw.len()].copy_from_slice(raw);
    }
    fn open(self, fail: Option<(u64, bool)>) -> (NtfsVolume, Reads, Arc<Vec<u8>>) {
        let bytes = Arc::new(self.bytes);
        let reads: Reads = Arc::default();
        let volume = NtfsVolume::from_device(&Cx::for_testing(), Box::new(Device {
            bytes: Arc::clone(&bytes), reads: Arc::clone(&reads), fail,
        }), BASE as u64, (256 * self.cluster) as u64).unwrap();
        (volume, reads, bytes)
    }
}

#[test]
fn allocation_native_fragmented_mft_extensions_sparse_and_preallocated_metadata() {
    for cluster in [512, 4096] {
        let image = Image::new(cluster);
        let expected = image.bytes.clone();
        let (volume, reads, bytes) = image.open(None);
        reads.lock().unwrap().clear();
        let report = volume.check_allocations(&Cx::for_testing(), AllocationLimits::default()).unwrap();
        assert!(report.is_consistent(), "{report:?}");
        assert_eq!(report.allocated_records_examined, 9);
        assert_eq!(report.extension_records_examined, 1);
        assert_eq!(report.sparse_clusters, 4);
        assert_eq!(report.referenced_clusters, (32768 / cluster + 4096 / cluster + 5) as u64);
        assert_eq!(bytes.as_slice(), expected);
        for &(at, count) in reads.lock().unwrap().iter() {
            assert!(at >= BASE as u64 && at + count as u64 <= (BASE + 256 * cluster) as u64);
            for lcn in [170, 180, 200] {
                let start = (BASE + lcn * cluster) as u64;
                assert!(at + count as u64 <= start || at >= start + cluster as u64,
                    "allocation scan read ordinary payload at {at}");
            }
        }
    }
}

#[test]
fn allocation_native_cross_links_free_references_and_unexplained_bits_are_distinct() {
    let mut image = Image::new(512);
    image.put(25, &record(25, &[mapped(512, 0, &[0x21, 1, 180, 0, 0], 1, 1, 0, false)], (7 << 48) | 24));
    let bitmap = BASE + 140 * 512;
    image.bytes[bitmap + 200 / 8] &= !(1 << (200 % 8));
    let (volume, _, _) = image.open(None);
    let report = volume.check_allocations(&Cx::for_testing(), AllocationLimits::default()).unwrap();
    assert!(report.complete);
    assert!(!report.is_consistent());
    assert_eq!(report.cross_linked_clusters, 1);
    assert_eq!(report.referenced_free_clusters, 1);
    assert_eq!(report.allocated_without_reference, Some(1)); // previous extent at 170.
}

#[test]
fn allocation_torn_or_io_failed_file_prevents_absence_conclusions_but_cancellation_is_terminal() {
    for case in 0..3 {
        let mut image = Image::new(512);
        let at = image.offset(25);
        if case == 0 { image.bytes[at + 510] ^= 1; }
        let fault = (case != 0).then_some((at as u64, case == 2));
        let (volume, reads, _) = image.open(fault);
        let result = volume.check_allocations(&Cx::for_testing(), AllocationLimits::default());
        if case == 2 {
            assert!(matches!(result, Err(FfsError::Cancelled)));
            assert_eq!(reads.lock().unwrap().last().unwrap().0, at as u64);
        } else {
            let report = result.unwrap();
            assert!(!report.complete && !report.is_consistent());
            assert_eq!(report.allocated_without_reference, None);
            assert_eq!(report.errors, 1);
            assert_eq!(report.issues[0].record, Some(25));
        }
    }
}

#[test]
fn allocation_bitmap_failure_is_not_a_successful_partial_report() {
    let image = Image::new(512);
    let (volume, _, _) = image.open(Some(((BASE + 140 * 512) as u64, false)));
    assert!(volume.check_allocations(&Cx::for_testing(), AllocationLimits::default()).is_err());
}

#[test]
fn allocation_budgets_and_overlay_refusal_do_not_invent_complete_coverage() {
    let (mut volume, reads, _) = Image::new(512).open(None);
    let cx = Cx::for_testing();
    for limits in [
        AllocationLimits { records: 1, ..AllocationLimits::default() },
        AllocationLimits { clusters: 1, ..AllocationLimits::default() },
    ] {
        reads.lock().unwrap().clear();
        let report = volume.check_allocations(&cx, limits).unwrap();
        assert!(!report.complete && !report.is_consistent());
        assert!(report.limit_reached.is_some());
        assert!(reads.lock().unwrap().is_empty());
    }
    let limited = volume.check_allocations(&cx, AllocationLimits { runs: 1, ..AllocationLimits::default() }).unwrap();
    assert_eq!(limited.limit_reached, Some("mapping run budget"));
    assert_eq!(limited.allocated_without_reference, None);
    assert!(volume.check_allocations(&cx, AllocationLimits { runs: 0, ..AllocationLimits::default() }).is_err());
    volume.source.overlay.insert(0, [0; 512]);
    reads.lock().unwrap().clear();
    assert!(volume.check_allocations(&cx, AllocationLimits::default()).is_err());
    assert!(reads.lock().unwrap().is_empty());
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(asupersync::types::CancelKind::User, Some("allocation scan"));
    assert!(matches!(volume.check_allocations(&cancelled, AllocationLimits::default()), Err(FfsError::Cancelled)));
}

#[test]
fn allocation_uninitialized_records_and_invalid_mappings_cannot_certify_absence() {
    let mut image = Image::new(512);
    // Initialized MFT length can trail logical length. A set bitmap bit in
    // that uninitialized tail is not permission to read stale FILE bytes.
    for start in [image.offset(0), BASE + 128 * 512] {
        image.bytes[start + 112..start + 120].copy_from_slice(&(26_u64 * 1024).to_le_bytes());
    }
    let at = image.offset(26) as u64;
    let (volume, reads, _) = image.open(None);
    let report = volume.check_allocations(&Cx::for_testing(), AllocationLimits::default()).unwrap();
    assert_eq!(report.initialized_records, 26);
    assert_eq!(report.logical_records, 32);
    assert_eq!(report.errors, 2);
    assert_eq!(report.allocated_without_reference, None);
    assert!(!reads.lock().unwrap().iter().any(|(offset, _)| *offset == at));

    for unknown_flags in [false, true] {
        let mut image = Image::new(512);
        let mut attr = mapped(512, 0, &[0x21, 1, 44, 1, 0], 1, 1, 0, false);
        if unknown_flags { attr[12..14].copy_from_slice(&2_u16.to_le_bytes()); }
        image.put(25, &record(25, &[attr], (7 << 48) | 24));
        let (volume, _, _) = image.open(None);
        let report = volume.check_allocations(&Cx::for_testing(), AllocationLimits::default()).unwrap();
        assert!(!report.complete && !report.is_consistent());
        assert_eq!(report.allocated_without_reference, None);
        assert_eq!(report.unsupported, u64::from(unknown_flags));
        assert_eq!(report.errors, u64::from(!unknown_flags));
    }
}
