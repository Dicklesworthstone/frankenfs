//! Complete constructed labels -> native pool -> MOS -> volume reads.
//! Not an OpenZFS-produced image or proof of native interoperability.
use super::*;
use crate::reader::Pool;
use crate::reader::tests::mirror::{Fault, MIRROR_GUID, install_labels, native_config, open_bytes};
use crate::reader::tests::raidz::fixture::StripedImage;

const POOL_ROOT: u64 = DATA_OFFSET + 0x38000;

fn mirror(order: Endian, case: Case, faults: [Fault; 2]) -> (Pool, [Reads; 2]) {
    let fixture = Fixture::new(order, case);
    let mut image = fixture.image;
    image[BASE + POOL_ROOT as usize..BASE + POOL_ROOT as usize + 1024]
        .copy_from_slice(&fixture.root.data);
    let guids = [1001, 1002];
    let mut uberblock = vec![0; 1024];
    for (at, value) in [(0, 0x00ba_b10c), (8, 5000), (16, 110),
        (24, 123 + MIRROR_GUID + guids[0] + guids[1]), (32, 1)] {
        word(&mut uberblock, at, value, order);
    }
    uberblock[40..168].copy_from_slice(&pointer(
        &fixture.root.data, POOL_ROOT, 11, 0, 100, order,
        fixture.root.uberblock.root.payload_order(),
    ));
    let reads: [Reads; 2] = std::array::from_fn(|_| Arc::default());
    let mut members = Vec::new();
    for index in 0..2 {
        let mut bytes = image.clone();
        let config = native_config(guids[index], &guids, 9,
            LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES, 100);
        install_labels(&mut bytes, BASE, LENGTH as u64, order, &config, &uberblock);
        if index == 0 {
            for at in [POOL_ROOT, OLD_INDIRECT, OLD_FIRST] {
                bytes[BASE + at as usize] ^= 1;
            }
        }
        members.push(open_bytes(bytes, BASE, LENGTH as u64, Arc::clone(&reads[index]), faults[index]));
    }
    (Pool::from_leaves(members).unwrap(), reads)
}

#[test]
fn mirrored_volumes_retain_snapshot_capacity_and_bytes_after_source_drop() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let (source, reads) = mirror(order, Case::Normal, [Fault::None; 2]);
        let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
        let mut head = objects.zvol(&cx, &[], None).unwrap();
        assert_eq!(head.read(&cx, 0, 1).unwrap(), b"E");
        let mut old = objects.zvol(&cx, &[], Some(b"before")).unwrap();
        drop(objects);
        drop(source);
        assert_eq!(old.len_bytes(), 16384);
        assert_eq!(head.len_bytes(), 32768);
        assert_eq!(old.read(&cx, 0, 16384).unwrap(), expected(true, 16384));
        for at in [POOL_ROOT, OLD_INDIRECT, OLD_FIRST] {
            for member in &reads {
                assert!(member.lock().unwrap().iter().any(|(offset, _)| *offset == BASE as u64 + at));
            }
        }
        let mut out = [0; 127];
        old.read_exact_at(&cx, ByteOffset(4000), &mut out).unwrap();
        assert_eq!(out.as_slice(), &expected(true, 16384)[4000..4127]);
        assert_eq!(head.read(&cx, 0, 1).unwrap(), b"E");
    }
}

#[test]
fn volume_mirror_failures_and_cancellation_preserve_the_entire_destination() {
    let cx = Cx::for_testing();
    for cancel in [false, true] {
        let case = if cancel { Case::Normal } else { Case::CorruptLast };
        let faults = if cancel { [Fault::Cancel(BASE as u64 + OLD_LAST), Fault::None] }
            else { [Fault::None; 2] };
        let (source, reads) = mirror(Endian::Big, case, faults);
        let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
        let old = objects.zvol(&cx, &[], Some(b"before")).unwrap();
        let mut out = [0xa5; 12288];
        let result = old.read_exact_at(&cx, ByteOffset(0), &mut out);
        if cancel { assert!(matches!(result, Err(FfsError::Cancelled))); }
        else { assert!(result.is_err()); }
        assert_eq!(out, [0xa5; 12288]);
        if cancel {
            assert!(!reads[1].lock().unwrap().iter().any(|(at, _)| *at == BASE as u64 + OLD_LAST));
        }
        for member in &reads {
            assert!(!member.lock().unwrap().iter().any(|(at, _)| *at == BASE as u64 + HEAD_FIRST));
        }
    }
}

#[test]
fn volume_snapshots_reconstruct_through_all_three_native_raidz_parities() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for parity in 1..=3 {
            let fixture = Fixture::new(order, Case::Normal);
            let root_order = fixture.root.uberblock.root.payload_order();
            let width = 2 * parity + 2;
            let mut image = StripedImage::graph_with_parity(
                &fixture.image, fixture.root.data, root_order, width, 110, 100, parity,
            );
            for index in 0..parity {
                image.poison(OLD_LAST, parity + index, 0);
            }
            let source = image.open(&vec![Fault::None; width], true);
            let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
            let mut old = objects.zvol(&cx, &[], Some(b"before")).unwrap();
            assert_eq!(old.read(&cx, 4071, 8230).unwrap(), expected(true, 16384)[4071..12301]);
            assert_eq!(old.seek_data_hole(&cx, 4096, true).unwrap(), 8192);
            assert_eq!((old.info().view_txg, old.len_bytes()), (40, 16384));
            assert_eq!(objects.zvol(&cx, &[], None).unwrap().read(&cx, 0, 1).unwrap(), b"E");
        }
    }
}
