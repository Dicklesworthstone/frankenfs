//! Independent native gang-pointer encoding for complete filesystem fixtures.

use super::*;

pub(in crate::reader) fn encode(data: &[u8], order: Endian, kind: u8, birth: u64) -> [u8; 128] {
    let sectors = data.len() as u64 / 512;
    assert!(sectors != 0 && data.len().is_multiple_of(512));
    let mut raw = [0; 128];
    let properties = (sectors - 1)
        | ((sectors - 1) << 16)
        | (2 << 32)
        | (7 << 40)
        | (u64::from(kind) << 48)
        | (u64::from(order == Endian::Little) << 63);
    raw[48..56].copy_from_slice(&order.encode(properties));
    raw[80..88].copy_from_slice(&order.encode(birth));
    for (index, value) in checksum(data, 7, order).unwrap().into_iter().enumerate() {
        raw[96 + index * 8..104 + index * 8].copy_from_slice(&order.encode(value));
    }
    raw
}

pub(in crate::reader) fn seal_header(raw: &mut [u8], parent: &[u8], order: Endian) {
    let physical = order.u64(parent, 72).unwrap();
    let verifier = [
        0x0210_da7a_b10c_7a11,
        (order.u64(parent, 0).unwrap() >> 32) & 0x00ff_ffff,
        (order.u64(parent, 8).unwrap() & 0x7fff_ffff_ffff_ffff) * 512,
        if physical == 0 {
            order.u64(parent, 80).unwrap()
        } else {
            physical
        },
        0,
    ];
    for (index, value) in verifier.into_iter().enumerate() {
        raw[472 + index * 8..480 + index * 8].copy_from_slice(&order.encode(value));
    }
    for (index, value) in checksum(raw, 8, order).unwrap().into_iter().enumerate() {
        raw[480 + index * 8..488 + index * 8].copy_from_slice(&order.encode(value));
    }
}
