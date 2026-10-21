//! Gang-fixture allocation and encoding, separate from the reader's tree walk.

use super::*;
use crate::reader::tests::gang::{encode, seal_header};

impl StripedImage {
    pub(in crate::reader) fn gang_graph(
        source: &[u8],
        mut root: Vec<u8>,
        order: Endian,
        width: usize,
        txg: u64,
        birth: u64,
        parity: usize,
    ) -> Self {
        let mut image = Self::new(order, width, 9, txg, birth, parity);
        image.gang_next = Some(0x40_0000);
        image.rewrite_block(source, &mut root, 11, 0, order, 0);
        let mut pointer = encode(&root, order, 11, birth);
        image.fragment_pointer(ROOT, &mut pointer, order, &root, 2);
        image.uberblock[40..168].copy_from_slice(&pointer);
        image.root = root;
        image.refresh_labels();
        image
    }

    fn reserve_gang(&mut self, size: usize) -> (u64, NativeMap) {
        let offset = self.gang_next.expect("gang fixture allocator enabled");
        let map =
            NativeMap::new(offset, size, self.ashift, self.members.len(), self.parity).unwrap();
        self.gang_next = Some(offset + map.allocated_bytes());
        (offset, map)
    }

    /// Preserve the leader's type, birth, byte order and transform. Child
    /// pointers describe already transformed physical bytes as DMU_OT_NONE.
    pub(super) fn fragment_pointer(
        &mut self,
        key: u64,
        raw: &mut [u8],
        container: Endian,
        physical: &[u8],
        depth: usize,
    ) {
        let pointer = BlockPointer::parse(raw, container).unwrap();
        let order = pointer.payload_order();
        let (first, first_map) = self.reserve_gang(512);
        let (second, second_map) = self.reserve_gang(512);
        let mut header = [0; 512];
        let mut totals = [first_map.allocated_bytes(), second_map.allocated_bytes()];
        let mut child_keys = Vec::new();
        let mut start = 0;
        for slot in 0..3 {
            if start == physical.len() {
                break;
            }
            let length = (physical.len() - start)
                .div_ceil(3 - slot)
                .next_multiple_of(512);
            let data = &physical[start..start + length];
            let mut child = encode(data, order, 0, pointer.physical_birth());
            if depth != 0 && data.len() > 512 {
                let child_key = DATA_OFFSET + self.gang_next.unwrap();
                self.fragment_pointer(child_key, &mut child, order, data, depth - 1);
                child_keys.push(child_key);
            } else {
                let (offset, map) = self.reserve_gang(data.len());
                let child_key = DATA_OFFSET + offset;
                self.store(child_key, offset, data);
                child[..8].copy_from_slice(&order.encode(map.allocated_bytes() / 512));
                child[8..16].copy_from_slice(&order.encode(offset / 512));
                child_keys.push(child_key);
            }
            for (index, total) in totals.iter_mut().enumerate() {
                *total += (order.u64(&child, index * 16).unwrap() & 0x00ff_ffff) * 512;
            }
            header[slot * 128..(slot + 1) * 128].copy_from_slice(&child);
            start += length;
        }
        assert_eq!(start, physical.len());
        raw[..48].fill(0);
        for (index, offset) in [first, second].into_iter().enumerate() {
            raw[index * 16..index * 16 + 8].copy_from_slice(&container.encode(totals[index] / 512));
            raw[index * 16 + 8..index * 16 + 16]
                .copy_from_slice(&container.encode((1 << 63) | (offset / 512)));
        }
        for (index, value) in checksum(physical, pointer.checksum_type(), order)
            .unwrap()
            .into_iter()
            .enumerate()
        {
            raw[96 + index * 8..104 + index * 8].copy_from_slice(&container.encode(value));
        }
        // The header's child-pointer order may differ from its parent's
        // container. Encode the verifier parent in the header order too.
        let mut verifier = [0; 128];
        for index in 0..16 {
            verifier[index * 8..index * 8 + 8]
                .copy_from_slice(&order.encode(container.u64(raw, index * 8).unwrap()));
        }
        seal_header(&mut header, &verifier, order);
        self.store(key, first, &header);
        self.store(DATA_OFFSET + second, second, &header);
        let words = std::array::from_fn(|index| {
            let at = if index < 6 {
                index * 8
            } else {
                96 + (index - 6) * 8
            };
            container.u64(raw, at).unwrap()
        });
        self.gang_rewrites.insert(key, words);
        self.gang_children.insert(key, child_keys);
    }

    pub(in crate::reader) fn gang_children(&self, key: u64) -> &[u64] {
        self.gang_children
            .get(&key)
            .expect("fragmented fixture parent")
    }
}
