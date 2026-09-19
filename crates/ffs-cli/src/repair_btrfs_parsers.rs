use anyhow::Result;

#[cfg(test)]
use ffs_ondisk::btrfs::BTRFS_FIRST_CHUNK_TREE_OBJECTID;

pub fn parse_btrfs_root_item_bytenr(data: &[u8]) -> Result<u64> {
    if data.len() < 184 {
        anyhow::bail!(
            "btrfs root item payload too short: expected at least 184 bytes, got {}",
            data.len()
        );
    }
    let mut bytenr_raw = [0_u8; 8];
    bytenr_raw.copy_from_slice(&data[176..184]);
    let bytenr = u64::from_le_bytes(bytenr_raw);
    if bytenr == 0 {
        anyhow::bail!("btrfs root item bytenr must be non-zero");
    }
    Ok(bytenr)
}

/// The three fields of one on-disk btrfs block-group item.
///
/// Kernel `struct btrfs_block_group_item` is `{ used: le64 @0,
/// chunk_objectid: le64 @8, flags: le64 @16 }` — 24 bytes. There is NO
/// `total_bytes` in the item: a block group's length is carried by its KEY
/// (`key.offset`), never by the payload. The previous
/// `parse_btrfs_block_group_total_bytes` read `data[8..16]` as "total", which
/// is the `chunk_objectid` slot — the constant
/// `BTRFS_FIRST_CHUNK_TREE_OBJECTID` (256) on every well-formed image
/// (bd-k1738).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsBlockGroupItemFields {
    /// Bytes currently allocated within the block group.
    pub used: u64,
    /// Kernel writes `BTRFS_FIRST_CHUNK_TREE_OBJECTID` (256) here on every
    /// block-group item; a different value means the extent tree is corrupt.
    pub chunk_objectid: u64,
    /// Type flags (DATA, METADATA, SYSTEM).
    pub flags: u64,
}

pub fn parse_btrfs_block_group_item(data: &[u8]) -> Result<BtrfsBlockGroupItemFields> {
    if data.len() < 24 {
        anyhow::bail!(
            "btrfs block-group payload too short: expected at least 24 bytes, got {}",
            data.len()
        );
    }
    let mut used_raw = [0_u8; 8];
    used_raw.copy_from_slice(&data[0..8]);
    let mut chunk_objectid_raw = [0_u8; 8];
    chunk_objectid_raw.copy_from_slice(&data[8..16]);
    let mut flags_raw = [0_u8; 8];
    flags_raw.copy_from_slice(&data[16..24]);
    Ok(BtrfsBlockGroupItemFields {
        used: u64::from_le_bytes(used_raw),
        chunk_objectid: u64::from_le_bytes(chunk_objectid_raw),
        flags: u64::from_le_bytes(flags_raw),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_item_payload(bytenr: u64) -> Vec<u8> {
        let mut payload = vec![0_u8; 184];
        payload[176..184].copy_from_slice(&bytenr.to_le_bytes());
        payload
    }

    fn block_group_item_payload(used: u64, chunk_objectid: u64, flags: u64) -> Vec<u8> {
        let mut payload = vec![0_u8; 24];
        payload[0..8].copy_from_slice(&used.to_le_bytes());
        payload[8..16].copy_from_slice(&chunk_objectid.to_le_bytes());
        payload[16..24].copy_from_slice(&flags.to_le_bytes());
        payload
    }

    #[test]
    fn parse_root_item_bytenr_rejects_empty_payload() {
        let err = parse_btrfs_root_item_bytenr(&[]).expect_err("empty payload must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("too short"),
            "error must mention length: {msg}"
        );
        assert!(
            msg.contains("184"),
            "error must mention required size: {msg}"
        );
        assert!(
            msg.ends_with("got 0"),
            "error must report actual length: {msg}"
        );
    }

    #[test]
    fn parse_root_item_bytenr_rejects_one_byte_under_minimum() {
        let err = parse_btrfs_root_item_bytenr(&[0xFF_u8; 183])
            .expect_err("183-byte payload must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("too short"),
            "error must mention length: {msg}"
        );
        assert!(
            msg.ends_with("got 183"),
            "error must report actual length: {msg}"
        );
    }

    #[test]
    fn parse_root_item_bytenr_rejects_zero_bytenr_at_minimum_length() {
        let err = parse_btrfs_root_item_bytenr(&root_item_payload(0))
            .expect_err("zero bytenr must be rejected");
        assert!(
            err.to_string().contains("non-zero"),
            "error must mention non-zero rule: {err}"
        );
    }

    #[test]
    fn parse_root_item_bytenr_accepts_minimum_length_with_valid_bytenr() {
        let bytenr = parse_btrfs_root_item_bytenr(&root_item_payload(0x0000_1234_5678_9ABC))
            .expect("valid bytenr should parse");
        assert_eq!(bytenr, 0x0000_1234_5678_9ABC);
    }

    #[test]
    fn parse_root_item_bytenr_accepts_payload_longer_than_minimum() {
        let mut payload = root_item_payload(0xCAFE_BABE_F00D_BAAD);
        payload.extend(std::iter::repeat_n(0xFF_u8, 64));
        let bytenr =
            parse_btrfs_root_item_bytenr(&payload).expect("oversized payload must still parse");
        assert_eq!(bytenr, 0xCAFE_BABE_F00D_BAAD);
    }

    #[test]
    fn parse_root_item_bytenr_decodes_little_endian_at_offset_176() {
        let mut payload = vec![0xAB_u8; 184];
        payload[176..184].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let bytenr =
            parse_btrfs_root_item_bytenr(&payload).expect("little-endian pattern must decode");
        assert_eq!(bytenr, 0x0807_0605_0403_0201);
    }

    #[test]
    fn parse_root_item_bytenr_ignores_bytes_outside_offset_window() {
        let mut payload = vec![0xAA_u8; 184];
        payload[176..184].copy_from_slice(&[0_u8; 8]);
        let err = parse_btrfs_root_item_bytenr(&payload)
            .expect_err("zero bytenr in window must be rejected despite surrounding noise");
        assert!(err.to_string().contains("non-zero"));
    }

    #[test]
    fn parse_root_item_bytenr_accepts_u64_max() {
        let bytenr = parse_btrfs_root_item_bytenr(&root_item_payload(u64::MAX))
            .expect("u64::MAX is non-zero");
        assert_eq!(bytenr, u64::MAX);
    }

    #[test]
    fn parse_root_item_bytenr_only_reads_offset_176_to_184() {
        // Decoy non-zero bytes elsewhere must not be mistaken for bytenr.
        let mut payload = vec![0_u8; 184];
        payload[0..8].copy_from_slice(&0xDEAD_BEEF_u64.to_le_bytes());
        payload[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        let err = parse_btrfs_root_item_bytenr(&payload)
            .expect_err("decoy bytes outside the bytenr window must not be parsed as bytenr");
        assert!(err.to_string().contains("non-zero"));
    }

    #[test]
    fn parse_block_group_item_rejects_empty_payload() {
        let err = parse_btrfs_block_group_item(&[])
            .expect_err("empty block-group payload must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("too short"),
            "error must mention length: {msg}"
        );
        assert!(
            msg.contains("24"),
            "error must mention required size: {msg}"
        );
        assert!(
            msg.ends_with("got 0"),
            "error must report actual length: {msg}"
        );
    }

    #[test]
    fn parse_block_group_item_rejects_one_byte_under_minimum() {
        let err = parse_btrfs_block_group_item(&[0xFF_u8; 23])
            .expect_err("23-byte payload must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("too short"),
            "error must mention length: {msg}"
        );
        assert!(
            msg.ends_with("got 23"),
            "error must report actual length: {msg}"
        );
    }

    #[test]
    fn parse_block_group_item_decodes_fields_at_kernel_offsets() {
        // Kernel struct btrfs_block_group_item: used @0, chunk_objectid @8,
        // flags @16, all little-endian u64.
        let item = parse_btrfs_block_group_item(&block_group_item_payload(
            0x1122_3344_5566_7788,
            BTRFS_FIRST_CHUNK_TREE_OBJECTID,
            0xCAFE_BABE_DEAD_BEEF,
        ))
        .expect("well-formed item must parse");
        assert_eq!(item.used, 0x1122_3344_5566_7788);
        assert_eq!(item.chunk_objectid, BTRFS_FIRST_CHUNK_TREE_OBJECTID);
        assert_eq!(item.flags, 0xCAFE_BABE_DEAD_BEEF);
    }

    #[test]
    fn parse_block_group_item_accepts_payload_longer_than_minimum() {
        let mut payload = block_group_item_payload(0x4000_0000, 256, 0x01);
        payload.extend(std::iter::repeat_n(0x55_u8, 32));
        let item =
            parse_btrfs_block_group_item(&payload).expect("oversized payload must still parse");
        assert_eq!(item.used, 0x4000_0000);
        assert_eq!(item.chunk_objectid, 256);
        assert_eq!(item.flags, 0x01);
    }

    #[test]
    fn parse_block_group_item_accepts_zero_used() {
        // used == 0 is legitimate: a freshly allocated block group is empty.
        let item = parse_btrfs_block_group_item(&block_group_item_payload(
            0,
            BTRFS_FIRST_CHUNK_TREE_OBJECTID,
            0x01,
        ))
        .expect("zero used must parse");
        assert_eq!(item.used, 0);
    }

    #[test]
    fn parse_block_group_item_accepts_u64_max_used() {
        let item = parse_btrfs_block_group_item(&block_group_item_payload(
            u64::MAX,
            BTRFS_FIRST_CHUNK_TREE_OBJECTID,
            0x04,
        ))
        .expect("u64::MAX used must parse");
        assert_eq!(item.used, u64::MAX);
    }

    // bd-vn9q4: metamorphic relations for the two btrfs scalar parsers.
    // Fixed-input tests cover endianness and offsets at named values; these
    // proptests sweep arbitrary inputs to catch regressions where the parser
    // reads from a near-but-wrong window or stops respecting append-invariance.
    proptest::proptest! {
        // MR-1 round-trip / determinism: stamp(v) → parse → v, for any non-zero u64.
        #[test]
        fn root_item_bytenr_round_trip(bytenr in 1_u64..=u64::MAX) {
            let payload = root_item_payload(bytenr);
            let parsed = parse_btrfs_root_item_bytenr(&payload).expect("non-zero must parse");
            proptest::prop_assert_eq!(parsed, bytenr);
        }

        // MR-2 field-locality: bytes outside [176..184] are not read.
        // Build payload with valid bytenr, then overwrite the surrounding
        // 176 bytes with arbitrary noise — parsed result must not change.
        #[test]
        fn root_item_bytenr_ignores_noise_outside_window(
            bytenr in 1_u64..=u64::MAX,
            prefix in proptest::collection::vec(proptest::prelude::any::<u8>(), 176),
        ) {
            let mut payload = root_item_payload(bytenr);
            payload[..176].copy_from_slice(&prefix);
            let parsed = parse_btrfs_root_item_bytenr(&payload).expect("bytenr unchanged");
            proptest::prop_assert_eq!(parsed, bytenr);
        }

        // MR-3 append-invariance: appending arbitrary bytes after the minimum
        // 184-byte payload must not change the parsed bytenr.
        #[test]
        fn root_item_bytenr_append_invariant(
            bytenr in 1_u64..=u64::MAX,
            suffix in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let mut payload = root_item_payload(bytenr);
            payload.extend_from_slice(&suffix);
            let parsed = parse_btrfs_root_item_bytenr(&payload).expect("oversized must parse");
            proptest::prop_assert_eq!(parsed, bytenr);
        }

        // MR-1 round-trip / determinism for each block-group item field.
        #[test]
        fn block_group_item_round_trip(
            used in proptest::prelude::any::<u64>(),
            chunk_objectid in proptest::prelude::any::<u64>(),
            flags in proptest::prelude::any::<u64>(),
        ) {
            let payload = block_group_item_payload(used, chunk_objectid, flags);
            let parsed = parse_btrfs_block_group_item(&payload)
                .expect("well-formed item must parse");
            proptest::prop_assert_eq!(parsed.used, used);
            proptest::prop_assert_eq!(parsed.chunk_objectid, chunk_objectid);
            proptest::prop_assert_eq!(parsed.flags, flags);
        }

        // MR-2 field-locality: each field decodes only from its own 8-byte
        // window; arbitrary noise in the other two windows must not leak in.
        #[test]
        fn block_group_item_fields_are_field_local(
            used in proptest::prelude::any::<u64>(),
            chunk_objectid in proptest::prelude::any::<u64>(),
            flags in proptest::prelude::any::<u64>(),
        ) {
            let mut payload = block_group_item_payload(used, chunk_objectid, flags);
            payload[0..8].reverse();
            payload[16..24].reverse();
            let parsed = parse_btrfs_block_group_item(&payload)
                .expect("reversed bytes are still well-formed");
            proptest::prop_assert_eq!(parsed.used, used.swap_bytes());
            proptest::prop_assert_eq!(parsed.chunk_objectid, chunk_objectid);
            proptest::prop_assert_eq!(parsed.flags, flags.swap_bytes());
        }

        // MR-3 append-invariance for the block-group payload.
        #[test]
        fn block_group_item_append_invariant(
            used in proptest::prelude::any::<u64>(),
            chunk_objectid in proptest::prelude::any::<u64>(),
            flags in proptest::prelude::any::<u64>(),
            suffix in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let mut payload = block_group_item_payload(used, chunk_objectid, flags);
            payload.extend_from_slice(&suffix);
            let parsed = parse_btrfs_block_group_item(&payload)
                .expect("oversized must parse");
            proptest::prop_assert_eq!(parsed.used, used);
            proptest::prop_assert_eq!(parsed.chunk_objectid, chunk_objectid);
            proptest::prop_assert_eq!(parsed.flags, flags);
        }

        // bd-k1738 cross-crate round-trip: ffs_btrfs writes a kernel-aligned
        // btrfs_block_group_item ({used, chunk_objectid=256, flags}); the
        // repair parser must read back exactly those fields. The group's
        // total_bytes is NOT representable in the item payload — the kernel
        // conveys it via the item key's offset — so the previous version of
        // this test demanded the parser return total from the chunk_objectid
        // slot and failed on every input.
        #[test]
        fn btrfs_block_group_item_writer_to_parser_round_trip(
            total in 1_u64..=u64::MAX,
            used in proptest::prelude::any::<u64>(),
            flags in proptest::prelude::any::<u64>(),
        ) {
            let written = ffs_btrfs::BtrfsBlockGroupItem {
                total_bytes: total,
                used_bytes: used,
                flags,
            }
            .to_bytes();
            proptest::prop_assert_eq!(written.len(), 24, "kernel-aligned 24-byte item");
            let parsed = parse_btrfs_block_group_item(&written)
                .expect("writer output must parse");
            proptest::prop_assert_eq!(parsed.used, used);
            proptest::prop_assert_eq!(
                parsed.chunk_objectid,
                BTRFS_FIRST_CHUNK_TREE_OBJECTID,
                "chunk_objectid slot must stay at the kernel constant"
            );
            proptest::prop_assert_eq!(parsed.flags, flags);
        }
    }

    // bd-k1738 named cross-crate round-trip — pins the writer-reader contract
    // for the canonical block-group sizes used in repair scenarios.
    #[test]
    fn btrfs_block_group_item_writer_to_parser_canonical_sizes() {
        for total in [
            8 * 1024 * 1024_u64,         // 8 MiB — minimum profile
            256 * 1024 * 1024,           // 256 MiB
            1024 * 1024 * 1024,          // 1 GiB — typical data BG size
            16_u64 * 1024 * 1024 * 1024, // 16 GiB — large data BG
        ] {
            let bytes = ffs_btrfs::BtrfsBlockGroupItem {
                total_bytes: total,
                used_bytes: total / 2,
                flags: 0x01, // BTRFS_BLOCK_GROUP_DATA
            }
            .to_bytes();
            let parsed = parse_btrfs_block_group_item(&bytes)
                .unwrap_or_else(|err| panic!("canonical size {total} must parse: {err}"));
            assert_eq!(parsed.used, total / 2, "used round-trip for size {total}");
            assert_eq!(
                parsed.chunk_objectid, BTRFS_FIRST_CHUNK_TREE_OBJECTID,
                "chunk_objectid slot for size {total}"
            );
            assert_eq!(parsed.flags, 0x01, "flags round-trip for size {total}");
        }
    }
}
