//! Strict per-record admission after native checksum/sequence verification.
//! No unknown operation, type flag, suffix or missing payload may disappear
//! from a successful replay. Block framing belongs to the native verifier.
//!
//! Layout: OpenZFS zfs-2.3.0 include/sys/zil.h and module/zfs/zfs_replay.c.

use super::{Cx, Result, checkpoint, corrupt, parse as parse_error, unsupported};
use ffs_ondisk::zfs::Endian;
use ffs_ondisk::zfs_dmu::{ZilRecord, ZilRecordPayload};

#[cfg(test)]
const CHAIN_BYTES: usize = 184;
#[cfg(test)]
const MAX_RECORDS: usize = 65_536;

fn word(raw: &[u8], at: usize, order: Endian) -> Result<u64> {
    order.u64(raw, at).map_err(|error| parse_error(&error))
}

fn padded_record(bytes: &[u8], used: usize) -> Result<()> {
    if used > bytes.len() || bytes.len() - used >= 8 {
        return Err(corrupt(
            "ZIL record contains missing data or an unexplained suffix",
        ));
    }
    // Native alignment padding is not required to contain zeroes.
    Ok(())
}

fn names_end(bytes: &[u8], mut at: usize, count: usize) -> Result<usize> {
    for _ in 0..count {
        let suffix = bytes
            .get(at..)
            .ok_or_else(|| corrupt("truncated ZIL name"))?;
        let length = suffix
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| corrupt("unterminated ZIL name or link target"))?;
        if length == 0 {
            return Err(corrupt("empty ZIL name or link target"));
        }
        at += length + 1;
    }
    Ok(at)
}

pub(super) fn verified(cx: &Cx, record: &[u8], order: Endian) -> Result<ZilRecord> {
    checkpoint(cx)?;
    if record.len() < 32
        || !record.len().is_multiple_of(8)
        || word(record, 8, order)? != record.len() as u64
    {
        return Err(corrupt("invalid complete ZIL record span"));
    }
    let kind = word(record, 0, order)?;
    if matches!(kind, 9 | 10) {
        let object = word(record, 32, order)?;
        let offset = word(record, 40, order)?;
        let length = word(record, 48, order)?;
        if object == 0
            || object >= 1_u64 << 48
            || offset > i64::MAX as u64
            || length > i64::MAX as u64 - offset
        {
            return Err(corrupt("ZIL file identity or signed file range is invalid"));
        }
    }
    // Do not mask unknown type bits into a different known operation.
    // TX_CI, ACL/xvattr creates, WRITE2 and newer operations need their own
    // semantics. None may silently disappear from a successful replay.
    match kind {
        1 | 2 | 4 => {
            if record.len() < 104 {
                return Err(corrupt("truncated plain ZIL create record"));
            }
            let foid = word(record, 40, order)?;
            if foid & 0x00FF_0000_0000_0000 != 0 || foid >> 56 >= 32 {
                return Err(unsupported("unsupported ZIL create object/slot encoding"));
            }
            if word(record, 96, order)? != 0 {
                return Err(unsupported("ZIL device creation is not implemented"));
            }
            padded_record(
                record,
                names_end(record, 104, if kind == 4 { 2 } else { 1 })?,
            )?;
        }
        5 | 6 => padded_record(record, names_end(record, 40, 1)?)?,
        7 => {
            for at in [32, 40] {
                let object = word(record, at, order)?;
                if object == 0 || object >= 1_u64 << 48 {
                    return Err(corrupt("invalid ZIL hard-link object identity"));
                }
            }
            padded_record(record, names_end(record, 48, 1)?)?;
        }
        8 | 22 => {
            for at in [32, 40] {
                let object = word(record, at, order)?;
                if object == 0 || object >= 1_u64 << 48 {
                    return Err(corrupt("invalid ZIL rename directory identity"));
                }
            }
            padded_record(record, names_end(record, 48, 2)?)?;
        }
        9 => {
            if record.len() < 192 {
                return Err(corrupt("truncated ZIL write record"));
            }
            if record.len() > 192 {
                let bytes = word(record, 48, order)?;
                if bytes == 0 || bytes > (record.len() - 192) as u64 {
                    return Err(corrupt("ZIL inline write is missing its declared bytes"));
                }
                padded_record(record, 192 + bytes as usize)?;
            }
        }
        10 if record.len() == 56 => {}
        11 if record.len() == 112 => {
            if word(record, 40, order)? & !0x3F != 0 {
                return Err(unsupported(
                    "extended ZIL setattr masks need native decoding",
                ));
            }
        }
        10 | 11 => return Err(corrupt("invalid fixed-size ZIL truncate/setattr record")),
        21 => {
            let object = word(record, 32, order)?;
            if object == 0 || object >= 1_u64 << 48 {
                return Err(corrupt("invalid ZIL SA xattr object identity"));
            }
            let start = names_end(record, 48, 1)?;
            let size = word(record, 40, order)?;
            if start - 49 > ffs_ondisk::zfs_zpl::XATTR_NAME_BYTES || size > 32_768 {
                return Err(unsupported("ZIL SA xattr exceeds native name/value limits"));
            }
            padded_record(record, start + size as usize)?;
        }
        _ => {
            return Err(unsupported(
                "ZIL operation or type flags are not implemented for replay",
            ));
        }
    }
    let mut record = ZilRecord::parse(record, order).map_err(|error| parse_error(&error))?;
    if let ZilRecordPayload::Create {
        symlink_target,
        is_dir,
        ..
    } = &mut record.payload
    {
        // A plain create has ONE name. Arbitrary alignment padding after
        // it must not become a second string and hence a symbolic link.
        if record.txtype != 4 {
            *symlink_target = None;
        }
        *is_dir = record.txtype == 2;
    }
    checkpoint(cx)?;
    Ok(record)
}

#[cfg(test)]
fn parse(cx: &Cx, raw: &[u8], order: Endian) -> Result<ffs_ondisk::zfs_dmu::ZilBlock> {
    checkpoint(cx)?;
    if raw.len() < 512
        || raw.len() > ffs_ondisk::zfs::MAX_BLOCK_BYTES
        || !raw.len().is_multiple_of(512)
    {
        return Err(corrupt("invalid ZIL block size"));
    }
    let trailer = raw.len() - CHAIN_BYTES;
    let used = word(raw, trailer + 136, order)?;
    if used > trailer as u64 || !used.is_multiple_of(8) {
        return Err(corrupt(
            "ZIL used bytes overlap the chain trailer or are unaligned",
        ));
    }
    let mut at = 0;
    let mut records = Vec::new();
    while at < used as usize {
        checkpoint(cx)?;
        if records.len() == MAX_RECORDS || used as usize - at < 32 {
            return Err(corrupt("partial or excessive legacy ZIL records"));
        }
        let length = word(raw, at + 8, order)?;
        if length < 32 || !length.is_multiple_of(8) || length > used - at as u64 {
            return Err(corrupt("invalid ZIL record length inside used bytes"));
        }
        let end = at + length as usize;
        if word(raw, at, order)? == 9 && length == 192 {
            return Err(unsupported(
                "legacy framing does not load indirect ZIL writes",
            ));
        }
        records.push(verified(cx, &raw[at..end], order)?);
        at = end;
    }
    checkpoint(cx)?;
    Ok(ffs_ondisk::zfs_dmu::ZilBlock {
        next_blk: ffs_ondisk::zfs::BlockPointer::parse(&raw[trailer + 8..trailer + 136], order)
            .map_err(|error| parse_error(&error))?,
        nused: used,
        records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u64, body: &[u8], order: Endian) -> Vec<u8> {
        let mut result = vec![0xA5; (32 + body.len()).next_multiple_of(8)];
        let length = result.len() as u64;
        for (at, value) in [(0, kind), (8, length), (16, 62), (24, 1)] {
            result[at..at + 8].copy_from_slice(&order.encode(value));
        }
        result[32..32 + body.len()].copy_from_slice(body);
        result
    }

    fn block(records: &[u8], used: u64, order: Endian) -> Vec<u8> {
        let mut result = vec![0; (records.len() + CHAIN_BYTES).max(512).next_multiple_of(512)];
        result[..records.len()].copy_from_slice(records);
        let at = result.len() - CHAIN_BYTES + 136;
        result[at..at + 8].copy_from_slice(&order.encode(used));
        result
    }

    fn inline(order: Endian) -> Vec<u8> {
        let mut body = vec![0; 160];
        body[..8].copy_from_slice(&order.encode(3));
        body[8..16].copy_from_slice(&order.encode(1_u64 << 33));
        body[16..24].copy_from_slice(&order.encode(3));
        body.extend_from_slice(b"A\0B");
        record(9, &body, order)
    }

    #[test]
    fn complete_inline_bytes_survive_both_orders_and_arbitrary_alignment_padding() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            let bytes = inline(order);
            let parsed = parse(&cx, &block(&bytes, bytes.len() as u64, order), order).unwrap();
            let ZilRecordPayload::Write {
                offset,
                inline_data,
                ..
            } = &parsed.records[0].payload
            else {
                panic!("write");
            };
            assert_eq!(*offset, 1_u64 << 33);
            assert_eq!(inline_data, b"A\0B");
        }
    }

    #[test]
    fn hard_link_records_preserve_native_ids_names_and_exact_framing() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            let mut body = Vec::new();
            body.extend_from_slice(&order.encode(2));
            body.extend_from_slice(&order.encode((1_u64 << 48) - 1));
            body.extend_from_slice(b"alias\0");
            let bytes = record(7, &body, order);
            let parsed = parse(&cx, &block(&bytes, bytes.len() as u64, order), order).unwrap();
            assert_eq!(
                parsed.records[0].payload,
                ZilRecordPayload::Link {
                    dir_obj: 2,
                    file_obj: (1_u64 << 48) - 1,
                    name: b"alias".to_vec(),
                }
            );
            // The inspection parser also retains links instead of skipping
            // type 7 while reporting the surrounding records.
            assert_eq!(
                ffs_ondisk::zfs_dmu::ZilBlock::parse(
                    &block(&bytes, bytes.len() as u64, order),
                    order,
                )
                .unwrap()
                .records,
                parsed.records
            );
            for at in [32, 40] {
                for id in [0, 1_u64 << 48, u64::MAX] {
                    let mut bad = bytes.clone();
                    bad[at..at + 8].copy_from_slice(&order.encode(id));
                    assert!(verified(&cx, &bad, order).is_err());
                }
            }
            for kind in [7 | (1_u64 << 63), 7 | 32] {
                let mut bad = bytes.clone();
                bad[..8].copy_from_slice(&order.encode(kind));
                assert!(matches!(
                    verified(&cx, &bad, order),
                    Err(super::super::FfsError::UnsupportedFeature(_))
                ));
            }
            let mut empty = bytes.clone();
            empty[48] = 0;
            assert!(verified(&cx, &empty, order).is_err());
            let mut unterminated = bytes.clone();
            unterminated[48..].fill(b'x');
            assert!(verified(&cx, &unterminated, order).is_err());
            let mut suffix = bytes.clone();
            suffix.extend_from_slice(&[0; 8]);
            let length = suffix.len() as u64;
            suffix[8..16].copy_from_slice(&order.encode(length));
            assert!(verified(&cx, &suffix, order).is_err());
            assert!(verified(&cx, &record(7, &body[..16], order), order).is_err());
        }
    }

    #[test]
    fn rename_exchange_records_keep_both_names_and_reject_bad_framing() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            let mut body = Vec::new();
            body.extend_from_slice(&order.encode(2));
            body.extend_from_slice(&order.encode((1_u64 << 48) - 1));
            body.extend_from_slice(b"left\0right\0");
            let bytes = record(22, &body, order);
            let parsed = parse(&cx, &block(&bytes, bytes.len() as u64, order), order).unwrap();
            assert_eq!(
                parsed.records[0].payload,
                ZilRecordPayload::RenameExchange {
                    src_dir_obj: 2,
                    dst_dir_obj: (1_u64 << 48) - 1,
                    src_name: b"left".to_vec(),
                    dst_name: b"right".to_vec(),
                }
            );
            assert_eq!(
                ffs_ondisk::zfs_dmu::ZilBlock::parse(
                    &block(&bytes, bytes.len() as u64, order),
                    order,
                )
                .unwrap()
                .records,
                parsed.records
            );
            for at in [32, 40] {
                for id in [0, 1_u64 << 48, u64::MAX] {
                    let mut bad = bytes.clone();
                    bad[at..at + 8].copy_from_slice(&order.encode(id));
                    assert!(verified(&cx, &bad, order).is_err());
                }
            }
            for kind in [0x16 | (1_u64 << 63), 0x16 | 0x20] {
                let mut bad = bytes.clone();
                bad[..8].copy_from_slice(&order.encode(kind));
                assert!(matches!(
                    verified(&cx, &bad, order),
                    Err(super::super::FfsError::UnsupportedFeature(_))
                ));
            }
            for at in [48, 53] {
                let mut empty = bytes.clone();
                empty[at] = 0;
                assert!(verified(&cx, &empty, order).is_err());
            }
            let mut unterminated = bytes.clone();
            unterminated[53..].fill(b'x');
            assert!(verified(&cx, &unterminated, order).is_err());
            let mut suffix = bytes.clone();
            suffix.extend_from_slice(&[0; 8]);
            let length = suffix.len() as u64;
            suffix[8..16].copy_from_slice(&order.encode(length));
            assert!(verified(&cx, &suffix, order).is_err());
            assert!(verified(&cx, &record(22, &body[..21], order), order).is_err());
        }
    }

    #[test]
    fn sa_xattr_records_preserve_binary_values_removal_and_exact_native_framing() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            let mut body = Vec::new();
            body.extend_from_slice(&order.encode(7));
            body.extend_from_slice(&order.encode(4));
            body.extend_from_slice(b"user.binary\0\0\xffA\0");
            let bytes = record(21, &body, order);
            let decoded = verified(&cx, &bytes, order).unwrap();
            assert_eq!(
                decoded.payload,
                ZilRecordPayload::SetSaXattr {
                    file_obj: 7,
                    name: b"user.binary".to_vec(),
                    value: Some(vec![0, 255, b'A', 0]),
                }
            );
            assert_eq!(
                ffs_ondisk::zfs_dmu::ZilBlock::parse(
                    &block(&bytes, bytes.len() as u64, order),
                    order,
                )
                .unwrap()
                .records,
                [decoded]
            );
            let mut removal = body[..16].to_vec();
            removal[8..16].copy_from_slice(&order.encode(0));
            removal.extend_from_slice(b"user.binary\0");
            assert!(matches!(
                verified(&cx, &record(21, &removal, order), order)
                    .unwrap()
                    .payload,
                ZilRecordPayload::SetSaXattr { value: None, .. }
            ));
            for at in [0, 32, 40] {
                let values = match at {
                    0 => vec![0x15 | (1_u64 << 63), 0x15 | 0x20],
                    32 => vec![0, 1_u64 << 48, u64::MAX],
                    _ => vec![32_769, u64::MAX, 12],
                };
                for value in values {
                    let mut bad = bytes.clone();
                    bad[at..at + 8].copy_from_slice(&order.encode(value));
                    assert!(verified(&cx, &bad, order).is_err());
                }
            }
            let mut empty = bytes.clone();
            empty[48] = 0;
            assert!(verified(&cx, &empty, order).is_err());
            let mut unterminated = bytes.clone();
            unterminated[48..].fill(b'x');
            assert!(verified(&cx, &unterminated, order).is_err());
            let mut suffix = bytes.clone();
            suffix.extend_from_slice(&[0; 8]);
            let length = suffix.len() as u64;
            suffix[8..16].copy_from_slice(&order.encode(length));
            assert!(verified(&cx, &suffix, order).is_err());
            assert!(verified(&cx, &record(21, &body[..16], order), order).is_err());

            let mut maximum = Vec::new();
            maximum.extend_from_slice(&order.encode(7));
            maximum.extend_from_slice(&order.encode(32_768));
            maximum.extend_from_slice(&vec![b'x'; 255]);
            maximum.push(0);
            maximum.extend_from_slice(&vec![0xA5; 32_768]);
            assert!(verified(&cx, &record(21, &maximum, order), order).is_ok());
            maximum.insert(16, b'x');
            assert!(verified(&cx, &record(21, &maximum, order), order).is_err());
        }
    }

    #[test]
    fn an_unknown_or_malformed_later_record_cannot_make_a_successful_prefix() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            for kind in [
                0,
                3,
                7,
                12,
                14,
                15,
                16,
                17,
                18,
                19,
                20,
                21,
                22,
                24,
                33,
                1_u64 << 63 | 8,
            ] {
                let mut records = inline(order);
                records.extend(record(kind, &[], order));
                assert!(parse(&cx, &block(&records, records.len() as u64, order), order).is_err());
            }
            for length in [0, 8, 31, 33, u64::MAX] {
                let mut records = inline(order);
                let at = records.len();
                records.extend(record(10, &[0; 24], order));
                records[at + 8..at + 16].copy_from_slice(&order.encode(length));
                assert!(parse(&cx, &block(&records, records.len() as u64, order), order).is_err());
            }
        }
    }

    #[test]
    fn used_bytes_and_inline_lengths_are_never_clipped() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            let bytes = inline(order);
            for used in [
                1,
                bytes.len() as u64 - 1,
                bytes.len() as u64 + 8,
                336,
                u64::MAX,
            ] {
                assert!(parse(&cx, &block(&bytes, used, order), order).is_err());
            }
            for declared in [0, 9, u64::MAX] {
                let mut bad = bytes.clone();
                bad[48..56].copy_from_slice(&order.encode(declared));
                assert!(parse(&cx, &block(&bad, bad.len() as u64, order), order).is_err());
            }
            // Padding beyond the last complete record belongs outside nused.
            let raw = block(&bytes, bytes.len() as u64, order);
            assert!(parse(&cx, &raw, order).is_ok());
            let indirect = record(9, &[0; 160], order);
            assert!(parse(&cx, &block(&indirect, indirect.len() as u64, order), order).is_err());
        }
    }

    #[test]
    fn plain_create_padding_is_not_a_symlink_and_names_have_exact_boundaries() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            let mut body = vec![0; 72];
            body.extend_from_slice(b"x\0");
            let mut bytes = record(1, &body, order);
            bytes[106..109].copy_from_slice(b"zz\0");
            let parsed = parse(&cx, &block(&bytes, bytes.len() as u64, order), order).unwrap();
            assert!(matches!(
                &parsed.records[0].payload,
                ZilRecordPayload::Create {
                    symlink_target: None,
                    is_dir: false,
                    ..
                }
            ));
            for kind in [4, 8] {
                let body = vec![b'x'; if kind == 4 { 80 } else { 24 }];
                let bytes = record(kind, &body, order);
                assert!(parse(&cx, &block(&bytes, bytes.len() as u64, order), order).is_err());
            }
        }
    }

    #[test]
    fn exact_fixed_records_empty_log_and_cancellation_are_distinct() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            for (kind, body_size) in [(10, 24), (11, 80)] {
                let mut bytes = record(kind, &vec![0; body_size], order);
                if kind == 10 {
                    let zero_object = bytes.clone();
                    assert!(
                        parse(
                            &cx,
                            &block(&zero_object, zero_object.len() as u64, order),
                            order
                        )
                        .is_err()
                    );
                    bytes[32..40].copy_from_slice(&order.encode(7));
                }
                assert_eq!(
                    parse(&cx, &block(&bytes, bytes.len() as u64, order), order)
                        .unwrap()
                        .records
                        .len(),
                    1
                );
                let shorter = record(kind, &vec![0; body_size - 8], order);
                assert!(parse(&cx, &block(&shorter, shorter.len() as u64, order), order).is_err());
            }
            assert_eq!(
                parse(&cx, &block(&[], 0, order), order).unwrap().records,
                [] as [ffs_ondisk::zfs_dmu::ZilRecord; 0]
            );
        }
        cx.cancel_with(
            asupersync::types::CancelKind::User,
            Some("ZIL admission test"),
        );
        assert!(matches!(
            parse(&cx, &block(&[], 0, Endian::Little), Endian::Little),
            Err(super::super::FfsError::Cancelled)
        ));
    }
}
