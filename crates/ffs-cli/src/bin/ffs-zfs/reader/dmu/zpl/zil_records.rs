//! Strict admission for the existing trailing-chain ZIL replay profile.
//!
//! The inspection parser may return recognized records from a block. Replay
//! cannot use that permissiveness: every used byte and operation must be known
//! before any operation is applied. This does not add slim-chain framing,
//! native ZIL checksum verification, claim processing or pool import.
//!
//! Layout: OpenZFS zfs-2.3.0 include/sys/zil.h and module/zfs/zfs_replay.c.

use super::{Cx, Result, checkpoint, corrupt, parse as parse_error, unsupported};
use crate::reader::Endian;
use ffs_ondisk::zfs::MAX_BLOCK_BYTES;
use ffs_ondisk::zfs_dmu::{ZilBlock, ZilRecordPayload};

const CHAIN_BYTES: usize = 184;
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

pub(super) fn parse(cx: &Cx, raw: &[u8], order: Endian) -> Result<ZilBlock> {
    checkpoint(cx)?;
    if raw.len() < 512 || raw.len() > MAX_BLOCK_BYTES || !raw.len().is_multiple_of(512) {
        return Err(corrupt("invalid ZIL block size"));
    }
    let trailer = raw.len() - CHAIN_BYTES;
    let used = word(raw, trailer + 136, order)?;
    if used > trailer as u64 || !used.is_multiple_of(8) {
        return Err(corrupt(
            "ZIL used bytes overlap the chain trailer or are unaligned",
        ));
    }
    let used = used as usize;
    let mut at = 0_usize;
    let mut count = 0_usize;
    while at < used {
        checkpoint(cx)?;
        count += 1;
        if count > MAX_RECORDS {
            return Err(unsupported("ZIL block exceeds 65536 records"));
        }
        if used - at < 32 {
            return Err(corrupt("partial ZIL record header inside used bytes"));
        }
        let kind = word(raw, at, order)?;
        let length = word(raw, at + 8, order)?;
        if length < 32 || !length.is_multiple_of(8) || length > (used - at) as u64 {
            return Err(corrupt("invalid ZIL record length inside used bytes"));
        }
        let end = at + length as usize;
        let record = &raw[at..end];
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
                padded_record(
                    record,
                    names_end(record, 104, if kind == 4 { 2 } else { 1 })?,
                )?;
            }
            5 | 6 => padded_record(record, names_end(record, 40, 1)?)?,
            8 => padded_record(record, names_end(record, 48, 2)?)?,
            9 => {
                if record.len() < 192 {
                    return Err(corrupt("truncated ZIL write record"));
                }
                if record.len() == 192 {
                    return Err(unsupported("indirect ZIL writes require full-block replay"));
                }
                let bytes = word(record, 48, order)?;
                if bytes == 0 || bytes > (record.len() - 192) as u64 {
                    return Err(corrupt("ZIL inline write is missing its declared bytes"));
                }
                padded_record(record, 192 + bytes as usize)?;
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
            _ => {
                return Err(unsupported(
                    "ZIL operation or type flags are not implemented for replay",
                ));
            }
        }
        at = end;
    }
    let mut block = ZilBlock::parse(raw, order).map_err(|error| parse_error(&error))?;
    if block.records.len() != count {
        return Err(corrupt("ZIL decoder did not consume every admitted record"));
    }
    for record in &mut block.records {
        checkpoint(cx)?;
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
    }
    checkpoint(cx)?;
    Ok(block)
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
                let bytes = record(kind, &vec![0; body_size], order);
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
            assert!(
                parse(&cx, &block(&[], 0, order), order)
                    .unwrap()
                    .records
                    .is_empty()
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
