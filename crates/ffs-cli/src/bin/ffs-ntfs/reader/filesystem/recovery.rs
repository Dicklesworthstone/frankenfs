//! Clean-only native $LogFile admission for immutable mounted views.
//!
//! The volume dirty bit is not a substitute for the recovery journal. A mount
//! selects the newest comparable USA-validated restart area, requires it to
//! be clean, or verifies a completely erased log. It never rolls back to an
//! older clean copy over newer dirty or uncertain recovery state.
//! Dirty-log preflight stages supported MFT edits only in private memory; it
//! does not publish a recovered view, detect hibernation or admit writes.
//!
//! Layout references: NTFS-3G 2022.10.3 include/ntfs-3g/logfile.h and Linux
//! v6.17 fs/ntfs3/fslog.c. Their single-client records reserve different name
//! capacities; only declared, bounded fields are interpreted here.

mod record;
mod selection;

use super::super::Storage;
use super::{Cx, NtfsVolume, Result, Stream, checkpoint, corrupt, unsupported};

const SECTOR: usize = 512;
const MAX_PAGE: usize = 65_536;
const MIN_LOG: u64 = 50 * 512;
const MAX_LOG: u64 = 0x0001_0000_0000;
const ERASED_SCAN_LIMIT: u64 = 64 * 1024 * 1024;
const NO_CLIENT: u16 = 0xFFFF;
const CLEAN: u16 = 0x0002;

#[derive(Debug, PartialEq, Eq)]
struct Restart {
    system_page: u32,
    log_page: u32,
    version: (u16, u16),
    clean: bool,
    current_lsn: u64,
    seq_num_bits: u32,
    file_size: u64,
    last_lsn_data_len: u32,
    record_header_len: u16,
    data_off: u16,
    active_client_seq: Option<u16>,
    active_client_oldest_lsn: Option<u64>,
    active_client_restart_lsn: Option<u64>,
    // Restored native restart bytes, excluding the header and its USA token.
    // Equal LSNs alone do not establish equal client/checkpoint state.
    area: Vec<u8>,
}

pub(super) fn admit(cx: &Cx, volume: &NtfsVolume) -> Result<()> {
    checkpoint(cx)?;
    let record = volume.record(cx, 2, None)?;
    let stream = volume.data_stream(cx, &record, &[])?;
    validate_storage(&stream)?;
    assess_volume(
        cx,
        stream.size,
        |offset, size| volume.read(cx, &stream, offset, size),
        Some(volume),
    )
}

fn validate_storage(stream: &Stream) -> Result<()> {
    let Storage::Mapped(runs) = &stream.storage else {
        return Err(corrupt(0, "$LogFile must have ordinary nonresident DATA"));
    };
    if stream.initialized != stream.size || runs.iter().any(|run| run.lcn.is_none()) {
        return Err(corrupt(
            0,
            "$LogFile has uninitialized or sparse recovery bytes",
        ));
    }
    Ok(())
}

fn bytes<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| corrupt(0, "$LogFile field offset overflow"))?;
    data.get(offset..end)
        .ok_or_else(|| corrupt(0, "truncated $LogFile field"))?
        .try_into()
        .map_err(|_| corrupt(0, "invalid $LogFile field width"))
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(bytes(data, offset)?))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes(data, offset)?))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(bytes(data, offset)?))
}

fn page_size(value: u32) -> Result<usize> {
    if !(512..=65_536).contains(&value) || !value.is_power_of_two() {
        return Err(unsupported(
            "$LogFile page geometry is outside 512..65536 bytes",
        ));
    }
    usize::try_from(value).map_err(|_| corrupt(0, "$LogFile page size overflow"))
}

fn read_exact(
    cx: &Cx,
    length: u64,
    offset: u64,
    size: usize,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    checkpoint(cx)?;
    if size > MAX_PAGE
        || offset
            .checked_add(size as u64)
            .is_none_or(|end| end > length)
    {
        return Err(corrupt(offset, "$LogFile read exceeds its bounded stream"));
    }
    let value = read(offset, size)?;
    if value.len() != size {
        return Err(corrupt(offset, "short $LogFile read"));
    }
    checkpoint(cx)?;
    Ok(value)
}

fn assess_volume(
    cx: &Cx,
    length: u64,
    mut read: impl FnMut(u64, usize) -> Result<Vec<u8>>,
    volume: Option<&NtfsVolume>,
) -> Result<()> {
    checkpoint(cx)?;
    if !(MIN_LOG..=MAX_LOG).contains(&length) || !length.is_multiple_of(SECTOR as u64) {
        return Err(corrupt(0, "invalid $LogFile initialized length"));
    }
    let prefix = read_exact(cx, length, 0, SECTOR, &mut read)?;
    if prefix.iter().all(|byte| *byte == 0xFF) {
        // A torn erase or a missing restart page is not an empty journal.
        // Verify the complete initialized stream, never just its first page.
        if length > ERASED_SCAN_LIMIT {
            return Err(unsupported("erased $LogFile verification exceeds 64 MiB"));
        }
        let mut offset = SECTOR as u64;
        while offset < length {
            let size = (length - offset).min(MAX_PAGE as u64) as usize;
            let part = read_exact(cx, length, offset, size, &mut read)?;
            if part.iter().any(|byte| *byte != 0xFF) {
                return Err(corrupt(
                    offset,
                    "partially erased $LogFile requires native recovery",
                ));
            }
            offset += size as u64;
        }
        return checkpoint(cx);
    }
    if bytes::<4>(&prefix, 0)? != *b"RSTR" {
        return Err(unsupported("$LogFile has no admitted RSTR restart header"));
    }
    let system_page = page_size(u32_at(&prefix, 16)?)?;
    let primary = if system_page == SECTOR {
        prefix
    } else {
        read_exact(cx, length, 0, system_page, &mut read)?
    };
    let first = restart(cx, primary, length)?;
    let second = restart(
        cx,
        read_exact(cx, length, system_page as u64, system_page, &mut read)?,
        length,
    )?;
    let selected = selection::choose(&first, &second)?;
    if !selected.clean {
        let tail = record::validate_dirty_volume(cx, selected, length, &mut read, volume)?;
        return Err(unsupported(format!(
            "$LogFile requires native redo/undo recovery before mounting; current transaction {} has redo opcode {:#04x} and undo opcode {:#04x}",
            tail.transaction_id, tail.redo_op, tail.undo_op
        )));
    }
    checkpoint(cx)
}

#[cfg(test)]
fn assess(cx: &Cx, length: u64, read: impl FnMut(u64, usize) -> Result<Vec<u8>>) -> Result<()> {
    assess_volume(cx, length, read, None)
}

fn restart(cx: &Cx, mut page: Vec<u8>, stream_length: u64) -> Result<Restart> {
    checkpoint(cx)?;
    if bytes::<4>(&page, 0)? != *b"RSTR" || u64_at(&page, 8)? != 0 {
        return Err(corrupt(
            0,
            "invalid or CHKDSK-modified $LogFile restart header",
        ));
    }
    let system_page = u32_at(&page, 16)?;
    let log_page = u32_at(&page, 20)?;
    let system_size = page_size(system_page)?;
    let log_size = page_size(log_page)?;
    if page.len() != system_size {
        return Err(corrupt(
            0,
            "$LogFile restart page length disagrees with its header",
        ));
    }
    let version = (u16_at(&page, 28)?, u16_at(&page, 26)?);
    if !matches!(version, (1, 1) | (2, 0)) {
        return Err(unsupported(format!(
            "$LogFile version {}.{} is not admitted",
            version.0, version.1
        )));
    }
    let usa = usize::from(u16_at(&page, 4)?);
    let count = usize::from(u16_at(&page, 6)?);
    let area_offset = usize::from(u16_at(&page, 24)?);
    if count != system_size / SECTOR + 1
        || usa < 30
        || !usa.is_multiple_of(2)
        || usa + count * 2 > SECTOR - 2
        || area_offset < usa + count * 2
        || !area_offset.is_multiple_of(8)
        || area_offset + 48 > system_size
    {
        return Err(corrupt(0, "invalid $LogFile USA or restart area bounds"));
    }
    let token = bytes::<2>(&page, usa)?;
    // Validate every trailer before restoring any of the record.
    for sector in 1..count {
        checkpoint(cx)?;
        if bytes::<2>(&page, sector * SECTOR - 2)? != token {
            return Err(corrupt(0, "torn $LogFile restart page"));
        }
    }
    for sector in 1..count {
        let saved = bytes::<2>(&page, usa + sector * 2)?;
        page[sector * SECTOR - 2..sector * SECTOR].copy_from_slice(&saved);
    }
    let tail = &page[area_offset..];
    let area_length = usize::from(u16_at(tail, 20)?);
    let client_offset = usize::from(u16_at(tail, 22)?);
    if area_length < 48
        || area_length > tail.len()
        || client_offset < 48
        || !client_offset.is_multiple_of(8)
        || client_offset > area_length
        || area_offset + client_offset > SECTOR - 2
    {
        return Err(corrupt(0, "invalid $LogFile restart/client region"));
    }
    let area = &tail[..area_length];
    let current_lsn = u64_at(area, 0)?;
    let seq_num_bits = u32_at(area, 16)?;
    let file_size = u64_at(area, 24)?;
    let last_lsn_data_len = u32_at(area, 32)?;
    let minimum = 2 * u64::from(system_page) + 48 * u64::from(log_page);
    if file_size < minimum
        || file_size > stream_length
        || file_size > MAX_LOG
        || !file_size.is_multiple_of(u64::from(log_page))
        || u32_at(area, 16)? != 67 - (64 - file_size.leading_zeros())
    {
        return Err(corrupt(0, "invalid $LogFile size or LSN sequence geometry"));
    }
    let record_header_len = u16_at(area, 36)?;
    let data_off = u16_at(area, 38)?;
    let record_header = usize::from(record_header_len);
    let data_offset = usize::from(data_off);
    let minimum_data_offset = 40 + (log_size / SECTOR + 1) * 2;
    if record_header < 48
        || !record_header.is_multiple_of(8)
        || data_offset < minimum_data_offset
        || !data_offset.is_multiple_of(8)
        || data_offset + record_header > log_size
        || u64::from(u32_at(area, 32)?) > file_size
    {
        return Err(corrupt(0, "invalid $LogFile record/page data geometry"));
    }
    let clients = u16_at(area, 8)?;
    let free = u16_at(area, 10)?;
    let active = u16_at(area, 12)?;
    let flags = u16_at(area, 14)?;
    let mut active_client_seq = None;
    let mut active_client_oldest_lsn = None;
    let mut active_client_restart_lsn = None;
    if flags & !0x0003 != 0 || clients > 1 {
        return Err(unsupported(
            "unknown $LogFile restart flags or multiple clients",
        ));
    }
    if clients == 0 {
        if free != NO_CLIENT || active != NO_CLIENT {
            return Err(corrupt(0, "$LogFile client index without a client record"));
        }
    } else {
        if !matches!((free, active), (0, NO_CLIENT) | (NO_CLIENT, 0)) {
            return Err(corrupt(
                0,
                "$LogFile client lists overlap or omit their sole record",
            ));
        }
        let client = &area[client_offset..];
        // Linux uses a 96-byte client; older Windows layouts reserve 160.
        // No unchecked indexing or guessed stride is needed for one client.
        if client.len() < 96 || u16_at(client, 16)? != NO_CLIENT || u16_at(client, 18)? != NO_CLIENT
        {
            return Err(corrupt(0, "truncated or cyclic $LogFile client record"));
        }
        let name_size = usize::try_from(u32_at(client, 28)?)
            .map_err(|_| corrupt(0, "$LogFile client name length overflow"))?;
        if name_size > 128 || !name_size.is_multiple_of(2) || name_size + 32 > client.len() {
            return Err(corrupt(0, "$LogFile client name exceeds its record"));
        }
        if active != NO_CLIENT && &client[32..32 + name_size] != b"N\0T\0F\0S\0" {
            return Err(unsupported("unknown active $LogFile client"));
        }
        if active != NO_CLIENT {
            active_client_oldest_lsn = Some(u64_at(client, 0)?);
            active_client_restart_lsn = Some(u64_at(client, 8)?);
            active_client_seq = Some(u16_at(client, 20)?);
        }
    }
    checkpoint(cx)?;
    Ok(Restart {
        system_page,
        log_page,
        version,
        clean: active == NO_CLIENT || flags & CLEAN != 0,
        current_lsn,
        seq_num_bits,
        file_size,
        last_lsn_data_len,
        record_header_len,
        data_off,
        active_client_seq,
        active_client_oldest_lsn,
        active_client_restart_lsn,
        area: area.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::FfsError;
    use super::*;
    use ffs_ondisk::ntfs::NtfsRun;

    const LOG_SIZE: usize = 4 * 1024 * 1024;

    fn plain(size: usize, version: (u16, u16), flags: u16, active: bool) -> Vec<u8> {
        let mut page = vec![0; size];
        let count = size / SECTOR + 1;
        let start = (30 + count * 2).next_multiple_of(8);
        page[..4].copy_from_slice(b"RSTR");
        page[4..6].copy_from_slice(&30_u16.to_le_bytes());
        page[6..8].copy_from_slice(&u16::try_from(count).unwrap().to_le_bytes());
        page[16..20].copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
        page[20..24].copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
        page[24..26].copy_from_slice(&u16::try_from(start).unwrap().to_le_bytes());
        page[26..28].copy_from_slice(&version.1.to_le_bytes());
        page[28..30].copy_from_slice(&version.0.to_le_bytes());
        let area = &mut page[start..start + 224];
        area[..8].copy_from_slice(&42_u64.to_le_bytes());
        area[8..10].copy_from_slice(&1_u16.to_le_bytes());
        area[10..12].copy_from_slice(&(if active { NO_CLIENT } else { 0 }).to_le_bytes());
        area[12..14].copy_from_slice(&(if active { 0 } else { NO_CLIENT }).to_le_bytes());
        area[14..16].copy_from_slice(&flags.to_le_bytes());
        area[16..20].copy_from_slice(&44_u32.to_le_bytes());
        area[20..22].copy_from_slice(&224_u16.to_le_bytes());
        area[22..24].copy_from_slice(&64_u16.to_le_bytes());
        area[24..32].copy_from_slice(&(LOG_SIZE as u64).to_le_bytes());
        area[36..38].copy_from_slice(&48_u16.to_le_bytes());
        let data = (40 + count * 2).next_multiple_of(8);
        area[38..40].copy_from_slice(&u16::try_from(data).unwrap().to_le_bytes());
        area[40..44].copy_from_slice(&9_u32.to_le_bytes());
        area[80..82].copy_from_slice(&NO_CLIENT.to_le_bytes());
        area[82..84].copy_from_slice(&NO_CLIENT.to_le_bytes());
        area[92..96].copy_from_slice(&8_u32.to_le_bytes());
        area[96..104].copy_from_slice(b"N\0T\0F\0S\0");
        page
    }

    fn protected(mut page: Vec<u8>, token: u16) -> Vec<u8> {
        let usa = usize::from(u16_at(&page, 4).unwrap());
        let count = usize::from(u16_at(&page, 6).unwrap());
        page[usa..usa + 2].copy_from_slice(&token.to_le_bytes());
        for sector in 1..count {
            let saved = [page[sector * SECTOR - 2], page[sector * SECTOR - 1]];
            page[usa + sector * 2..usa + sector * 2 + 2].copy_from_slice(&saved);
            page[sector * SECTOR - 2..sector * SECTOR].copy_from_slice(&token.to_le_bytes());
        }
        page
    }

    fn pair(first: Vec<u8>, second: Vec<u8>) -> Vec<u8> {
        let mut log = vec![0xFF; LOG_SIZE];
        let size = first.len();
        log[..size].copy_from_slice(&protected(first, 0xCAFE));
        log[size..size + second.len()].copy_from_slice(&protected(second, 0xBEEF));
        log
    }

    fn check(log: &[u8]) -> Result<()> {
        assess(&Cx::for_testing(), log.len() as u64, |offset, size| {
            let start = usize::try_from(offset).unwrap();
            log.get(start..start + size)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| corrupt(offset, "test read beyond log"))
        })
    }

    #[test]
    fn clean_restarts_support_both_versions_and_all_bounded_page_sizes() {
        for size in [512, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_536] {
            for version in [(1, 1), (2, 0)] {
                for (flags, active) in [(0, false), (CLEAN, true), (CLEAN | 1, true)] {
                    let page = plain(size, version, flags, active);
                    let log = pair(page.clone(), page);
                    let before = log.clone();
                    check(&log).unwrap();
                    assert_eq!(log, before, "admission must never alter native bytes");
                }
            }
        }
    }

    #[test]
    fn both_published_client_capacities_and_empty_client_arrays_are_bounded() {
        for (client_offset, area_length) in [(48_u16, 208_u16), (64, 160)] {
            let mut page = plain(4096, (1, 1), CLEAN, true);
            let start = usize::from(u16_at(&page, 24).unwrap());
            let mut client = [0; 96];
            client.copy_from_slice(&page[start + 64..start + 160]);
            page[start + 22..start + 24].copy_from_slice(&client_offset.to_le_bytes());
            page[start + 20..start + 22].copy_from_slice(&area_length.to_le_bytes());
            let at = start + usize::from(client_offset);
            page[at..at + 96].copy_from_slice(&client);
            check(&pair(page.clone(), page)).unwrap();
        }
        let mut page = plain(4096, (1, 1), 0, false);
        let start = usize::from(u16_at(&page, 24).unwrap());
        page[start + 8..start + 10].copy_from_slice(&0_u16.to_le_bytes());
        page[start + 10..start + 12].copy_from_slice(&NO_CLIENT.to_le_bytes());
        check(&pair(page.clone(), page)).unwrap();
    }

    #[test]
    fn ordered_clean_restart_copies_are_admitted_without_mutating_the_image() {
        for version in [(1, 1), (2, 0)] {
            for wrap in [false, true] {
                for old_clean in [false, true] {
                    let first = (if version.0 >= 2 { 34_u64 } else { 4 }) * 4096;
                    let old_vbo = if wrap { LOG_SIZE as u64 - 4096 } else { first };
                    let new_vbo = if wrap { first } else { first + 4096 };
                    let old_lsn = (1_u64 << 20) | ((old_vbo + 128) / 8);
                    let new_lsn = ((if wrap { 2_u64 } else { 1 }) << 20) | ((new_vbo + 128) / 8);
                    let mut old = plain(4096, version, if old_clean { CLEAN } else { 0 }, true);
                    let mut new = plain(4096, version, CLEAN, true);
                    let start = usize::from(u16_at(&old, 24).unwrap());
                    old[start..start + 8].copy_from_slice(&old_lsn.to_le_bytes());
                    new[start..start + 8].copy_from_slice(&new_lsn.to_le_bytes());
                    for (first, second) in [(old.clone(), new.clone()), (new.clone(), old.clone())]
                    {
                        let log = pair(first, second);
                        let before = log.clone();
                        check(&log).unwrap();
                        assert_eq!(log, before);
                    }
                }
            }
        }
    }

    #[test]
    fn newer_dirty_restart_reaches_recovery_instead_of_using_the_clean_copy() {
        let mut old = plain(4096, (2, 0), CLEAN, true);
        let mut new = plain(4096, (2, 0), 0, true);
        let start = usize::from(u16_at(&old, 24).unwrap());
        let old_lsn = (1_u64 << 20) | ((34 * 4096 + 128) / 8);
        let new_lsn = (1_u64 << 20) | ((35 * 4096 + 128) / 8);
        old[start..start + 8].copy_from_slice(&old_lsn.to_le_bytes());
        new[start..start + 8].copy_from_slice(&new_lsn.to_le_bytes());
        for (first, second) in [(old.clone(), new.clone()), (new, old)] {
            // The selected dirty tail points into erased RCRD storage. This
            // must reach the decoder and fail, never admit the older clean RSTR.
            assert!(matches!(
                check(&pair(first, second)),
                Err(FfsError::Corruption { .. })
            ));
        }
    }

    #[test]
    fn dirty_or_disagreeing_copy_never_falls_back_to_an_older_clean_restart() {
        let clean = plain(4096, (1, 1), CLEAN, true);
        let mut dirty = plain(4096, (1, 1), 0, true);
        let start = usize::from(u16_at(&dirty, 24).unwrap());
        dirty[start..start + 8].copy_from_slice(&43_u64.to_le_bytes());
        for (first, second) in [
            (clean.clone(), dirty.clone()),
            (dirty.clone(), clean.clone()),
        ] {
            assert!(matches!(
                check(&pair(first, second)),
                Err(FfsError::UnsupportedFeature(_))
            ));
        }
        // Matching dirty copies advance to the record decoder. This fixture's
        // tiny synthetic current LSN does not address a legal record page, so
        // it is structural corruption rather than merely unsupported replay.
        assert!(matches!(
            check(&pair(dirty.clone(), dirty)),
            Err(FfsError::Corruption { .. })
        ));
        for at in [0, 40, 84] {
            let mut other = clean.clone();
            other[start + at] ^= 1;
            assert!(matches!(
                check(&pair(clean.clone(), other)),
                Err(FfsError::UnsupportedFeature(_))
            ));
        }
    }

    #[test]
    fn every_sector_of_both_restart_copies_must_pass_update_sequence_validation() {
        let page = plain(4096, (1, 1), CLEAN, true);
        let good = pair(page.clone(), page);
        for copy in 0..2 {
            for sector in 1..=8 {
                let mut torn = good.clone();
                torn[copy * 4096 + sector * SECTOR - 1] ^= 1;
                assert!(matches!(check(&torn), Err(FfsError::Corruption { .. })));
            }
        }
    }

    #[test]
    fn restart_parser_rejects_truncation_invalid_geometry_and_unknown_versions() {
        let cx = Cx::for_testing();
        let valid = protected(plain(512, (1, 1), CLEAN, true), 0xCAFE);
        for size in 0..valid.len() {
            assert!(restart(&cx, valid[..size].to_vec(), LOG_SIZE as u64).is_err());
        }
        for (offset, word) in [(4, 28), (6, 1), (24, 33), (24, 504)] {
            let mut invalid = valid.clone();
            invalid[offset..offset + 2]
                .copy_from_slice(&u16::try_from(word).unwrap().to_le_bytes());
            assert!(restart(&cx, invalid, LOG_SIZE as u64).is_err());
        }
        for size in [0_u32, 256, 513, 131_072, u32::MAX] {
            let mut invalid = valid.clone();
            invalid[16..20].copy_from_slice(&size.to_le_bytes());
            assert!(restart(&cx, invalid, LOG_SIZE as u64).is_err());
        }
        for version in [(1, 0), (2, 1), (3, 0), (u16::MAX, u16::MAX)] {
            assert!(matches!(
                restart(
                    &cx,
                    protected(plain(512, version, CLEAN, true), 7),
                    LOG_SIZE as u64,
                ),
                Err(FfsError::UnsupportedFeature(_))
            ));
        }
        let mut chkd = valid;
        chkd[..4].copy_from_slice(b"CHKD");
        assert!(restart(&cx, chkd, LOG_SIZE as u64).is_err());
    }

    #[test]
    fn malformed_client_bounds_lists_and_lsn_geometry_are_refused() {
        let cx = Cx::for_testing();
        for (relative, value) in [
            (8, 2_u16),
            (10, 0),
            (12, 1),
            (14, 4),
            (16, 0),
            (20, 47),
            (20, 4096),
            (22, 40),
            (22, 65),
            (36, 0),
            (36, 49),
            (38, 40),
            (38, 4080),
            (80, 0),
            (82, 0),
            (92, 129),
        ] {
            let mut page = plain(4096, (1, 1), CLEAN, true);
            let start = usize::from(u16_at(&page, 24).unwrap());
            page[start + relative..start + relative + 2].copy_from_slice(&value.to_le_bytes());
            assert!(
                restart(&cx, protected(page, 7), LOG_SIZE as u64).is_err(),
                "field {relative}"
            );
        }
        for size in [0_u64, 8192, (LOG_SIZE + 512) as u64, u64::MAX] {
            let mut page = plain(4096, (1, 1), CLEAN, true);
            let start = usize::from(u16_at(&page, 24).unwrap());
            page[start + 24..start + 32].copy_from_slice(&size.to_le_bytes());
            assert!(restart(&cx, protected(page, 7), LOG_SIZE as u64).is_err());
        }
        let mut page = plain(4096, (1, 1), CLEAN, true);
        let start = usize::from(u16_at(&page, 24).unwrap());
        page[start + 96] = b'X';
        assert!(matches!(
            restart(&cx, protected(page, 7), LOG_SIZE as u64),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }

    #[test]
    fn erased_journal_requires_every_byte_and_has_a_work_budget() {
        let mut erased = vec![0xFF; LOG_SIZE];
        check(&erased).unwrap();
        erased[LOG_SIZE - 1] = 0;
        assert!(matches!(check(&erased), Err(FfsError::Corruption { .. })));
        assert!(check(&vec![0; LOG_SIZE]).is_err());
        let mut reads = 0;
        let result = assess(&Cx::for_testing(), ERASED_SCAN_LIMIT + 512, |_, size| {
            reads += 1;
            Ok(vec![0xFF; size])
        });
        assert!(matches!(result, Err(FfsError::UnsupportedFeature(_))));
        assert_eq!(reads, 1);
    }

    #[test]
    fn io_short_reads_and_cancellation_are_never_converted_into_clean_state() {
        let cx = Cx::for_testing();
        for erased in [false, true] {
            let page = plain(4096, (1, 1), CLEAN, true);
            let log = if erased {
                vec![0xFF; LOG_SIZE]
            } else {
                pair(page.clone(), page)
            };
            for failure in 0..3 {
                let mut reads = 0;
                let result = assess(&cx, LOG_SIZE as u64, |offset, size| {
                    reads += 1;
                    if reads == 2 {
                        return match failure {
                            0 => Err(FfsError::Cancelled),
                            1 => Err(FfsError::Io(std::io::Error::other(
                                "injected journal I/O failure",
                            ))),
                            _ => Ok(vec![0xFF; size - 1]),
                        };
                    }
                    let start = usize::try_from(offset).unwrap();
                    Ok(log[start..start + size].to_vec())
                });
                assert_eq!(reads, 2);
                match failure {
                    0 => assert!(matches!(result, Err(FfsError::Cancelled))),
                    1 => assert!(matches!(result, Err(FfsError::Io(_)))),
                    _ => assert!(matches!(result, Err(FfsError::Corruption { .. }))),
                }
            }
        }
    }

    #[test]
    fn journal_storage_cannot_invent_recovery_bytes_from_holes_or_vdl() {
        let mut stream = Stream {
            storage: Storage::Mapped(vec![NtfsRun {
                vcn: 0,
                clusters: 64,
                lcn: Some(192),
            }]),
            size: 32_768,
            initialized: 32_768,
            allocated: 32_768,
        };
        validate_storage(&stream).unwrap();
        stream.initialized -= 1;
        assert!(validate_storage(&stream).is_err());
        stream.initialized = stream.size;
        stream.storage = Storage::Mapped(vec![NtfsRun {
            vcn: 0,
            clusters: 64,
            lcn: None,
        }]);
        assert!(validate_storage(&stream).is_err());
        stream.storage = Storage::Resident(vec![0xFF; 512]);
        assert!(validate_storage(&stream).is_err());
    }
}
