//! Select the newest provably comparable, fully validated native restart copy.
//!
//! LFS ordering includes the LSN sequence number, not just the physical offset.
//! Linux v6.17 fs/ntfs3/fslog.c also selects the greatest restart last_lsn. This
//! read-only profile adds conservative same-epoch and same-geometry admission;
//! it does not salvage a damaged copy, interpret CHKDSK state, or repair either.

use super::{Restart, Result, u32_at, unsupported};

fn comparable_lsn(restart: &Restart, lsn: u64) -> Result<()> {
    let page = u64::from(restart.log_page);
    if !(3..64).contains(&restart.seq_num_bits) || page < 512 || !page.is_power_of_two() || lsn == 0
    {
        return Err(unsupported("$LogFile restart LSNs are not comparable"));
    }
    let vbo = lsn.wrapping_shl(restart.seq_num_bits) >> (restart.seq_num_bits - 3);
    let offset = vbo & (page - 1);
    let reserved = if restart.version.0 >= 2 { 34 } else { 4 };
    let header = u64::from(restart.record_header_len);
    if vbo >= restart.file_size
        || vbo / page < reserved
        || offset < u64::from(restart.data_off)
        || header < 48
        || !header.is_multiple_of(8)
        || offset.checked_add(header).is_none_or(|end| end > page)
        || lsn > restart.current_lsn
    {
        // Initial/pseudo LSNs can occur natively, but do not prove ordering of
        // differing checkpoints in this profile. Equal copies remain admitted.
        return Err(unsupported(
            "$LogFile differing restart copies need real bounded record LSNs",
        ));
    }
    Ok(())
}

pub(super) fn choose<'a>(first: &'a Restart, second: &'a Restart) -> Result<&'a Restart> {
    if first == second {
        return Ok(first);
    }
    if first.current_lsn == second.current_lsn {
        return Err(unsupported(
            "$LogFile equal-LSN restart copies disagree on checkpoint state",
        ));
    }
    if first.system_page != second.system_page
        || first.log_page != second.log_page
        || first.version != second.version
        || first.seq_num_bits != second.seq_num_bits
        || first.file_size != second.file_size
        || first.record_header_len != second.record_header_len
        || first.data_off != second.data_off
        || first.active_client_seq != second.active_client_seq
        || u32_at(&first.area, 40)? != u32_at(&second.area, 40)?
    {
        return Err(unsupported(
            "$LogFile restart copies have incompatible geometry or epochs",
        ));
    }
    for restart in [first, second] {
        comparable_lsn(restart, restart.current_lsn)?;
        for lsn in [
            restart.active_client_oldest_lsn,
            restart.active_client_restart_lsn,
        ]
        .into_iter()
        .flatten()
        .filter(|lsn| *lsn != 0)
        {
            comparable_lsn(restart, lsn)?;
        }
    }
    let (older, newer) = if first.current_lsn < second.current_lsn {
        (first, second)
    } else {
        (second, first)
    };
    let address_bits = 64 - newer.seq_num_bits;
    let old_sequence = older.current_lsn >> address_bits;
    let new_sequence = newer.current_lsn >> address_bits;
    if new_sequence - old_sequence > 1
        || newer.active_client_oldest_lsn.unwrap_or(0) < older.active_client_oldest_lsn.unwrap_or(0)
        || newer.active_client_restart_lsn.unwrap_or(0)
            < older.active_client_restart_lsn.unwrap_or(0)
    {
        return Err(unsupported(
            "$LogFile restart generations or client progress are ambiguous",
        ));
    }
    // Deliberately do not prefer 'clean'. A newer dirty checkpoint wins and is
    // rejected by the caller's recovery-required policy, never rolled back.
    Ok(newer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 4096;
    const LOG: u64 = 4 * 1024 * 1024;
    const FIRST: u64 = 34 * PAGE;

    fn lsn(sequence: u64, offset: u64) -> u64 {
        (sequence << 20) | (offset / 8)
    }

    fn restart(current: u64, clean: bool) -> Restart {
        let mut area = vec![0; 48];
        area[..8].copy_from_slice(&current.to_le_bytes());
        area[40..44].copy_from_slice(&9_u32.to_le_bytes());
        Restart {
            system_page: PAGE as u32,
            log_page: PAGE as u32,
            version: (2, 0),
            clean,
            current_lsn: current,
            seq_num_bits: 44,
            file_size: LOG,
            last_lsn_data_len: 48,
            record_header_len: 48,
            data_off: 64,
            active_client_seq: Some(7),
            active_client_oldest_lsn: Some(0),
            active_client_restart_lsn: Some(0),
            area,
        }
    }

    #[test]
    fn newest_copy_wins_in_either_slot_without_preferring_clean_state() {
        for old_clean in [false, true] {
            for new_clean in [false, true] {
                let old = restart(lsn(1, FIRST + 128), old_clean);
                let new = restart(lsn(1, FIRST + PAGE + 128), new_clean);
                assert!(std::ptr::eq(choose(&old, &new).unwrap(), &raw const new));
                assert!(std::ptr::eq(choose(&new, &old).unwrap(), &raw const new));
            }
        }
    }

    #[test]
    fn native_wrap_uses_lsn_sequence_not_the_smaller_physical_offset() {
        let old = restart(lsn(1, LOG - PAGE + 128), true);
        let new = restart(lsn(2, FIRST + 128), false);
        assert!(std::ptr::eq(choose(&old, &new).unwrap(), &raw const new));
        assert!(std::ptr::eq(choose(&new, &old).unwrap(), &raw const new));
        let too_old = restart(lsn(0, FIRST + 128), true);
        assert!(choose(&too_old, &new).is_err());
    }

    #[test]
    fn equal_lsns_do_not_hide_client_or_clean_flag_disagreement() {
        let old = restart(lsn(1, FIRST + 128), true);
        let mut new = restart(old.current_lsn, false);
        assert!(choose(&old, &new).is_err());
        new.clean = true;
        assert!(choose(&old, &new).is_ok());
        new.area[44] ^= 1;
        assert!(choose(&old, &new).is_err());
    }

    #[test]
    fn differing_geometry_client_incarnation_or_open_epoch_cannot_be_selected() {
        let old = restart(lsn(1, FIRST + 128), true);
        for change in 0..9 {
            let mut new = restart(lsn(1, FIRST + PAGE + 128), true);
            match change {
                0 => new.system_page *= 2,
                1 => new.log_page *= 2,
                2 => new.version = (1, 1),
                3 => new.seq_num_bits -= 1,
                4 => new.file_size *= 2,
                5 => new.record_header_len += 8,
                6 => new.data_off += 8,
                7 => new.active_client_seq = Some(8),
                _ => new.area[40] ^= 1,
            }
            assert!(choose(&old, &new).is_err());
            assert!(choose(&new, &old).is_err());
        }
    }

    #[test]
    fn pseudo_reserved_header_and_future_client_lsns_are_not_ordering_evidence() {
        let good = restart(lsn(1, FIRST + PAGE + 128), true);
        for current in [
            0,
            42,
            lsn(1, PAGE + 128),
            lsn(1, FIRST),
            lsn(1, FIRST + PAGE - 8),
        ] {
            let bad = restart(current, true);
            assert!(choose(&bad, &good).is_err());
        }
        let mut bad = restart(lsn(1, FIRST + 128), true);
        bad.active_client_restart_lsn = Some(good.current_lsn);
        assert!(choose(&bad, &good).is_err());
    }

    #[test]
    fn newer_checkpoint_cannot_rewind_retained_client_progress() {
        for oldest in [false, true] {
            let mut old = restart(lsn(1, FIRST + 256), true);
            let mut new = restart(lsn(1, FIRST + PAGE + 128), true);
            if oldest {
                old.active_client_oldest_lsn = Some(lsn(1, FIRST + 128));
                new.active_client_oldest_lsn = Some(lsn(1, FIRST + 64));
            } else {
                old.active_client_restart_lsn = Some(lsn(1, FIRST + 128));
                new.active_client_restart_lsn = Some(lsn(1, FIRST + 64));
            }
            assert!(choose(&old, &new).is_err());
        }
    }
}
