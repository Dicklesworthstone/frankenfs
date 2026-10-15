//! Native restart-table slots and free-list ownership, without pointer casts.

use super::{Cx, Result, buffer, checkpoint, corrupt, u16_at, u32_at};
use std::collections::BTreeMap;

const HEADER: usize = 24;
const ALLOCATED: u32 = u32::MAX;

pub(super) struct RestartTable<'a> {
    pub(super) entry_size: usize,
    pub(super) entries: BTreeMap<u32, &'a [u8]>,
}

impl<'a> RestartTable<'a> {
    pub(super) fn parse(cx: &Cx, data: &'a [u8]) -> Result<Self> {
        checkpoint(cx)?;
        if data.len() < HEADER {
            return Err(corrupt(0, "truncated $LogFile restart table"));
        }
        let entry_size = usize::from(u16_at(data, 0)?);
        // Native 'used' is slot capacity; 'total' counts allocated entries.
        let capacity = usize::from(u16_at(data, 2)?);
        let allocated = usize::from(u16_at(data, 4)?);
        let end = entry_size
            .checked_mul(capacity)
            .and_then(|size| size.checked_add(HEADER))
            .ok_or_else(|| corrupt(0, "$LogFile restart-table size overflow"))?;
        if entry_size < 4 || end > data.len() || allocated > capacity {
            return Err(corrupt(0, "invalid $LogFile restart-table geometry"));
        }
        let index = |offset: u32| -> Result<usize> {
            let offset = usize::try_from(offset)
                .map_err(|_| corrupt(0, "$LogFile restart-table offset overflow"))?;
            let relative = offset
                .checked_sub(HEADER)
                .ok_or_else(|| corrupt(0, "$LogFile restart-table link enters its header"))?;
            if !relative.is_multiple_of(entry_size) || relative / entry_size >= capacity {
                return Err(corrupt(
                    0,
                    "$LogFile restart-table link does not address a slot",
                ));
            }
            Ok(relative / entry_size)
        };
        let mut entries = BTreeMap::new();
        for slot in 0..capacity {
            checkpoint(cx)?;
            let at = HEADER + slot * entry_size;
            let next = u32_at(data, at)?;
            if next == ALLOCATED {
                let offset =
                    u32::try_from(at).map_err(|_| corrupt(0, "$LogFile slot offset overflow"))?;
                entries.insert(offset, &data[at..at + entry_size]);
            } else if next != 0 {
                index(next)?;
            }
        }
        if entries.len() != allocated {
            return Err(corrupt(
                0,
                "$LogFile restart-table allocation count disagrees",
            ));
        }
        let first = u32_at(data, 16)?;
        let last = u32_at(data, 20)?;
        if (first == 0) != (last == 0) {
            return Err(corrupt(0, "$LogFile free-list endpoints disagree"));
        }
        if last != 0 {
            index(last)?;
        }
        let mut seen = buffer(capacity)?;
        let mut next = first;
        let mut final_offset = 0;
        let mut free_count = 0;
        while next != 0 {
            checkpoint(cx)?;
            let slot = index(next)?;
            if seen[slot] != 0 {
                return Err(corrupt(0, "cycle in $LogFile restart-table free list"));
            }
            seen[slot] = 1;
            let value = u32_at(data, HEADER + slot * entry_size)?;
            if value == ALLOCATED {
                return Err(corrupt(0, "$LogFile free list contains an allocated slot"));
            }
            final_offset = next;
            next = value;
            free_count += 1;
        }
        if final_offset != last || free_count != capacity - allocated {
            return Err(corrupt(
                0,
                "$LogFile free list omits slots or has a false tail",
            ));
        }
        checkpoint(cx)?;
        Ok(Self {
            entry_size,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> Vec<u8> {
        let mut data = vec![0; HEADER + 3 * 40];
        data[..2].copy_from_slice(&40_u16.to_le_bytes());
        data[2..4].copy_from_slice(&3_u16.to_le_bytes());
        data[4..6].copy_from_slice(&1_u16.to_le_bytes());
        data[16..20].copy_from_slice(&64_u32.to_le_bytes());
        data[20..24].copy_from_slice(&104_u32.to_le_bytes());
        data[24..28].copy_from_slice(&ALLOCATED.to_le_bytes());
        data[64..68].copy_from_slice(&104_u32.to_le_bytes());
        data
    }

    #[test]
    fn native_capacity_and_allocated_count_are_not_interchanged() {
        let data = table();
        let parsed = RestartTable::parse(&Cx::for_testing(), &data).unwrap();
        assert_eq!(parsed.entry_size, 40);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[&24], &data[24..64]);
    }

    #[test]
    fn malformed_free_lists_and_unowned_slots_fail_closed() {
        for (at, value) in [
            (16, 25),
            (16, 144),
            (20, 64),
            (64, 64),
            (104, 64),
            (64, 24),
            (64, 0),
            (16, 0),
            (64, u32::MAX),
            (64, u32::MAX - 1),
        ] {
            let mut data = table();
            data[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(RestartTable::parse(&Cx::for_testing(), &data).is_err());
        }
    }

    #[test]
    fn every_truncation_and_false_count_is_rejected() {
        let data = table();
        for length in 0..data.len() {
            assert!(RestartTable::parse(&Cx::for_testing(), &data[..length]).is_err());
        }
        for at in [0, 2, 4] {
            let mut bad = data.clone();
            bad[at..at + 2].copy_from_slice(&u16::MAX.to_le_bytes());
            assert!(RestartTable::parse(&Cx::for_testing(), &bad).is_err());
        }
    }

    #[test]
    fn empty_and_fully_allocated_tables_need_no_free_list() {
        let mut empty = vec![0; HEADER];
        empty[..2].copy_from_slice(&40_u16.to_le_bytes());
        assert!(RestartTable::parse(&Cx::for_testing(), &empty).is_ok());
        let mut full = table();
        full[4..6].copy_from_slice(&3_u16.to_le_bytes());
        full[16..24].fill(0);
        full[64..68].copy_from_slice(&ALLOCATED.to_le_bytes());
        full[104..108].copy_from_slice(&ALLOCATED.to_le_bytes());
        assert_eq!(
            RestartTable::parse(&Cx::for_testing(), &full)
                .unwrap()
                .entries
                .len(),
            3
        );
    }
}
