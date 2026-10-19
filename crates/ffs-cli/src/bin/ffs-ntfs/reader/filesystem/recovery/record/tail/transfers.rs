//! Complete native tail transfers, selected without splicing publication attempts.
//!
//! Linux v6.17 fs/ntfs3/fslog.c uses two v2 banks of sixteen pages and checks
//! destination continuity, page_count/page_pos and LSN progress. This bounded
//! profile requires each transfer to be complete within one bank and not wrap
//! its destination range. Ambiguous overlapping transfer boundaries are refused.
//! Recovery consumes only private normalized copies; no native bytes are written.

use super::{
    BTreeMap, Cx, Page, Restart, Result, blank, checkpoint, corrupt, generation, read_exact,
    restore_page, u16_at, u32_at, u64_at, unsupported,
};

pub(super) struct Copies {
    pub(super) pages: BTreeMap<u64, Page>,
    pub(super) groups: Vec<Vec<u64>>,
}

#[derive(Clone, Copy)]
pub(super) enum Selection {
    Copy,
    Ring,
    Equal,
}

struct Transfer {
    pages: Vec<(u64, Page)>,
}

/// Validate the original fixups before touching destination/header words.
fn copy_page(cx: &Cx, restart: &Restart, slot: u64, mut raw: Vec<u8>) -> Result<(u64, Page)> {
    let page_bytes = u64::from(restart.log_page);
    let first = (if restart.version.0 == 2 { 34 } else { 4 }) * page_bytes;
    let destination = if restart.version.0 == 1 {
        u64_at(&raw, 8)?
    } else {
        u64::from(u32_at(&raw, 60)?)
    };
    if destination < first
        || destination >= restart.file_size
        || !destination.is_multiple_of(page_bytes)
    {
        return Err(corrupt(
            slot,
            "$LogFile tail copy has an invalid native destination",
        ));
    }
    let fixed = restore_page(cx, raw.clone(), restart, destination)?;
    if restart.version.0 == 1 {
        raw[8..16].copy_from_slice(&u64_at(&fixed.bytes, 32)?.to_le_bytes());
    } else {
        let usa = usize::from(u16_at(&fixed.bytes, 4)?);
        let end = usa + usize::from(u16_at(&fixed.bytes, 6)?) * 2;
        if usa < 64 && end > 60 {
            return Err(corrupt(
                slot,
                "$LogFile v2 tail normalization would overwrite its USA",
            ));
        }
        raw[60..64].fill(0);
    }
    Ok((destination, Page::parse(cx, restart, destination, raw)?))
}

fn transfer(cx: &Cx, restart: &Restart, oldest: u64, pages: Vec<(u64, Page)>) -> Result<Transfer> {
    let count = pages.len();
    let first = pages
        .first()
        .ok_or_else(|| corrupt(0, "empty native tail transfer"))?;
    let bytes = u64::from(restart.log_page);
    let sequence = first.1.last >> (64 - restart.seq_num_bits);
    let mut last = 0;
    let mut completed = 0;
    for (index, (destination, page)) in pages.iter().enumerate() {
        checkpoint(cx)?;
        let expected = first
            .0
            .checked_add(index as u64 * bytes)
            .filter(|at| *at < restart.file_size)
            .ok_or_else(|| unsupported("$LogFile tail transfer wraps its destination range"))?;
        if *destination != expected
            || usize::from(u16_at(&page.fixed.bytes, 20)?) != count
            || usize::from(u16_at(&page.fixed.bytes, 22)?) != index + 1
        {
            return Err(corrupt(
                *destination,
                "$LogFile tail transfer has discontinuous destinations or positions",
            ));
        }
        generation(restart, page.last, oldest)?;
        if page.completed != 0 {
            generation(restart, page.completed, oldest)?;
        }
        if page.last < last
            || page.last >> (64 - restart.seq_num_bits) != sequence
            || (page.completed != 0 && page.completed < completed)
        {
            return Err(unsupported(
                "$LogFile tail transfer has incompatible LSN progress",
            ));
        }
        last = page.last;
        completed = completed.max(page.completed);
    }
    let final_page = &pages[count - 1].1;
    if final_page.completed == 0
        || final_page.last != final_page.completed
        || final_page.fixed.next_record_off == 0
    {
        return Err(unsupported(
            "$LogFile tail transfer does not end with a complete record",
        ));
    }
    Ok(Transfer { pages })
}

/// Compare competing complete transfers only when their destination sets agree.
/// Mixed ordering is not resolved by taking a per-page maximum.
fn select(groups: &mut Vec<Transfer>, incoming: Transfer, data_off: usize) -> Result<()> {
    let first = incoming.pages[0].0;
    let last = incoming.pages[incoming.pages.len() - 1].0;
    for previous in groups.iter_mut() {
        let old_first = previous.pages[0].0;
        let old_last = previous.pages[previous.pages.len() - 1].0;
        if last < old_first || old_last < first {
            continue;
        }
        if first != old_first || last != old_last || incoming.pages.len() != previous.pages.len() {
            return Err(unsupported(
                "$LogFile overlapping tail transfers have different publication boundaries",
            ));
        }
        let mut newer = false;
        let mut older = false;
        for ((_, a), (_, b)) in incoming.pages.iter().zip(&previous.pages) {
            newer |= a.last > b.last;
            older |= a.last < b.last;
            if a.last == b.last && !a.same_contents(b, data_off) {
                return Err(corrupt(
                    first,
                    "$LogFile equal-LSN transfer pages have conflicting contents",
                ));
            }
        }
        if newer && older {
            return Err(unsupported(
                "$LogFile competing tail transfers have crossed publication order",
            ));
        }
        if newer {
            *previous = incoming;
        }
        return Ok(());
    }
    groups.push(incoming);
    Ok(())
}

pub(super) fn read(
    cx: &Cx,
    restart: &Restart,
    oldest: u64,
    source: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<Copies> {
    let page_bytes = u64::from(restart.log_page);
    let page_size =
        usize::try_from(page_bytes).map_err(|_| corrupt(0, "$LogFile tail page size overflows"))?;
    let width = if restart.version.0 == 2 { 16_u64 } else { 1 };
    let mut groups = Vec::new();
    for bank in [2_u64, 2 + width] {
        let mut slot = bank;
        while slot < bank + width {
            checkpoint(cx)?;
            let at = slot * page_bytes;
            let raw = read_exact(cx, restart.file_size, at, page_size, source)?;
            if blank(&raw) {
                slot += 1;
                continue;
            }
            let first = copy_page(cx, restart, at, raw)?;
            let count = u64::from(u16_at(&first.1.fixed.bytes, 20)?);
            if u16_at(&first.1.fixed.bytes, 22)? != 1 || count == 0 || count > bank + width - slot {
                return Err(unsupported(
                    "$LogFile tail transfer is incomplete within its native bank",
                ));
            }
            let mut pages = vec![first];
            for index in 1..count {
                let at = (slot + index) * page_bytes;
                let raw = read_exact(cx, restart.file_size, at, page_size, source)?;
                if blank(&raw) {
                    return Err(unsupported(
                        "$LogFile tail transfer has a missing continuation page",
                    ));
                }
                pages.push(copy_page(cx, restart, at, raw)?);
            }
            select(
                &mut groups,
                transfer(cx, restart, oldest, pages)?,
                usize::from(restart.data_off),
            )?;
            slot += count;
        }
    }
    let mut result = Copies {
        pages: BTreeMap::new(),
        groups: Vec::new(),
    };
    for group in groups {
        result
            .groups
            .push(group.pages.iter().map(|(at, _)| *at).collect());
        for (at, page) in group.pages {
            if result.pages.insert(at, page).is_some() {
                return Err(corrupt(at, "$LogFile selected transfers overlap"));
            }
        }
    }
    checkpoint(cx)?;
    Ok(result)
}

/// The ring may contain an already-published equivalent transfer, or a wholly
/// newer one. A partially newer ring cannot be combined with a tail bank here.
pub(super) fn validate_selection(
    groups: &[Vec<u64>],
    decisions: &BTreeMap<u64, Selection>,
) -> Result<()> {
    for group in groups {
        let mut copied = false;
        let mut newer_ring = false;
        for at in group {
            match decisions.get(at) {
                Some(Selection::Copy) => copied = true,
                Some(Selection::Ring) => newer_ring = true,
                Some(Selection::Equal) => {}
                None => {
                    return Err(corrupt(
                        *at,
                        "$LogFile transfer lost a publication decision",
                    ));
                }
            }
        }
        if copied && newer_ring {
            return Err(unsupported(
                "$LogFile ring and tail require mixed-transfer salvage",
            ));
        }
    }
    Ok(())
}
