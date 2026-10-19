//! Discover complete native log work newer than the selected restart.
//!
//! Reference: Linux v6.17 fs/ntfs3/fslog.c, last_log_lsn and tail-page restore.
//! A restart is a checkpoint, not necessarily the last durable log record. The
//! bounded view below normalizes complete tail transfers only in private memory,
//! then the existing chronological reader and checkpoint/transaction Analysis
//! validate the entire retained interval. A largest page LSN alone is NOT proof.
//! Torn/ambiguous copies and incomplete or mixed-publication transfers are
//! refused. No native page, restart area, dirty flag or mount policy changes.

mod transfers;

use super::{
    Cx, NtfsVolume, RecordPage, Restart, Result, TailRecord, checkpoint, corrupt,
    lsn_to_vbo, preflight, read_exact, read_record, restore_page, u16_at, u32_at,
    u64_at, unsupported, validate_lsn_reference,
};
use std::cell::Cell;
use std::collections::BTreeMap;

const MAX_PAGES: u64 = 4096;
const IO_BUDGET: u64 = 64 * 1024 * 1024;

struct Page {
    raw: Vec<u8>,
    fixed: RecordPage,
    last: u64,
    completed: u64,
}

impl Page {
    fn parse(cx: &Cx, restart: &Restart, at: u64, raw: Vec<u8>) -> Result<Self> {
        let fixed = restore_page(cx, raw.clone(), restart, at)?;
        if restart.version.0 == 2 {
            let usa = usize::from(u16_at(&fixed.bytes, 4)?);
            let usa_end = usa + usize::from(u16_at(&fixed.bytes, 6)?) * 2;
            if usa < 64 && usa_end > 60 {
                return Err(corrupt(at, "$LogFile v2 USA overlaps the tail destination field"));
            }
        }
        let last = u64_at(&fixed.bytes, 8)?;
        let completed = u64_at(&fixed.bytes, 32)?;
        let has_end = u32_at(&fixed.bytes, 16)? & super::PAGE_RECORD_END != 0;
        if last == 0 || completed > last || (!has_end && completed != 0) {
            return Err(corrupt(at, "$LogFile tail page has inconsistent completion markers"));
        }
        Ok(Self { raw, fixed, last, completed: if has_end { completed } else { 0 } })
    }

    /// USA tokens, transfer positions and unused slack are not log contents.
    /// Compare all initialized client bytes and their completion boundaries.
    fn same_contents(&self, other: &Self, data_off: usize) -> bool {
        // A page containing an incomplete record uses its entire data area,
        // even when next_record_off marks an earlier completed record. Do not
        // ignore the newer record's bytes when comparing a ring/tail pair.
        let end = if self.fixed.next_record_off == 0 || self.last != self.completed {
            self.fixed.bytes.len()
        } else {
            usize::from(self.fixed.next_record_off)
        };
        self.last == other.last
            && self.completed == other.completed
            && self.fixed.next_record_off == other.fixed.next_record_off
            && self.fixed.bytes[16..20] == other.fixed.bytes[16..20]
            && end >= data_off
            && self.fixed.bytes[data_off..end] == other.fixed.bytes[data_off..end]
    }
}

fn blank(raw: &[u8]) -> bool {
    raw.iter().all(|byte| *byte == 0xFF) || raw.iter().all(|byte| *byte == 0)
}

struct View {
    // This is an in-memory replay boundary; the selected native restart bytes
    // in area are deliberately not rewritten or published as a new checkpoint.
    boundary: Restart,
    pages: BTreeMap<u64, Vec<u8>>,
}

impl View {
    fn read(
        &self,
        cx: &Cx,
        offset: u64,
        size: usize,
        source: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        // All native LFS consumers read complete aligned pages. Refuse a new
        // partial-read caller rather than accidentally bypass a tail override.
        if size as u64 != u64::from(self.boundary.log_page)
            || !offset.is_multiple_of(u64::from(self.boundary.log_page))
        {
            return Err(corrupt(offset, "$LogFile tail view requires complete aligned pages"));
        }
        let result = if let Some(page) = self.pages.get(&offset) {
            page.clone()
        } else {
            read_exact(cx, self.boundary.file_size, offset, size, source)?
        };
        checkpoint(cx)?;
        Ok(result)
    }
}

fn record_location(restart: &Restart, lsn: u64) -> Result<()> {
    // Reuse the existing checked LSN geometry without the old checkpoint's
    // upper bound. The caller separately bounds the generation to one wrap.
    let mut probe = restart.clone();
    probe.current_lsn = u64::MAX;
    validate_lsn_reference(&probe, lsn, "durable-tail")
}

fn generation(restart: &Restart, lsn: u64, oldest: u64) -> Result<()> {
    if lsn < oldest {
        return Ok(()); // Fully protected, but outside the retained interval.
    }
    record_location(restart, lsn)?;
    let address_bits = 64 - restart.seq_num_bits;
    let selected = restart.current_lsn >> address_bits;
    let observed = lsn >> address_bits;
    if observed > selected && observed - selected > 1 {
        return Err(unsupported("$LogFile tail generations exceed one comparable ring wrap"));
    }
    Ok(())
}

fn discover(
    cx: &Cx,
    restart: &Restart,
    stream_length: u64,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<View> {
    checkpoint(cx)?;
    let page_bytes = u64::from(restart.log_page);
    if !(512..=65_536).contains(&page_bytes)
        || !page_bytes.is_power_of_two()
        || restart.system_page != restart.log_page
        || restart.file_size > stream_length
        || !restart.file_size.is_multiple_of(page_bytes)
        || !(3..64).contains(&restart.seq_num_bits)
        || restart.current_lsn == 0
        || !matches!(restart.version, (1, 1) | (2, 0))
    {
        return Err(unsupported("$LogFile tail discovery requires a bounded native record-ring geometry"));
    }
    // The v2 tail destination is at 0x3c. A larger-page USA would overlap it;
    // its alternative layout needs independent native evidence, not a guess.
    if restart.version == (2, 0) && page_bytes != 4096 {
        return Err(unsupported("$LogFile v2 tail discovery currently requires 4 KiB pages"));
    }
    let reserved = if restart.version.0 == 2 { 34_u64 } else { 4 };
    let total_pages = restart.file_size / page_bytes;
    if total_pages <= reserved || total_pages > MAX_PAGES || restart.file_size > IO_BUDGET {
        return Err(unsupported("$LogFile tail discovery exceeds its page or byte scan budget"));
    }
    validate_lsn_reference(restart, restart.current_lsn, "selected-checkpoint")?;
    let oldest = restart.active_client_oldest_lsn.filter(|lsn| *lsn != 0)
        .unwrap_or(restart.current_lsn);
    validate_lsn_reference(restart, oldest, "retained-tail-start")?;
    let page_size = usize::try_from(page_bytes)
        .map_err(|_| corrupt(0, "$LogFile tail page size overflows"))?;
    let data_off = usize::from(restart.data_off);
    let transfers::Copies { pages: mut copies, groups } =
        transfers::read(cx, restart, oldest, read)?;
    let mut decisions = BTreeMap::new();

    let mut view = View { boundary: restart.clone(), pages: BTreeMap::new() };
    let mut completed = restart.current_lsn;
    let mut started = restart.current_lsn;
    for number in reserved..total_pages {
        checkpoint(cx)?;
        let at = number * page_bytes;
        let raw = read_exact(cx, restart.file_size, at, page_size, read)?;
        let ring = if blank(&raw) { None } else { Some(Page::parse(cx, restart, at, raw)?) };
        let chosen = if let Some(copy) = copies.remove(&at) {
            let decision = match &ring {
                None => transfers::Selection::Copy,
                Some(ring) if copy.last > ring.last => transfers::Selection::Copy,
                Some(ring) if copy.last < ring.last => transfers::Selection::Ring,
                Some(ring) => {
                    if !copy.same_contents(ring, data_off) {
                        return Err(corrupt(at, "$LogFile tail and ring disagree at the same LSN"));
                    }
                    transfers::Selection::Equal
                }
            };
            decisions.insert(at, decision);
            if matches!(decision, transfers::Selection::Copy) {
                view.pages.insert(at, copy.raw.clone());
                Some(copy)
            } else { ring }
        } else { ring };
        let Some(page) = chosen else { continue };
        for lsn in [page.last, page.completed].into_iter().filter(|lsn| *lsn != 0) {
            generation(restart, lsn, oldest)?;
        }
        started = started.max(page.last);
        completed = completed.max(page.completed);
    }
    transfers::validate_selection(&groups, &decisions)?;
    if started > completed {
        return Err(unsupported("$LogFile has a newer incomplete record; partial-tail salvage is not admitted"));
    }
    let address_bits = 64 - restart.seq_num_bits;
    let old_sequence = oldest >> address_bits;
    let end_sequence = completed >> address_bits;
    let old_vbo = lsn_to_vbo(oldest, restart.seq_num_bits)?;
    let end_vbo = lsn_to_vbo(completed, restart.seq_num_bits)?;
    if end_sequence < old_sequence || end_sequence - old_sequence > 1
        || (end_sequence != old_sequence && end_vbo >= old_vbo)
    {
        return Err(unsupported("$LogFile durable tail has overwritten or outlived the retained window"));
    }
    if completed != restart.current_lsn {
        // Do not copy a page marker into restart metadata blindly. The actual
        // LFS record at that address must supply the correct identity/length;
        // read_record and chronological Analysis validate its complete payload.
        let at = end_vbo & !(page_bytes - 1);
        let raw = view.read(cx, at, page_size, read)?;
        let fixed = restore_page(cx, raw, restart, at)?;
        let within = usize::try_from(end_vbo - at)
            .map_err(|_| corrupt(at, "$LogFile tail offset overflows"))?;
        if u64_at(&fixed.bytes, within)? != completed {
            return Err(corrupt(at, "$LogFile tail marker does not identify its claimed record"));
        }
        view.boundary.current_lsn = completed;
        view.boundary.last_lsn_data_len = u32_at(&fixed.bytes, within + 24)?;
    }
    checkpoint(cx)?;
    Ok(view)
}

/// The production dirty-volume preflight: resolve tail copies, validate the
/// original checkpoint anchor, then analyze ALL records through the new end.
/// Success still means private preflight only; the caller keeps dirty mounts
/// refused. Both discovery and all downstream reads share the outer I/O budget.
pub(in super::super) fn validate_latest_volume(
    cx: &Cx,
    restart: &Restart,
    stream_length: u64,
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
    volume: Option<&NtfsVolume>,
) -> Result<TailRecord> {
    checkpoint(cx)?;
    for (reference, label) in [
        (restart.active_client_oldest_lsn, "oldest-client"),
        (restart.active_client_restart_lsn, "client-restart"),
    ] {
        if let Some(lsn) = reference {
            validate_lsn_reference(restart, lsn, label)?;
        }
    }
    let remaining = Cell::new(IO_BUDGET);
    let charge = |size: usize| -> Result<()> {
        let left = remaining.get().checked_sub(size as u64)
            .ok_or_else(|| unsupported("$LogFile tail and preflight exceed the 64 MiB read budget"))?;
        remaining.set(left);
        Ok(())
    };
    let mut bounded = |offset: u64, size: usize| {
        checkpoint(cx)?;
        charge(size)?;
        read(offset, size)
    };
    let view = discover(cx, restart, stream_length, &mut bounded)?;
    // The old checkpoint's current record is still an anchor. A newer page or
    // copy must not erase its advertised record or change its declared length.
    let mut restored = |offset, size| {
        // Cached copies still consume work. A reference graph must not turn
        // one private page into unlimited free reassembly or cloned payloads.
        if view.pages.contains_key(&offset) { charge(size)?; }
        view.read(cx, offset, size, &mut bounded)
    };
    read_record(cx, restart, stream_length, restart.current_lsn, &mut restored)?;
    let boundary = &view.boundary;
    // Check append continuity independently of checkpoint-table seeding. In
    // particular, an absent oldest/client-restart pointer must not let the
    // existing diagnostic preflight start at the new tail and skip a gap.
    if boundary.current_lsn != restart.current_lsn {
        drop(preflight::scan::collect(
            cx, boundary, stream_length, restart.current_lsn, &mut restored,
        )?);
    }
    let tail = super::validate_dirty_volume(cx, boundary, stream_length, &mut restored, volume)?;
    checkpoint(cx)?;
    Ok(tail)
}

#[cfg(test)]
mod tests;
