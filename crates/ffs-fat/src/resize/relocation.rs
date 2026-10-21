//! Live-tail relocation as a private, read-only native-image view.
//!
//! Only clusters above the target limit move, and only into proven-free lower
//! clusters. Keep chain order, EOF, preallocation and native name records. The
//! existing resize planner/publisher then consumes this checked view normally;
//! neither relocation nor its validation obtains source write/sync authority.

use super::{Slice, TRANSFER, buffer, checked, fat_start, invalid, layout, word};
use crate::reader::{Directory, FatVolume, checkpoint};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_ondisk::fat::{FatEntry, FatGeometry, FatKind, FatOemCodePage};
use ffs_types::ByteOffset;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

// Match the admitted checker's namespace/depth envelope. Patches include at
// most one first-cluster field per object, two dot records per directory, and
// the two root boot records. No whole-file payload is retained in this plan.
const MAX_OBJECTS: usize = 131_072;
const MAX_PATCHES: usize = 3 * MAX_OBJECTS + 2;

#[derive(Clone, Copy, Debug)]
struct Move {
    from: u32,
    to: u32,
    /// Original selected FAT's low bits. Source immutability is required for
    /// the complete operation, just as for the enclosing resize plan.
    value: u32,
}

/// Both columns are strictly increasing, so one vector supports checked
/// forward and inverse lookup without two volume-sized hash tables.
#[derive(Default)]
struct Moves(Vec<Move>);

impl Moves {
    fn target(&self, cluster: u32) -> u32 {
        self.0
            .binary_search_by_key(&cluster, |item| item.from)
            .map_or(cluster, |index| self.0[index].to)
    }

    fn destination(&self, cluster: u32) -> Option<&Move> {
        self.0
            .binary_search_by_key(&cluster, |item| item.to)
            .ok()
            .map(|index| &self.0[index])
    }

    fn source(&self, cluster: u32) -> Option<u32> {
        self.destination(cluster).map_or_else(
            || {
                // Vacated tail storage is not recoverable deleted-file data.
                (self.target(cluster) == cluster).then_some(cluster)
            },
            |item| Some(item.from),
        )
    }

    fn value(&self, kind: FatKind, cluster: u32, original: u32) -> u32 {
        let value = if self.target(cluster) == cluster {
            self.destination(cluster)
                .map_or(original, |item| item.value)
        } else {
            0
        };
        match kind.decode_entry(value) {
            FatEntry::Next(next) => self.target(next),
            _ => value,
        }
    }
}

fn mask(kind: FatKind) -> u32 {
    match kind {
        FatKind::Fat16 => 0xFFFF,
        FatKind::Fat32 => 0x0FFF_FFFF,
    }
}

/// Scan selected allocation in bounded windows. Lower free slots are already
/// classified by the time a high cluster needs a destination. Bad clusters
/// never become relocation sources or targets; a bad tail remains a refusal.
fn plan_moves(
    cx: &Cx,
    source: &Slice,
    old: &FatGeometry,
    limit: u32,
    expected_used: u64,
) -> Result<Moves> {
    let mut allocation = buffer(old.cluster_count() as usize)?;
    let mut bytes = buffer(TRANSFER)?;
    let copy = if old.mirrored() { 0 } else { old.active_fat() };
    let start = fat_start(old, copy)?;
    let width = old.kind().entry_bytes() as usize;
    let mut moves = Moves::default();
    let max_moves = (old.cluster_count() - limit).min(limit) as usize;
    let mut gap = 0_usize;
    let mut index = 0_usize;
    let mut used = 0_u64;
    while index < allocation.len() {
        checkpoint(cx)?;
        let count = (allocation.len() - index).min(TRANSFER / width);
        source.read_exact_at(
            cx,
            ByteOffset(start + (index as u64 + 2) * width as u64),
            &mut bytes[..count * width],
        )?;
        for local in 0..count {
            checkpoint(cx)?;
            let position = local * width;
            let raw = if width == 2 {
                u32::from(u16::from_le_bytes([bytes[position], bytes[position + 1]]))
            } else {
                word(&bytes, position)
            };
            let state = match old.kind().decode_entry(raw) {
                FatEntry::Free => 0,
                FatEntry::Next(_) | FatEntry::End => 1,
                FatEntry::Bad => 2,
                FatEntry::Reserved => bail!("reserved allocation during relocation preflight"),
            };
            let current = index + local;
            allocation[current] = state;
            used += u64::from(state != 0);
            if current < limit as usize || state == 0 {
                continue;
            }
            if state == 2 {
                bail!("relocation cannot discard bad tail cluster {}", current + 2);
            }
            while gap < limit as usize && allocation[gap] != 0 {
                checkpoint(cx)?;
                gap += 1;
            }
            if gap == limit as usize {
                bail!("insufficient free retained clusters for relocation");
            }
            if moves.0.len() == moves.0.capacity() {
                moves
                    .0
                    .try_reserve_exact(1024.min(max_moves - moves.0.len()))
                    .context("allocating bounded relocation map")?;
            }
            moves.0.push(Move {
                from: current as u32 + 2,
                to: gap as u32 + 2,
                value: raw & mask(old.kind()),
            });
            gap += 1;
        }
        index += count;
    }
    if used != expected_used {
        bail!("source allocation changed during relocation planning");
    }
    checkpoint(cx)?;
    Ok(moves)
}

struct Relocated {
    source: Slice,
    geometry: FatGeometry,
    moves: Moves,
    data_start: u64,
    patches: BTreeMap<u64, Vec<u8>>,
}

impl Relocated {
    fn record_offset(&self, offset: u64) -> Result<u64> {
        if let Some((start, length)) = self.geometry.fixed_root()
            && offset >= start
            && offset + 32 <= start + length
        {
            return Ok(offset);
        }
        let bytes = u64::from(self.geometry.cluster_bytes());
        let relative = offset
            .checked_sub(self.data_start)
            .context("directory record outside data")?;
        let cluster = u32::try_from(relative / bytes + 2).context("directory cluster overflow")?;
        let target = self.moves.target(cluster);
        Ok(self
            .geometry
            .cluster_offset(target)
            .map_err(|e| invalid(e.to_string()))?
            + relative % bytes)
    }

    fn first_cluster(&self, bytes: &[u8]) -> u32 {
        let low = u32::from(u16::from_le_bytes([bytes[26], bytes[27]]));
        if self.geometry.kind() == FatKind::Fat16 {
            low
        } else {
            low | (u32::from(u16::from_le_bytes([bytes[20], bytes[21]]) & 0x0FFF) << 16)
        }
    }

    fn add_pointer(&mut self, cx: &Cx, offset: u64, first: u32) -> Result<()> {
        let target = self.moves.target(first);
        if target == first {
            return Ok(());
        }
        let mut bytes = buffer(32)?;
        self.source
            .read_exact_at(cx, ByteOffset(offset), &mut bytes)?;
        if self.first_cluster(&bytes) != first || matches!(bytes[0], 0 | 0xE5) || bytes[11] & 8 != 0
        {
            bail!("native directory record changed during relocation planning");
        }
        if self.geometry.kind() == FatKind::Fat32 {
            let reserved = u16::from_le_bytes([bytes[20], bytes[21]]) & 0xF000;
            bytes[20..22].copy_from_slice(&(reserved | (target >> 16) as u16).to_le_bytes());
        }
        // FAT16's bytes 20..22 may be an OS/2 EA index; never rewrite them.
        bytes[26..28].copy_from_slice(&(target as u16).to_le_bytes());
        let position = self.record_offset(offset)?;
        if self.patches.len() >= MAX_PATCHES || self.patches.insert(position, bytes).is_some() {
            bail!("relocation directory patch budget or unique-ownership violation");
        }
        Ok(())
    }

    fn directory_pointers(&mut self, cx: &Cx, volume: &FatVolume) -> Result<()> {
        let mut pending = VecDeque::from([(Directory::Root, 0_u32, 0_u16)]);
        let mut seen = BTreeSet::new();
        if self.geometry.kind() == FatKind::Fat32 {
            seen.insert(self.geometry.root_cluster());
        }
        let mut objects = 1_usize;
        while let Some((directory, parent, depth)) = pending.pop_front() {
            checkpoint(cx)?;
            if let Directory::Cluster(first) = directory {
                let start = self
                    .geometry
                    .cluster_offset(first)
                    .map_err(|e| invalid(e.to_string()))?;
                let mut dots = [0; 64];
                self.source
                    .read_exact_at(cx, ByteOffset(start), &mut dots)?;
                for (index, name, expected) in
                    [(0, b".          ", first), (1, b"..         ", parent)]
                {
                    let record = &dots[index * 32..(index + 1) * 32];
                    if &record[..11] != name
                        || record[11] & 0x10 == 0
                        || self.first_cluster(record) != expected
                        || record[28..32] != [0; 4]
                    {
                        bail!("directory ancestry changed during relocation planning");
                    }
                    self.add_pointer(cx, start + index as u64 * 32, expected)?;
                }
            }
            let parent_cluster = match directory {
                Directory::Root => 0,
                Directory::Cluster(first) => first,
            };
            for entry in volume.list(cx, directory)? {
                checkpoint(cx)?;
                objects += 1;
                if objects > MAX_OBJECTS {
                    bail!("relocation namespace exceeds object budget");
                }
                self.add_pointer(cx, entry.offset, entry.native.first_cluster)?;
                if entry.native.is_directory() {
                    if depth == 256 || !seen.insert(entry.native.first_cluster) {
                        bail!("relocation namespace exceeds depth or repeats a directory");
                    }
                    pending
                        .try_reserve(1)
                        .context("reserving bounded relocation traversal")?;
                    pending.push_back((entry.directory()?, parent_cluster, depth + 1));
                }
            }
        }
        checkpoint(cx)?;
        Ok(())
    }

    /// Same geometry as the source: only data-cluster identities are translated.
    /// Preserve sequential runs instead of reducing a 64 KiB copy to 128 calls.
    fn mapping(&self, at: u64, maximum: u64) -> (Option<u64>, usize) {
        let cluster_bytes = u64::from(self.geometry.cluster_bytes());
        let data_end = self.data_start + u64::from(self.geometry.cluster_count()) * cluster_bytes;
        if at < self.data_start {
            return (Some(at), maximum.min(self.data_start - at) as usize);
        }
        if at >= data_end {
            return (Some(at), maximum as usize);
        }
        let relative = at - self.data_start;
        let cluster = (relative / cluster_bytes) as u32 + 2;
        let within = relative % cluster_bytes;
        let origin = self.moves.source(cluster);
        let source =
            origin.map(|first| self.data_start + u64::from(first - 2) * cluster_bytes + within);
        let mut count = maximum.min(cluster_bytes - within).min(data_end - at);
        let mut next = cluster + 1;
        while count < maximum && at + count < data_end {
            let following = self.moves.source(next);
            let contiguous = match (source, following) {
                (None, None) => true,
                (Some(start), Some(first)) => {
                    start + count == self.data_start + u64::from(first - 2) * cluster_bytes
                }
                _ => false,
            };
            if !contiguous {
                break;
            }
            count += (maximum - count)
                .min(cluster_bytes)
                .min(data_end - at - count);
            next += 1;
        }
        (source, count as usize)
    }

    fn rewrite_fats(&self, cx: &Cx, at: u64, bytes: &mut [u8]) -> ffs_error::Result<()> {
        let width = u64::from(self.geometry.kind().entry_bytes());
        let end = at + bytes.len() as u64; // Validated by read_exact_at.
        let value_mask = mask(self.geometry.kind());
        for copy in 0..self.geometry.fat_count() {
            if !self.geometry.mirrored() && copy != self.geometry.active_fat() {
                continue;
            }
            let start = self
                .geometry
                .entry_offset(copy, 2)
                .map_err(|e| invalid(e.to_string()))?;
            let left = at.max(start);
            let right = end.min(start + u64::from(self.geometry.cluster_count()) * width);
            if left >= right {
                continue;
            }
            let first = (left - start) / width + 2;
            let last = (right - start).div_ceil(width) + 2;
            for cluster in first..last {
                checkpoint(cx)?;
                let position = start + (cluster - 2) * width;
                let mut original = [0; 4];
                if position >= at && position + width <= end {
                    original[..width as usize].copy_from_slice(
                        &bytes[(position - at) as usize..(position + width - at) as usize],
                    );
                } else {
                    // An arbitrary caller window may split either native word.
                    // Complete only this word from the immutable ORIGINAL view.
                    self.source.read_exact_at(
                        cx,
                        ByteOffset(position),
                        &mut original[..width as usize],
                    )?;
                }
                let raw = u32::from_le_bytes(original);
                let value =
                    self.moves
                        .value(self.geometry.kind(), cluster as u32, raw & value_mask);
                // Reserved high bits belong to the destination FAT slot, not
                // the relocated object. Inactive copies are untouched above.
                let updated = ((raw & !value_mask) | value).to_le_bytes();
                let lo = at.max(position);
                let hi = end.min(position + width);
                bytes[(lo - at) as usize..(hi - at) as usize]
                    .copy_from_slice(&updated[(lo - position) as usize..(hi - position) as usize]);
            }
        }
        Ok(())
    }

    fn patch_bytes(at: u64, bytes: &mut [u8], offset: u64, patch: &[u8]) {
        let left = at.max(offset);
        let right = (at + bytes.len() as u64).min(offset + patch.len() as u64);
        if left < right {
            bytes[(left - at) as usize..(right - at) as usize]
                .copy_from_slice(&patch[(left - offset) as usize..(right - offset) as usize]);
        }
    }
}

impl ByteDevice for Relocated {
    fn len_bytes(&self) -> u64 {
        self.geometry.volume_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let end =
            at.0.checked_add(bytes.len() as u64)
                .filter(|end| *end <= self.len_bytes())
                .ok_or_else(|| invalid("relocation view range overflow"))?;
        if bytes.is_empty() {
            return Ok(());
        }
        let mut done = 0;
        while done < bytes.len() {
            checkpoint(cx)?;
            let (source, count) = self.mapping(
                at.0 + done as u64,
                (bytes.len() - done).min(TRANSFER) as u64,
            );
            if let Some(source) = source {
                self.source.read_exact_at(
                    cx,
                    ByteOffset(source),
                    &mut bytes[done..done + count],
                )?;
            } else {
                bytes[done..done + count].fill(0);
            }
            done += count;
        }
        self.rewrite_fats(cx, at.0, bytes)?;
        // Do not scan every directory patch for every payload read. Only one
        // preceding patch can overlap the left edge; the rest start in range.
        if let Some((&offset, patch)) = self.patches.range(..at.0).next_back() {
            Self::patch_bytes(at.0, bytes, offset, patch);
        }
        for (&offset, patch) in self.patches.range(at.0..end) {
            checkpoint(cx)?;
            Self::patch_bytes(at.0, bytes, offset, patch);
        }
        checkpoint(cx)
    }

    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
    fn sync(&self, _: &Cx) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
}

pub(super) fn prepare(
    cx: &Cx,
    source: Slice,
    length: u64,
    page: FatOemCodePage,
) -> Result<(Slice, usize)> {
    checkpoint(cx)?;
    let volume = FatVolume::from_device(cx, Box::new(source.clone()), 0, source.length)?
        .with_oem_code_page(page);
    let before = checked(cx, &volume)?;
    let old = &volume.geometry;
    let mut boot = buffer(old.sector_bytes() as usize)?;
    source.read_exact_at(cx, ByteOffset(0), &mut boot)?;
    // Derive capacity before choosing destinations. A root in the removed tail
    // must not make geometry parsing reject an otherwise feasible relocation.
    // This private geometry probe is NEVER exposed as a readable filesystem.
    let mut probe = boot.clone();
    if old.kind() == FatKind::Fat32 {
        probe[44..48].copy_from_slice(&2_u32.to_le_bytes());
    }
    let (_, target) = layout(&probe, old, length)?;
    if target.cluster_count() >= old.cluster_count() {
        return Ok((source, 0));
    }
    let moves = plan_moves(
        cx,
        &source,
        old,
        target.cluster_count(),
        before.0.allocated + before.0.bad,
    )?;
    let count = moves.0.len();
    if count == 0 {
        return Ok((source, 0));
    }
    let mut view = Relocated {
        source,
        geometry: old.clone(),
        moves,
        data_start: old.cluster_offset(2).map_err(|e| invalid(e.to_string()))?,
        patches: BTreeMap::new(),
    };
    if old.kind() == FatKind::Fat32 && view.moves.target(old.root_cluster()) != old.root_cluster() {
        for number in std::iter::once(0_u16).chain(old.backup_boot_sector()) {
            let offset = u64::from(number) * u64::from(old.sector_bytes());
            let mut bytes = buffer(old.sector_bytes() as usize)?;
            view.source
                .read_exact_at(cx, ByteOffset(offset), &mut bytes)?;
            bytes[44..48].copy_from_slice(&view.moves.target(old.root_cluster()).to_le_bytes());
            view.patches.insert(offset, bytes);
        }
        boot[44..48].copy_from_slice(&view.moves.target(old.root_cluster()).to_le_bytes());
    }
    let expected_geometry =
        FatGeometry::parse(&boot, old.volume_bytes()).map_err(|e| invalid(e.to_string()))?;
    view.directory_pointers(cx, &volume)?;
    let inner: Arc<dyn ByteDevice> = Arc::new(view);
    let source = Slice {
        inner,
        base: 0,
        length: old.volume_bytes(),
    };
    let candidate = FatVolume::from_device(cx, Box::new(source.clone()), 0, source.length)?
        .with_oem_code_page(page);
    if candidate.geometry != expected_geometry || checked(cx, &candidate)? != before {
        bail!("relocation changed reachable ownership, preallocation or free space");
    }
    checkpoint(cx)?;
    Ok((source, count))
}
