//! Explicit retirement of unbound LFN records left by interrupted namespace edits.
//!
//! An LFN run is discardable only when followed by a deleted slot, the directory
//! end marker, or the end of the validated directory allocation. A malformed run
//! followed by a live short entry is ambiguous and is NEVER repaired here. The
//! ordinary checker and mount admission are unchanged.

use super::{FatCheckReport, FatVolume, checkpoint, write_patch};
use super::super::super::{Directory, Entry, MAX_DIRECTORY_SLOTS, allocate};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_ondisk::fat::{FatDirectoryDecoder, FatKind};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};

const MAX_ORPHAN_SLOTS: usize = 65_536;
const MAX_TOTAL_SLOTS: usize = 4_194_304;
const MAX_OBJECTS: u64 = 131_072;
const MAX_LFN_RUN: usize = 20;

#[derive(Debug, PartialEq, Eq)]
struct Slot {
    offset: u64,
    bytes: [u8; 32],
}

impl Slot {
    fn retired(&self) -> [u8; 32] {
        let mut bytes = self.bytes;
        bytes[0] = 0xE5;
        bytes
    }
}

/// The fingerprint covers every examined directory record, including native
/// names, aliases, dot entries, deleted records and end markers. Only proposed
/// orphan deletion markers are normalized. It is NOT a file-content checksum.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Names {
    slots: Vec<Slot>,
    fingerprint: [u8; 32],
    records: usize,
    storage_slots: usize,
    files: u64,
    directories: u64,
}

struct Scan {
    names: Names,
    digest: Sha256,
    pending: VecDeque<(Directory, u16)>,
    visited: BTreeSet<u32>,
}

impl Scan {
    fn record(&mut self, offset: u64, bytes: &[u8; 32]) -> Result<()> {
        if self.names.records == MAX_TOTAL_SLOTS {
            bail!("orphan-name recovery exceeds the directory-record budget");
        }
        self.names.records += 1;
        self.digest.update(b"R");
        self.digest.update(offset.to_le_bytes());
        self.digest.update(bytes);
        Ok(())
    }

    fn orphan_run(&mut self, run: &mut Vec<Slot>) -> Result<()> {
        if self.names.slots.len() + run.len() > MAX_ORPHAN_SLOTS {
            bail!("orphan-name recovery exceeds the explicit 65536-record repair budget");
        }
        self.names.slots.try_reserve(run.len())
            .context("reserving bounded orphan-name repair evidence")?;
        for slot in run.drain(..) {
            self.record(slot.offset, &slot.retired())?;
            self.names.slots.push(slot);
        }
        Ok(())
    }

    fn live_entry(
        &mut self,
        cx: &Cx,
        volume: &FatVolume,
        depth: u16,
        run: &mut Vec<Slot>,
        slot: &Slot,
    ) -> Result<()> {
        // Validate EACH checksum-bound set independently. A decoder reset at a
        // later LAST slot cannot silently turn an earlier, ambiguous set into
        // discardable records attached to the same live short entry.
        let mut decoder = FatDirectoryDecoder::default();
        for long in run.iter() {
            decoder.push(&long.bytes, volume.geometry.kind())
                .map_err(|error| anyhow::anyhow!("invalid live FAT name: {error}"))?;
        }
        let native = decoder.push(&slot.bytes, volume.geometry.kind())
            .map_err(|error| anyhow::anyhow!("invalid live FAT entry: {error}"))?;
        decoder.finish();
        if decoder.has_malformed_long_name() || (!run.is_empty() && native.is_none()) {
            bail!("orphan-name recovery refuses malformed names attached to a live entry at {}", slot.offset);
        }
        for long in run.drain(..) {
            self.record(long.offset, &long.bytes)?;
        }
        self.record(slot.offset, &slot.bytes)?;
        let Some(native) = native else { return Ok(()); };
        if native.short_name == *b".          " || native.short_name == *b"..         " {
            return Ok(());
        }
        let entry = Entry { offset: slot.offset, native, oem_code_page: volume.oem_code_page() };
        // The checker uses invalid_long_name for unsafe live path components
        // too. Explicit cleanup must not turn that distinct finding into an
        // allowed orphan; require the full native presentation to be valid.
        entry.name()?;
        if entry.native.is_directory() {
            if depth >= 256 { bail!("orphan-name recovery exceeds the directory-depth budget"); }
            if !self.visited.insert(entry.native.first_cluster) {
                bail!("orphan-name recovery encountered repeated directory ownership");
            }
            self.pending.try_reserve(1).context("reserving bounded directory traversal")?;
            self.pending.push_back((entry.directory()?, depth + 1));
        } else {
            self.names.files += 1;
        }
        if self.names.files + self.names.directories + self.pending.len() as u64 > MAX_OBJECTS {
            bail!("orphan-name recovery exceeds the namespace-object budget");
        }
        checkpoint(cx)?;
        Ok(())
    }

    fn directory(&mut self, cx: &Cx, volume: &FatVolume, directory: Directory, depth: u16) -> Result<()> {
        self.names.directories += 1;
        // Validate the entire allocation chain, including storage beyond the
        // logical end marker. Never follow unchecked links to find name slots.
        let fixed = if directory == Directory::Root { volume.geometry.fixed_root() } else { None };
        let mut offsets = Vec::new();
        let bytes = if let Some((start, length)) = fixed {
            let bytes = volume.geometry.sector_bytes() as usize;
            if length / 32 > MAX_DIRECTORY_SLOTS as u64 {
                bail!("orphan-name recovery directory exceeds its record budget");
            }
            offsets.try_reserve_exact((length / bytes as u64) as usize)
                .context("reserving fixed-root traversal")?;
            offsets.extend((start..start + length).step_by(bytes));
            bytes
        } else {
            let first = match directory {
                Directory::Root => volume.geometry.root_cluster(),
                Directory::Cluster(first) => first,
            };
            let bytes = volume.geometry.cluster_bytes() as usize;
            let chain = volume.allocation_chain(cx, first, 1, volume.cluster_offset(first)?,
                (MAX_DIRECTORY_SLOTS * 32).div_ceil(bytes))?;
            if chain.len() * (bytes / 32) > MAX_DIRECTORY_SLOTS {
                bail!("orphan-name recovery directory exceeds its record budget");
            }
            offsets.try_reserve_exact(chain.len()).context("reserving directory traversal")?;
            for cluster in chain {
                checkpoint(cx)?;
                offsets.push(volume.cluster_offset(cluster)?);
            }
            bytes
        };
        // Bound allocated directory storage too, not just visible records.
        // A directory may end immediately while retaining a long unused tail.
        let storage_slots = offsets.len() * (bytes / 32);
        self.names.storage_slots = self.names.storage_slots.checked_add(storage_slots)
            .filter(|&total| total <= MAX_TOTAL_SLOTS)
            .context("orphan-name recovery exceeds its allocated-directory budget")?;
        // Include the entire directory mapping, even beyond an end marker, in
        // the retained proof. Marker normalization must not hide a changed tail.
        self.digest.update(b"D");
        self.digest.update((offsets.len() as u64).to_le_bytes());
        for &offset in &offsets { self.digest.update(offset.to_le_bytes()); }
        let mut buffer = allocate(bytes)?;
        let mut run = Vec::new();
        run.try_reserve_exact(MAX_LFN_RUN).context("reserving bounded pending long name")?;
        for start in offsets {
            checkpoint(cx)?;
            volume.read_exact(cx, start, &mut buffer)?;
            for (index, bytes) in buffer.as_chunks::<32>().0.iter().enumerate() {
                checkpoint(cx)?;
                let slot = Slot { offset: start + index as u64 * 32, bytes: *bytes };
                if matches!(bytes[0], 0 | 0xE5) {
                    // Neither deleted entries nor end markers can own an LFN.
                    self.orphan_run(&mut run)?;
                    self.record(slot.offset, bytes)?;
                    if bytes[0] == 0 { return Ok(()); }
                } else if bytes[11] == 0x0F {
                    if run.len() == MAX_LFN_RUN {
                        bail!("orphan-name recovery refuses runs longer than twenty LFN records");
                    }
                    run.push(slot);
                } else {
                    self.live_entry(cx, volume, depth, &mut run, &slot)?;
                }
            }
        }
        // No short entry exists outside this fully validated native directory.
        self.orphan_run(&mut run)
    }
}

impl Names {
    /// Retained namespace evidence for other explicitly authorized repairs.
    /// Unlike orphan cleanup, an intact namespace may have no orphan records.
    pub(super) fn capture(cx: &Cx, volume: &FatVolume) -> Result<Self> {
        Self::scan(cx, volume)
    }

    fn scan(cx: &Cx, volume: &FatVolume) -> Result<Self> {
        checkpoint(cx)?;
        let mut scan = Scan {
            names: Self::default(), digest: Sha256::new(),
            pending: VecDeque::from([(Directory::Root, 0)]), visited: BTreeSet::new(),
        };
        if volume.geometry.kind() == FatKind::Fat32 {
            scan.visited.insert(volume.geometry.root_cluster());
        }
        while let Some((directory, depth)) = scan.pending.pop_front() {
            scan.directory(cx, volume, directory, depth)?;
        }
        scan.names.fingerprint = scan.digest.finalize().into();
        // Only publication is ordered by physical sector; identification and
        // fingerprinting always follow logical directory/cluster order.
        scan.names.slots.sort_unstable_by_key(|slot| slot.offset);
        if scan.names.slots.windows(2).any(|pair| pair[0].offset == pair[1].offset) {
            bail!("orphan-name recovery encountered duplicate record ownership");
        }
        checkpoint(cx)?;
        Ok(scan.names)
    }

    pub(super) fn prepare(cx: &Cx, volume: &FatVolume, before: &FatCheckReport) -> Result<Self> {
        let result = Self::scan(cx, volume)?;
        if result.files != before.files || result.directories != before.directories {
            bail!("orphan-name recovery namespace differs from the complete checker");
        }
        if result.slots.is_empty() {
            bail!("invalid long-name findings are not explained by unbound records");
        }
        Ok(result)
    }

    pub(super) fn count(&self) -> usize { self.slots.len() }

    pub(super) fn validate(&self, cx: &Cx, volume: &FatVolume) -> Result<()> {
        if self.slots.is_empty() { return Ok(()); }
        if Self::scan(cx, volume)? != *self {
            bail!("orphan-name recovery evidence changed before mutation");
        }
        Ok(())
    }

    pub(super) fn verify(&self, cx: &Cx, volume: &FatVolume) -> Result<()> {
        if self.slots.is_empty() { return Ok(()); }
        let actual = Self::scan(cx, volume)?;
        if !actual.slots.is_empty() || actual.fingerprint != self.fingerprint
            || actual.files != self.files || actual.directories != self.directories
            || actual.records != self.records
            || actual.storage_slots != self.storage_slots
        {
            bail!("orphan-name recovery changed the retained native namespace or left unbound names");
        }
        for slot in &self.slots {
            checkpoint(cx)?;
            let mut actual = [0; 32];
            volume.read_exact(cx, slot.offset, &mut actual)?;
            if actual != slot.retired() {
                bail!("orphan-name retirement failed readback at {}", slot.offset);
            }
        }
        Ok(())
    }

    /// Called only after the common recovery engine has synchronized dirty
    /// state. Reuse its expected-value, sector-preserving, exact-readback writer.
    pub(super) fn retire(&self, cx: &Cx, volume: &FatVolume) -> Result<()> {
        if self.slots.is_empty() { return Ok(()); }
        let size = volume.geometry.sector_bytes() as usize;
        let mut original = allocate(size)?;
        let mut updated = allocate(size)?;
        let mut position = None;
        for slot in &self.slots {
            checkpoint(cx)?;
            let start = slot.offset / size as u64 * size as u64;
            if position != Some(start) {
                if let Some(previous) = position {
                    write_patch(cx, volume, previous, &original, &updated)?;
                }
                volume.read_exact(cx, start, &mut original)?;
                updated.copy_from_slice(&original);
                position = Some(start);
            }
            let within = (slot.offset - start) as usize;
            if original[within..within + 32] != slot.bytes {
                bail!("orphan-name record changed before publication at {}", slot.offset);
            }
            updated[within] = 0xE5;
        }
        if let Some(last) = position { write_patch(cx, volume, last, &original, &updated)?; }
        volume.device.sync(cx)?;
        // Never free allocation while a lost acknowledged directory write or
        // a damaged adjacent live entry remains hidden behind an unchecked sync.
        self.verify(cx, volume)
    }
}
