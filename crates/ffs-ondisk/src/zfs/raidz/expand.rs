//! OpenZFS `zfs-2.4.0` expanded RAIDZ (`org.openzfs:raidz_expansion`) layout,
//! reflow scratch-state codec, mapping, encoding, and P/Q/R reconstruction.
//!
//! Sources: OpenZFS `zfs-2.4.0` `include/sys/uberblock_impl.h` (`RRSS_GET_*`),
//! `include/sys/vdev_raidz_impl.h`, and `module/zfs/vdev_raidz.c`
//! (`vdev_raidz_map_alloc_expanded`).

use super::parity::{encode_pqr_parity, reconstruct_pqr};
use crate::zfs::{DATA_OFFSET, MAX_BLOCK_BYTES, invalid};
use ffs_types::ParseError;

/// OpenZFS `VDEV_BOOT_SIZE` (`3.5 MiB`), used as the scratch offset delta when
/// `ub_raidz_reflow_info` indicates `ScratchValid`.
pub const VDEV_BOOT_SIZE: u64 = 7 << 19;

/// OpenZFS `zfs-2.4.0` `raidz_reflow_scratch_state_t` (`uberblock_impl.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RaidzReflowScratchState {
    /// Normal state: scratch area is not active.
    NotInUse = 0,
    /// Scratch space holds valid reflowed data during an active/interrupted sync.
    Valid = 1,
    /// Scratch invalidated after normal TXG sync.
    InvalidSynced = 2,
    /// Scratch invalidated on pool import.
    InvalidSyncedOnImport = 3,
    /// Scratch invalidated after reflow completion.
    InvalidSyncedReflow = 4,
}

impl RaidzReflowScratchState {
    pub fn from_raw(raw: u16) -> Result<Self, ParseError> {
        match raw {
            0 => Ok(Self::NotInUse),
            1 => Ok(Self::Valid),
            2 => Ok(Self::InvalidSynced),
            3 => Ok(Self::InvalidSyncedOnImport),
            4 => Ok(Self::InvalidSyncedReflow),
            _ => Err(invalid("unknown RAIDZ reflow scratch state")),
        }
    }
}

/// Decoded `ub_raidz_reflow_info` bitfield (`uberblock_impl.h`).
///
/// - Bits `0..55`: `offset >> 9` (byte offset shifted right by 9, 512-byte sectors)
/// - Bits `55..64`: `raidz_reflow_scratch_state_t` (`0..=4`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaidzReflowInfo {
    pub offset: u64,
    pub state: RaidzReflowScratchState,
}

impl RaidzReflowInfo {
    const OFFSET_SECTORS_MASK: u64 = (1_u64 << 55) - 1;

    /// Decode raw 64-bit `ub_raidz_reflow_info`.
    pub fn decode(raw: u64) -> Result<Self, ParseError> {
        let state_raw =
            u16::try_from(raw >> 55).map_err(|_| invalid("RAIDZ reflow scratch state overflow"))?;
        let state = RaidzReflowScratchState::from_raw(state_raw)?;
        let offset = (raw & Self::OFFSET_SECTORS_MASK) << 9;
        Ok(Self { offset, state })
    }

    /// Encode into raw 64-bit `ub_raidz_reflow_info`.
    pub fn encode(self) -> Result<u64, ParseError> {
        if !self.offset.is_multiple_of(512) {
            return Err(invalid("unaligned RAIDZ reflow offset"));
        }
        let sectors = self.offset >> 9;
        if sectors > Self::OFFSET_SECTORS_MASK {
            return Err(invalid("RAIDZ reflow offset exceeds 55-bit sector field"));
        }
        Ok((u64::from(self.state as u16) << 55) | sectors)
    }

    #[must_use]
    pub const fn use_scratch(self) -> bool {
        matches!(self.state, RaidzReflowScratchState::Valid)
    }
}

/// Configuration for a RAIDZ vdev that has undergone one or more expansions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedRaidzConfig {
    pub ashift: u8,
    pub parity: usize,
    pub original_width: usize,
    pub physical_width: usize,
    /// Sorted list of TXGs at which each width expansion completed (one per
    /// added disk, length `<= physical_width - original_width`).
    pub expand_txgs: Vec<u64>,
    /// Byte offset up to which reflow has synced onto `physical_width` disks.
    /// `u64::MAX` when no reflow is currently in progress.
    pub reflow_offset_synced: u64,
    /// Byte offset up to which reflow copy has been initiated (`>= reflow_offset_synced`).
    pub reflow_offset_next: u64,
    /// Whether reads in the reflowed range must consult the scratch region.
    pub use_scratch: bool,
}

impl ExpandedRaidzConfig {
    pub fn validate(&self) -> Result<(), ParseError> {
        if !(9..=16).contains(&self.ashift)
            || !(1..=3).contains(&self.parity)
            || !(self.parity + 1..=255).contains(&self.original_width)
            || !(self.original_width..=255).contains(&self.physical_width)
        {
            return Err(invalid("invalid expanded RAIDZ geometry"));
        }
        if self.expand_txgs.len() > self.physical_width - self.original_width {
            return Err(invalid("too many RAIDZ expansion TXGs for physical width"));
        }
        for pair in self.expand_txgs.windows(2) {
            if pair[0] == 0 || pair[1] < pair[0] {
                return Err(invalid("non-monotonic RAIDZ expansion TXG history"));
            }
        }
        if self.expand_txgs.first() == Some(&0) {
            return Err(invalid("zero RAIDZ expansion TXG"));
        }
        if self.reflow_offset_next < self.reflow_offset_synced {
            return Err(invalid("RAIDZ reflow next offset precedes synced offset"));
        }
        Ok(())
    }

    /// Determine the logical stripe width that was active when a block born at
    /// `birth_txg` was written (OpenZFS `vdev_raidz_logical_width`).
    #[must_use]
    pub fn logical_width_for_birth(&self, birth_txg: u64) -> usize {
        let mut width = self.original_width;
        for &expand_txg in &self.expand_txgs {
            if birth_txg >= expand_txg {
                width += 1;
            }
        }
        width.min(self.physical_width)
    }
}

/// One physical sector placement inside an expanded RAIDZ row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpandedRaidzCol {
    pub child_id: usize,
    /// Child-relative allocation offset before `DATA_OFFSET` (or scratch offset
    /// when `use_scratch` is set — use [`Self::leaf_byte_offset`] for I/O).
    pub offset: u64,
    /// True when this sector resides in the scratch region (`offset - VDEV_BOOT_SIZE`).
    pub use_scratch: bool,
    /// Active sector length (`1 << ashift`), or `0` for phantom trailing sectors
    /// on a partial final row.
    pub bytes: usize,
    /// Offset in the ashift-aligned physical block buffer, or `None` for parity
    /// and phantom trailing sectors.
    pub data_offset: Option<usize>,
    /// Optional shadow write location when a write straddles an in-progress reflow.
    pub shadow_child_id: Option<usize>,
    pub shadow_offset: Option<u64>,
}

impl ExpandedRaidzCol {
    /// Absolute byte offset on the leaf vdev (`DATA_OFFSET + offset`, adjusted
    /// by `-VDEV_BOOT_SIZE` when reading/writing scratch space).
    pub fn leaf_byte_offset(&self) -> Result<u64, ParseError> {
        let base = DATA_OFFSET
            .checked_add(self.offset)
            .ok_or_else(|| invalid("expanded RAIDZ leaf offset overflow"))?;
        if self.use_scratch {
            base.checked_sub(VDEV_BOOT_SIZE)
                .ok_or_else(|| invalid("expanded RAIDZ scratch offset underflow"))
        } else {
            Ok(base)
        }
    }

    /// Absolute byte offset of the shadow copy on `shadow_child_id`, if any.
    pub fn shadow_leaf_byte_offset(&self) -> Result<Option<u64>, ParseError> {
        let Some(shadow_off) = self.shadow_offset else {
            return Ok(None);
        };
        let base = DATA_OFFSET
            .checked_add(shadow_off)
            .ok_or_else(|| invalid("expanded RAIDZ shadow offset overflow"))?;
        let resolved = if self.use_scratch {
            base.checked_sub(VDEV_BOOT_SIZE)
                .ok_or_else(|| invalid("expanded RAIDZ shadow scratch underflow"))?
        } else {
            base
        };
        Ok(Some(resolved))
    }
}

/// One row of an expanded RAIDZ block map. Every row always has `cols` columns
/// (`0..parity` are parity, `parity..cols` are data or zero-sized phantoms) so
/// Q/R Vandermonde parity equations use the full logical stripe width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedRaidzRow {
    pub parity: usize,
    pub cols: Vec<ExpandedRaidzCol>,
}

/// Complete OpenZFS `zfs-2.4.0` expanded RAIDZ block map (`vdev_raidz_map_alloc_expanded`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedRaidzMap {
    physical_bytes: usize,
    aligned_bytes: usize,
    allocated_bytes: u64,
    parity: usize,
    sector_bytes: usize,
    rows: Vec<ExpandedRaidzRow>,
}

impl ExpandedRaidzMap {
    #[allow(clippy::too_many_lines)]
    pub fn new(
        config: &ExpandedRaidzConfig,
        dva_offset: u64,
        physical_bytes: usize,
        logical_width: usize,
    ) -> Result<Self, ParseError> {
        config.validate()?;
        if !(config.parity + 1..=config.physical_width).contains(&logical_width)
            || physical_bytes == 0
            || physical_bytes > MAX_BLOCK_BYTES
            || !physical_bytes.is_multiple_of(512)
        {
            return Err(invalid("invalid expanded RAIDZ block geometry"));
        }
        let sector = 1_usize << config.ashift;
        if !dva_offset.is_multiple_of(sector as u64) {
            return Err(invalid("unaligned expanded RAIDZ DVA offset"));
        }

        let parity = config.parity;
        let data_sectors = physical_bytes.div_ceil(sector);
        let ndata = logical_width - parity;
        let q = data_sectors / ndata;
        let r = data_sectors - q * ndata;
        let bc = if r == 0 { 0 } else { r + parity };
        let tot = data_sectors + parity * (q + usize::from(r != 0));
        let row_count = tot.div_ceil(logical_width);
        let cols = tot.min(logical_width);
        let allocated_sectors = tot.next_multiple_of(parity + 1);
        let allocated_bytes = (allocated_sectors * sector) as u64;
        dva_offset
            .checked_add(allocated_bytes)
            .ok_or_else(|| invalid("expanded RAIDZ offset overflow"))?;

        let physical_cols = config.physical_width;
        let reflow_synced_sectors = config.reflow_offset_synced >> config.ashift;
        let reflow_next_sectors = config.reflow_offset_next >> config.ashift;
        let start_sector = dva_offset >> config.ashift;

        let mut rows = Vec::with_capacity(row_count);
        for row in 0..row_count {
            let b = start_sector
                .checked_add((row * logical_width) as u64)
                .ok_or_else(|| invalid("expanded RAIDZ row sector overflow"))?;
            let (row_phys_cols, row_use_scratch) =
                if b.saturating_add(cols as u64) > reflow_synced_sectors {
                    if physical_cols <= parity + 1 {
                        return Err(invalid(
                            "expanded RAIDZ pre-reflow width below minimum parity+1",
                        ));
                    }
                    (physical_cols - 1, false)
                } else {
                    (physical_cols, config.use_scratch)
                };

            let mut child_id = (b % row_phys_cols as u64) as usize;
            let mut child_offset = (b / row_phys_cols as u64) << config.ashift;
            let mut row_cols = Vec::with_capacity(cols);

            for c in 0..cols {
                if child_id >= row_phys_cols {
                    child_id -= row_phys_cols;
                    child_offset = child_offset
                        .checked_add(sector as u64)
                        .ok_or_else(|| invalid("expanded RAIDZ child offset overflow"))?;
                }
                let (bytes, data_offset) = if c < parity {
                    (sector, None)
                } else if row == row_count - 1 && bc != 0 && c >= bc {
                    (0, None)
                } else {
                    let dc = c - parity;
                    let off_sectors = if c < bc || r == 0 {
                        dc * row_count + row
                    } else {
                        r * row_count + (dc - r) * (row_count - 1) + row
                    };
                    (sector, Some(off_sectors * sector))
                };

                let (shadow_child_id, shadow_offset) = if bytes != 0
                    && (row_use_scratch
                        || (row_phys_cols != physical_cols
                            && b.saturating_add(c as u64) < reflow_next_sectors))
                {
                    let sc = ((b + c as u64) % physical_cols as u64) as usize;
                    let so = ((b + c as u64) / physical_cols as u64) << config.ashift;
                    (Some(sc), Some(so))
                } else {
                    (None, None)
                };

                row_cols.push(ExpandedRaidzCol {
                    child_id,
                    offset: child_offset,
                    use_scratch: row_use_scratch,
                    bytes,
                    data_offset,
                    shadow_child_id,
                    shadow_offset,
                });
                child_id += 1;
            }

            // Historical RAIDZ1 bit-20 parity/data-0 column placement swap.
            if parity == 1 && cols > 1 && (dva_offset & (1_u64 << 20)) != 0 {
                let c0_child = row_cols[0].child_id;
                let c0_off = row_cols[0].offset;
                let c0_s_child = row_cols[0].shadow_child_id;
                let c0_s_off = row_cols[0].shadow_offset;

                row_cols[0].child_id = row_cols[1].child_id;
                row_cols[0].offset = row_cols[1].offset;
                row_cols[0].shadow_child_id = row_cols[1].shadow_child_id;
                row_cols[0].shadow_offset = row_cols[1].shadow_offset;

                row_cols[1].child_id = c0_child;
                row_cols[1].offset = c0_off;
                row_cols[1].shadow_child_id = c0_s_child;
                row_cols[1].shadow_offset = c0_s_off;
            }

            rows.push(ExpandedRaidzRow {
                parity,
                cols: row_cols,
            });
        }

        Ok(Self {
            physical_bytes,
            aligned_bytes: data_sectors * sector,
            allocated_bytes,
            parity,
            sector_bytes: sector,
            rows,
        })
    }

    #[must_use]
    pub const fn physical_bytes(&self) -> usize {
        self.physical_bytes
    }

    #[must_use]
    pub const fn aligned_bytes(&self) -> usize {
        self.aligned_bytes
    }

    #[must_use]
    pub const fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }

    #[must_use]
    pub const fn parity(&self) -> usize {
        self.parity
    }

    #[must_use]
    pub fn rows(&self) -> &[ExpandedRaidzRow] {
        &self.rows
    }

    /// Encode `physical` into per-row, per-column sector buffers (`bytes == 0`
    /// phantom columns produce empty `Vec`s).
    pub fn encode(&self, physical: &[u8]) -> Result<Vec<Vec<Vec<u8>>>, ParseError> {
        if physical.len() != self.physical_bytes {
            return Err(invalid("expanded RAIDZ encode physical length mismatch"));
        }
        let mut padded = Vec::new();
        padded
            .try_reserve_exact(self.aligned_bytes)
            .map_err(|_| invalid("expanded RAIDZ encode allocation failed"))?;
        padded.extend_from_slice(physical);
        padded.resize(self.aligned_bytes, 0);

        let zero_sector = vec![0_u8; self.sector_bytes];
        let mut encoded_rows = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let mut data_slices = Vec::with_capacity(row.cols.len() - self.parity);
            for col in &row.cols[self.parity..] {
                if let Some(off) = col.data_offset {
                    let slice = padded
                        .get(off..off + col.bytes)
                        .ok_or_else(|| invalid("expanded RAIDZ encode data offset out of range"))?;
                    data_slices.push(slice);
                } else {
                    data_slices.push(zero_sector.as_slice());
                }
            }
            let parity_cols = encode_pqr_parity(&data_slices, self.parity, self.sector_bytes)?;
            let mut row_out = Vec::with_capacity(row.cols.len());
            for p in parity_cols {
                row_out.push(p);
            }
            for col in &row.cols[self.parity..] {
                if let Some(off) = col.data_offset {
                    row_out.push(padded[off..off + col.bytes].to_vec());
                } else {
                    row_out.push(Vec::new());
                }
            }
            encoded_rows.push(row_out);
        }
        Ok(encoded_rows)
    }

    /// Assemble original `physical_bytes` from per-row column payloads,
    /// reconstructing up to `parity` erased columns per row.
    ///
    /// `erased_per_row[r]` lists erased column ordinals (`0..row.cols.len()`)
    /// for row `r`. Phantom (`bytes == 0`) columns are treated as known zeros
    /// during parity reconstruction and need not be read from disk.
    pub fn assemble(
        &self,
        row_columns: &[Vec<Option<&[u8]>>],
        erased_per_row: &[&[usize]],
    ) -> Result<Vec<u8>, ParseError> {
        if row_columns.len() != self.rows.len() || erased_per_row.len() != self.rows.len() {
            return Err(invalid("expanded RAIDZ row count mismatch"));
        }
        let mut aligned = Vec::new();
        aligned
            .try_reserve_exact(self.aligned_bytes)
            .map_err(|_| invalid("expanded RAIDZ assembly allocation failed"))?;
        aligned.resize(self.aligned_bytes, 0);

        let zero_sector = vec![0_u8; self.sector_bytes];
        for ((row, cols), &erased) in self.rows.iter().zip(row_columns).zip(erased_per_row) {
            if cols.len() != row.cols.len() || erased.len() > self.parity {
                return Err(invalid("invalid expanded RAIDZ row column or erasure set"));
            }
            let mut full_slices: Vec<Option<&[u8]>> = Vec::with_capacity(row.cols.len());
            let mut col_bytes = vec![self.sector_bytes; row.cols.len()];
            for (idx, (col, &bytes)) in row.cols.iter().zip(cols).enumerate() {
                if col.bytes == 0 {
                    if bytes.is_some_and(|b| !b.is_empty()) {
                        return Err(invalid("non-empty bytes supplied for phantom column"));
                    }
                    if erased.contains(&idx) {
                        return Err(invalid("phantom column cannot be erased"));
                    }
                    full_slices.push(Some(zero_sector.as_slice()));
                } else {
                    if bytes.is_some_and(|b| b.len() != col.bytes) {
                        return Err(invalid("expanded RAIDZ sector length mismatch"));
                    }
                    if col.data_offset.is_some() && bytes.is_none() && !erased.contains(&idx) {
                        return Err(invalid("missing expanded RAIDZ data sector"));
                    }
                    full_slices.push(bytes);
                }
            }
            let recovered = reconstruct_pqr(
                &full_slices,
                row.cols.len(),
                self.parity,
                &col_bytes,
                erased,
            )?;
            let missing_data: Vec<usize> = (self.parity..row.cols.len())
                .filter(|idx| erased.contains(idx))
                .collect();
            for (idx, col) in row.cols.iter().enumerate().skip(self.parity) {
                let Some(off) = col.data_offset else {
                    continue;
                };
                let data = if let Some(slot) = missing_data.iter().position(|&m| m == idx) {
                    recovered[slot].as_slice()
                } else {
                    cols[idx].ok_or_else(|| invalid("missing expanded RAIDZ data sector"))?
                };
                aligned[off..off + col.bytes].copy_from_slice(data);
            }
            let _ = &mut col_bytes;
        }
        aligned.truncate(self.physical_bytes);
        Ok(aligned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflow_info_bitfield_roundtrip_matches_openzfs_2_4() {
        for (offset, state) in [
            (0_u64, RaidzReflowScratchState::NotInUse),
            (4096, RaidzReflowScratchState::Valid),
            (16 * 1024 * 1024, RaidzReflowScratchState::InvalidSynced),
            (
                (1_u64 << 40) + 512,
                RaidzReflowScratchState::InvalidSyncedOnImport,
            ),
            (
                ((1_u64 << 55) - 1) << 9,
                RaidzReflowScratchState::InvalidSyncedReflow,
            ),
        ] {
            let info = RaidzReflowInfo { offset, state };
            let raw = info.encode().unwrap();
            assert_eq!(raw >> 55, u64::from(state as u16));
            assert_eq!((raw & ((1_u64 << 55) - 1)) << 9, offset);
            assert_eq!(RaidzReflowInfo::decode(raw).unwrap(), info);
        }
        assert!(
            RaidzReflowInfo {
                offset: 1,
                state: RaidzReflowScratchState::Valid
            }
            .encode()
            .is_err()
        );
        assert!(RaidzReflowInfo::decode(5_u64 << 55).is_err());
    }

    #[test]
    fn expanded_raidz_roundtrips_and_recovers_pre_straddle_post_and_scratch() {
        for parity in 1..=3 {
            let orig = parity + 2;
            let phys = orig + 2;
            let cfg = ExpandedRaidzConfig {
                ashift: 12,
                parity,
                original_width: orig,
                physical_width: phys,
                expand_txgs: vec![10, 20],
                // Straddle midway through a multi-row block at offset 0.
                reflow_offset_synced: (orig as u64) * 4096,
                reflow_offset_next: (orig as u64 * 2) * 4096,
                use_scratch: false,
            };
            assert_eq!(cfg.logical_width_for_birth(5), orig);
            assert_eq!(cfg.logical_width_for_birth(10), orig + 1);
            assert_eq!(cfg.logical_width_for_birth(25), phys);

            for offset in [0_u64, 1 << 20] {
                for psize in [512_usize, 4096, 12_288, 28_672] {
                    let map = ExpandedRaidzMap::new(&cfg, offset, psize, orig).unwrap();
                    let payload: Vec<u8> = (0..psize)
                        .map(|i| u8::try_from((i * 73 + offset as usize + parity) % 256).unwrap())
                        .collect();
                    let encoded = map.encode(&payload).unwrap();

                    // Verify every single valid erasure subset per row up to `parity`.
                    let row_slices: Vec<Vec<Option<&[u8]>>> = encoded
                        .iter()
                        .map(|r| r.iter().map(|c| Some(c.as_slice())).collect())
                        .collect();
                    let empty_erased: Vec<&[usize]> = vec![&[]; map.rows().len()];
                    assert_eq!(map.assemble(&row_slices, &empty_erased).unwrap(), payload);

                    // Erase `parity` active columns on every row and reconstruct.
                    let mut erased_storage: Vec<Vec<usize>> = Vec::new();
                    let mut damaged_rows = row_slices.clone();
                    for (r_idx, row) in map.rows().iter().enumerate() {
                        let active: Vec<usize> = row
                            .cols
                            .iter()
                            .enumerate()
                            .filter(|(_, c)| c.bytes > 0)
                            .map(|(i, _)| i)
                            .collect();
                        let erase: Vec<usize> = active
                            .iter()
                            .rev()
                            .take(parity.min(active.len()))
                            .copied()
                            .collect();
                        for &idx in &erase {
                            damaged_rows[r_idx][idx] = None;
                        }
                        erased_storage.push(erase);
                    }
                    let erased_refs: Vec<&[usize]> =
                        erased_storage.iter().map(Vec::as_slice).collect();
                    assert_eq!(map.assemble(&damaged_rows, &erased_refs).unwrap(), payload);
                }
            }
        }
    }

    #[test]
    fn scratch_mode_maps_into_boot_scratch_area_without_underflow() {
        let cfg = ExpandedRaidzConfig {
            ashift: 12,
            parity: 1,
            original_width: 3,
            physical_width: 4,
            expand_txgs: vec![12],
            reflow_offset_synced: 64 * 1024,
            reflow_offset_next: 64 * 1024,
            use_scratch: true,
        };
        let map = ExpandedRaidzMap::new(&cfg, 0, 8192, 3).unwrap();
        let col0 = map.rows()[0].cols[0];
        assert!(col0.use_scratch);
        assert_eq!(
            col0.leaf_byte_offset().unwrap(),
            DATA_OFFSET - VDEV_BOOT_SIZE
        );
        assert_eq!(
            col0.shadow_leaf_byte_offset().unwrap(),
            Some(DATA_OFFSET - VDEV_BOOT_SIZE)
        );
    }
}
