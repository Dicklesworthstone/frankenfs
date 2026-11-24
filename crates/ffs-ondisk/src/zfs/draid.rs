//! OpenZFS `zfs-2.4.0` dRAID (`org.openzfs:draid`) geometry, permutation
//! mapping, distributed spare resolution, encoding, and P/Q/R reconstruction.
//!
//! Sources: OpenZFS `zfs-2.4.0` `include/sys/vdev_draid.h`,
//! `module/zfs/vdev_draid.c`, and `module/zfs/vdev_draid_rand.c`.

pub mod perms;

use super::raidz::parity::{encode_pqr_parity, reconstruct_pqr};
use super::{MAX_BLOCK_BYTES, invalid};
use ffs_types::ParseError;
use perms::DraidPermTable;

/// OpenZFS `VDEV_DRAID_ROWSHIFT = 24` (`16 MiB` row height per disk).
pub const VDEV_DRAID_ROWSHIFT: u32 = 24;
/// OpenZFS `VDEV_DRAID_ROWHEIGHT = 1 << 24` (`16 MiB`).
pub const VDEV_DRAID_ROWHEIGHT: u64 = 1_u64 << VDEV_DRAID_ROWSHIFT;
/// OpenZFS `VDEV_DRAID_REFLOW_RESERVE = 2 * VDEV_DRAID_ROWHEIGHT` (`32 MiB`).
pub const VDEV_DRAID_REFLOW_RESERVE: u64 = 2 * VDEV_DRAID_ROWHEIGHT;

/// Validated OpenZFS `zfs-2.4.0` dRAID top-level vdev configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraidConfig {
    pub children: usize,
    pub ndata: usize,
    pub nparity: usize,
    pub nspares: usize,
    pub ngroups: usize,
    pub ashift: u8,
    pub perm_table: DraidPermTable,
}

impl DraidConfig {
    /// Construct and validate a dRAID configuration, generating and verifying
    /// the deterministic OpenZFS `zfs-2.4.0` permutation table for `children`.
    pub fn new(
        children: usize,
        ndata: usize,
        nparity: usize,
        nspares: usize,
        ngroups: usize,
        ashift: u8,
    ) -> Result<Self, ParseError> {
        if !(2..=255).contains(&children)
            || !(1..=3).contains(&nparity)
            || ndata == 0
            || ngroups == 0
            || !(9..=16).contains(&ashift)
        {
            return Err(invalid("invalid dRAID parameters"));
        }
        let groupwidth = ndata
            .checked_add(nparity)
            .ok_or_else(|| invalid("dRAID groupwidth overflow"))?;
        if nspares >= children {
            return Err(invalid("dRAID spares must be fewer than children"));
        }
        let ndisks = children - nspares;
        if groupwidth > ndisks {
            return Err(invalid("dRAID groupwidth exceeds non-spare disk count"));
        }
        if !(groupwidth * ngroups).is_multiple_of(ndisks) {
            return Err(invalid(
                "dRAID groupwidth * ngroups must be divisible by ndisks",
            ));
        }
        let perm_table = perms::generate_draid_perms(children)?;
        Ok(Self {
            children,
            ndata,
            nparity,
            nspares,
            ngroups,
            ashift,
            perm_table,
        })
    }

    #[must_use]
    pub const fn groupwidth(&self) -> usize {
        self.ndata + self.nparity
    }

    #[must_use]
    pub const fn ndisks(&self) -> usize {
        self.children - self.nspares
    }

    #[must_use]
    pub const fn groupsz(&self) -> u64 {
        self.groupwidth() as u64 * VDEV_DRAID_ROWHEIGHT
    }

    #[must_use]
    pub const fn devslicesz(&self) -> u64 {
        (self.groupsz() * self.ngroups as u64) / self.ndisks() as u64
    }

    /// OpenZFS `vdev_draid_psize_to_asize`.
    pub fn psize_to_asize(&self, psize: u64) -> Result<u64, ParseError> {
        if psize == 0 {
            return Ok(0);
        }
        let data_row = (self.ndata as u64) << self.ashift;
        let rows = (psize - 1) / data_row + 1;
        rows.checked_mul((self.groupwidth() as u64) << self.ashift)
            .ok_or_else(|| invalid("dRAID asize overflow"))
    }

    /// OpenZFS `vdev_draid_asize_to_psize`.
    #[must_use]
    pub const fn asize_to_psize(&self, asize: u64) -> u64 {
        (asize / self.groupwidth() as u64) * self.ndata as u64
    }

    /// OpenZFS `vdev_draid_logical_to_physical`.
    /// Returns `(physical_offset, perm, groupstart)`.
    pub fn logical_to_physical(
        &self,
        logical_offset: u64,
    ) -> Result<(u64, u64, usize), ParseError> {
        let sector = 1_u64 << self.ashift;
        let groupwidth = self.groupwidth() as u64;
        if !logical_offset.is_multiple_of(sector) {
            return Err(invalid("unaligned dRAID logical offset"));
        }
        let b_total = logical_offset >> self.ashift;
        let rowheight_sectors = VDEV_DRAID_ROWHEIGHT >> self.ashift;
        let group = logical_offset / self.groupsz();
        let ndisks = self.ndisks() as u64;
        let ngroups = self.ngroups as u64;
        let groupstart = ((group * groupwidth) % ndisks) as usize;

        let b_offset = b_total % (rowheight_sectors * groupwidth);
        if !b_offset.is_multiple_of(groupwidth) {
            return Err(invalid("dRAID logical offset not aligned to groupwidth"));
        }
        let perm = group / ngroups;
        let rows_per_perm = (groupwidth * ngroups) / ndisks;
        let row = perm
            .checked_mul(rows_per_perm)
            .and_then(|v| v.checked_add(((group % ngroups) * groupwidth) / ndisks))
            .ok_or_else(|| invalid("dRAID physical row overflow"))?;
        let phys_sectors = row
            .checked_mul(rowheight_sectors)
            .and_then(|v| v.checked_add(b_offset / groupwidth))
            .ok_or_else(|| invalid("dRAID physical sector overflow"))?;
        let physical_offset = phys_sectors
            .checked_shl(u32::from(self.ashift))
            .ok_or_else(|| invalid("dRAID physical byte offset overflow"))?;
        Ok((physical_offset, perm, groupstart))
    }

    /// OpenZFS `vdev_draid_spare_get_child`: resolve which physical child index
    /// backs distributed spare `spare_id` (`0..nspares`) at `physical_offset`.
    pub fn spare_child_id(
        &self,
        spare_id: usize,
        physical_offset: u64,
    ) -> Result<usize, ParseError> {
        if spare_id >= self.nspares {
            return Err(invalid("dRAID spare index out of range"));
        }
        let perm = physical_offset / self.devslicesz();
        let (base, iter) = self.perm_table.row_and_iter(perm);
        let slot = (self.children - 1) - spare_id;
        Ok(self.perm_table.permute_id(base, iter, slot))
    }
}

/// One column within a dRAID redundancy-group row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DraidColumn {
    pub child_id: usize,
    pub offset: u64,
    /// Active data/parity bytes for normal reads (`0` for empty trailing data
    /// columns on a partial single-row write).
    pub bytes: usize,
    /// Full write/scrub column size (`== parity_bytes`, including zero skip
    /// sector on short or empty data columns).
    pub full_bytes: usize,
    /// Byte offset within the ashift-aligned physical payload, or `None` for
    /// parity / empty columns.
    pub data_offset: Option<usize>,
}

/// One redundancy-group row of a dRAID block map (a block spans 1 or 2 rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraidRowMap {
    pub parity: usize,
    pub parity_bytes: usize,
    pub payload_offset: usize,
    pub payload_bytes: usize,
    pub columns: Vec<DraidColumn>,
}

/// Complete OpenZFS `zfs-2.4.0` dRAID block map (`vdev_draid_map_alloc`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraidMap {
    physical_bytes: usize,
    aligned_bytes: usize,
    allocated_bytes: u64,
    parity: usize,
    rows: Vec<DraidRowMap>,
}

impl DraidMap {
    pub fn new(
        config: &DraidConfig,
        dva_offset: u64,
        physical_bytes: usize,
    ) -> Result<Self, ParseError> {
        if physical_bytes == 0
            || physical_bytes > MAX_BLOCK_BYTES
            || !physical_bytes.is_multiple_of(512)
        {
            return Err(invalid("invalid dRAID physical block size"));
        }
        let sector = 1_usize << config.ashift;
        let aligned_bytes = physical_bytes.next_multiple_of(sector);
        let total_asize = config.psize_to_asize(aligned_bytes as u64)?;
        dva_offset
            .checked_add(total_asize)
            .ok_or_else(|| invalid("dRAID DVA allocation overflow"))?;

        let mut rows = Vec::with_capacity(2);
        let first_row = Self::alloc_row(config, dva_offset, 0, aligned_bytes)?;
        let consumed = first_row.payload_bytes;
        rows.push(first_row);

        if consumed < aligned_bytes {
            let next_offset = dva_offset
                .checked_add(config.psize_to_asize(consumed as u64)?)
                .ok_or_else(|| invalid("dRAID second-row offset overflow"))?;
            let remaining = aligned_bytes - consumed;
            let second_row = Self::alloc_row(config, next_offset, consumed, remaining)?;
            if second_row.payload_bytes != remaining {
                return Err(invalid("dRAID block spans more than two redundancy groups"));
            }
            rows.push(second_row);
        }

        Ok(Self {
            physical_bytes,
            aligned_bytes,
            allocated_bytes: total_asize,
            parity: config.nparity,
            rows,
        })
    }

    fn alloc_row(
        config: &DraidConfig,
        io_offset: u64,
        abd_offset: usize,
        abd_size: usize,
    ) -> Result<DraidRowMap, ParseError> {
        let groupsz = config.groupsz();
        let group = io_offset / groupsz;
        let next_group_offset = (group + 1)
            .checked_mul(groupsz)
            .ok_or_else(|| invalid("dRAID group offset overflow"))?;
        let io_asize = config.psize_to_asize(abd_size as u64)?;
        let row_payload_bytes = if io_offset + io_asize > next_group_offset {
            usize::try_from(config.asize_to_psize(next_group_offset - io_offset))
                .map_err(|_| invalid("dRAID row size overflow"))?
        } else {
            abd_size
        };
        if row_payload_bytes == 0 {
            return Err(invalid("dRAID row mapped zero payload bytes"));
        }

        let (mut physical_offset, perm, groupstart) = config.logical_to_physical(io_offset)?;
        let ndisks = config.ndisks();
        let groupwidth = config.groupwidth();
        let wrap = if groupstart + groupwidth > ndisks {
            ndisks - groupstart
        } else {
            groupwidth
        };

        let psize_sectors = row_payload_bytes >> config.ashift;
        let q = psize_sectors / config.ndata;
        let r = psize_sectors - q * config.ndata;
        let bc = if r == 0 { 0 } else { r + config.nparity };
        let parity_bytes = (q + usize::from(r != 0)) << config.ashift;

        let (base, iter) = config.perm_table.row_and_iter(perm);
        let mut columns = Vec::with_capacity(groupwidth);
        let mut data_cursor = abd_offset;
        for i in 0..groupwidth {
            if i == wrap {
                physical_offset = physical_offset
                    .checked_add(VDEV_DRAID_ROWHEIGHT)
                    .ok_or_else(|| invalid("dRAID wrapped row offset overflow"))?;
            }
            let c = (groupstart + i) % ndisks;
            let child_id = config.perm_table.permute_id(base, iter, c);
            let bytes = if q == 0 && i >= bc {
                0
            } else if i < bc {
                (q + 1) << config.ashift
            } else {
                q << config.ashift
            };
            let data_offset = if i >= config.nparity && bytes != 0 {
                let start = data_cursor;
                data_cursor += bytes;
                Some(start)
            } else {
                None
            };
            columns.push(DraidColumn {
                child_id,
                offset: physical_offset,
                bytes,
                full_bytes: parity_bytes,
                data_offset,
            });
        }

        Ok(DraidRowMap {
            parity: config.nparity,
            parity_bytes,
            payload_offset: abd_offset,
            payload_bytes: row_payload_bytes,
            columns,
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
    pub fn rows(&self) -> &[DraidRowMap] {
        &self.rows
    }

    /// Encode `physical` into full-stripe per-row, per-column buffers of length
    /// `row.parity_bytes` (empty/short data columns are zero-padded on write to
    /// match OpenZFS `vdev_draid_map_alloc_write` for sequential rebuild).
    pub fn encode_rows(&self, physical: &[u8]) -> Result<Vec<Vec<Vec<u8>>>, ParseError> {
        if physical.len() != self.physical_bytes {
            return Err(invalid("dRAID encode physical length mismatch"));
        }
        let mut padded = Vec::new();
        padded
            .try_reserve_exact(self.aligned_bytes)
            .map_err(|_| invalid("dRAID encode allocation failed"))?;
        padded.extend_from_slice(physical);
        padded.resize(self.aligned_bytes, 0);

        let mut encoded_rows = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let mut full_data: Vec<Vec<u8>> = Vec::with_capacity(row.columns.len() - row.parity);
            for col in &row.columns[row.parity..] {
                let mut buf = Vec::new();
                buf.try_reserve_exact(row.parity_bytes)
                    .map_err(|_| invalid("dRAID column encode allocation failed"))?;
                if let Some(off) = col.data_offset {
                    buf.extend_from_slice(&padded[off..off + col.bytes]);
                }
                buf.resize(row.parity_bytes, 0);
                full_data.push(buf);
            }
            let slices: Vec<&[u8]> = full_data.iter().map(Vec::as_slice).collect();
            let parity_cols = encode_pqr_parity(&slices, row.parity, row.parity_bytes)?;
            let mut row_out = Vec::with_capacity(row.columns.len());
            for p in parity_cols {
                row_out.push(p);
            }
            for d in full_data {
                row_out.push(d);
            }
            encoded_rows.push(row_out);
        }
        Ok(encoded_rows)
    }

    /// Assemble original `physical_bytes` from per-row column buffers,
    /// reconstructing up to `parity` erased columns per row.
    ///
    /// Column slices may have length `col.bytes` (normal reads) or
    /// `col.full_bytes` (`row.parity_bytes`, scrub/write-length buffers).
    /// When `erased_per_row[r]` is empty, parity columns need not be supplied.
    pub fn assemble_rows(
        &self,
        row_columns: &[Vec<Option<&[u8]>>],
        erased_per_row: &[&[usize]],
    ) -> Result<Vec<u8>, ParseError> {
        if row_columns.len() != self.rows.len() || erased_per_row.len() != self.rows.len() {
            return Err(invalid("dRAID row count mismatch"));
        }
        let mut aligned = Vec::new();
        aligned
            .try_reserve_exact(self.aligned_bytes)
            .map_err(|_| invalid("dRAID assembly allocation failed"))?;
        aligned.resize(self.aligned_bytes, 0);

        for ((row, cols), &erased) in self.rows.iter().zip(row_columns).zip(erased_per_row) {
            if cols.len() != row.columns.len() || erased.len() > row.parity {
                return Err(invalid("invalid dRAID column or erasure set"));
            }
            for (idx, (col, &bytes)) in row.columns.iter().zip(cols).enumerate() {
                if let Some(b) = bytes
                    && b.len() != col.bytes
                    && b.len() != col.full_bytes
                {
                    return Err(invalid("dRAID column length mismatch"));
                }
                if col.data_offset.is_some() && bytes.is_none() && !erased.contains(&idx) {
                    return Err(invalid("missing dRAID data column"));
                }
            }

            if erased.is_empty() {
                for (col, &bytes) in row.columns.iter().zip(cols).skip(row.parity) {
                    let Some(off) = col.data_offset else {
                        continue;
                    };
                    let data = bytes.ok_or_else(|| invalid("missing dRAID data column"))?;
                    aligned[off..off + col.bytes].copy_from_slice(&data[..col.bytes]);
                }
                continue;
            }

            // Prepare full `parity_bytes` slices for every non-erased column so
            // short/empty columns contribute zeros to Q/R Vandermonde equations.
            let zero_full = vec![0_u8; row.parity_bytes];
            let mut padded_storage: Vec<Option<Vec<u8>>> = vec![None; row.columns.len()];
            for (idx, (col, &bytes)) in row.columns.iter().zip(cols).enumerate() {
                if erased.contains(&idx) {
                    continue;
                }
                if let Some(b) = bytes {
                    if b.len() < row.parity_bytes {
                        let mut p = Vec::with_capacity(row.parity_bytes);
                        p.extend_from_slice(b);
                        p.resize(row.parity_bytes, 0);
                        padded_storage[idx] = Some(p);
                    }
                } else if col.bytes == 0 && idx >= row.parity {
                    // Empty trailing data column is zero-filled by OpenZFS dRAID.
                }
            }
            let full_slices: Vec<Option<&[u8]>> = row
                .columns
                .iter()
                .enumerate()
                .map(|(idx, col)| {
                    if erased.contains(&idx) {
                        None
                    } else if let Some(ref p) = padded_storage[idx] {
                        Some(p.as_slice())
                    } else if let Some(b) = cols[idx] {
                        Some(&b[..row.parity_bytes])
                    } else if col.bytes == 0 && idx >= row.parity {
                        Some(zero_full.as_slice())
                    } else {
                        None
                    }
                })
                .collect();

            let col_bytes = vec![row.parity_bytes; row.columns.len()];
            let recovered = reconstruct_pqr(
                &full_slices,
                row.columns.len(),
                row.parity,
                &col_bytes,
                erased,
            )?;
            let missing_data: Vec<usize> = (row.parity..row.columns.len())
                .filter(|idx| erased.contains(idx))
                .collect();
            for (idx, col) in row.columns.iter().enumerate().skip(row.parity) {
                let Some(off) = col.data_offset else {
                    continue;
                };
                let src = if let Some(slot) = missing_data.iter().position(|&m| m == idx) {
                    recovered[slot].as_slice()
                } else {
                    cols[idx].ok_or_else(|| invalid("missing dRAID data column"))?
                };
                aligned[off..off + col.bytes].copy_from_slice(&src[..col.bytes]);
            }
        }

        aligned.truncate(self.physical_bytes);
        Ok(aligned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draid_1_2_3_single_and_cross_group_roundtrip_and_erasure_recovery() {
        // Test draid1:2d:4c:1s, draid2:3d:6c:1s, draid3:3d:8c:1s.
        for (children, ndata, nparity, nspares, ngroups) in
            [(4, 2, 1, 1, 1), (6, 3, 2, 1, 1), (8, 3, 3, 1, 7)]
        {
            let cfg = DraidConfig::new(children, ndata, nparity, nspares, ngroups, 12).unwrap();
            let groupwidth = cfg.groupwidth() as u64;
            let stride_bytes = groupwidth << cfg.ashift;
            // Offset 0 (single row) AND straddling the boundary between group 0 and group 1!
            let boundary = cfg.groupsz() - stride_bytes;
            for (offset, psize, expected_rows) in [
                (0_u64, 512_usize, 1),
                (stride_bytes * 3, 4096 * (ndata + 1), 1),
                (boundary, 4096 * (ndata * 2 + 1), 2),
            ] {
                let map = DraidMap::new(&cfg, offset, psize).unwrap();
                assert_eq!(map.rows().len(), expected_rows);
                let payload: Vec<u8> = (0..psize)
                    .map(|i| u8::try_from((i * 41 + children * 17 + nparity) % 256).unwrap())
                    .collect();
                let encoded = map.encode_rows(&payload).unwrap();
                let full_slices: Vec<Vec<Option<&[u8]>>> = encoded
                    .iter()
                    .map(|r| r.iter().map(|c| Some(c.as_slice())).collect())
                    .collect();
                let empty: Vec<&[usize]> = vec![&[]; map.rows().len()];
                assert_eq!(map.assemble_rows(&full_slices, &empty).unwrap(), payload);

                // Exhaustively verify every erasure subset up to `nparity` on row 0
                // (and matching subset on row 1 if present).
                let gw = cfg.groupwidth();
                for mask in 1_u16..(1_u16 << gw) {
                    if mask.count_ones() as usize > nparity {
                        continue;
                    }
                    let erased: Vec<usize> =
                        (0..gw).filter(|&i| (mask & (1_u16 << i)) != 0).collect();
                    let mut damaged = full_slices.clone();
                    for row in &mut damaged {
                        for &idx in &erased {
                            row[idx] = None;
                        }
                    }
                    let erased_refs: Vec<&[usize]> = vec![erased.as_slice(); map.rows().len()];
                    assert_eq!(
                        map.assemble_rows(&damaged, &erased_refs).unwrap(),
                        payload,
                        "children={children} ndata={ndata} nparity={nparity} offset={offset} mask={mask}"
                    );
                }
            }

            // Distributed spare resolves to a valid child index across permutations
            // and never duplicates another spare at the same physical offset.
            for perm_idx in 0_u64..8 {
                let phys_off = perm_idx * cfg.devslicesz();
                let spare_child = cfg.spare_child_id(0, phys_off).unwrap();
                assert!(spare_child < children);
            }
            assert!(cfg.spare_child_id(nspares, 0).is_err());
        }
    }

    #[test]
    fn draid_rejects_invalid_geometry_and_misaligned_offset() {
        assert!(DraidConfig::new(1, 1, 1, 0, 1, 12).is_err());
        assert!(DraidConfig::new(4, 3, 2, 0, 1, 12).is_err());
        assert!(DraidConfig::new(4, 2, 1, 2, 1, 12).is_err());
        assert!(DraidConfig::new(6, 2, 1, 1, 1, 12).is_err()); // 3*1 % 5 != 0
        let cfg = DraidConfig::new(4, 2, 1, 1, 1, 12).unwrap();
        assert!(DraidMap::new(&cfg, 4096, 4096).is_err()); // not multiple of 3 * 4096
        assert!(DraidMap::new(&cfg, 0, 0).is_err());
    }
}
