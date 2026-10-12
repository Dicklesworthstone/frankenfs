//! Ordinary, unexpanded RAIDZ1 column mapping and in-memory reconstruction.
//!
//! Contract: OpenZFS zfs-2.3.0 vdev_raidz.c and zio.c. Round PSIZE to ashift,
//! concatenate variable-width data columns, XOR P with zero tails for short
//! columns, include allocation-only skip sectors, and preserve the historical
//! offset-bit-20 parity/address swap. No writes, topology discovery or checksum
//! authority live here; the caller must verify the assembled original PSIZE.

use super::{MAX_BLOCK_BYTES, invalid};
use ffs_types::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raidz1Column {
    /// Native child ID, independent of the caller's image ordering.
    pub child_id: usize,
    /// Child-relative allocation offset, before the leaf's label/boot prefix.
    pub offset: u64,
    /// Data/parity bytes to read. Allocation-only skip columns have zero bytes.
    pub bytes: usize,
    /// Includes an optional skip sector, which is excluded from parity.
    pub allocated_bytes: usize,
    /// Offset within the ashift-padded physical stream; absent for parity/skip.
    pub data_offset: Option<usize>,
}

/// Construction validates the bounded geometry; callers cannot alter its map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raidz1Map {
    physical_bytes: usize,
    aligned_bytes: usize,
    allocated_bytes: u64,
    columns: Vec<Raidz1Column>,
}

impl Raidz1Map {
    pub fn new(
        dva_offset: u64,
        physical_bytes: usize,
        ashift: u8,
        width: usize,
    ) -> Result<Self, ParseError> {
        if !(2..=8).contains(&width)
            || !(9..=16).contains(&ashift)
            || physical_bytes == 0
            || physical_bytes > MAX_BLOCK_BYTES
            || !physical_bytes.is_multiple_of(512)
        {
            return Err(invalid("unsupported RAIDZ1 width, ashift or physical size"));
        }
        let sector = 1_usize << ashift;
        if !dva_offset.is_multiple_of(sector as u64) {
            return Err(invalid("unaligned RAIDZ1 DVA offset"));
        }
        let data_sectors = physical_bytes.div_ceil(sector);
        let rows = data_sectors.div_ceil(width - 1);
        let remainder = data_sectors % (width - 1);
        let long_columns = if remainder == 0 { 0 } else { remainder + 1 };
        let used_columns = (data_sectors + 1).min(width);
        let column_count = used_columns.next_multiple_of(2).min(width);
        let occupied_sectors = data_sectors + rows;
        let allocated_sectors = occupied_sectors.next_multiple_of(2);
        let allocated_bytes = (allocated_sectors * sector) as u64;
        dva_offset
            .checked_add(allocated_bytes)
            .ok_or_else(|| invalid("RAIDZ1 allocation offset overflow"))?;

        let first = (dva_offset / sector as u64 % width as u64) as usize;
        let row_start = (dva_offset / sector as u64 / width as u64) * sector as u64;
        let swapped = dva_offset & (1_u64 << 20) != 0;
        let skip_start = if long_columns == 0 && swapped {
            1
        } else {
            long_columns
        };
        let short_rows = data_sectors / (width - 1);
        let mut data_offset = 0;
        let mut columns = Vec::with_capacity(column_count);
        for ordinal in 0..column_count {
            let physical_column = if swapped && ordinal < 2 {
                1 - ordinal
            } else {
                ordinal
            };
            let position = first + physical_column;
            let offset = row_start + (position / width * sector) as u64;
            let bytes = if ordinal < used_columns {
                (short_rows + usize::from(ordinal < long_columns)) * sector
            } else {
                0
            };
            let padding =
                if allocated_sectors != occupied_sectors && ordinal == skip_start % column_count {
                    sector
                } else {
                    0
                };
            let logical = if ordinal != 0 && bytes != 0 {
                let start = data_offset;
                data_offset += bytes;
                Some(start)
            } else {
                None
            };
            columns.push(Raidz1Column {
                child_id: position % width,
                offset,
                bytes,
                allocated_bytes: bytes + padding,
                data_offset: logical,
            });
        }
        Ok(Self {
            physical_bytes,
            aligned_bytes: data_sectors * sector,
            allocated_bytes,
            columns,
        })
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
    pub fn columns(&self) -> &[Raidz1Column] {
        &self.columns
    }

    /// Assemble original PSIZE, optionally treating one data column as erased.
    /// A present erased column is ignored, enabling checksum-guided corruption
    /// hypotheses. The caller must verify the entire result before exposing it.
    pub fn assemble(
        &self,
        columns: &[Option<&[u8]>],
        erased: Option<usize>,
    ) -> Result<Vec<u8>, ParseError> {
        if columns.len() != self.columns.len()
            || erased.is_some_and(|index| {
                self.columns
                    .get(index)
                    .is_none_or(|column| column.data_offset.is_none())
            })
        {
            return Err(invalid("invalid RAIDZ1 reconstruction column set"));
        }
        for (index, (column, bytes)) in self.columns.iter().zip(columns).enumerate() {
            if bytes.is_some_and(|bytes| bytes.len() != column.bytes)
                || (bytes.is_none() && column.data_offset.is_some() && erased != Some(index))
            {
                return Err(invalid("missing or incorrectly sized RAIDZ1 column"));
            }
        }
        let recovered = erased
            .map(|index| self.reconstruct(columns, index))
            .transpose()?;
        let mut physical = Vec::new();
        physical
            .try_reserve_exact(self.physical_bytes)
            .map_err(|_| invalid("RAIDZ1 assembly allocation failed"))?;
        for (index, column) in self.columns.iter().enumerate() {
            if column.data_offset.is_none() {
                continue;
            }
            let bytes = if erased == Some(index) {
                recovered.as_deref()
            } else {
                columns[index]
            }
            .ok_or_else(|| invalid("missing RAIDZ1 data column"))?;
            let take = column.bytes.min(self.physical_bytes - physical.len());
            physical.extend_from_slice(&bytes[..take]);
        }
        if physical.len() != self.physical_bytes {
            return Err(invalid("RAIDZ1 physical stream length mismatch"));
        }
        Ok(physical)
    }

    fn reconstruct(&self, columns: &[Option<&[u8]>], erased: usize) -> Result<Vec<u8>, ParseError> {
        let parity = columns[0].ok_or_else(|| invalid("RAIDZ1 parity is unavailable"))?;
        let length = self.columns[erased].bytes;
        let mut recovered = Vec::new();
        recovered
            .try_reserve_exact(length)
            .map_err(|_| invalid("RAIDZ1 reconstruction allocation failed"))?;
        recovered.extend_from_slice(&parity[..length]);
        for (index, column) in self.columns.iter().enumerate() {
            if index == erased || column.data_offset.is_none() {
                continue;
            }
            let bytes = columns[index].ok_or_else(|| invalid("multiple RAIDZ1 data erasures"))?;
            // A short native data column contributes implicit zeroes after its
            // own end. Skip sectors are not among these bytes.
            for (target, byte) in recovered.iter_mut().zip(bytes) {
                *target ^= byte;
            }
        }
        Ok(recovered)
    }
}

#[cfg(test)]
mod tests;
