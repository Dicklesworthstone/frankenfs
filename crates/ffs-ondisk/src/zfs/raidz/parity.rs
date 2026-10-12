//! Ordinary, unexpanded RAIDZ2/3 mapping and bounded P/Q/R reconstruction.
//!
//! Native contract: OpenZFS zfs-2.3.0 vdev_raidz.c, source blob
//! 6103f780e6bc9b6a7ca88f8d2265076bd94d04c4. Q and R use powers of 2 and 4
//! in GF(2^8), polynomial 0x11d, in *logical* data-column order. Short-column
//! tails are zero, not skip-sector contents. The historical RAIDZ1 address
//! swap does not apply. A reconstructed result still needs its block checksum.

use super::{MAX_BLOCK_BYTES, RaidzColumn, invalid};
use ffs_types::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaidzParityMap {
    physical_bytes: usize,
    aligned_bytes: usize,
    allocated_bytes: u64,
    parity: usize,
    active_columns: usize,
    columns: Vec<RaidzColumn>,
}

impl RaidzParityMap {
    pub fn new(
        dva_offset: u64,
        physical_bytes: usize,
        ashift: u8,
        width: usize,
        parity: usize,
    ) -> Result<Self, ParseError> {
        if !(2..=3).contains(&parity)
            || !(parity + 1..=8).contains(&width)
            || !(9..=16).contains(&ashift)
            || physical_bytes == 0
            || physical_bytes > MAX_BLOCK_BYTES
            || !physical_bytes.is_multiple_of(512)
        {
            return Err(invalid(
                "unsupported RAIDZ2/3 width, parity, ashift or physical size",
            ));
        }
        let sector = 1_usize << ashift;
        if !dva_offset.is_multiple_of(sector as u64) {
            return Err(invalid("unaligned RAIDZ2/3 DVA offset"));
        }
        let data_sectors = physical_bytes.div_ceil(sector);
        let short_rows = data_sectors / (width - parity);
        let remainder = data_sectors % (width - parity);
        let long_columns = if remainder == 0 {
            0
        } else {
            remainder + parity
        };
        let rows = short_rows + usize::from(remainder != 0);
        let active_columns = if short_rows == 0 { long_columns } else { width };
        let column_count = if short_rows == 0 {
            active_columns.next_multiple_of(parity + 1).min(width)
        } else {
            width
        };
        let occupied_sectors = data_sectors + parity * rows;
        let allocated_sectors = occupied_sectors.next_multiple_of(parity + 1);
        let skip_sectors = allocated_sectors - occupied_sectors;
        let allocated_bytes = (allocated_sectors * sector) as u64;
        dva_offset
            .checked_add(allocated_bytes)
            .ok_or_else(|| invalid("RAIDZ2/3 allocation offset overflow"))?;

        let first = (dva_offset / sector as u64 % width as u64) as usize;
        let row_start = (dva_offset / sector as u64 / width as u64) * sector as u64;
        let mut logical = 0;
        let mut columns = Vec::with_capacity(column_count);
        for ordinal in 0..column_count {
            let position = first + ordinal;
            let bytes = if ordinal < active_columns {
                (short_rows + usize::from(ordinal < long_columns)) * sector
            } else {
                0
            };
            // Skip sectors can wrap onto parity columns. They are allocation
            // extents only and must never enter the coding equations.
            let skip_distance = (ordinal + column_count - long_columns) % column_count;
            let padding = usize::from(skip_distance < skip_sectors) * sector;
            let data_offset = if ordinal >= parity && bytes != 0 {
                let start = logical;
                logical += bytes;
                Some(start)
            } else {
                None
            };
            columns.push(RaidzColumn {
                child_id: position % width,
                offset: row_start + (position / width * sector) as u64,
                bytes,
                allocated_bytes: bytes + padding,
                data_offset,
            });
        }
        Ok(Self {
            physical_bytes,
            aligned_bytes: data_sectors * sector,
            allocated_bytes,
            parity,
            active_columns,
            columns,
        })
    }

    #[must_use]
    pub const fn parity(&self) -> usize {
        self.parity
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
    pub fn columns(&self) -> &[RaidzColumn] {
        &self.columns
    }

    /// Assemble original PSIZE, excluding the named native column ordinals.
    /// Erasures may include corrupt-but-readable data or parity. Missing
    /// parity need not be listed, but every missing data column must be. The
    /// caller chooses hypotheses and verifies the complete result; this pure
    /// function cannot determine which readable column contains corruption.
    pub fn assemble(
        &self,
        columns: &[Option<&[u8]>],
        erased: &[usize],
    ) -> Result<Vec<u8>, ParseError> {
        if columns.len() != self.columns.len() || erased.len() > self.parity {
            return Err(invalid("invalid RAIDZ2/3 reconstruction column set"));
        }
        let mut excluded = [false; 8];
        for &index in erased {
            if index >= self.active_columns || excluded[index] {
                return Err(invalid(
                    "duplicate, skip-only or out-of-range RAIDZ2/3 erasure",
                ));
            }
            excluded[index] = true;
        }
        for (index, (column, bytes)) in self.columns.iter().zip(columns).enumerate() {
            if bytes.is_some_and(|bytes| bytes.len() != column.bytes)
                || (column.data_offset.is_some() && bytes.is_none() && !excluded[index])
            {
                return Err(invalid("missing or incorrectly sized RAIDZ2/3 column"));
            }
        }
        let missing: Vec<_> = (self.parity..self.active_columns)
            .filter(|&index| excluded[index])
            .collect();
        let recovered = self.reconstruct(columns, excluded, &missing)?;
        let mut physical = Vec::new();
        physical
            .try_reserve_exact(self.physical_bytes)
            .map_err(|_| invalid("RAIDZ2/3 assembly allocation failed"))?;
        for (index, column) in columns
            .iter()
            .enumerate()
            .take(self.active_columns)
            .skip(self.parity)
        {
            let bytes = if let Some(slot) = missing.iter().position(|&item| item == index) {
                recovered[slot].as_slice()
            } else {
                column.ok_or_else(|| invalid("missing RAIDZ2/3 data column"))?
            };
            let take = bytes.len().min(self.physical_bytes - physical.len());
            physical.extend_from_slice(&bytes[..take]);
        }
        if physical.len() != self.physical_bytes {
            return Err(invalid("RAIDZ2/3 physical stream length mismatch"));
        }
        Ok(physical)
    }

    fn reconstruct(
        &self,
        columns: &[Option<&[u8]>],
        excluded: [bool; 8],
        missing: &[usize],
    ) -> Result<Vec<Vec<u8>>, ParseError> {
        let count = missing.len();
        if count == 0 {
            return Ok(Vec::new());
        }
        let rows: Vec<_> = (0..self.parity)
            .filter(|&index| !excluded[index] && columns[index].is_some())
            .take(count)
            .collect();
        if rows.len() != count {
            return Err(invalid(
                "insufficient RAIDZ2/3 parity for required data erasures",
            ));
        }
        let mut matrix = [[0; 3]; 3];
        for (row, &parity_row) in rows.iter().enumerate() {
            for (column, &data_column) in missing.iter().enumerate() {
                matrix[row][column] = self.coefficient(parity_row, data_column);
            }
        }
        let inverse = invert(matrix, count)?;
        let mut recovered = Vec::with_capacity(count);
        for (slot, &target_column) in missing.iter().enumerate() {
            // Combine equations once. The byte loop then uses fixed 256-entry
            // multiplication tables, not Gaussian elimination or GF division.
            let mut weights = [0; 8];
            for (row, &parity_row) in rows.iter().enumerate() {
                let factor = inverse[slot][row];
                weights[parity_row] ^= factor;
                for column in self.parity..self.active_columns {
                    if !excluded[column] {
                        weights[column] ^= multiply(factor, self.coefficient(parity_row, column));
                    }
                }
            }
            let length = self.columns[target_column].bytes;
            let mut data = Vec::new();
            data.try_reserve_exact(length)
                .map_err(|_| invalid("RAIDZ2/3 reconstruction allocation failed"))?;
            data.resize(length, 0);
            for (column, &weight) in weights[..self.active_columns].iter().enumerate() {
                if weight == 0 {
                    continue;
                }
                let source = columns[column]
                    .ok_or_else(|| invalid("required RAIDZ2/3 reconstruction source is missing"))?;
                if weight == 1 {
                    for (target, byte) in data.iter_mut().zip(source) {
                        *target ^= byte;
                    }
                } else {
                    let mut table = [0; 256];
                    for (input, value) in (0_u8..=255).zip(&mut table) {
                        *value = multiply(weight, input);
                    }
                    for (target, &byte) in data.iter_mut().zip(source) {
                        *target ^= table[usize::from(byte)];
                    }
                }
            }
            recovered.push(data);
        }
        Ok(recovered)
    }

    fn coefficient(&self, parity_row: usize, data_column: usize) -> u8 {
        let exponent = parity_row * (self.active_columns - 1 - data_column);
        let mut value = 1;
        for _ in 0..exponent {
            value = multiply(value, 2);
        }
        value
    }
}

fn multiply(mut left: u8, mut right: u8) -> u8 {
    let mut value = 0;
    while right != 0 {
        if right & 1 != 0 {
            value ^= left;
        }
        left = (left << 1) ^ if left & 0x80 == 0 { 0 } else { 0x1d };
        right >>= 1;
    }
    value
}

fn reciprocal(value: u8) -> u8 {
    // Nonzero a has inverse a^254 in the native field.
    let mut result = 1;
    let mut factor = value;
    let mut exponent = 254_u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, factor);
        }
        factor = multiply(factor, factor);
        exponent >>= 1;
    }
    result
}

fn invert(mut matrix: [[u8; 3]; 3], count: usize) -> Result<[[u8; 3]; 3], ParseError> {
    let mut inverse = [[0; 3]; 3];
    for (index, row) in inverse.iter_mut().enumerate().take(count) {
        row[index] = 1;
    }
    for column in 0..count {
        let pivot = (column..count)
            .find(|&row| matrix[row][column] != 0)
            .ok_or_else(|| invalid("singular RAIDZ2/3 reconstruction equations"))?;
        matrix.swap(column, pivot);
        inverse.swap(column, pivot);
        let scale = reciprocal(matrix[column][column]);
        for index in 0..count {
            matrix[column][index] = multiply(matrix[column][index], scale);
            inverse[column][index] = multiply(inverse[column][index], scale);
        }
        let pivot_matrix = matrix[column];
        let pivot_inverse = inverse[column];
        for row in 0..count {
            if row == column {
                continue;
            }
            let scale = matrix[row][column];
            for index in 0..count {
                matrix[row][index] ^= multiply(scale, pivot_matrix[index]);
                inverse[row][index] ^= multiply(scale, pivot_inverse[index]);
            }
        }
    }
    Ok(inverse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_skip_sectors_are_not_parity_bytes() {
        let map = RaidzParityMap::new(1536, 1536, 9, 4, 2).unwrap();
        let expected = [
            (3, 0, 1024, 1536),
            (0, 512, 1024, 1024),
            (1, 512, 1024, 1024),
            (2, 512, 512, 1024),
        ];
        let actual: Vec<_> = map
            .columns()
            .iter()
            .map(|column| {
                (
                    column.child_id,
                    column.offset,
                    column.bytes,
                    column.allocated_bytes,
                )
            })
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(map.allocated_bytes(), 4608);
        assert_eq!(map.aligned_bytes(), 1536);
        assert_eq!(map.columns()[2].data_offset, Some(0));
        assert_eq!(map.columns()[3].data_offset, Some(1024));
    }

    #[test]
    fn triple_parity_does_not_inherit_the_raidz1_address_swap() {
        let map = RaidzParityMap::new(1 << 20, 1024, 9, 5, 3).unwrap();
        let expected = [
            (3, 209_408, 512, 1024),
            (4, 209_408, 512, 1024),
            (0, 209_920, 512, 1024),
            (1, 209_920, 512, 512),
            (2, 209_920, 512, 512),
        ];
        let actual: Vec<_> = map
            .columns()
            .iter()
            .map(|column| {
                (
                    column.child_id,
                    column.offset,
                    column.bytes,
                    column.allocated_bytes,
                )
            })
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(map.allocated_bytes(), 4096);
    }

    // Independent Horner-form native encoder. It deliberately does not use
    // the decoder's multiplication, coefficient or inverse implementations.
    fn twice(value: u8) -> u8 {
        let widened = u16::from(value) * 2;
        u8::try_from(if widened >= 256 {
            widened ^ 0x11d
        } else {
            widened
        })
        .unwrap()
    }

    fn stored_columns(map: &RaidzParityMap) -> Vec<Vec<u8>> {
        let mut stored: Vec<_> = map
            .columns()
            .iter()
            .enumerate()
            .map(|(index, column)| {
                if column.data_offset.is_some() {
                    (0..column.bytes)
                        .map(|byte| {
                            u8::try_from((byte * 37 + index * 113 + byte / 7) % 256).unwrap()
                        })
                        .collect()
                } else {
                    vec![0; column.bytes]
                }
            })
            .collect();
        for row in 0..map.parity() {
            for offset in 0..stored[row].len() {
                let mut value = 0;
                for data in &stored[map.parity()..map.active_columns] {
                    for _ in 0..row {
                        value = twice(value);
                    }
                    value ^= data.get(offset).copied().unwrap_or(0);
                }
                stored[row][offset] = value;
            }
        }
        stored
    }

    #[test]
    fn every_admitted_erasure_combination_recovers_native_horner_parity() {
        for parity in 2..=3 {
            for width in parity + 1..=8 {
                for sectors in [1, width - parity, width - parity + 1, 2 * width + 1] {
                    let map =
                        RaidzParityMap::new(1 << 20, sectors * 512, 9, width, parity).unwrap();
                    let stored = stored_columns(&map);
                    let expected = stored[parity..map.active_columns].concat();
                    for mask in 0_u16..1 << map.active_columns {
                        if mask.count_ones() as usize > parity {
                            continue;
                        }
                        let erased: Vec<_> = (0..map.active_columns)
                            .filter(|&index| mask & (1 << index) != 0)
                            .collect();
                        let slices: Vec<_> = stored
                            .iter()
                            .enumerate()
                            .map(|(index, data)| {
                                if erased.contains(&index) {
                                    None
                                } else {
                                    Some(data.as_slice())
                                }
                            })
                            .collect();
                        assert_eq!(
                            map.assemble(&slices, &erased).unwrap(),
                            expected,
                            "parity={parity}, width={width}, sectors={sectors}, mask={mask}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn corruption_hypotheses_can_exclude_bad_parity_as_well_as_data() {
        let map = RaidzParityMap::new(0, 2560, 9, 6, 3).unwrap();
        let stored = stored_columns(&map);
        let expected = stored[3..map.active_columns].concat();
        let mut damaged = stored;
        for index in [0, 3, 5] {
            damaged[index].fill(0xa5);
        }
        let slices: Vec<_> = damaged.iter().map(|data| Some(data.as_slice())).collect();
        assert_ne!(map.assemble(&slices, &[]).unwrap(), expected);
        assert_eq!(map.assemble(&slices, &[0, 3, 5]).unwrap(), expected);
        assert_ne!(map.assemble(&slices, &[3, 5]).unwrap(), expected);
    }

    #[test]
    fn intact_data_does_not_require_any_parity_reads() {
        let map = RaidzParityMap::new(0, 2560, 9, 6, 3).unwrap();
        let stored = stored_columns(&map);
        let expected = stored[3..map.active_columns].concat();
        let slices: Vec<_> = stored
            .iter()
            .enumerate()
            .map(|(index, data)| {
                if index < 3 {
                    None
                } else {
                    Some(data.as_slice())
                }
            })
            .collect();
        assert_eq!(map.assemble(&slices, &[]).unwrap(), expected);
        assert!(map.assemble(&slices, &[3]).is_err());
    }

    #[test]
    fn original_psize_excludes_ashift_and_allocation_padding() {
        let map = RaidzParityMap::new(4096, 512, 12, 6, 2).unwrap();
        let stored = stored_columns(&map);
        let expected = &stored[2][..512];
        let slices: Vec<_> = stored.iter().map(|data| Some(data.as_slice())).collect();
        assert_eq!(map.assemble(&slices, &[0, 2]).unwrap(), expected);
        assert_eq!(map.aligned_bytes(), 4096);
        assert_eq!(map.allocated_bytes(), 12288);
        let map = RaidzParityMap::new(3584, 1024, 9, 8, 2).unwrap();
        assert_eq!(map.columns().len(), 6);
        assert_eq!(map.columns()[4].bytes, 0);
        assert_eq!(map.columns()[4].allocated_bytes, 512);
        assert_eq!(map.columns()[5].bytes, 0);
        assert_eq!(map.columns()[5].allocated_bytes, 512);
    }

    #[test]
    fn malformed_or_over_budget_reconstruction_is_rejected() {
        let map = RaidzParityMap::new(0, 2560, 9, 6, 3).unwrap();
        let stored = stored_columns(&map);
        let columns: Vec<_> = stored.iter().map(|data| Some(data.as_slice())).collect();
        for erased in [&[3, 3][..], &[6], &[0, 1, 2, 3]] {
            assert!(map.assemble(&columns, erased).is_err());
        }
        assert!(map.assemble(&columns[..5], &[]).is_err());
        let mut missing = columns.clone();
        missing[3] = None;
        assert!(map.assemble(&missing, &[]).is_err());
        missing[0] = None;
        missing[1] = None;
        assert!(map.assemble(&missing, &[3, 4]).is_err());
        let short = vec![0; stored[3].len() - 1];
        let mut malformed = columns.clone();
        malformed[3] = Some(&short);
        assert!(map.assemble(&malformed, &[3]).is_err());
        let narrow = RaidzParityMap::new(0, 1024, 9, 8, 2).unwrap();
        assert!(narrow.assemble(&[None; 6], &[4]).is_err());
    }

    #[test]
    fn geometry_and_field_boundaries_are_checked() {
        for (size, ashift, width, parity, offset) in [
            (0, 9, 4, 2, 0),
            (513, 9, 4, 2, 0),
            (MAX_BLOCK_BYTES + 512, 9, 4, 2, 0),
            (512, 8, 4, 2, 0),
            (512, 17, 4, 2, 0),
            (512, 9, 2, 2, 0),
            (512, 9, 9, 2, 0),
            (512, 9, 4, 1, 0),
            (512, 9, 5, 4, 0),
            (512, 12, 4, 2, 512),
            (512, 9, 4, 2, u64::MAX - 511),
        ] {
            assert!(RaidzParityMap::new(offset, size, ashift, width, parity).is_err());
        }
        for value in 1_u8..=255 {
            assert_eq!(multiply(value, reciprocal(value)), 1);
        }
        assert!(invert([[0; 3]; 3], 3).is_err());
    }
}
