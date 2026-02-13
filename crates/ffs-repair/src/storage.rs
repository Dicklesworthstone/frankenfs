//! Durable on-image storage for repair symbols.
//!
//! This module provides a deterministic per-group tail layout and read/write
//! helpers for:
//! - [`RepairGroupDescExt`] (stored in dual descriptor slots)
//! - repair symbol blocks ([`RepairBlockHeader`] + payload)
//!
//! Crash-safety rule:
//! 1. Write all symbol blocks for generation `G`.
//! 2. Sync device.
//! 3. Publish descriptor with generation `G` to the inactive descriptor slot.
//! 4. Sync device.
//!
//! On read, the storage picks the latest descriptor generation whose symbol
//! blocks are fully valid, falling back to older generations if the newest is
//! torn or corrupt.

use asupersync::Cx;
use ffs_block::BlockDevice;
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};
use std::cmp::Reverse;

use crate::symbol::{RepairBlockHeader, RepairGroupDescExt};

/// Number of descriptor slots stored per group.
pub const REPAIR_DESC_SLOT_COUNT: u32 = 2;
const REPAIR_DESC_SLOT_COUNT_USIZE: usize = 2;
type SymbolBatch = Vec<(u32, Vec<u8>)>;

/// Deterministic per-group layout for validation/repair metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairGroupLayout {
    /// Block group number.
    pub group: GroupNumber,
    /// Absolute first block of this group.
    pub group_start: BlockNumber,
    /// Total blocks in this group.
    pub blocks_per_group: u32,
    /// Validation digest blocks reserved before repair blocks.
    pub validation_block_count: u32,
    /// Reserved repair symbol blocks.
    pub repair_block_count: u32,
}

impl RepairGroupLayout {
    /// Construct a per-group tail layout.
    ///
    /// Tail reservation order:
    /// `validation blocks | repair blocks | descriptor slot A | descriptor slot B`
    pub fn new(
        group: GroupNumber,
        group_start: BlockNumber,
        blocks_per_group: u32,
        validation_block_count: u32,
        repair_block_count: u32,
    ) -> Result<Self> {
        if blocks_per_group == 0 {
            return Err(FfsError::InvalidGeometry(
                "blocks_per_group must be > 0".to_owned(),
            ));
        }
        if repair_block_count == 0 {
            return Err(FfsError::InvalidGeometry(
                "repair_block_count must be > 0".to_owned(),
            ));
        }

        let reserved = u64::from(validation_block_count)
            + u64::from(repair_block_count)
            + u64::from(REPAIR_DESC_SLOT_COUNT);
        if reserved > u64::from(blocks_per_group) {
            return Err(FfsError::InvalidGeometry(format!(
                "repair tail does not fit group: reserved={reserved} blocks_per_group={blocks_per_group}"
            )));
        }

        Ok(Self {
            group,
            group_start,
            blocks_per_group,
            validation_block_count,
            repair_block_count,
        })
    }

    #[must_use]
    pub fn group_end_exclusive(self) -> u64 {
        self.group_start.0 + u64::from(self.blocks_per_group)
    }

    #[must_use]
    pub fn repair_start_block(self) -> BlockNumber {
        BlockNumber(
            self.group_end_exclusive()
                - u64::from(REPAIR_DESC_SLOT_COUNT)
                - u64::from(self.repair_block_count),
        )
    }

    #[must_use]
    pub fn validation_start_block(self) -> BlockNumber {
        BlockNumber(self.repair_start_block().0 - u64::from(self.validation_block_count))
    }

    #[must_use]
    pub fn descriptor_blocks(self) -> [BlockNumber; REPAIR_DESC_SLOT_COUNT_USIZE] {
        let end = self.group_end_exclusive();
        [BlockNumber(end - 2), BlockNumber(end - 1)]
    }
}

/// Storage facade for one block group's repair metadata.
pub struct RepairGroupStorage<'a> {
    device: &'a dyn BlockDevice,
    layout: RepairGroupLayout,
}

impl<'a> RepairGroupStorage<'a> {
    #[must_use]
    pub fn new(device: &'a dyn BlockDevice, layout: RepairGroupLayout) -> Self {
        Self { device, layout }
    }

    #[must_use]
    pub fn layout(&self) -> RepairGroupLayout {
        self.layout
    }

    /// Read the active group descriptor extension.
    ///
    /// Chooses the newest descriptor generation whose symbol blocks validate.
    /// If no symbol generation exists yet and the newest descriptor has
    /// generation 0, returns that bootstrap descriptor.
    pub fn read_group_desc_ext(&self, cx: &Cx) -> Result<RepairGroupDescExt> {
        let candidates = self.read_descriptor_candidates(cx)?;
        if candidates.is_empty() {
            return Err(FfsError::NotFound(format!(
                "repair descriptor missing for group {}",
                self.layout.group.0
            )));
        }

        for (_slot, desc) in &candidates {
            if self.read_symbols_for_desc(cx, desc).is_ok() {
                return Ok(desc.clone());
            }
        }

        let (_slot, newest) = &candidates[0];
        self.validate_desc_layout(newest)?;
        if newest.repair_generation == 0 {
            return Ok(newest.clone());
        }

        Err(FfsError::RepairFailed(format!(
            "no fully-valid repair generation for group {}",
            self.layout.group.0
        )))
    }

    /// Write a descriptor extension to the inactive descriptor slot.
    ///
    /// The caller controls generation monotonicity. This helper enforces that
    /// generations never regress relative to the newest readable descriptor.
    pub fn write_group_desc_ext(&self, cx: &Cx, new_ext: &RepairGroupDescExt) -> Result<()> {
        self.validate_desc_layout(new_ext)?;

        let candidates = self.read_descriptor_candidates(cx)?;
        let target_slot = if let Some((active_slot, active_desc)) = candidates.first() {
            if new_ext.repair_generation < active_desc.repair_generation {
                return Err(FfsError::RepairFailed(format!(
                    "descriptor generation regression for group {}: new={} active={}",
                    self.layout.group.0, new_ext.repair_generation, active_desc.repair_generation
                )));
            }
            1usize.saturating_sub(*active_slot)
        } else {
            0
        };

        let block_size = self.block_size_usize()?;
        if block_size < RepairGroupDescExt::SIZE {
            return Err(FfsError::RepairFailed(format!(
                "block size too small for RepairGroupDescExt: block_size={} required={}",
                block_size,
                RepairGroupDescExt::SIZE
            )));
        }

        let mut block = vec![0_u8; block_size];
        block[..RepairGroupDescExt::SIZE].copy_from_slice(&new_ext.to_bytes());
        self.device
            .write_block(cx, self.descriptor_block(target_slot)?, &block)
    }

    /// Read repair symbols for the active generation.
    ///
    /// Chooses the newest descriptor whose symbols validate. If the newest
    /// descriptor is torn, older generations are tried.
    pub fn read_repair_symbols(&self, cx: &Cx) -> Result<SymbolBatch> {
        let candidates = self.read_descriptor_candidates(cx)?;
        if candidates.is_empty() {
            return Err(FfsError::NotFound(format!(
                "repair descriptor missing for group {}",
                self.layout.group.0
            )));
        }

        for (_slot, desc) in &candidates {
            if let Ok(symbols) = self.read_symbols_for_desc(cx, desc) {
                return Ok(symbols);
            }
        }

        let (_slot, newest) = &candidates[0];
        self.validate_desc_layout(newest)?;
        if newest.repair_generation == 0 {
            return Ok(Vec::new());
        }

        Err(FfsError::RepairFailed(format!(
            "no fully-valid repair symbols for group {}",
            self.layout.group.0
        )))
    }

    /// Atomically publish repair symbols for `generation`.
    ///
    /// Sequence:
    /// 1. Write all symbol blocks with header generation = `generation`.
    /// 2. `sync()`
    /// 3. Write descriptor extension with `repair_generation = generation` to
    ///    inactive slot.
    /// 4. `sync()`
    pub fn write_repair_symbols(
        &self,
        cx: &Cx,
        symbols: &[(u32, Vec<u8>)],
        generation: u64,
    ) -> Result<()> {
        let current = self.read_group_desc_ext(cx)?;
        if generation <= current.repair_generation {
            return Err(FfsError::RepairFailed(format!(
                "generation must increase for group {}: new={} current={}",
                self.layout.group.0, generation, current.repair_generation
            )));
        }

        let mut next = current;
        next.repair_generation = generation;
        next.checksum = 0;

        self.write_symbols_for_desc(cx, &next, symbols)?;
        self.device.sync(cx)?;
        self.write_group_desc_ext(cx, &next)?;
        self.device.sync(cx)?;
        Ok(())
    }

    fn read_descriptor_candidates(&self, cx: &Cx) -> Result<Vec<(usize, RepairGroupDescExt)>> {
        let mut candidates = Vec::new();
        for slot in 0..REPAIR_DESC_SLOT_COUNT_USIZE {
            let block = self.descriptor_block(slot)?;
            let bytes = self.device.read_block(cx, block)?;
            let parse_region = bytes
                .as_slice()
                .get(..RepairGroupDescExt::SIZE)
                .ok_or_else(|| {
                    FfsError::RepairFailed(format!(
                        "descriptor block {} is too small for RepairGroupDescExt",
                        block.0
                    ))
                })?;
            if let Ok(desc) = RepairGroupDescExt::parse(parse_region) {
                candidates.push((slot, desc));
            }
        }
        candidates.sort_by_key(|(_slot, desc)| Reverse(desc.repair_generation));
        Ok(candidates)
    }

    fn read_symbols_for_desc(&self, cx: &Cx, desc: &RepairGroupDescExt) -> Result<SymbolBatch> {
        self.validate_desc_layout(desc)?;
        let block_size = self.block_size_usize()?;
        let symbol_size = usize::from(desc.symbol_size);
        if symbol_size == 0 {
            return Err(FfsError::RepairFailed(format!(
                "symbol_size is zero for group {}",
                self.layout.group.0
            )));
        }
        if Self::raw_symbol_mode(block_size, symbol_size) {
            return self.read_raw_symbols(cx, desc, block_size, symbol_size);
        }
        if block_size <= RepairBlockHeader::SIZE {
            return Err(FfsError::RepairFailed(format!(
                "block size too small for RepairBlockHeader payload: block_size={} header={}",
                block_size,
                RepairBlockHeader::SIZE
            )));
        }
        let payload_capacity = block_size - RepairBlockHeader::SIZE;

        let mut out = Vec::new();
        let mut next_expected_esi: Option<u32> = None;
        for block_index in 0..desc.repair_block_count {
            let block_num = BlockNumber(desc.repair_start_block.0 + u64::from(block_index));
            let block = self.device.read_block(cx, block_num)?;
            let (mut block_symbols, next_esi) = self.read_symbol_block(
                block.as_slice(),
                block_num,
                desc,
                payload_capacity,
                symbol_size,
                next_expected_esi,
            )?;
            out.append(&mut block_symbols);
            next_expected_esi = next_esi;
        }

        Ok(out)
    }

    fn read_raw_symbols(
        &self,
        cx: &Cx,
        desc: &RepairGroupDescExt,
        block_size: usize,
        symbol_size: usize,
    ) -> Result<SymbolBatch> {
        if symbol_size > block_size {
            return Err(FfsError::RepairFailed(format!(
                "raw symbol_size {symbol_size} exceeds block_size {block_size}"
            )));
        }

        let mut out = Vec::new();
        let base_esi = u32::from(desc.source_block_count);
        for block_index in 0..desc.repair_block_count {
            let block_num = BlockNumber(desc.repair_start_block.0 + u64::from(block_index));
            let bytes = self.device.read_block(cx, block_num)?;
            let symbol = bytes
                .as_slice()
                .get(..symbol_size)
                .ok_or_else(|| {
                    FfsError::RepairFailed(format!(
                        "raw symbol slice out of bounds at block {}",
                        block_num.0
                    ))
                })?
                .to_vec();
            if symbol.iter().all(|byte| *byte == 0) {
                continue;
            }
            let esi = base_esi
                .checked_add(block_index)
                .ok_or_else(|| FfsError::RepairFailed("raw ESI overflow".to_owned()))?;
            out.push((esi, symbol));
        }

        Ok(out)
    }

    fn read_symbol_block(
        &self,
        bytes: &[u8],
        block_num: BlockNumber,
        desc: &RepairGroupDescExt,
        payload_capacity: usize,
        symbol_size: usize,
        next_expected_esi: Option<u32>,
    ) -> Result<(SymbolBatch, Option<u32>)> {
        let header = RepairBlockHeader::parse(bytes).map_err(|err| {
            FfsError::RepairFailed(format!(
                "group {} generation {} block {} header parse failed: {err}",
                self.layout.group.0, desc.repair_generation, block_num.0
            ))
        })?;

        if header.block_group != self.layout.group {
            return Err(FfsError::RepairFailed(format!(
                "group mismatch at block {}: header_group={} expected_group={}",
                block_num.0, header.block_group.0, self.layout.group.0
            )));
        }
        if header.repair_generation != desc.repair_generation {
            return Err(FfsError::RepairFailed(format!(
                "generation mismatch at block {}: header={} expected={}",
                block_num.0, header.repair_generation, desc.repair_generation
            )));
        }
        if header.symbol_size != desc.symbol_size {
            return Err(FfsError::RepairFailed(format!(
                "symbol_size mismatch at block {}: header={} expected={}",
                block_num.0, header.symbol_size, desc.symbol_size
            )));
        }

        let payload_size = header.payload_size();
        if payload_size > payload_capacity {
            return Err(FfsError::RepairFailed(format!(
                "payload overflow at block {}: payload_size={} capacity={}",
                block_num.0, payload_size, payload_capacity
            )));
        }

        if let Some(expected) = next_expected_esi {
            if header.symbol_count > 0 && header.first_esi != expected {
                return Err(FfsError::RepairFailed(format!(
                    "non-contiguous ESI at block {}: first_esi={} expected={}",
                    block_num.0, header.first_esi, expected
                )));
            }
        }

        let mut out = Vec::with_capacity(usize::from(header.symbol_count));
        for i in 0..usize::from(header.symbol_count) {
            let start = RepairBlockHeader::SIZE + i * symbol_size;
            let end = start + symbol_size;
            let symbol = bytes.get(start..end).ok_or_else(|| {
                FfsError::RepairFailed(format!(
                    "symbol slice out of bounds at block {}: start={} end={} len={}",
                    block_num.0,
                    start,
                    end,
                    bytes.len()
                ))
            })?;
            let esi = header
                .first_esi
                .checked_add(u32::try_from(i).map_err(|_| {
                    FfsError::RepairFailed(format!(
                        "ESI index does not fit u32 at block {}",
                        block_num.0
                    ))
                })?)
                .ok_or_else(|| {
                    FfsError::RepairFailed(format!("ESI overflow at block {}", block_num.0))
                })?;
            out.push((esi, symbol.to_vec()));
        }

        let next_esi = Some(
            header
                .first_esi
                .checked_add(u32::from(header.symbol_count))
                .ok_or_else(|| {
                    FfsError::RepairFailed(format!("ESI range overflow at block {}", block_num.0))
                })?,
        );
        Ok((out, next_esi))
    }

    fn write_symbols_for_desc(
        &self,
        cx: &Cx,
        desc: &RepairGroupDescExt,
        symbols: &[(u32, Vec<u8>)],
    ) -> Result<()> {
        self.validate_desc_layout(desc)?;
        let block_size = self.block_size_usize()?;
        if block_size <= RepairBlockHeader::SIZE {
            return Err(FfsError::RepairFailed(format!(
                "block size too small for RepairBlockHeader payload: block_size={} header={}",
                block_size,
                RepairBlockHeader::SIZE
            )));
        }

        let symbol_size = usize::from(desc.symbol_size);
        if symbol_size == 0 {
            return Err(FfsError::RepairFailed(format!(
                "symbol_size is zero for group {}",
                self.layout.group.0
            )));
        }
        if Self::raw_symbol_mode(block_size, symbol_size) {
            return self.write_raw_symbols(cx, desc, symbols, block_size, symbol_size);
        }

        let payload_capacity = block_size - RepairBlockHeader::SIZE;
        let symbols_per_block = payload_capacity / symbol_size;
        if symbols_per_block == 0 {
            return Err(FfsError::RepairFailed(format!(
                "symbol_size {symbol_size} exceeds per-block payload capacity {payload_capacity}"
            )));
        }

        let max_symbols = symbols_per_block
            .checked_mul(usize::try_from(desc.repair_block_count).map_err(|_| {
                FfsError::RepairFailed(format!(
                    "repair_block_count {} does not fit usize",
                    desc.repair_block_count
                ))
            })?)
            .ok_or_else(|| FfsError::RepairFailed("max symbol count overflow".to_owned()))?;
        if symbols.len() > max_symbols {
            return Err(FfsError::RepairFailed(format!(
                "too many symbols for reserved region: symbols={} capacity={}",
                symbols.len(),
                max_symbols
            )));
        }

        Self::validate_symbol_input(symbols, symbol_size)?;

        let mut cursor = 0usize;
        let mut next_esi = symbols.first().map_or(0, |(esi, _)| *esi);
        for block_index in 0..desc.repair_block_count {
            let remaining = symbols.len().saturating_sub(cursor);
            let count = remaining.min(symbols_per_block);
            let first_esi = if count > 0 {
                symbols[cursor].0
            } else {
                next_esi
            };
            let block_num = BlockNumber(desc.repair_start_block.0 + u64::from(block_index));
            self.write_symbol_block(
                cx,
                block_num,
                desc,
                first_esi,
                &symbols[cursor..cursor + count],
            )?;

            cursor += count;
            if count > 0 {
                next_esi = symbols[cursor - 1].0.checked_add(1).ok_or_else(|| {
                    FfsError::RepairFailed(format!("ESI overflow after block {}", block_num.0))
                })?;
            }
        }

        Ok(())
    }

    fn write_raw_symbols(
        &self,
        cx: &Cx,
        desc: &RepairGroupDescExt,
        symbols: &[(u32, Vec<u8>)],
        block_size: usize,
        symbol_size: usize,
    ) -> Result<()> {
        Self::validate_symbol_input(symbols, symbol_size)?;
        if symbol_size > block_size {
            return Err(FfsError::RepairFailed(format!(
                "raw symbol_size {symbol_size} exceeds block_size {block_size}"
            )));
        }
        if symbols.len()
            > usize::try_from(desc.repair_block_count).map_err(|_| {
                FfsError::RepairFailed("repair_block_count does not fit usize".to_owned())
            })?
        {
            return Err(FfsError::RepairFailed(format!(
                "too many raw symbols for reserved region: symbols={} capacity={}",
                symbols.len(),
                desc.repair_block_count
            )));
        }

        let expected_first_esi = u32::from(desc.source_block_count);
        if let Some((first_esi, _)) = symbols.first() {
            if *first_esi != expected_first_esi {
                return Err(FfsError::RepairFailed(format!(
                    "raw symbol stream must start at ESI {expected_first_esi} (got {first_esi})"
                )));
            }
        }

        for block_index in 0..desc.repair_block_count {
            let mut block = vec![0_u8; block_size];
            let idx = usize::try_from(block_index).map_err(|_| {
                FfsError::RepairFailed(format!("block index {block_index} does not fit usize"))
            })?;
            if idx < symbols.len() {
                block[..symbol_size].copy_from_slice(&symbols[idx].1);
            }

            let block_num = BlockNumber(desc.repair_start_block.0 + u64::from(block_index));
            self.device.write_block(cx, block_num, &block)?;
        }

        Ok(())
    }

    fn validate_symbol_input(symbols: &[(u32, Vec<u8>)], symbol_size: usize) -> Result<()> {
        for (idx, (esi, data)) in symbols.iter().enumerate() {
            if data.len() != symbol_size {
                return Err(FfsError::RepairFailed(format!(
                    "symbol size mismatch at index {} (esi={}): got={} expected={}",
                    idx,
                    esi,
                    data.len(),
                    symbol_size
                )));
            }
            if idx > 0 {
                let expected = symbols[idx - 1].0.checked_add(1).ok_or_else(|| {
                    FfsError::RepairFailed("ESI overflow while validating input".to_owned())
                })?;
                if *esi != expected {
                    return Err(FfsError::RepairFailed(format!(
                        "non-contiguous ESI input at index {idx}: got={esi} expected={expected}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn write_symbol_block(
        &self,
        cx: &Cx,
        block_num: BlockNumber,
        desc: &RepairGroupDescExt,
        first_esi: u32,
        chunk: &[(u32, Vec<u8>)],
    ) -> Result<()> {
        let block_size = self.block_size_usize()?;
        let symbol_size = usize::from(desc.symbol_size);
        let symbol_count = u16::try_from(chunk.len()).map_err(|_| {
            FfsError::RepairFailed(format!(
                "symbol_count {} exceeds u16 at block {}",
                chunk.len(),
                block_num.0
            ))
        })?;
        let header = RepairBlockHeader {
            first_esi,
            symbol_count,
            symbol_size: desc.symbol_size,
            block_group: self.layout.group,
            repair_generation: desc.repair_generation,
            checksum: 0,
        };

        let mut block = vec![0_u8; block_size];
        block[..RepairBlockHeader::SIZE].copy_from_slice(&header.to_bytes());
        for (local_idx, (_esi, data)) in chunk.iter().enumerate() {
            let payload_start = RepairBlockHeader::SIZE + local_idx * symbol_size;
            let payload_end = payload_start + symbol_size;
            block[payload_start..payload_end].copy_from_slice(data);
        }
        self.device.write_block(cx, block_num, &block)
    }

    fn block_size_usize(&self) -> Result<usize> {
        usize::try_from(self.device.block_size())
            .map_err(|_| FfsError::RepairFailed("device block_size does not fit usize".to_owned()))
    }

    fn descriptor_block(&self, slot: usize) -> Result<BlockNumber> {
        if slot >= REPAIR_DESC_SLOT_COUNT_USIZE {
            return Err(FfsError::RepairFailed(format!(
                "descriptor slot {slot} out of range [0, {REPAIR_DESC_SLOT_COUNT_USIZE})"
            )));
        }
        Ok(self.layout.descriptor_blocks()[slot])
    }

    fn validate_desc_layout(&self, desc: &RepairGroupDescExt) -> Result<()> {
        let expected_start = self.layout.repair_start_block();
        if desc.repair_start_block != expected_start {
            return Err(FfsError::RepairFailed(format!(
                "repair_start_block mismatch for group {}: desc={} expected={}",
                self.layout.group.0, desc.repair_start_block.0, expected_start.0
            )));
        }
        if desc.repair_block_count != self.layout.repair_block_count {
            return Err(FfsError::RepairFailed(format!(
                "repair_block_count mismatch for group {}: desc={} expected={}",
                self.layout.group.0, desc.repair_block_count, self.layout.repair_block_count
            )));
        }
        if desc.symbol_size == 0 {
            return Err(FfsError::RepairFailed(format!(
                "descriptor symbol_size is zero for group {}",
                self.layout.group.0
            )));
        }
        Ok(())
    }

    #[must_use]
    fn raw_symbol_mode(block_size: usize, symbol_size: usize) -> bool {
        symbol_size > block_size.saturating_sub(RepairBlockHeader::SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_block::BlockBuf;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    struct MemBlockDevice {
        blocks: Mutex<HashMap<u64, Vec<u8>>>,
        block_size: u32,
        block_count: u64,
    }

    impl MemBlockDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                blocks: Mutex::new(HashMap::new()),
                block_size,
                block_count,
            }
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            if block.0 >= self.block_count {
                return Err(FfsError::Format(format!(
                    "read out of range: block={} block_count={}",
                    block.0, self.block_count
                )));
            }
            let bytes = self
                .blocks
                .lock()
                .get(&block.0)
                .cloned()
                .unwrap_or_else(|| vec![0_u8; self.block_size as usize]);
            Ok(BlockBuf::new(bytes))
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            if block.0 >= self.block_count {
                return Err(FfsError::Format(format!(
                    "write out of range: block={} block_count={}",
                    block.0, self.block_count
                )));
            }
            if data.len() != self.block_size as usize {
                return Err(FfsError::Format(format!(
                    "write size mismatch: got={} expected={}",
                    data.len(),
                    self.block_size
                )));
            }
            self.blocks.lock().insert(block.0, data.to_vec());
            Ok(())
        }

        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn block_count(&self) -> u64 {
            self.block_count
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    fn make_desc(
        layout: RepairGroupLayout,
        generation: u64,
        symbol_size: u16,
    ) -> RepairGroupDescExt {
        RepairGroupDescExt {
            transfer_length: u64::from(symbol_size) * 8,
            symbol_size,
            source_block_count: 8,
            sub_blocks: 1,
            symbol_alignment: 4,
            repair_start_block: layout.repair_start_block(),
            repair_block_count: layout.repair_block_count,
            repair_generation: generation,
            checksum: 0,
        }
    }

    fn make_symbols(first_esi: u32, count: usize, symbol_size: usize) -> Vec<(u32, Vec<u8>)> {
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let esi = first_esi + u32::try_from(i).expect("i fits u32");
            let mut payload = vec![0_u8; symbol_size];
            for (j, byte) in payload.iter_mut().enumerate() {
                *byte = u8::try_from((esi as usize + j * 17 + 11) % 251)
                    .expect("value is always < 251");
            }
            out.push((esi, payload));
        }
        out
    }

    #[test]
    fn layout_places_regions_at_group_tail() {
        let layout =
            RepairGroupLayout::new(GroupNumber(2), BlockNumber(64), 32, 2, 5).expect("layout");
        assert_eq!(layout.validation_start_block(), BlockNumber(87));
        assert_eq!(layout.repair_start_block(), BlockNumber(89));
        assert_eq!(
            layout.descriptor_blocks(),
            [BlockNumber(94), BlockNumber(95)]
        );
    }

    #[test]
    fn storage_round_trip_symbols_and_generation_commit() {
        let cx = Cx::for_testing();
        let device = MemBlockDevice::new(256, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 32, 0, 4).expect("layout");
        let storage = RepairGroupStorage::new(&device, layout);

        let bootstrap = make_desc(layout, 0, 32);
        storage
            .write_group_desc_ext(&cx, &bootstrap)
            .expect("write bootstrap descriptor");

        let symbols = make_symbols(1_000, 10, usize::from(bootstrap.symbol_size));
        storage
            .write_repair_symbols(&cx, &symbols, 1)
            .expect("write repair symbols");

        let active_desc = storage.read_group_desc_ext(&cx).expect("active desc");
        assert_eq!(
            active_desc.repair_generation, 1,
            "group={} expected generation=1 got={}",
            layout.group.0, active_desc.repair_generation
        );

        let round_trip = storage.read_repair_symbols(&cx).expect("read symbols");
        assert_eq!(
            round_trip, symbols,
            "group={} generation={} repair_start={}",
            layout.group.0, active_desc.repair_generation, active_desc.repair_start_block.0
        );
    }

    #[test]
    fn storage_prefers_latest_fully_valid_generation() {
        let cx = Cx::for_testing();
        let device = MemBlockDevice::new(256, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(1), BlockNumber(32), 32, 0, 3).expect("layout");
        let storage = RepairGroupStorage::new(&device, layout);

        let bootstrap = make_desc(layout, 0, 32);
        storage
            .write_group_desc_ext(&cx, &bootstrap)
            .expect("write bootstrap descriptor");

        let symbols_g1 = make_symbols(2_000, 6, usize::from(bootstrap.symbol_size));
        storage
            .write_repair_symbols(&cx, &symbols_g1, 1)
            .expect("publish generation 1");

        let mut desc_g2 = storage.read_group_desc_ext(&cx).expect("read generation 1");
        desc_g2.repair_generation = 2;
        // Publish a higher-generation descriptor without committing generation-2
        // symbol blocks. Reader should keep generation 1 as latest fully-valid.
        storage
            .write_group_desc_ext(&cx, &desc_g2)
            .expect("publish descriptor-only generation 2 update");

        let active = storage
            .read_group_desc_ext(&cx)
            .expect("fallback descriptor");
        assert_eq!(
            active.repair_generation, 1,
            "group={} expected fallback to generation 1 after descriptor-only generation 2 publish",
            layout.group.0
        );
        let read_back = storage.read_repair_symbols(&cx).expect("fallback symbols");
        assert_eq!(
            read_back, symbols_g1,
            "group={} expected symbol payload from generation 1",
            layout.group.0
        );
    }

    #[test]
    fn storage_rejects_incomplete_generation_without_fallback() {
        let cx = Cx::for_testing();
        let device = MemBlockDevice::new(256, 64);
        let layout =
            RepairGroupLayout::new(GroupNumber(3), BlockNumber(0), 16, 0, 2).expect("layout");
        let storage = RepairGroupStorage::new(&device, layout);

        let bootstrap = make_desc(layout, 0, 32);
        storage
            .write_group_desc_ext(&cx, &bootstrap)
            .expect("write bootstrap descriptor");

        let mut desc_g1 = bootstrap;
        desc_g1.repair_generation = 1;
        let symbols_g1 = make_symbols(5_000, 4, usize::from(desc_g1.symbol_size));
        storage
            .write_symbols_for_desc(&cx, &desc_g1, &symbols_g1)
            .expect("write generation 1 symbol blocks");

        let torn_block = BlockNumber(desc_g1.repair_start_block.0 + 1);
        device
            .write_block(&cx, torn_block, &vec![0_u8; device.block_size() as usize])
            .expect("simulate torn write");
        storage
            .write_group_desc_ext(&cx, &desc_g1)
            .expect("publish torn generation 1 descriptor");

        let err = storage
            .read_repair_symbols(&cx)
            .expect_err("incomplete generation must fail");
        assert!(
            matches!(err, FfsError::RepairFailed(_)),
            "group={} generation={} torn_block={} expected RepairFailed, got {err:?}",
            layout.group.0,
            desc_g1.repair_generation,
            torn_block.0
        );
    }
}
