//! Complete micro/fat-ZAP reads through the owning DMU view, never raw offsets.

use super::{
    CheckedBlock, Cx, FfsError, Object, Objects, Result, checkpoint, corrupt, parse, unsupported,
};
use ffs_ondisk::zfs_zap::names::{NamePolicy, microzap_with_names};
use ffs_ondisk::zfs_zap::{Entry, FAT_TAG, FatHeader, MAX_ENTRIES, MICRO_TAG};
use std::collections::BTreeSet;

const MAX_ZAP_BLOCK_BYTES: usize = 64 * 1024 * 1024;
const MAX_ZAP_RESULT_BYTES: usize = 16 * 1024 * 1024;

impl Objects<'_> {
    /// Return the entire validated map or an error. No zero-filled missing
    /// leaves, skipped bad values, guessed integer widths or partial inventories.
    pub fn zap_values(&mut self, cx: &Cx, number: u64) -> Result<Vec<Entry>> {
        self.zap_values_with_names(cx, number, NamePolicy::Unnormalized)
    }

    /// Only an owner that implements the corresponding naming contract may
    /// opt into normalized metadata. The generic/ZPL path remains unnormalized.
    pub(super) fn zap_values_with_names(
        &mut self,
        cx: &Cx,
        number: u64,
        policy: NamePolicy,
    ) -> Result<Vec<Entry>> {
        let object = self.load(cx, number)?;
        let mut work = 0;
        let block = self.zap_block(cx, &object, 0, &mut work)?;
        let tag = block
            .order
            .u64(&block.bytes, 0)
            .map_err(|error| parse(&error))?;
        if tag == MICRO_TAG {
            if object.node.max_block() != 0 {
                return Err(corrupt("micro-ZAP unexpectedly has multiple blocks"));
            }
            let entries = microzap_with_names(&block.bytes, block.order, policy)
                .map_err(|error| parse(&error))?;
            let entries = entries
                .into_iter()
                .map(|entry| Entry {
                    name: entry.name,
                    values: vec![entry.value],
                    integer_bytes: 8,
                    collision: entry.collision,
                })
                .collect();
            checkpoint(cx)?;
            return Ok(entries);
        }
        if tag != FAT_TAG {
            return Err(corrupt("object is neither a micro-ZAP nor a fat-ZAP"));
        }
        let header = FatHeader::parse_with_names(&block.bytes, block.order, object.node.max_block(), policy)
            .map_err(|error| parse(&error))?;
        let table = if header.table_blocks().is_empty() {
            header
                .embedded_table(&block.bytes, block.order)
                .map_err(|error| parse(&error))?
        } else {
            let mut table = Vec::new();
            table
                .try_reserve_exact(header.table_len())
                .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
            for id in header.table_blocks() {
                let block = self.zap_block(cx, &object, id, &mut work)?;
                table.extend(
                    header
                        .table_block(&block.bytes, block.order)
                        .map_err(|error| parse(&error))?,
                );
            }
            table
        };
        let routes = header
            .routes(&table, object.node.max_block())
            .map_err(|error| parse(&error))?;
        for id in header.copied_blocks() {
            let block = self.zap_block(cx, &object, id, &mut work)?;
            let values = header
                .table_block(&block.bytes, block.order)
                .map_err(|error| parse(&error))?;
            header
                .check_copied_block(id, &values, &table)
                .map_err(|error| parse(&error))?;
        }
        let mut result = Vec::new();
        let mut names = BTreeSet::new();
        let mut result_bytes = 0_usize;
        for route in routes {
            let block = self.zap_block(cx, &object, route.block, &mut work)?;
            for entry in header
                .leaf(&block.bytes, block.order, route)
                .map_err(|error| parse(&error))?
            {
                checkpoint(cx)?;
                // Charge both the returned name and duplicate-name index. This
                // bounds payload retention, not allocator/Arc bookkeeping.
                let bytes =
                    2 * entry.name.len() + entry.values.len() * 8 + std::mem::size_of::<Entry>();
                result_bytes = result_bytes
                    .checked_add(bytes)
                    .filter(|size| *size <= MAX_ZAP_RESULT_BYTES)
                    .ok_or_else(|| unsupported("ZAP result payload exceeds 16 MiB"))?;
                if result.len() >= header.entry_count() || result.len() >= MAX_ENTRIES {
                    return Err(corrupt("ZAP has more reachable entries than its header"));
                }
                if !names.insert(entry.name.clone()) {
                    return Err(corrupt("duplicate ZAP key across leaves"));
                }
                result.push(entry);
            }
        }
        if result.len() != header.entry_count() {
            return Err(corrupt("ZAP entry count does not match reachable leaves"));
        }
        result.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        checkpoint(cx)?;
        Ok(result)
    }

    fn zap_block(
        &mut self,
        cx: &Cx,
        object: &Object,
        id: u64,
        work: &mut usize,
    ) -> Result<CheckedBlock> {
        checkpoint(cx)?;
        *work = work
            .checked_add(object.node.data_bytes())
            .filter(|bytes| *bytes <= MAX_ZAP_BLOCK_BYTES)
            .ok_or_else(|| unsupported("ZAP enumeration exceeds 64 MiB block-work budget"))?;
        self.data_block(cx, object, id)?
            .ok_or_else(|| corrupt("required ZAP metadata block is a hole"))
    }
}

#[cfg(test)]
mod tests;
