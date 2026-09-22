//! Degraded reads of one committed, full-block repair generation.
//!
//! The ordinary storage reader validates every parity read before selecting a
//! descriptor. That cannot recover a source read error together with a parity
//! read error. Here a checksum-valid descriptor selects the generation first;
//! unreadable raw parity blocks are omitted at their original ESI positions.
//! Never substitute an older descriptor after a newer valid commit is observed.
//! Raw parity has no per-payload checksum or generation header, so this retains
//! the offline/exclusive-writer requirement; it does not certify payload damage
//! or resolve interrupted, in-place symbol refreshes.

use super::{checkpoint, is_media_read_failure};
use crate::storage::RepairGroupLayout;
use crate::symbol::RepairGroupDescExt;
use asupersync::Cx;
use ffs_block::BlockDevice;
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;

type SymbolBatch = Vec<(u32, Vec<u8>)>;

#[derive(Debug)]
pub(super) struct RepairGeneration {
    pub(super) descriptor: RepairGroupDescExt,
    pub(super) symbols: SymbolBatch,
}

fn invalid(message: &str) -> FfsError {
    FfsError::RepairFailed(message.to_owned())
}

/// Descriptor-only read: a parity failure must not hide the latest commit.
/// Descriptor I/O errors remain fatal because a missing slot could conceal a
/// newer generation. CRC-invalid/torn descriptors retain the dual-slot policy.
fn committed_descriptor(
    cx: &Cx,
    device: &dyn BlockDevice,
    layout: RepairGroupLayout,
    source_count: u32,
) -> Result<RepairGroupDescExt> {
    checkpoint(cx)?;
    let mut candidates = Vec::new();
    let slots = layout.descriptor_blocks();
    if slots[0] == slots[1]
        || slots
            .iter()
            .any(|block| block.0 < layout.group_start.0 || block.0 >= device.block_count())
    {
        return Err(invalid("invalid erasure recovery descriptor locations"));
    }
    for block in slots {
        checkpoint(cx)?;
        let bytes = device.read_block(cx, block)?;
        let region = bytes
            .as_slice()
            .get(..RepairGroupDescExt::SIZE)
            .ok_or_else(|| invalid("short erasure recovery descriptor block"))?;
        if let Ok(desc) = RepairGroupDescExt::parse(region) {
            candidates.push(desc);
        }
    }
    checkpoint(cx)?;
    candidates.sort_by_key(|desc| std::cmp::Reverse(desc.repair_generation));
    let desc = candidates
        .first()
        .ok_or_else(|| invalid("no committed erasure recovery descriptor"))?;
    if candidates
        .iter()
        .skip(1)
        .any(|other| other.repair_generation == desc.repair_generation && other != desc)
    {
        return Err(invalid("ambiguous descriptors for one repair generation"));
    }
    if desc.repair_generation == 0 {
        return Err(invalid("repair generation is not committed"));
    }
    if u32::from(desc.source_block_count) != source_count
        || source_count == 0
        || u32::from(desc.symbol_size) != device.block_size()
        || desc.transfer_length != u64::from(source_count) * u64::from(device.block_size())
        || desc.sub_blocks != 1
        || desc.symbol_alignment != 4
        || desc.repair_start_block != layout.repair_start_block()
        || desc.repair_block_count != layout.repair_block_count
    {
        return Err(invalid("repair descriptor does not match the source geometry"));
    }
    let end = desc
        .repair_start_block
        .0
        .checked_add(u64::from(desc.repair_block_count))
        .ok_or_else(|| invalid("repair symbol range overflows"))?;
    if desc.repair_start_block.0 < layout.group_start.0
        || end > slots[0].0
        || end > device.block_count()
    {
        return Err(invalid("repair symbols exceed the declared device geometry"));
    }
    Ok(desc.clone())
}

/// Require the same checksum-valid descriptor after capture and after decode.
pub(super) fn ensure_generation(
    cx: &Cx,
    device: &dyn BlockDevice,
    layout: RepairGroupLayout,
    source_count: u32,
    expected: &RepairGroupDescExt,
) -> Result<()> {
    if committed_descriptor(cx, device, layout, source_count)? != *expected {
        return Err(invalid("repair generation changed during erasure recovery"));
    }
    Ok(())
}

pub(super) fn read_generation(
    cx: &Cx,
    device: &dyn BlockDevice,
    layout: RepairGroupLayout,
    source_count: u32,
) -> Result<RepairGeneration> {
    let descriptor = committed_descriptor(cx, device, layout, source_count)?;
    let mut symbols = Vec::new();
    let mut unreadable = 0_u32;
    for index in 0..descriptor.repair_block_count {
        checkpoint(cx)?;
        let block = BlockNumber(descriptor.repair_start_block.0 + u64::from(index));
        let bytes = match device.read_block(cx, block) {
            Ok(bytes) => bytes,
            Err(error) if is_media_read_failure(&error) => {
                unreadable += 1;
                continue;
            }
            Err(error) => return Err(error),
        };
        if bytes.len() != usize::from(descriptor.symbol_size) {
            return Err(invalid("short raw parity buffer without a media error"));
        }
        // The existing raw storage format reserves all-zero blocks as unused.
        if crate::scrub::is_all_zero(bytes.as_slice()) {
            continue;
        }
        let esi = source_count
            .checked_add(index)
            .ok_or_else(|| invalid("repair ESI overflow"))?;
        symbols.push((esi, bytes.into_inner()));
    }
    ensure_generation(cx, device, layout, source_count, &descriptor)?;
    if unreadable > 0 {
        tracing::warn!(
            target: "ffs::repair::recovery",
            group = layout.group.0,
            generation = descriptor.repair_generation,
            unreadable_parity_blocks = unreadable,
            available_symbols = symbols.len(),
            "repair_generation_read_degraded"
        );
    }
    Ok(RepairGeneration {
        descriptor,
        symbols,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_block::BlockBuf;
    use ffs_types::GroupNumber;
    use std::collections::BTreeSet;
    use std::io::ErrorKind;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Device {
        blocks: Mutex<Vec<Vec<u8>>>,
        failures: BTreeSet<u64>,
        error_kind: ErrorKind,
        change_on_parity_read: AtomicBool,
    }

    impl BlockDevice for Device {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            if self.failures.contains(&block.0) {
                return Err(std::io::Error::new(self.error_kind, "injected read error").into());
            }
            let mut blocks = self.blocks.lock().expect("blocks");
            if block.0 == 58 && self.change_on_parity_read.swap(false, Ordering::Relaxed) {
                let mut next = RepairGroupDescExt::parse(&blocks[63]).expect("descriptor");
                next.repair_generation += 1;
                blocks[62][..RepairGroupDescExt::SIZE].copy_from_slice(&next.to_bytes());
            }
            Ok(BlockBuf::new(blocks[block.0 as usize].clone()))
        }

        fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
            Err(FfsError::ReadOnly)
        }

        fn block_size(&self) -> u32 {
            256
        }

        fn block_count(&self) -> u64 {
            64
        }

        fn sync(&self, cx: &Cx) -> Result<()> {
            checkpoint(cx)
        }
    }

    fn fixture() -> (Device, RepairGroupLayout) {
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let desc = RepairGroupDescExt {
            transfer_length: 8 * 256,
            symbol_size: 256,
            source_block_count: 8,
            sub_blocks: 1,
            symbol_alignment: 4,
            repair_start_block: layout.repair_start_block(),
            repair_block_count: 4,
            repair_generation: 1,
            checksum: 0,
        };
        let mut blocks = vec![vec![0; 256]; 64];
        let bootstrap = RepairGroupDescExt {
            repair_generation: 0,
            ..desc.clone()
        };
        blocks[62][..RepairGroupDescExt::SIZE].copy_from_slice(&bootstrap.to_bytes());
        blocks[63][..RepairGroupDescExt::SIZE].copy_from_slice(&desc.to_bytes());
        for (index, block) in blocks[58..62].iter_mut().enumerate() {
            block.fill(index as u8 + 1);
        }
        (
            Device {
                blocks: Mutex::new(blocks),
                failures: BTreeSet::new(),
                error_kind: ErrorKind::UnexpectedEof,
                change_on_parity_read: AtomicBool::new(false),
            },
            layout,
        )
    }

    #[test]
    fn missing_parity_retains_original_esi_positions_and_payloads() {
        let (mut device, layout) = fixture();
        device.failures.extend([58, 60]);
        let generation = read_generation(&Cx::for_testing(), &device, layout, 8).expect("read");
        assert_eq!(generation.descriptor.repair_generation, 1);
        assert_eq!(
            generation.symbols,
            vec![(9, vec![2; 256]), (11, vec![4; 256])]
        );
    }

    #[test]
    fn parity_capture_rejects_generation_change_before_decode() {
        let (device, layout) = fixture();
        device.change_on_parity_read.store(true, Ordering::Relaxed);
        let error =
            read_generation(&Cx::for_testing(), &device, layout, 8).expect_err("changed");
        assert!(error.to_string().contains("generation changed"));
    }

    #[test]
    fn descriptor_io_and_parity_permission_errors_never_select_an_older_generation() {
        let (mut device, layout) = fixture();
        device.failures.insert(63);
        assert!(read_generation(&Cx::for_testing(), &device, layout, 8).is_err());
        device.failures.clear();
        device.failures.insert(58);
        device.error_kind = ErrorKind::PermissionDenied;
        assert!(read_generation(&Cx::for_testing(), &device, layout, 8).is_err());
    }

    #[test]
    fn bootstrap_and_conflicting_same_generation_descriptors_fail_closed() {
        let (device, layout) = fixture();
        let mut blocks = device.blocks.lock().expect("blocks");
        let mut conflicting = RepairGroupDescExt::parse(&blocks[63]).expect("descriptor");
        conflicting.transfer_length += 256;
        blocks[62][..RepairGroupDescExt::SIZE].copy_from_slice(&conflicting.to_bytes());
        drop(blocks);
        let error =
            read_generation(&Cx::for_testing(), &device, layout, 8).expect_err("conflict");
        assert!(error.to_string().contains("ambiguous"));
        let mut blocks = device.blocks.lock().expect("blocks");
        conflicting.repair_generation = 0;
        conflicting.transfer_length = 8 * 256;
        blocks[62][..RepairGroupDescExt::SIZE].copy_from_slice(&conflicting.to_bytes());
        blocks[63].fill(0);
        drop(blocks);
        let error =
            read_generation(&Cx::for_testing(), &device, layout, 8).expect_err("bootstrap");
        assert!(error.to_string().contains("not committed"));
    }
}
