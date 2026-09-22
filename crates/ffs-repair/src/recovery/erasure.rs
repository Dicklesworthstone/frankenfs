//! Recovery of source blocks whose current bytes cannot be read.
//!
//! Unreadability is evidence, not a zero-filled before-image. Only an explicitly
//! opted-in writeback authority may consume it. The direct authority is for an
//! offline device or a client-read-only mount with exclusive repair ownership;
//! its preflight is not an atomic compare-and-write primitive for live writers.

use super::{
    GroupRecoveryOrchestrator, RecoveryAttemptResult, RecoveryDecoderStats, RecoveryEvidence,
    RecoveryOutcome,
};
use crate::codec::decode_group_with_owned_repair_symbols;
use asupersync::Cx;
use ffs_block::BlockDevice;
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;
use std::collections::BTreeSet;
use std::io::ErrorKind;

/// A recovered target with an explicitly optional before-image.
///
/// `None` means the target returned a media read error during planning. It must
/// still be unreadable at the writeback gate. It never means an empty block, a
/// zero-filled block, or permission to skip a mounted mutation serializer.
#[derive(Debug, Clone, Copy)]
pub struct ErasureRecoveryWritebackBlock<'a> {
    pub block: BlockNumber,
    pub expected_current: Option<&'a [u8]>,
    pub data: &'a [u8],
}

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

/// Do not turn cancellation, permissions, contention, or bad geometry into
/// erasures. Linux EIO is 5; other raw OS failures remain fail-closed. A short
/// positioned read is also a recoverable erasure when the writeback can restore
/// and reread the entire block inside the declared device geometry.
pub(super) fn is_media_read_failure(error: &FfsError) -> bool {
    match error {
        FfsError::Io(error) => {
            error.kind() == ErrorKind::UnexpectedEof
                || (cfg!(target_os = "linux") && error.raw_os_error() == Some(5))
        }
        _ => false,
    }
}

impl GroupRecoveryOrchestrator<'_> {
    /// Slow path after a target's normal before-image capture hit a media error.
    /// The common readable-target path and existing mounted authority stay intact.
    pub(super) fn recover_unreadable_targets(
        &self,
        cx: &Cx,
        indices: &[u32],
    ) -> RecoveryAttemptResult {
        let mut evidence = RecoveryEvidence {
            group: self.group().0,
            generation: 0,
            corrupt_count: indices.len(),
            symbols_available: 0,
            symbols_used: 0,
            decoder_stats: RecoveryDecoderStats::default(),
            outcome: RecoveryOutcome::Failed,
            reason: None,
        };
        let repaired_blocks = match self.recover_erasures(cx, indices, &mut evidence) {
            Ok(blocks) => {
                evidence.outcome = RecoveryOutcome::Recovered;
                blocks
            }
            Err(error) => {
                evidence.reason = Some(error.to_string());
                Vec::new()
            }
        };
        RecoveryAttemptResult {
            evidence,
            repaired_blocks,
        }
    }

    fn recover_erasures(
        &self,
        cx: &Cx,
        indices: &[u32],
        evidence: &mut RecoveryEvidence,
    ) -> Result<Vec<BlockNumber>> {
        checkpoint(cx)?;
        if !self.writeback.supports_unreadable_targets() {
            return Err(FfsError::RepairFailed(
                "writeback authority does not support unreadable repair targets".to_owned(),
            ));
        }
        let block_size = self.device.block_size() as usize;
        let mut before = Vec::with_capacity(indices.len());
        let mut unreadable = 0_usize;
        for &index in indices {
            checkpoint(cx)?;
            let block = BlockNumber(self.source_first_block.0 + u64::from(index));
            match self.device.read_block(cx, block) {
                Ok(bytes) => {
                    if bytes.len() != block_size {
                        return Err(FfsError::RepairFailed(format!(
                            "short before-image at repair target {}",
                            block.0
                        )));
                    }
                    before.push(Some(bytes.into_inner()));
                }
                Err(error) if is_media_read_failure(&error) => {
                    unreadable += 1;
                    before.push(None);
                }
                Err(error) => return Err(error),
            }
        }
        checkpoint(cx)?;
        if unreadable == 0 {
            return Err(FfsError::RepairFailed(
                "target read failure was transient; rescrub before attempting repair".to_owned(),
            ));
        }

        let desc = self.storage.read_group_desc_ext(cx)?;
        evidence.generation = desc.repair_generation;
        if u32::from(desc.source_block_count) != self.source_block_count
            || u32::from(desc.symbol_size) != self.device.block_size()
            || desc.transfer_length
                != u64::from(self.source_block_count) * u64::from(self.device.block_size())
        {
            return Err(FfsError::RepairFailed(
                "repair descriptor does not match the source geometry".to_owned(),
            ));
        }
        let symbols = self.storage.read_repair_symbols(cx)?;
        evidence.symbols_available = symbols.len();
        if self.storage.read_group_desc_ext(cx)? != desc {
            return Err(FfsError::RepairFailed(
                "repair generation changed while loading erasure recovery symbols".to_owned(),
            ));
        }
        evidence.symbols_used = symbols.len();
        let decode = decode_group_with_owned_repair_symbols(
            cx,
            self.device,
            &self.fs_uuid,
            self.group(),
            self.source_first_block,
            self.source_block_count,
            indices,
            symbols,
        )?;
        checkpoint(cx)?;
        evidence.decoder_stats = RecoveryDecoderStats::from(&decode.stats);
        if !decode.complete || decode.recovered.len() != indices.len() {
            evidence.outcome = RecoveryOutcome::Partial;
            return Err(FfsError::RepairFailed(
                "decoder returned incomplete erasure recovery".to_owned(),
            ));
        }
        if self.storage.read_group_desc_ext(cx)? != desc {
            return Err(FfsError::RepairFailed(
                "repair generation changed during erasure decoding".to_owned(),
            ));
        }
        let mut writeback = Vec::with_capacity(indices.len());
        for ((&index, expected), recovered) in indices.iter().zip(&before).zip(&decode.recovered) {
            let block = BlockNumber(self.source_first_block.0 + u64::from(index));
            if recovered.block != block || recovered.data.len() != block_size {
                return Err(FfsError::RepairFailed(
                    "decoder returned invalid erasure recovery targets".to_owned(),
                ));
            }
            writeback.push(ErasureRecoveryWritebackBlock {
                block,
                expected_current: expected.as_deref(),
                data: &recovered.data,
            });
        }
        self.writeback
            .writeback_recovered_erasures(cx, self.device, &writeback)?;
        Ok(writeback.iter().map(|target| target.block).collect())
    }
}

/// Preflight the ENTIRE batch before any write. A formerly unreadable block
/// becoming readable is a changed observation, not an implicit permission to
/// overwrite whatever became visible. A mounted RW implementation needs an
/// equivalent check under its own mutation serializer; it must explicitly opt in.
pub(super) fn writeback_direct(
    cx: &Cx,
    device: &dyn BlockDevice,
    recovered: &[ErasureRecoveryWritebackBlock<'_>],
) -> Result<()> {
    checkpoint(cx)?;
    let block_size = device.block_size() as usize;
    let mut seen = BTreeSet::new();
    for target in recovered {
        if block_size == 0
            || target.block.0 >= device.block_count()
            || target.data.len() != block_size
            || target
                .expected_current
                .is_some_and(|bytes| bytes.len() != block_size)
            || !seen.insert(target.block)
        {
            return Err(FfsError::RepairFailed(
                "invalid or duplicate erasure writeback target".to_owned(),
            ));
        }
    }
    for target in recovered {
        checkpoint(cx)?;
        match (target.expected_current, device.read_block(cx, target.block)) {
            (Some(expected), Ok(observed)) if observed.as_slice() == expected => {}
            (None, Err(error)) if is_media_read_failure(&error) => {}
            (_, Err(error)) => return Err(error),
            _ => {
                return Err(FfsError::RepairFailed(format!(
                    "erasure recovery writeback compare failed at block {}",
                    target.block.0
                )));
            }
        }
    }
    checkpoint(cx)?;
    for target in recovered {
        checkpoint(cx)?;
        device.write_block(cx, target.block, target.data)?;
    }
    device.sync(cx)?;
    for target in recovered {
        checkpoint(cx)?;
        let observed = device.read_block(cx, target.block)?;
        if observed.as_slice() != target.data {
            return Err(FfsError::RepairFailed(format!(
                "post-erasure-repair verification failed at block {}",
                target.block.0
            )));
        }
    }
    checkpoint(cx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode_group;
    use crate::recovery::{
        DirectDeviceRecoveryWriteback, RecoveryWriteback, RecoveryWritebackBlock,
    };
    use crate::storage::{RepairGroupLayout, RepairGroupStorage};
    use crate::symbol::RepairGroupDescExt;
    use ffs_block::BlockBuf;
    use ffs_types::GroupNumber;
    use std::fs::File;
    use std::os::unix::fs::FileExt;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const BLOCK_SIZE: u32 = 256;
    const SOURCE_COUNT: u32 = 8;
    const UUID: [u8; 16] = [0x11; 16];

    /// Real positioned file I/O, with a read fault that a successful write heals.
    #[derive(Debug)]
    struct ReadFaultDevice {
        file: File,
        unreadable: Mutex<BTreeSet<u64>>,
        writes: Mutex<Vec<BlockNumber>>,
        fault_reads: AtomicUsize,
        become_readable_after: usize,
        persistent_fault: AtomicBool,
        permission_fault: AtomicBool,
    }

    impl ReadFaultDevice {
        fn new() -> Self {
            let file = tempfile::tempfile().expect("temporary device");
            file.set_len(64 * u64::from(BLOCK_SIZE)).expect("size device");
            Self {
                file,
                unreadable: Mutex::new(BTreeSet::new()),
                writes: Mutex::new(Vec::new()),
                fault_reads: AtomicUsize::new(0),
                become_readable_after: usize::MAX,
                persistent_fault: AtomicBool::new(false),
                permission_fault: AtomicBool::new(false),
            }
        }

        fn fail_reads(&self, block: u64) {
            self.unreadable.lock().expect("fault lock").insert(block);
        }

        fn raw_block(&self, block: u64) -> Vec<u8> {
            let mut data = vec![0; BLOCK_SIZE as usize];
            self.file
                .read_exact_at(&mut data, block * u64::from(BLOCK_SIZE))
                .expect("raw device read");
            data
        }
    }

    impl BlockDevice for ReadFaultDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            if self.unreadable.lock().expect("fault lock").contains(&block.0) {
                let count = self.fault_reads.fetch_add(1, Ordering::Relaxed);
                if count < self.become_readable_after {
                    let kind = if self.permission_fault.load(Ordering::Relaxed) {
                        ErrorKind::PermissionDenied
                    } else {
                        ErrorKind::UnexpectedEof
                    };
                    return Err(std::io::Error::new(kind, "injected target read failure").into());
                }
            }
            let mut data = vec![0; BLOCK_SIZE as usize];
            self.file
                .read_exact_at(&mut data, block.0 * u64::from(BLOCK_SIZE))?;
            Ok(BlockBuf::new(data))
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            assert_eq!(data.len(), BLOCK_SIZE as usize);
            self.file.write_all_at(data, block.0 * u64::from(BLOCK_SIZE))?;
            self.writes.lock().expect("write log").push(block);
            if !self.persistent_fault.load(Ordering::Relaxed) {
                self.unreadable.lock().expect("fault lock").remove(&block.0);
            }
            Ok(())
        }

        fn block_size(&self) -> u32 {
            BLOCK_SIZE
        }

        fn block_count(&self) -> u64 {
            64
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(self.file.sync_all()?)
        }
    }

    fn fixture() -> (ReadFaultDevice, RepairGroupLayout, Vec<Vec<u8>>) {
        let device = ReadFaultDevice::new();
        let cx = Cx::for_testing();
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let originals: Vec<Vec<u8>> = (0..SOURCE_COUNT)
            .map(|block| {
                let data: Vec<u8> = (0..BLOCK_SIZE)
                    .map(|byte| ((block * 31 + byte + 7) % 251) as u8)
                    .collect();
                device
                    .write_block(&cx, BlockNumber(u64::from(block)), &data)
                    .expect("source");
                data
            })
            .collect();
        let encoded = encode_group(
            &cx,
            &device,
            &UUID,
            GroupNumber(0),
            BlockNumber(0),
            SOURCE_COUNT,
            4,
        )
        .expect("encode real parity");
        let storage = RepairGroupStorage::new(&device, layout);
        storage
            .write_group_desc_ext(
                &cx,
                &RepairGroupDescExt {
                    transfer_length: u64::from(SOURCE_COUNT) * u64::from(BLOCK_SIZE),
                    symbol_size: BLOCK_SIZE as u16,
                    source_block_count: SOURCE_COUNT as u16,
                    sub_blocks: 1,
                    symbol_alignment: 4,
                    repair_start_block: layout.repair_start_block(),
                    repair_block_count: layout.repair_block_count,
                    repair_generation: 0,
                    checksum: 0,
                },
            )
            .expect("descriptor");
        let symbols = encoded
            .repair_symbols
            .into_iter()
            .map(|symbol| (symbol.esi, symbol.data))
            .collect::<Vec<_>>();
        storage.write_repair_symbols(&cx, &symbols, 1).expect("parity");
        device.writes.lock().expect("write log").clear();
        (device, layout, originals)
    }

    fn recover(
        device: &ReadFaultDevice,
        layout: RepairGroupLayout,
        targets: &[u32],
    ) -> RecoveryAttemptResult {
        let cx = Cx::for_testing();
        GroupRecoveryOrchestrator::new(device, UUID, layout, BlockNumber(0), SOURCE_COUNT)
            .expect("orchestrator")
            .recover_from_indices(&cx, targets)
    }

    #[test]
    fn unreadable_source_target_is_reconstructed_from_real_parity() {
        let (device, layout, originals) = fixture();
        device
            .file
            .write_all_at(&[0xff; BLOCK_SIZE as usize], u64::from(BLOCK_SIZE))
            .expect("damage");
        device.fail_reads(1);
        let result = recover(&device, layout, &[1]);
        assert!(result.is_success(), "{:?}", result.evidence);
        assert_eq!(result.repaired_blocks, [BlockNumber(1)]);
        assert_eq!(device.raw_block(1), originals[1]);
    }

    #[test]
    fn mixed_readable_corruption_and_unreadable_targets_recover_together() {
        let (device, layout, originals) = fixture();
        for block in [1, 5] {
            device
                .file
                .write_all_at(&[0xa5; BLOCK_SIZE as usize], block * u64::from(BLOCK_SIZE))
                .expect("damage");
        }
        device.fail_reads(1);
        let result = recover(&device, layout, &[5, 1, 1]);
        assert!(result.is_success(), "{:?}", result.evidence);
        assert_eq!(result.repaired_blocks, [BlockNumber(1), BlockNumber(5)]);
        assert_eq!(device.raw_block(1), originals[1]);
        assert_eq!(device.raw_block(5), originals[5]);
    }

    #[derive(Debug, Default)]
    struct MountedAuthority {
        calls: AtomicUsize,
    }

    impl RecoveryWriteback for MountedAuthority {
        fn writeback_recovered(
            &self,
            _cx: &Cx,
            _device: &dyn BlockDevice,
            _blocks: &[RecoveryWritebackBlock<'_>],
        ) -> Result<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn authority_name(&self) -> &'static str {
            "mounted_test"
        }
    }

    #[test]
    fn existing_mounted_authority_does_not_implicitly_allow_unreadable_targets() {
        let (device, layout, _) = fixture();
        device.fail_reads(1);
        let authority = MountedAuthority::default();
        let cx = Cx::for_testing();
        let result = GroupRecoveryOrchestrator::new_with_writeback(
            &device,
            &authority,
            UUID,
            layout,
            BlockNumber(0),
            SOURCE_COUNT,
        )
        .expect("orchestrator")
        .recover_from_indices(&cx, &[1]);
        assert!(!result.is_success());
        assert_eq!(authority.calls.load(Ordering::Relaxed), 0);
        assert!(device.writes.lock().expect("writes").is_empty());
    }

    #[test]
    fn permission_errors_are_not_interpreted_as_media_erasures() {
        let (device, layout, _) = fixture();
        device.fail_reads(1);
        device.permission_fault.store(true, Ordering::Relaxed);
        let result = recover(&device, layout, &[1]);
        assert!(!result.is_success());
        assert!(device.writes.lock().expect("writes").is_empty());
        assert!(!is_media_read_failure(&FfsError::Cancelled));
        assert!(!is_media_read_failure(&FfsError::PermissionDenied));
        assert!(!is_media_read_failure(
            &std::io::Error::from(ErrorKind::WouldBlock).into()
        ));
    }

    #[test]
    fn newly_readable_target_is_not_overwritten_at_the_writeback_gate() {
        let (mut device, layout, _) = fixture();
        device.become_readable_after = 2;
        let newer = [0x92; BLOCK_SIZE as usize];
        device
            .file
            .write_all_at(&newer, u64::from(BLOCK_SIZE))
            .expect("newer bytes");
        device.fail_reads(1);
        let result = recover(&device, layout, &[1]);
        assert!(!result.is_success());
        assert!(
            result
                .evidence
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("compare failed")
        );
        assert!(device.writes.lock().expect("writes").is_empty());
        assert_eq!(device.raw_block(1), newer);
    }

    #[test]
    fn persistent_postwrite_read_failure_never_reports_success() {
        let (device, layout, _) = fixture();
        device.fail_reads(1);
        device.persistent_fault.store(true, Ordering::Relaxed);
        let result = recover(&device, layout, &[1]);
        assert!(!result.is_success());
        assert!(result.repaired_blocks.is_empty());
        assert_eq!(*device.writes.lock().expect("writes"), [BlockNumber(1)]);
    }

    #[test]
    fn whole_batch_compare_precedes_first_erasure_write() {
        let (device, _, originals) = fixture();
        device.fail_reads(1);
        let wrong_before = [0x99; BLOCK_SIZE as usize];
        let targets = [
            ErasureRecoveryWritebackBlock {
                block: BlockNumber(1),
                expected_current: None,
                data: &originals[1],
            },
            ErasureRecoveryWritebackBlock {
                block: BlockNumber(2),
                expected_current: Some(&wrong_before),
                data: &originals[2],
            },
        ];
        let result = DirectDeviceRecoveryWriteback.writeback_recovered_erasures(
            &Cx::for_testing(),
            &device,
            &targets,
        );
        assert!(result.is_err());
        assert!(device.writes.lock().expect("writes").is_empty());
    }

    #[test]
    fn cancellation_is_checked_even_when_the_device_ignores_the_context() {
        let (device, _, originals) = fixture();
        device.fail_reads(1);
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let target = ErasureRecoveryWritebackBlock {
            block: BlockNumber(1),
            expected_current: None,
            data: &originals[1],
        };
        assert!(matches!(
            writeback_direct(&cx, &device, &[target]),
            Err(FfsError::Cancelled)
        ));
        assert!(device.writes.lock().expect("writes").is_empty());
    }

    #[test]
    fn erasure_recovery_rejects_mismatched_descriptor_geometry() {
        let (device, layout, _) = fixture();
        device.fail_reads(1);
        let result = GroupRecoveryOrchestrator::new(
            &device,
            UUID,
            layout,
            BlockNumber(0),
            SOURCE_COUNT - 1,
        )
        .expect("orchestrator")
        .recover_from_indices(&Cx::for_testing(), &[1]);
        assert!(!result.is_success());
        assert!(
            result
                .evidence
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("source geometry")
        );
        assert!(device.writes.lock().expect("writes").is_empty());
    }
}
