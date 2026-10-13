//! Generation-bound checksums and durable refresh fencing for raw parity.
//!
//! The two descriptor blocks contain a checksummed table of BLAKE3 bucket
//! digests. Buckets cover consecutive physical parity slots; large regions use
//! wider buckets instead of consuming unreserved image space. A bad bucket is
//! discarded as a unit, preserving the original ESIs of surviving symbols.
//!
//! Before overwriting any parity, BOTH descriptor slots receive a durable
//! pending record. A crash during refresh therefore cannot expose old metadata
//! as authority for mixed-generation raw bytes. This is fail-closed publication,
//! not double-buffered parity: an interrupted refresh must be regenerated from
//! independently trusted source data. It does not establish source freshness
//! after client writes or provide exclusion against concurrent repair writers.

use super::{RawRefreshAdmission, RepairGroupLayout, RepairGroupStorage, SymbolBatch};
use crate::symbol::RepairGroupDescExt;
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;

const COMMITTED: &[u8; 8] = b"RQHASH01";
const PENDING: &[u8; 8] = b"RQPEND01";
const TABLE_OFFSET: usize = 96;
const HASH_BYTES: usize = 32;

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

fn invalid(message: &str) -> FfsError {
    FfsError::RepairFailed(message.to_owned())
}

struct Record {
    descriptor: RepairGroupDescExt,
    bytes: Vec<u8>,
}

struct Manifest {
    record: Record,
    symbol_count: u32,
    bucket_width: u32,
}

fn bucket_geometry(storage: &RepairGroupStorage<'_>) -> Result<(usize, u32, usize)> {
    let block_size = storage.block_size_usize()?;
    let capacity = block_size.saturating_sub(TABLE_OFFSET) / HASH_BYTES;
    let capacity =
        u32::try_from(capacity).map_err(|_| invalid("raw repair checksum capacity overflows"))?;
    if capacity == 0 || storage.layout.repair_block_count == 0 {
        return Err(invalid(
            "raw repair integrity requires descriptor blocks of at least 128 bytes",
        ));
    }
    let width = storage.layout.repair_block_count.div_ceil(capacity);
    let count = storage.layout.repair_block_count.div_ceil(width) as usize;
    Ok((block_size, width, count))
}

fn record_hash(storage: &RepairGroupStorage<'_>, bytes: &[u8], table_end: usize) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"ffs-raw-repair-manifest-v1");
    hash.update(&storage.layout.group.0.to_le_bytes());
    hash.update(&storage.layout.group_start.0.to_le_bytes());
    hash.update(&bytes[..64]);
    hash.update(&bytes[TABLE_OFFSET..table_end]);
    *hash.finalize().as_bytes()
}

fn bucket_hasher(
    storage: &RepairGroupStorage<'_>,
    descriptor: &RepairGroupDescExt,
    first: u32,
) -> blake3::Hasher {
    let mut hash = blake3::Hasher::new();
    hash.update(b"ffs-raw-repair-bucket-v1");
    hash.update(&storage.layout.group.0.to_le_bytes());
    hash.update(&descriptor.to_bytes());
    hash.update(&first.to_le_bytes());
    hash
}

fn newest_records(storage: &RepairGroupStorage<'_>, cx: &Cx) -> Result<Vec<Record>> {
    checkpoint(cx)?;
    let mut records = Vec::new();
    for slot in 0..2 {
        let block = storage.descriptor_block(slot)?;
        if block.0 >= storage.device.block_count() {
            return Err(invalid("raw repair descriptor exceeds device geometry"));
        }
        // An unreadable descriptor could conceal a newer pending generation.
        // Do not interpret I/O errors as an absent or torn slot.
        let bytes = storage.device.read_block(cx, block)?;
        checkpoint(cx)?;
        if bytes.len() != storage.block_size_usize()? {
            return Err(invalid("short raw repair descriptor block"));
        }
        if let Ok(descriptor) = RepairGroupDescExt::parse(bytes.as_slice()) {
            records.push(Record {
                descriptor,
                bytes: bytes.into_inner(),
            });
        }
    }
    let newest = records
        .iter()
        .map(|record| record.descriptor.repair_generation)
        .max()
        .ok_or_else(|| invalid("no committed raw repair descriptor"))?;
    records.retain(|record| record.descriptor.repair_generation == newest);
    let descriptor = &records[0].descriptor;
    storage.validate_desc_layout(descriptor)?;
    if records
        .iter()
        .any(|record| record.descriptor.to_bytes() != descriptor.to_bytes())
    {
        return Err(invalid("ambiguous descriptors for one repair generation"));
    }
    let end = descriptor
        .repair_start_block
        .0
        .checked_add(u64::from(descriptor.repair_block_count))
        .ok_or_else(|| invalid("raw repair range overflows"))?;
    if end > storage.descriptor_block(0)?.0
        || end > storage.device.block_count()
        || descriptor.repair_start_block.0 < storage.layout.group_start.0
        || storage.descriptor_block(1)?.0 >= storage.device.block_count()
        || usize::from(descriptor.symbol_size) > storage.block_size_usize()?
    {
        return Err(invalid("raw repair range exceeds device geometry"));
    }
    Ok(records)
}

fn decode_manifest(storage: &RepairGroupStorage<'_>, record: Record) -> Result<Manifest> {
    let (block_size, expected_width, count) = bucket_geometry(storage)?;
    let table_end = TABLE_OFFSET + count * HASH_BYTES;
    if record.bytes.len() != block_size || record.bytes[48..56] != COMMITTED[..] {
        return Err(invalid(
            "raw repair generation has no committed integrity manifest; regenerate from trusted sources",
        ));
    }
    let symbol_count = u32::from_le_bytes(
        record.bytes[56..60]
            .try_into()
            .map_err(|_| invalid("short raw repair symbol count"))?,
    );
    let bucket_width = u32::from_le_bytes(
        record.bytes[60..64]
            .try_into()
            .map_err(|_| invalid("short raw repair bucket width"))?,
    );
    if bucket_width != expected_width
        || symbol_count > storage.layout.repair_block_count
        || record.bytes[64..TABLE_OFFSET] != record_hash(storage, &record.bytes, table_end)
        || record.bytes[table_end..].iter().any(|&byte| byte != 0)
    {
        return Err(invalid(
            "raw repair integrity manifest checksum or geometry mismatch",
        ));
    }
    Ok(Manifest {
        record,
        symbol_count,
        bucket_width,
    })
}

fn committed_manifest(storage: &RepairGroupStorage<'_>, cx: &Cx) -> Result<Manifest> {
    let records = newest_records(storage, cx)?;
    if records[0].descriptor.repair_generation == 0 {
        return Err(invalid("raw repair generation is not committed"));
    }
    let mut selected: Option<Manifest> = None;
    for record in records {
        // A good same-generation copy may survive a torn descriptor write.
        // Never search an older generation after observing a newer descriptor.
        if let Ok(manifest) = decode_manifest(storage, record) {
            if let Some(previous) = &selected
                && previous.record.bytes != manifest.record.bytes
            {
                return Err(invalid(
                    "ambiguous integrity manifests for one repair generation",
                ));
            }
            selected = Some(manifest);
        }
    }
    selected.ok_or_else(|| {
        invalid(
            "raw repair generation is pending or has no valid integrity manifest; regenerate from trusted sources",
        )
    })
}

pub(super) fn is_raw(
    storage: &RepairGroupStorage<'_>,
    descriptor: &RepairGroupDescExt,
) -> Result<bool> {
    Ok(RepairGroupStorage::raw_symbol_mode(
        storage.block_size_usize()?,
        usize::from(descriptor.symbol_size),
    ))
}

/// A metadata-only high-water mark, NOT authority to recover source bytes.
pub(super) fn refresh_descriptor(
    storage: &RepairGroupStorage<'_>,
    cx: &Cx,
) -> Result<RepairGroupDescExt> {
    Ok(newest_records(storage, cx)?.remove(0).descriptor)
}

fn validate_bootstrap(
    storage: &RepairGroupStorage<'_>,
    expected: &RepairGroupDescExt,
) -> Result<()> {
    let layout = storage.layout;
    RepairGroupLayout::new(
        layout.group,
        layout.group_start,
        layout.blocks_per_group,
        layout.validation_block_count,
        layout.repair_block_count,
    )?;
    storage.validate_desc_layout(expected)?;
    let block_size = storage.device.block_size();
    if expected.repair_generation != 0
        || expected.source_block_count == 0
        || u32::from(expected.symbol_size) != block_size
        || expected.transfer_length
            != u64::from(expected.source_block_count) * u64::from(block_size)
        || expected.sub_blocks != 1
        || expected.symbol_alignment != 4
    {
        return Err(invalid("invalid raw bootstrap source geometry"));
    }
    let source_end = layout
        .group_start
        .0
        .checked_add(u64::from(expected.source_block_count))
        .ok_or_else(|| invalid("raw bootstrap source range overflows"))?;
    if layout.group_end_exclusive() > storage.device.block_count()
        || source_end > layout.validation_start_block().0
    {
        return Err(invalid("raw bootstrap exceeds source or device geometry"));
    }
    bucket_geometry(storage)?;
    Ok(())
}

fn pending_record(
    storage: &RepairGroupStorage<'_>,
    descriptor: &RepairGroupDescExt,
    block_size: usize,
) -> Vec<u8> {
    let mut pending = vec![0; block_size];
    pending[..RepairGroupDescExt::SIZE].copy_from_slice(&descriptor.to_bytes());
    pending[48..56].copy_from_slice(PENDING);
    let checksum = record_hash(storage, &pending, TABLE_OFFSET);
    pending[64..TABLE_OFFSET].copy_from_slice(&checksum);
    pending
}

fn strict_record(
    storage: &RepairGroupStorage<'_>,
    expected: &RepairGroupDescExt,
    bytes: Vec<u8>,
) -> Result<Option<(Record, bool)>> {
    if bytes.iter().all(|&byte| byte == 0) {
        return Ok(None);
    }
    let descriptor = RepairGroupDescExt::parse(&bytes)
        .map_err(|_| invalid("unknown or torn raw repair descriptor"))?;
    let mut geometry = descriptor.clone();
    geometry.repair_generation = 0;
    geometry.checksum = 0;
    if geometry.to_bytes() != expected.to_bytes() {
        return Err(invalid(
            "raw repair descriptor differs from expected geometry",
        ));
    }
    if descriptor.repair_generation == 0 {
        let mut bootstrap = vec![0; bytes.len()];
        bootstrap[..RepairGroupDescExt::SIZE].copy_from_slice(&expected.to_bytes());
        if bytes != bootstrap {
            return Err(invalid("noncanonical raw bootstrap descriptor"));
        }
        return Ok(Some((Record { descriptor, bytes }, false)));
    }
    if bytes[48..56] == PENDING[..] {
        if bytes != pending_record(storage, &descriptor, bytes.len()) {
            return Err(invalid("noncanonical raw pending descriptor"));
        }
        return Ok(Some((Record { descriptor, bytes }, false)));
    }
    let manifest = decode_manifest(storage, Record { descriptor, bytes })?;
    Ok(Some((manifest.record, true)))
}

pub(super) fn preflight_refresh(
    storage: &RepairGroupStorage<'_>,
    cx: &Cx,
    expected: &RepairGroupDescExt,
) -> Result<RawRefreshAdmission> {
    checkpoint(cx)?;
    validate_bootstrap(storage, expected)?;
    let mut selected: Option<(Record, bool)> = None;
    for slot in 0..2 {
        checkpoint(cx)?;
        let bytes = storage
            .device
            .read_block(cx, storage.descriptor_block(slot)?)?;
        checkpoint(cx)?;
        if bytes.len() != storage.block_size_usize()? {
            return Err(invalid("short raw repair descriptor block"));
        }
        let Some((record, committed)) = strict_record(storage, expected, bytes.into_inner())?
        else {
            continue;
        };
        if let Some((previous, previous_committed)) = &selected {
            let previous_generation = previous.descriptor.repair_generation;
            let generation = record.descriptor.repair_generation;
            if generation == previous_generation
                && committed
                && *previous_committed
                && record.bytes != previous.bytes
            {
                return Err(invalid(
                    "ambiguous integrity manifests for one repair generation",
                ));
            }
            if generation < previous_generation
                || (generation == previous_generation && *previous_committed)
            {
                continue;
            }
        }
        selected = Some((record, committed));
    }
    checkpoint(cx)?;
    let pristine = selected.is_none();
    let (descriptor, committed) = selected.map_or_else(
        || (expected.clone(), false),
        |(record, committed)| (record.descriptor, committed),
    );
    let next_generation = descriptor
        .repair_generation
        .checked_add(1)
        .ok_or_else(|| invalid("raw repair generation exhausted"))?;
    Ok(RawRefreshAdmission {
        descriptor,
        pristine,
        next_generation,
        committed,
    })
}

/// Preserve the seal when an existing committed descriptor is mirrored again.
/// An arbitrary descriptor-only update never manufactures an integrity seal.
pub(super) fn preserve_manifest(
    storage: &RepairGroupStorage<'_>,
    cx: &Cx,
    descriptor: &RepairGroupDescExt,
    bytes: &mut [u8],
) -> Result<()> {
    if descriptor.repair_generation == 0 || !is_raw(storage, descriptor)? {
        return Ok(());
    }
    let records = newest_records(storage, cx)?;
    for record in records {
        if record.descriptor.to_bytes() == descriptor.to_bytes()
            && let Ok(manifest) = decode_manifest(storage, record)
        {
            bytes.copy_from_slice(&manifest.record.bytes);
            return Ok(());
        }
    }
    Ok(())
}

fn media_error(error: &FfsError) -> bool {
    matches!(error, FfsError::Io(error) if error.kind() == std::io::ErrorKind::UnexpectedEof
        || (cfg!(target_os = "linux") && error.raw_os_error() == Some(5)))
}

pub(super) fn read_generation(
    storage: &RepairGroupStorage<'_>,
    cx: &Cx,
    tolerate_media_errors: bool,
) -> Result<(RepairGroupDescExt, SymbolBatch)> {
    let manifest = committed_manifest(storage, cx)?;
    let descriptor = &manifest.record.descriptor;
    if !is_raw(storage, descriptor)? {
        return Err(invalid(
            "verified raw generation requires full-block parity storage",
        ));
    }
    let block_size = storage.block_size_usize()?;
    let mut symbols = Vec::new();
    let mut first = 0_u32;
    let mut bucket = 0_usize;
    while first < descriptor.repair_block_count {
        checkpoint(cx)?;
        let end = first
            .saturating_add(manifest.bucket_width)
            .min(descriptor.repair_block_count);
        let mut hash = bucket_hasher(storage, descriptor, first);
        let mut captured = Vec::new();
        let mut readable = true;
        for index in first..end {
            checkpoint(cx)?;
            let block = BlockNumber(descriptor.repair_start_block.0 + u64::from(index));
            match storage.device.read_block(cx, block) {
                Ok(bytes) => {
                    if bytes.len() != block_size {
                        return Err(invalid("short raw parity buffer without a media error"));
                    }
                    hash.update(bytes.as_slice());
                    if index < manifest.symbol_count {
                        let esi = u32::from(descriptor.source_block_count)
                            .checked_add(index)
                            .ok_or_else(|| invalid("raw repair ESI overflow"))?;
                        captured.push((
                            esi,
                            bytes.as_slice()[..usize::from(descriptor.symbol_size)].to_vec(),
                        ));
                    }
                }
                Err(error) if tolerate_media_errors && media_error(&error) => readable = false,
                Err(error) => return Err(error),
            }
        }
        let offset = TABLE_OFFSET + bucket * HASH_BYTES;
        if readable
            && hash.finalize().as_bytes()[..] == manifest.record.bytes[offset..offset + HASH_BYTES]
        {
            symbols.append(&mut captured);
        } else {
            tracing::warn!(
                group = storage.layout.group.0,
                generation = descriptor.repair_generation,
                first_slot = first,
                end_slot = end,
                "discarding invalid raw repair checksum bucket"
            );
        }
        first = end;
        bucket += 1;
    }
    checkpoint(cx)?;
    if refresh_descriptor(storage, cx)?.to_bytes() != descriptor.to_bytes() {
        return Err(invalid(
            "repair generation changed while loading verified parity",
        ));
    }
    let current = committed_manifest(storage, cx)?;
    if current.record.bytes != manifest.record.bytes {
        return Err(invalid(
            "repair generation changed while loading verified parity",
        ));
    }
    Ok((manifest.record.descriptor, symbols))
}

pub(super) fn ensure_generation(
    storage: &RepairGroupStorage<'_>,
    cx: &Cx,
    expected: &RepairGroupDescExt,
) -> Result<()> {
    checkpoint(cx)?;
    if refresh_descriptor(storage, cx)?.to_bytes() != expected.to_bytes() {
        return Err(invalid("repair generation changed during recovery"));
    }
    if committed_manifest(storage, cx)?
        .record
        .descriptor
        .to_bytes()
        != expected.to_bytes()
    {
        return Err(invalid("repair generation changed during recovery"));
    }
    checkpoint(cx)
}

pub(super) fn publish(
    storage: &RepairGroupStorage<'_>,
    cx: &Cx,
    symbols: &[(u32, Vec<u8>)],
    generation: u64,
) -> Result<()> {
    checkpoint(cx)?;
    let current = refresh_descriptor(storage, cx)?;
    if generation <= current.repair_generation {
        return Err(invalid(
            "raw repair generation must increase, including after an interrupted refresh",
        ));
    }
    publish_admitted(storage, cx, symbols, current, generation)
}

pub(super) fn initialize(
    storage: &RepairGroupStorage<'_>,
    cx: &Cx,
    expected: &RepairGroupDescExt,
    symbols: &[(u32, Vec<u8>)],
    generation: u64,
) -> Result<()> {
    checkpoint(cx)?;
    if generation == 0 {
        return Err(invalid("raw initialization generation must be positive"));
    }
    let admission = preflight_refresh(storage, cx, expected)?;
    if !admission.pristine {
        return Err(invalid(
            "raw initialization requires two zero descriptor slots",
        ));
    }
    publish_admitted(storage, cx, symbols, admission.descriptor, generation)
}

fn publish_admitted(
    storage: &RepairGroupStorage<'_>,
    cx: &Cx,
    symbols: &[(u32, Vec<u8>)],
    mut descriptor: RepairGroupDescExt,
    generation: u64,
) -> Result<()> {
    descriptor.repair_generation = generation;
    descriptor.checksum = 0;
    storage.validate_desc_layout(&descriptor)?;
    let (block_size, width, count) = bucket_geometry(storage)?;
    let symbol_size = usize::from(descriptor.symbol_size);
    RepairGroupStorage::validate_symbol_input(&descriptor, symbols, symbol_size)?;
    let symbol_count =
        u32::try_from(symbols.len()).map_err(|_| invalid("raw repair symbol count overflows"))?;
    if symbol_count > descriptor.repair_block_count {
        return Err(FfsError::RepairFailed(format!(
            "too many raw symbols for reserved region: symbols={} capacity={}",
            symbols.len(),
            descriptor.repair_block_count
        )));
    }
    if symbol_size > block_size {
        return Err(FfsError::RepairFailed(format!(
            "raw symbol_size {symbol_size} exceeds block_size {block_size}"
        )));
    }
    // Compute the manifest from the supplied bytes, NEVER from a potentially
    // damaged readback that would bless corruption as the intended generation.
    let mut sealed = vec![0; block_size];
    sealed[..RepairGroupDescExt::SIZE].copy_from_slice(&descriptor.to_bytes());
    sealed[48..56].copy_from_slice(COMMITTED);
    sealed[56..60].copy_from_slice(&symbol_count.to_le_bytes());
    sealed[60..64].copy_from_slice(&width.to_le_bytes());
    let mut block = vec![0; block_size];
    let mut first = 0_u32;
    for bucket in 0..count {
        let end = first
            .saturating_add(width)
            .min(descriptor.repair_block_count);
        let mut hash = bucket_hasher(storage, &descriptor, first);
        for index in first..end {
            checkpoint(cx)?;
            block.fill(0);
            if let Some((_, data)) = symbols.get(index as usize) {
                block[..symbol_size].copy_from_slice(data);
            }
            hash.update(&block);
        }
        let offset = TABLE_OFFSET + bucket * HASH_BYTES;
        sealed[offset..offset + HASH_BYTES].copy_from_slice(hash.finalize().as_bytes());
        first = end;
    }
    let checksum = record_hash(storage, &sealed, TABLE_OFFSET + count * HASH_BYTES);
    sealed[64..TABLE_OFFSET].copy_from_slice(&checksum);
    let pending = pending_record(storage, &descriptor, block_size);
    // Invalidation must reach BOTH durable slots before any in-place parity
    // overwrite. No older descriptor can survive this barrier as a fallback.
    for slot in 0..2 {
        checkpoint(cx)?;
        storage
            .device
            .write_block(cx, storage.descriptor_block(slot)?, &pending)?;
    }
    storage.device.sync(cx)?;
    checkpoint(cx)?;
    storage.write_raw_symbols(cx, &descriptor, symbols, block_size, symbol_size)?;
    storage.device.sync(cx)?;
    // Readback failure leaves the durable pending fence in place.
    for index in 0..descriptor.repair_block_count {
        checkpoint(cx)?;
        block.fill(0);
        if let Some((_, data)) = symbols.get(index as usize) {
            block[..symbol_size].copy_from_slice(data);
        }
        let number = BlockNumber(descriptor.repair_start_block.0 + u64::from(index));
        if storage.device.read_block(cx, number)?.as_slice() != block.as_slice() {
            return Err(invalid(
                "raw repair parity readback mismatch before publication",
            ));
        }
    }
    for slot in 0..2 {
        checkpoint(cx)?;
        storage
            .device
            .write_block(cx, storage.descriptor_block(slot)?, &sealed)?;
    }
    storage.device.sync(cx)?;
    checkpoint(cx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::RepairGroupLayout;
    use ffs_block::{BlockBuf, BlockDevice};
    use ffs_types::GroupNumber;
    use std::sync::Mutex;

    struct State {
        live: Vec<Vec<u8>>,
        durable: Vec<Vec<u8>>,
        events: usize,
        fail_at: Option<usize>,
        persist_writes: bool,
    }

    struct Device(Mutex<State>);

    impl Device {
        fn new(block_size: usize) -> Self {
            let blocks = vec![vec![0; block_size]; 64];
            Self(Mutex::new(State {
                live: blocks.clone(),
                durable: blocks,
                events: 0,
                fail_at: None,
                persist_writes: false,
            }))
        }

        fn crash(&self) {
            let mut state = self.0.lock().expect("state");
            let State { live, durable, .. } = &mut *state;
            live.clone_from(durable);
            state.fail_at = None;
        }

        fn corrupt(&self, block: BlockNumber, offset: usize) {
            self.0.lock().expect("state").live[block.0 as usize][offset] ^= 0x80;
        }
    }

    fn event(state: &mut State) -> Result<()> {
        let event = state.events;
        state.events += 1;
        if state.fail_at == Some(event) {
            return Err(std::io::Error::other("injected persistence failure").into());
        }
        Ok(())
    }

    impl BlockDevice for Device {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            checkpoint(cx)?;
            Ok(BlockBuf::new(
                self.0.lock().expect("state").live[block.0 as usize].clone(),
            ))
        }

        fn write_block(&self, cx: &Cx, block: BlockNumber, bytes: &[u8]) -> Result<()> {
            checkpoint(cx)?;
            let mut state = self.0.lock().expect("state");
            event(&mut state)?;
            state.live[block.0 as usize].copy_from_slice(bytes);
            if state.persist_writes {
                state.durable[block.0 as usize].copy_from_slice(bytes);
            }
            Ok(())
        }

        fn block_size(&self) -> u32 {
            self.0.lock().expect("state").live[0].len() as u32
        }

        fn block_count(&self) -> u64 {
            64
        }

        fn sync(&self, cx: &Cx) -> Result<()> {
            checkpoint(cx)?;
            let mut state = self.0.lock().expect("state");
            event(&mut state)?;
            let State { live, durable, .. } = &mut *state;
            durable.clone_from(live);
            Ok(())
        }
    }

    fn fixture(repair_blocks: u32) -> (Device, RepairGroupLayout) {
        let device = Device::new(256);
        let layout = RepairGroupLayout::new(GroupNumber(7), BlockNumber(0), 64, 0, repair_blocks)
            .expect("layout");
        let descriptor = RepairGroupDescExt {
            transfer_length: 8 * 256,
            symbol_size: 256,
            source_block_count: 8,
            sub_blocks: 1,
            symbol_alignment: 4,
            repair_start_block: layout.repair_start_block(),
            repair_block_count: repair_blocks,
            repair_generation: 0,
            checksum: 0,
        };
        RepairGroupStorage::new(&device, layout)
            .write_group_desc_ext(&Cx::for_testing(), &descriptor)
            .expect("bootstrap");
        (device, layout)
    }

    fn symbols(count: u32, salt: u8) -> SymbolBatch {
        (0..count)
            .map(|index| (8 + index, vec![salt.wrapping_add(index as u8); 256]))
            .collect()
    }

    fn pristine_fixture() -> (Device, RepairGroupLayout, RepairGroupDescExt) {
        let device = Device::new(256);
        let layout = RepairGroupLayout::new(GroupNumber(7), BlockNumber(0), 64, 1, 4).unwrap();
        let bootstrap = RepairGroupDescExt {
            transfer_length: 8 * 256,
            symbol_size: 256,
            source_block_count: 8,
            sub_blocks: 1,
            symbol_alignment: 4,
            repair_start_block: layout.repair_start_block(),
            repair_block_count: 4,
            repair_generation: 0,
            checksum: 0,
        };
        (device, layout, bootstrap)
    }

    #[test]
    fn raw_strict_refresh_admits_pristine_bootstrap_and_committed_generation() {
        let cx = Cx::for_testing();
        let (device, layout, bootstrap) = pristine_fixture();
        let storage = RepairGroupStorage::new(&device, layout);
        let empty = storage.preflight_raw_refresh(&cx, &bootstrap).unwrap();
        assert!(empty.pristine);
        assert!(!empty.committed);
        assert_eq!(empty.descriptor.to_bytes(), bootstrap.to_bytes());
        assert_eq!(empty.next_generation, 1);
        assert_eq!(device.0.lock().unwrap().events, 0);

        storage.write_group_desc_ext(&cx, &bootstrap).unwrap();
        let initialized = storage.preflight_raw_refresh(&cx, &bootstrap).unwrap();
        assert!(!initialized.pristine);
        assert!(!initialized.committed);
        assert_eq!(initialized.next_generation, 1);
        let expected = symbols(4, 27);
        storage.write_repair_symbols(&cx, &expected, 7).unwrap();
        let committed = storage.preflight_raw_refresh(&cx, &bootstrap).unwrap();
        assert!(!committed.pristine);
        assert!(committed.committed);
        assert_eq!(committed.descriptor.repair_generation, 7);
        assert_eq!(committed.next_generation, 8);

        let (fresh_device, fresh_layout, fresh_bootstrap) = pristine_fixture();
        let fresh = RepairGroupStorage::new(&fresh_device, fresh_layout);
        fresh
            .initialize_raw_repair_symbols(&cx, &fresh_bootstrap, &expected, 7)
            .unwrap();
        assert_eq!(fresh_device.0.lock().unwrap().events, 11);
        assert_eq!(
            device.0.lock().unwrap().durable,
            fresh_device.0.lock().unwrap().durable,
            "direct initialization must publish the same bytes without a bootstrap write"
        );
        fresh_device.crash();
        let (descriptor, actual) = fresh.read_verified_raw_generation(&cx, false).unwrap();
        assert_eq!(descriptor.repair_generation, 7);
        assert_eq!(actual, expected);
    }

    #[test]
    fn raw_strict_refresh_rejects_unknown_older_and_noncanonical_slots() {
        for case in [
            "torn",
            "older geometry",
            "pending checksum",
            "pending reserved",
            "pending trailing",
            "unknown marker",
            "bootstrap trailing",
            "committed checksum",
        ] {
            let cx = Cx::for_testing();
            let (device, layout, bootstrap) = pristine_fixture();
            let storage = RepairGroupStorage::new(&device, layout);
            storage
                .initialize_raw_repair_symbols(&cx, &bootstrap, &symbols(4, 3), 7)
                .unwrap();
            let mut older = bootstrap.clone();
            older.repair_generation = 3;
            let mut bytes = pending_record(&storage, &older, 256);
            let reason = match case {
                "torn" => {
                    bytes[0] ^= 1;
                    "unknown or torn"
                }
                "older geometry" => {
                    older.source_block_count = 9;
                    older.transfer_length = 9 * 256;
                    bytes = pending_record(&storage, &older, 256);
                    "expected geometry"
                }
                "pending checksum" => {
                    bytes[64] ^= 1;
                    "noncanonical raw pending"
                }
                "pending reserved" => {
                    bytes[56] = 1;
                    let hash = record_hash(&storage, &bytes, TABLE_OFFSET);
                    bytes[64..TABLE_OFFSET].copy_from_slice(&hash);
                    "noncanonical raw pending"
                }
                "pending trailing" => {
                    bytes[TABLE_OFFSET] = 1;
                    "noncanonical raw pending"
                }
                "unknown marker" => {
                    bytes[48] = b'?';
                    "no committed integrity manifest"
                }
                "bootstrap trailing" => {
                    bytes.fill(0);
                    bytes[..RepairGroupDescExt::SIZE].copy_from_slice(&bootstrap.to_bytes());
                    bytes[255] = 1;
                    "noncanonical raw bootstrap"
                }
                "committed checksum" => {
                    bytes = device
                        .read_block(&cx, layout.descriptor_blocks()[0])
                        .unwrap()
                        .into_inner();
                    bytes[TABLE_OFFSET] ^= 1;
                    "manifest checksum or geometry"
                }
                _ => unreachable!(),
            };
            device
                .write_block(&cx, layout.descriptor_blocks()[0], &bytes)
                .unwrap();
            let before = device.0.lock().unwrap().live.clone();
            let events = device.0.lock().unwrap().events;
            let error = storage.preflight_raw_refresh(&cx, &bootstrap).unwrap_err();
            assert!(error.to_string().contains(reason), "{case}: {error}");
            assert_eq!(device.0.lock().unwrap().live, before, "{case}");
            assert_eq!(device.0.lock().unwrap().events, events, "{case}");
            assert_eq!(
                storage
                    .read_refresh_descriptor(&cx)
                    .unwrap()
                    .repair_generation,
                7,
                "existing tolerant high-water behavior stays unchanged: {case}"
            );
        }
    }

    #[test]
    fn raw_strict_refresh_detects_ambiguous_manifests_and_generation_exhaustion() {
        let cx = Cx::for_testing();
        let (device, layout, bootstrap) = pristine_fixture();
        let storage = RepairGroupStorage::new(&device, layout);
        storage
            .initialize_raw_repair_symbols(&cx, &bootstrap, &symbols(4, 3), 7)
            .unwrap();
        let (other_device, other_layout, other_bootstrap) = pristine_fixture();
        RepairGroupStorage::new(&other_device, other_layout)
            .initialize_raw_repair_symbols(&cx, &other_bootstrap, &symbols(4, 99), 7)
            .unwrap();
        let different = other_device
            .read_block(&cx, other_layout.descriptor_blocks()[0])
            .unwrap();
        device
            .write_block(&cx, layout.descriptor_blocks()[0], different.as_slice())
            .unwrap();
        let before = device.0.lock().unwrap().live.clone();
        assert!(
            storage
                .preflight_raw_refresh(&cx, &bootstrap)
                .unwrap_err()
                .to_string()
                .contains("ambiguous integrity manifests")
        );
        assert_eq!(device.0.lock().unwrap().live, before);

        let (last_device, last_layout, last_bootstrap) = pristine_fixture();
        let last = RepairGroupStorage::new(&last_device, last_layout);
        last.initialize_raw_repair_symbols(&cx, &last_bootstrap, &symbols(4, 3), u64::MAX)
            .unwrap();
        let before = last_device.0.lock().unwrap().live.clone();
        assert!(
            last.preflight_raw_refresh(&cx, &last_bootstrap)
                .unwrap_err()
                .to_string()
                .contains("generation exhausted")
        );
        assert_eq!(last_device.0.lock().unwrap().live, before);
    }

    #[test]
    fn raw_strict_initialization_pending_retry_keeps_explicit_high_water() {
        let cx = Cx::for_testing();
        let (device, layout, bootstrap) = pristine_fixture();
        let storage = RepairGroupStorage::new(&device, layout);
        device.0.lock().unwrap().fail_at = Some(0);
        let expected = symbols(4, 19);
        assert!(
            storage
                .initialize_raw_repair_symbols(&cx, &bootstrap, &expected, 9)
                .is_err()
        );
        device.crash();
        assert!(
            storage
                .preflight_raw_refresh(&cx, &bootstrap)
                .unwrap()
                .pristine
        );
        // The caller's ownership record supplies the next generation even if
        // neither zero descriptor was changed by the failed first publication.
        {
            let mut state = device.0.lock().unwrap();
            state.events = 0;
            state.fail_at = Some(3);
        }
        assert!(
            storage
                .initialize_raw_repair_symbols(&cx, &bootstrap, &expected, 10)
                .is_err()
        );
        device.crash();
        let pending = storage.preflight_raw_refresh(&cx, &bootstrap).unwrap();
        assert!(!pending.pristine);
        assert!(!pending.committed);
        assert_eq!(pending.descriptor.repair_generation, 10);
        assert_eq!(pending.next_generation, 11);
        assert!(storage.read_verified_raw_generation(&cx, false).is_err());
        let before = device.0.lock().unwrap().live.clone();
        let events = device.0.lock().unwrap().events;
        assert!(
            storage
                .initialize_raw_repair_symbols(&cx, &bootstrap, &expected, 11)
                .is_err()
        );
        assert!(storage.write_repair_symbols(&cx, &expected, 10).is_err());
        assert_eq!(device.0.lock().unwrap().live, before);
        assert_eq!(device.0.lock().unwrap().events, events);
        storage
            .write_repair_symbols(&cx, &expected, pending.next_generation)
            .unwrap();
        device.crash();
        let (descriptor, actual) = storage.read_verified_raw_generation(&cx, false).unwrap();
        assert_eq!(descriptor.repair_generation, 11);
        assert_eq!(actual, expected);
        assert!(
            storage
                .preflight_raw_refresh(&cx, &bootstrap)
                .unwrap()
                .committed
        );
    }

    #[test]
    fn raw_strict_initialization_refuses_invalid_inputs_before_any_write() {
        let cx = Cx::for_testing();
        let (device, layout, bootstrap) = pristine_fixture();
        let storage = RepairGroupStorage::new(&device, layout);
        let before = device.0.lock().unwrap().live.clone();
        let expected = symbols(4, 3);
        assert!(
            storage
                .initialize_raw_repair_symbols(&cx, &bootstrap, &expected, 0)
                .is_err()
        );
        assert!(
            storage
                .initialize_raw_repair_symbols(&cx, &bootstrap, &symbols(5, 3), 1)
                .is_err()
        );
        let mut short = expected.clone();
        short[3].1.pop();
        assert!(
            storage
                .initialize_raw_repair_symbols(&cx, &bootstrap, &short, 1)
                .is_err()
        );
        let mut wrong_esi = expected.clone();
        wrong_esi[3].0 += 1;
        assert!(
            storage
                .initialize_raw_repair_symbols(&cx, &bootstrap, &wrong_esi, 1)
                .is_err()
        );
        for case in [
            "generation",
            "transfer",
            "symbol",
            "source",
            "sub-blocks",
            "alignment",
        ] {
            let mut bad = bootstrap.clone();
            match case {
                "generation" => bad.repair_generation = 1,
                "transfer" => bad.transfer_length += 1,
                "symbol" => bad.symbol_size -= 1,
                "source" => {
                    bad.source_block_count = 63;
                    bad.transfer_length = 63 * 256;
                }
                "sub-blocks" => bad.sub_blocks = 2,
                "alignment" => bad.symbol_alignment = 8,
                _ => unreachable!(),
            }
            assert!(
                storage
                    .initialize_raw_repair_symbols(&cx, &bad, &expected, 1)
                    .is_err(),
                "{case}"
            );
        }
        let beyond_device =
            RepairGroupLayout::new(GroupNumber(7), BlockNumber(0), 65, 1, 4).unwrap();
        let mut bad = bootstrap.clone();
        bad.repair_start_block = beyond_device.repair_start_block();
        assert!(
            RepairGroupStorage::new(&device, beyond_device)
                .initialize_raw_repair_symbols(&cx, &bad, &expected, 1)
                .is_err()
        );
        cx.set_cancel_requested(true);
        assert!(matches!(
            storage.initialize_raw_repair_symbols(&cx, &bootstrap, &expected, 1),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(device.0.lock().unwrap().live, before);
        assert_eq!(device.0.lock().unwrap().events, 0);
    }

    #[test]
    fn raw_strict_refresh_accepts_only_canonical_interrupted_publication_states() {
        for fail_at in [1, 9] {
            let cx = Cx::for_testing();
            let (device, layout, bootstrap) = pristine_fixture();
            let storage = RepairGroupStorage::new(&device, layout);
            {
                let mut state = device.0.lock().unwrap();
                state.persist_writes = true;
                state.fail_at = Some(fail_at);
            }
            let expected = symbols(4, 51);
            assert!(
                storage
                    .initialize_raw_repair_symbols(&cx, &bootstrap, &expected, 23)
                    .is_err()
            );
            device.crash();
            let admission = storage.preflight_raw_refresh(&cx, &bootstrap).unwrap();
            assert!(!admission.pristine);
            assert_eq!(admission.descriptor.repair_generation, 23);
            assert_eq!(admission.next_generation, 24);
            assert_eq!(admission.committed, fail_at == 9);
            // Cut 1 leaves one canonical pending slot and one zero slot. Cut 9
            // leaves one committed copy and one pending copy of the same generation.
            if fail_at == 1 {
                assert!(storage.read_verified_raw_generation(&cx, false).is_err());
            } else {
                assert_eq!(
                    storage.read_verified_raw_generation(&cx, false).unwrap().1,
                    expected
                );
            }
            let mut state = device.0.lock().unwrap();
            state.live.swap(62, 63);
            drop(state);
            assert_eq!(
                storage.preflight_raw_refresh(&cx, &bootstrap).unwrap(),
                admission,
                "slot ordering must not change the admitted generation"
            );
        }
    }

    struct DescriptorReadFault<'a> {
        device: &'a Device,
        block: BlockNumber,
        short: bool,
    }

    impl BlockDevice for DescriptorReadFault<'_> {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            if block == self.block {
                if self.short {
                    return Ok(BlockBuf::zeroed(255));
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "planted descriptor read refusal",
                )
                .into());
            }
            self.device.read_block(cx, block)
        }

        fn write_block(&self, cx: &Cx, block: BlockNumber, bytes: &[u8]) -> Result<()> {
            self.device.write_block(cx, block, bytes)
        }

        fn block_size(&self) -> u32 {
            self.device.block_size()
        }

        fn block_count(&self) -> u64 {
            self.device.block_count()
        }

        fn sync(&self, cx: &Cx) -> Result<()> {
            self.device.sync(cx)
        }
    }

    #[test]
    fn raw_strict_refresh_never_treats_unreadable_or_short_slots_as_zero() {
        let cx = Cx::for_testing();
        let (device, layout, bootstrap) = pristine_fixture();
        let before = device.0.lock().unwrap().live.clone();
        for short in [false, true] {
            let fault = DescriptorReadFault {
                device: &device,
                block: layout.descriptor_blocks()[1],
                short,
            };
            let storage = RepairGroupStorage::new(&fault, layout);
            for error in [
                storage.preflight_raw_refresh(&cx, &bootstrap).unwrap_err(),
                storage
                    .initialize_raw_repair_symbols(&cx, &bootstrap, &symbols(4, 3), 1)
                    .unwrap_err(),
            ] {
                if short {
                    assert!(error.to_string().contains("short raw repair descriptor"));
                } else {
                    assert!(
                        matches!(error, FfsError::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied)
                    );
                }
            }
        }
        assert_eq!(device.0.lock().unwrap().live, before);
        assert_eq!(device.0.lock().unwrap().events, 0);
    }

    #[test]
    fn raw_integrity_keeps_zero_symbols_and_excludes_unused_slots() {
        let cx = Cx::for_testing();
        let (device, layout) = fixture(4);
        let storage = RepairGroupStorage::new(&device, layout);
        let expected = symbols(2, 0);
        storage
            .write_repair_symbols(&cx, &expected, 1)
            .expect("publish");
        device.crash();
        assert_eq!(storage.read_repair_symbols(&cx).expect("read"), expected);
    }

    #[test]
    fn raw_integrity_discards_bitflips_without_renumbering_survivors() {
        let cx = Cx::for_testing();
        let (device, layout) = fixture(4);
        let storage = RepairGroupStorage::new(&device, layout);
        let expected = symbols(4, 3);
        storage
            .write_repair_symbols(&cx, &expected, 1)
            .expect("publish");
        device.corrupt(BlockNumber(layout.repair_start_block().0 + 1), 17);
        assert_eq!(
            storage.read_repair_symbols(&cx).expect("degraded"),
            vec![
                expected[0].clone(),
                expected[2].clone(),
                expected[3].clone()
            ]
        );
    }

    #[test]
    fn raw_integrity_scales_bucket_width_without_consuming_extra_blocks() {
        let cx = Cx::for_testing();
        let (device, layout) = fixture(12);
        let storage = RepairGroupStorage::new(&device, layout);
        let expected = symbols(12, 11);
        storage
            .write_repair_symbols(&cx, &expected, 1)
            .expect("publish");
        let source_end = layout.repair_start_block().0 as usize;
        let before = device.0.lock().expect("state").live[..source_end].to_vec();
        device.corrupt(layout.repair_start_block(), 9);
        assert_eq!(
            storage.read_repair_symbols(&cx).expect("degraded"),
            expected[3..]
        );
        assert_eq!(device.0.lock().expect("state").live[..source_end], before);
    }

    #[test]
    fn raw_integrity_never_authorizes_a_mixed_generation_at_any_write_or_sync_cut() {
        for persist_writes in [false, true] {
            // Two pending writes + sync + four parity writes + sync + two
            // committed writes + sync. Fault every mutation and every barrier.
            for fail_at in 0..=11 {
                let cx = Cx::for_testing();
                let (device, layout) = fixture(4);
                let storage = RepairGroupStorage::new(&device, layout);
                let old = symbols(4, 3);
                let new = symbols(4, 91);
                storage
                    .write_repair_symbols(&cx, &old, 1)
                    .expect("generation 1");
                {
                    let mut state = device.0.lock().expect("state");
                    state.events = 0;
                    state.fail_at = Some(fail_at);
                    state.persist_writes = persist_writes;
                }
                let result = storage.write_repair_symbols(&cx, &new, 2);
                assert_eq!(result.is_ok(), fail_at == 11);
                device.crash();
                if let Ok((descriptor, recovered)) = read_generation(&storage, &cx, false) {
                    match descriptor.repair_generation {
                        1 => assert_eq!(recovered, old),
                        2 => assert_eq!(recovered, new),
                        other => panic!("unexpected generation {other}"),
                    }
                } else {
                    assert!(
                        fail_at >= 1,
                        "failure before the first write must preserve generation 1"
                    );
                }
            }
        }
    }

    #[test]
    fn raw_integrity_pending_fence_survives_one_lost_descriptor_and_can_be_refreshed() {
        let cx = Cx::for_testing();
        let (device, layout) = fixture(4);
        let storage = RepairGroupStorage::new(&device, layout);
        storage
            .write_repair_symbols(&cx, &symbols(4, 3), 1)
            .expect("generation 1");
        {
            let mut state = device.0.lock().expect("state");
            state.events = 0;
            state.fail_at = Some(4);
        }
        assert!(
            storage
                .write_repair_symbols(&cx, &symbols(4, 91), 2)
                .is_err()
        );
        device.crash();
        device.corrupt(layout.descriptor_blocks()[0], 0);
        assert!(storage.read_group_desc_ext(&cx).is_err());
        assert!(storage.read_repair_symbols(&cx).is_err());
        assert_eq!(
            storage
                .read_refresh_descriptor(&cx)
                .expect("high-water mark")
                .repair_generation,
            2
        );
        let expected = symbols(4, 120);
        storage
            .write_repair_symbols(&cx, &expected, 3)
            .expect("explicit trusted regeneration");
        assert_eq!(
            storage.read_repair_symbols(&cx).expect("generation 3"),
            expected
        );
    }

    #[test]
    fn raw_integrity_mirroring_descriptor_preserves_seal() {
        let cx = Cx::for_testing();
        let (device, layout) = fixture(4);
        let storage = RepairGroupStorage::new(&device, layout);
        let expected = symbols(4, 3);
        storage
            .write_repair_symbols(&cx, &expected, 1)
            .expect("publish");
        let descriptor = storage.read_group_desc_ext(&cx).expect("descriptor");
        storage
            .write_group_desc_ext(&cx, &descriptor)
            .expect("mirror");
        assert_eq!(storage.read_repair_symbols(&cx).expect("read"), expected);
    }

    #[test]
    fn raw_integrity_rejects_unsealed_legacy_and_damaged_manifest_copies() {
        let cx = Cx::for_testing();
        let (device, layout) = fixture(4);
        let storage = RepairGroupStorage::new(&device, layout);
        let mut descriptor = storage.read_group_desc_ext(&cx).expect("bootstrap");
        descriptor.repair_generation = 1;
        storage
            .write_group_desc_ext(&cx, &descriptor)
            .expect("unsealed legacy record");
        assert!(storage.read_repair_symbols(&cx).is_err());
        storage
            .write_repair_symbols(&cx, &symbols(4, 3), 2)
            .expect("trusted regeneration");
        device.corrupt(layout.descriptor_blocks()[0], 100);
        assert!(
            storage.read_repair_symbols(&cx).is_ok(),
            "second sealed copy survives"
        );
        device.corrupt(layout.descriptor_blocks()[1], 100);
        assert!(storage.read_repair_symbols(&cx).is_err());
    }

    #[test]
    fn raw_integrity_invalid_input_and_cancellation_do_not_invalidate_good_parity() {
        let cx = Cx::for_testing();
        let (device, layout) = fixture(4);
        let storage = RepairGroupStorage::new(&device, layout);
        let expected = symbols(4, 3);
        storage
            .write_repair_symbols(&cx, &expected, 1)
            .expect("publish");
        let before = device.0.lock().expect("state").live.clone();
        assert!(
            storage
                .write_repair_symbols(&cx, &symbols(5, 8), 2)
                .is_err()
        );
        let mut malformed = symbols(4, 8);
        malformed[3].1.pop();
        assert!(storage.write_repair_symbols(&cx, &malformed, 2).is_err());
        cx.set_cancel_requested(true);
        assert!(matches!(
            storage.write_repair_symbols(&cx, &expected, 2),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(device.0.lock().expect("state").live, before);
    }
}
