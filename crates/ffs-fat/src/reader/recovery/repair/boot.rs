//! Explicit FAT32 primary/backup boot-sector restoration. No boot-copy guessing.
//! A private read-only projection admits the selected interpretation for full
//! structural preflight. The actual repair always leaves native dirty state;
//! clearing it and reclaiming lost allocation require a separate recovery call.

use super::{
    DiagnosticVolume, FatCheckReport, FatKind, FatVolume, ImageArgs, MAX_CHAIN_CLUSTERS, allocate,
    checkpoint, hex_digest, long_names::Names, write_patch,
};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_ondisk::fat::FatGeometry;
use ffs_types::ByteOffset;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const WINDOW: usize = 64 * 1024;
const MAX_FAT_BYTES: u64 = 128 * 1024 * 1024;

struct Shared(Arc<dyn ByteDevice>);

impl ByteDevice for Shared {
    fn len_bytes(&self) -> u64 {
        self.0.len_bytes()
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        self.0.read_exact_at(cx, at, bytes)
    }
    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        self.0.write_all_at(cx, at, bytes)
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.0.sync(cx)
    }
}

/// Substitution is confined to the two already range-checked boot sectors.
/// Reserved FAT state, FSInfo, allocation, and namespace bytes are never masked.
struct View {
    device: Arc<dyn ByteDevice>,
    starts: [u64; 2],
    source: Arc<[u8]>,
}

impl ByteDevice for View {
    fn len_bytes(&self) -> u64 {
        self.device.len_bytes()
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let end =
            at.0.checked_add(bytes.len() as u64)
                .filter(|&end| end <= self.len_bytes())
                .ok_or_else(|| FfsError::Format("boot projection exceeds backing".into()))?;
        self.device.read_exact_at(cx, at, bytes)?;
        for &start in &self.starts {
            let stop = start
                .checked_add(self.source.len() as u64)
                .ok_or_else(|| FfsError::Format("boot projection overflow".into()))?;
            let begin = start.max(at.0);
            let stop = stop.min(end);
            if begin < stop {
                bytes[(begin - at.0) as usize..(stop - at.0) as usize].copy_from_slice(
                    &self.source[(begin - start) as usize..(stop - start) as usize],
                );
            }
        }
        checkpoint(cx)
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
    fn sync(&self, _: &Cx) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
}

struct Header {
    offset: u64,
    original: Vec<u8>,
}

impl Header {
    fn dirty(&self) -> Vec<u8> {
        let mut bytes = self.original.clone();
        // FAT32 FAT[1].ClnShutBitMask only. Keep I/O-error bits and high nibble.
        bytes[7] &= !0x08;
        bytes
    }
}

struct Evidence {
    offset: u64,
    length: usize,
    fat_header: bool,
    digest: [u8; 32],
}

fn digest(bytes: &[u8], fat_header: bool) -> [u8; 32] {
    let mut hash = Sha256::new();
    if fat_header {
        hash.update(&bytes[..7]);
        hash.update([bytes[7] & !0x08]);
        hash.update(&bytes[8..]);
    } else {
        hash.update(bytes);
    }
    hash.finalize().into()
}

fn admissible(report: &FatCheckReport) -> Result<()> {
    if !report.complete
        || !report.namespace_complete
        || report.omitted_issues != 0
        || report.lost_clusters.is_none()
    {
        bail!("boot repair needs complete, untruncated allocation/namespace evidence");
    }
    for issue in &report.issues {
        if !matches!(
            issue.kind,
            "native_boot_dirty"
                | "native_fat_dirty"
                | "lost_allocation"
                | "fs_info_free_count"
                | "fs_info_next_free"
        ) {
            bail!(
                "selected boot interpretation is not repair authority: {}: {}",
                issue.kind,
                issue.detail
            );
        }
    }
    Ok(())
}

fn same_structure(a: &FatCheckReport, b: &FatCheckReport) -> bool {
    a.scanned_clusters == b.scanned_clusters
        && a.free_clusters == b.free_clusters
        && a.allocated_clusters == b.allocated_clusters
        && a.bad_clusters == b.bad_clusters
        && a.reserved_clusters == b.reserved_clusters
        && a.conflicting_clusters == b.conflicting_clusters
        && a.referenced_clusters == b.referenced_clusters
        && a.preallocated_clusters == b.preallocated_clusters
        && a.files == b.files
        && a.directories == b.directories
        && a.lost_clusters == b.lost_clusters
}

pub(super) struct BootPlan<'a> {
    // Private raw view uses geometry already admitted through the projection.
    // It never escapes recovery as an ordinarily admitted mount capability.
    volume: FatVolume,
    device: Arc<dyn ByteDevice>,
    args: &'a ImageArgs,
    source_at: u64,
    target_at: u64,
    source: Vec<u8>,
    target: Vec<u8>,
    target_parseable: bool,
    before: FatCheckReport,
    names: Names,
    headers: Vec<Header>,
    evidence: Vec<Evidence>,
}

impl<'a> BootPlan<'a> {
    pub(super) fn prepare(
        cx: &Cx,
        device: Box<dyn ByteDevice>,
        args: &'a ImageArgs,
        source_at: u64,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let length = args
            .length
            .unwrap_or_else(|| device.len_bytes().saturating_sub(args.offset));
        let end = args
            .offset
            .checked_add(length)
            .context("selected boot volume range overflow")?;
        if length < 512
            || end > device.len_bytes()
            || source_at.checked_add(512).is_none_or(|stop| stop > length)
        {
            bail!("boot source is outside the explicitly selected volume");
        }
        let physical = args
            .offset
            .checked_add(source_at)
            .context("boot source offset overflow")?;
        let mut first = [0; 512];
        device.read_exact_at(cx, ByteOffset(physical), &mut first)?;
        let geometry = FatGeometry::parse(&first, length)
            .map_err(|error| anyhow::anyhow!("selected boot sector is invalid: {error}"))?;
        if geometry.kind() != FatKind::Fat32 {
            bail!("native backup boot-sector repair is FAT32-only");
        }
        if geometry.cluster_count() as usize > MAX_CHAIN_CLUSTERS {
            bail!("selected boot geometry exceeds the structural-check budget");
        }
        let size = geometry.sector_bytes() as usize;
        let backup = u64::from(
            geometry
                .backup_boot_sector()
                .context("selected BPB has no backup boot sector")?,
        ) * size as u64;
        if backup == 0
            || (source_at != 0 && source_at != backup)
            || backup
                .checked_add(size as u64)
                .is_none_or(|stop| stop > geometry.volume_bytes())
        {
            bail!("explicit boot source does not match its own BPB backup location");
        }
        let target_at = if source_at == 0 { backup } else { 0 };
        let mut source = allocate(size)?;
        let mut target = allocate(size)?;
        device.read_exact_at(cx, ByteOffset(physical), &mut source)?;
        if source[..512] != first {
            bail!("boot source changed while selecting geometry");
        }
        device.read_exact_at(cx, ByteOffset(args.offset + target_at), &mut target)?;
        if &target[3..11] == b"NTFS    " || &target[3..11] == b"EXFAT   " {
            bail!("boot destination identifies a different filesystem; refusing conversion");
        }
        // Neither a copy choice nor a damaged signature authorizes erasing a
        // recorded surface-test request or unsupported boot state.
        if source[65] & !1 != 0 || target[65] & !1 != 0 {
            bail!("boot repair refuses surface-test or unknown state flags in either copy");
        }
        let target_geometry = FatGeometry::parse(&target, length);
        let target_parseable = target_geometry.is_ok();
        if let Ok(other) = target_geometry
            && (other != geometry
                || target[21] != source[21]
                || target[28..32] != source[28..32]
                || target[67..71] != source[67..71])
        {
            bail!(
                "two parseable boot copies disagree on geometry or volume identity; refusing relocation or source guessing"
            );
        }
        let device: Arc<dyn ByteDevice> = Arc::from(device);
        let projected = DiagnosticVolume::from_device(
            cx,
            Box::new(View {
                device: Arc::clone(&device),
                starts: [args.offset, args.offset + backup],
                source: Arc::from(source.clone()),
            }),
            args,
        )?;
        let before = projected.report(cx)?;
        admissible(&before)?;
        let names = Names::capture(cx, &projected.volume)?;
        let volume = FatVolume {
            device: Box::new(Shared(Arc::clone(&device))),
            base: args.offset,
            geometry,
            oem_code_page: args.oem_code_page,
        };
        let mut plan = Self {
            volume,
            device,
            args,
            source_at,
            target_at,
            source,
            target,
            target_parseable,
            before,
            names,
            headers: Vec::new(),
            evidence: Vec::new(),
        };
        plan.capture(cx)?;
        // Anchor the structural walk to the captured table windows, not just
        // to an earlier successful walk that preceded evidence collection.
        let checked = projected.report(cx)?;
        admissible(&checked)?;
        if !same_structure(&plan.before, &checked) {
            bail!("selected structure changed during boot-repair preflight");
        }
        plan.validate(cx)?;
        Ok(plan)
    }

    fn capture(&mut self, cx: &Cx) -> Result<()> {
        let size = self.volume.geometry.sector_bytes() as usize;
        let fat_bytes =
            u64::from(u32::from_le_bytes(self.source[36..40].try_into()?)) * size as u64;
        if fat_bytes
            .checked_mul(self.volume.copies().len() as u64)
            .is_none_or(|total| total > MAX_FAT_BYTES)
        {
            bail!("boot repair exceeds the 128 MiB allocation-evidence budget");
        }
        let mut ranges = Vec::new();
        for copy in self.volume.copies() {
            let start = self
                .volume
                .geometry
                .entry_offset(copy, 2)
                .map_err(|error| anyhow::anyhow!("invalid selected FAT: {error}"))?
                - 8;
            let mut original = allocate(size)?;
            self.volume.read_exact(cx, start, &mut original)?;
            self.headers.push(Header {
                offset: start,
                original,
            });
            ranges.push((start, fat_bytes, true));
        }
        if let Some(info) = self.volume.geometry.fs_info_sector() {
            ranges.push((u64::from(info) * size as u64, size as u64, false));
        }
        let windows = ranges
            .iter()
            .map(|(_, length, _)| length.div_ceil(WINDOW as u64) as usize)
            .sum();
        self.evidence
            .try_reserve_exact(windows)
            .context("reserving bounded boot-repair evidence")?;
        let mut bytes = allocate(WINDOW)?;
        for (start, length, fat) in ranges {
            let mut done = 0;
            while done < length {
                checkpoint(cx)?;
                let count = (length - done).min(WINDOW as u64) as usize;
                self.volume
                    .read_exact(cx, start + done, &mut bytes[..count])?;
                self.evidence.push(Evidence {
                    offset: start + done,
                    length: count,
                    fat_header: fat && done == 0,
                    digest: digest(&bytes[..count], fat && done == 0),
                });
                done += count as u64;
            }
        }
        Ok(())
    }

    fn verify_evidence(&self, cx: &Cx) -> Result<()> {
        let mut bytes = allocate(WINDOW)?;
        for evidence in &self.evidence {
            checkpoint(cx)?;
            self.volume
                .read_exact(cx, evidence.offset, &mut bytes[..evidence.length])?;
            if digest(&bytes[..evidence.length], evidence.fat_header) != evidence.digest {
                bail!(
                    "allocation or FSInfo changed during boot recovery at {}",
                    evidence.offset
                );
            }
        }
        // Boot repair retains the namespace even when no orphan names exist.
        // The orphan-retirement validator intentionally skips that case.
        if Names::capture(cx, &self.volume)? != self.names {
            bail!("native namespace changed during boot recovery");
        }
        Ok(())
    }

    fn expect(&self, cx: &Cx, offset: u64, expected: &[u8]) -> Result<()> {
        let mut actual = allocate(expected.len())?;
        self.volume.read_exact(cx, offset, &mut actual)?;
        if actual != expected {
            bail!("boot-repair sector changed or failed readback at {offset}");
        }
        Ok(())
    }

    fn validate(&self, cx: &Cx) -> Result<()> {
        self.expect(cx, self.source_at, &self.source)?;
        self.expect(cx, self.target_at, &self.target)?;
        for header in &self.headers {
            self.expect(cx, header.offset, &header.original)?;
        }
        self.verify_evidence(cx)
    }

    fn unchanged(&self) -> bool {
        self.source[..65] == self.target[..65]
            && self.source[65] & !1 == self.target[65] & !1
            && self.source[66..] == self.target[66..]
    }

    pub(super) fn report(&self, dry_run: bool) -> serde_json::Value {
        serde_json::json!({
            "operation": "repair_native_boot_sector", "dry_run": dry_run,
            "changed": !dry_run && !self.unchanged(), "format": "Fat32",
            "volume_offset": self.args.offset, "volume_bytes": self.volume.geometry.volume_bytes(),
            "source_byte_offset": self.source_at, "destination_byte_offset": self.target_at,
            "sector_bytes": self.source.len(), "original_destination_parseable": self.target_parseable,
            "source_sha256": hex_digest(&Sha256::digest(&self.source).into()),
            "original_destination_sha256": hex_digest(&Sha256::digest(&self.target).into()),
            "selected_interpretation": self.before,
            "file_contents_verified": false, "clean_state_published": false,
            "requires_recovery": !self.unchanged() || !self.before.clean || self.target[65] & 1 != 0,
            "contract": "explicit first-logical-boot-sector restoration only; not a bootloader, FSInfo, partition-table, namespace or payload repair; changed images remain dirty"
        })
    }

    pub(super) fn execute(&self, cx: &Cx) -> Result<serde_json::Value> {
        checkpoint(cx)?;
        self.validate(cx)?;
        if self.unchanged() {
            return Ok(self.report(false));
        }
        let mut dirty_source = self.source.clone();
        dirty_source[65] |= 1;
        let mut phase = "synchronizing native allocation dirty markers";
        let result = (|| -> Result<serde_json::Value> {
            for header in &self.headers {
                write_patch(
                    cx,
                    &self.volume,
                    header.offset,
                    &header.original,
                    &header.dirty(),
                )?;
            }
            self.volume.device.sync(cx)?;
            for header in &self.headers {
                self.expect(cx, header.offset, &header.dirty())?;
            }
            self.verify_evidence(cx)?;

            phase = "synchronizing the retained boot source as dirty";
            write_patch(
                cx,
                &self.volume,
                self.source_at,
                &self.source,
                &dirty_source,
            )?;
            self.volume.device.sync(cx)?;
            self.expect(cx, self.source_at, &dirty_source)?;

            phase = "restoring the destination boot sector";
            write_patch(
                cx,
                &self.volume,
                self.target_at,
                &self.target,
                &dirty_source,
            )?;
            self.volume.device.sync(cx)?;
            self.expect(cx, self.source_at, &dirty_source)?;
            self.expect(cx, self.target_at, &dirty_source)?;
            for header in &self.headers {
                self.expect(cx, header.offset, &header.dirty())?;
            }
            self.verify_evidence(cx)?;

            phase = "verifying native diagnosis without a boot projection";
            let actual = DiagnosticVolume::from_device(
                cx,
                Box::new(Shared(Arc::clone(&self.device))),
                self.args,
            )?;
            let after = actual.report(cx)?;
            admissible(&after)?;
            if actual.volume.geometry != self.volume.geometry
                || !same_structure(&self.before, &after)
                || after.clean
                || !after
                    .issues
                    .iter()
                    .any(|issue| issue.kind == "native_boot_dirty")
                || !after
                    .issues
                    .iter()
                    .any(|issue| issue.kind == "native_fat_dirty")
            {
                bail!("restored boot changed native ownership or did not retain dirty state");
            }
            self.expect(cx, self.source_at, &dirty_source)?;
            self.expect(cx, self.target_at, &dirty_source)?;
            for header in &self.headers {
                self.expect(cx, header.offset, &header.dirty())?;
            }
            self.verify_evidence(cx)?;
            let mut report = self.report(false);
            report["verification"] = serde_json::to_value(after)?;
            report["durability"] = "boot_sectors_and_native_dirty_markers_synced".into();
            checkpoint(cx)?;
            Ok(report)
        })();
        result.with_context(|| format!(
            "FAT32 boot repair failed while {phase}; image retained and may be dirty or partially changed; no rollback or atomicity is claimed"
        ))
    }
}

companion_bin_tests! {
#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::fat::FatOemCodePage;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct Sparse {
        pages: Arc<Mutex<BTreeMap<u64, [u8; 512]>>>,
        length: u64,
        mutations: Arc<Mutex<usize>>,
    }

    impl Sparse {
        fn new(length: u64) -> Self {
            Self { pages: Arc::new(Mutex::new(BTreeMap::new())), length,
                mutations: Arc::new(Mutex::new(0)) }
        }
        fn put(&self, mut at: u64, mut bytes: &[u8]) {
            let mut pages = self.pages.lock().unwrap();
            while !bytes.is_empty() {
                let within = (at % 512) as usize;
                let count = bytes.len().min(512 - within);
                pages.entry(at / 512).or_insert([0; 512])[within..within + count]
                    .copy_from_slice(&bytes[..count]);
                at += count as u64;
                bytes = &bytes[count..];
            }
        }
        fn read(&self, at: u64, count: usize) -> Vec<u8> {
            let mut bytes = vec![0; count];
            self.read_exact_at(&Cx::for_testing(), ByteOffset(at), &mut bytes).unwrap();
            bytes
        }
    }

    impl ByteDevice for Sparse {
        fn len_bytes(&self) -> u64 { self.length }
        fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
            checkpoint(cx)?;
            if at.0.checked_add(bytes.len() as u64).is_none_or(|end| end > self.length) {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            let pages = self.pages.lock().unwrap();
            for (index, byte) in bytes.iter_mut().enumerate() {
                let at = at.0 + index as u64;
                *byte = pages.get(&(at / 512)).map_or(0, |page| page[(at % 512) as usize]);
            }
            Ok(())
        }
        fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
            checkpoint(cx)?;
            assert!(at.0 + bytes.len() as u64 <= self.length);
            *self.mutations.lock().unwrap() += 1;
            self.put(at.0, bytes);
            Ok(())
        }
        fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
            checkpoint(cx)?;
            *self.mutations.lock().unwrap() += 1;
            Ok(())
        }
    }

    #[test]
    fn boot_projection_is_range_exact_read_only_and_cancellation_aware() {
        let cx = Cx::for_testing();
        let device = Sparse::new(16384);
        let original: Vec<u8> = (0_u32..16384).map(|at| (at % 251) as u8).collect();
        device.put(0, &original);
        let source: Vec<u8> = (0_u32..512).map(|at| (at % 127 + 17) as u8).collect();
        let view = View { device: Arc::new(device.clone()), starts: [2048, 8192], source: Arc::from(source.clone()) };
        let mut expected = original.clone();
        expected[2048..2560].copy_from_slice(&source);
        expected[8192..8704].copy_from_slice(&source);
        for start in [0, 2047, 2048, 2049, 2559, 2560, 8191, 8192, 8703, 8704, 16384] {
            for stop in [2048, 2560, 8192, 8704, 16384].into_iter().filter(|stop| *stop >= start) {
                let mut bytes = vec![0xFF; stop - start];
                view.read_exact_at(&cx, ByteOffset(start as u64), &mut bytes).unwrap();
                assert_eq!(bytes, expected[start..stop]);
            }
        }
        assert_eq!(device.read(0, 16384), original);
        assert!(matches!(view.write_all_at(&cx, ByteOffset(2048), b"x"), Err(FfsError::ReadOnly)));
        assert!(matches!(view.sync(&cx), Err(FfsError::ReadOnly)));
        let mut bytes = [0x5A; 2];
        assert!(view.read_exact_at(&cx, ByteOffset(u64::MAX), &mut bytes).is_err());
        assert_eq!(bytes, [0x5A; 2]);
        cx.set_cancel_requested(true);
        assert!(matches!(view.read_exact_at(&cx, ByteOffset(2048), &mut bytes), Err(FfsError::Cancelled)));
        assert_eq!(*device.mutations.lock().unwrap(), 0);
    }

    #[test]
    fn evidence_normalizes_only_the_fat32_clean_bit() {
        let mut original = vec![0xA7; 4096];
        original[7] |= 8;
        let expected = digest(&original, true);
        for at in 0..original.len() {
            for bit in [1, 4, 8, 16, 128] {
                let mut changed = original.clone();
                changed[at] ^= bit;
                assert_eq!(digest(&changed, true) == expected, at == 7 && bit == 8);
                assert_ne!(digest(&changed, false), digest(&original, false));
            }
        }
    }

    #[test]
    fn four_kib_logical_boot_restoration_preserves_native_payload_and_partition_guards() {
        let cx = Cx::for_testing();
        let size = 4096_u64;
        let count = 70_000_u32;
        let fat_sectors = ((u64::from(count) + 2) * 4).div_ceil(size) as u32;
        let total = 32 + 2 * fat_sectors + count;
        let length = u64::from(total) * size;
        let base = 8192;
        let device = Sparse::new(base + length + 4096);
        let mut boot = vec![0; size as usize];
        boot[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"MSWIN4.1");
        boot[11..13].copy_from_slice(&4096_u16.to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&32_u16.to_le_bytes());
        boot[16] = 2;
        boot[21] = 0xF8;
        boot[32..36].copy_from_slice(&total.to_le_bytes());
        boot[36..40].copy_from_slice(&fat_sectors.to_le_bytes());
        boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
        boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
        boot[66] = 0x29;
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510..512].copy_from_slice(&[0x55, 0xAA]);
        boot[512..].fill(0xD7); // restore the WHOLE selected logical sector
        let geometry = FatGeometry::parse(&boot, length).unwrap();
        device.put(base + 6 * size, &boot);
        device.put(base, &boot);
        device.put(base + 11, &[0, 0]);
        device.put(base + 510, &[0, 0]);
        let mut info = [0; 512];
        info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
        info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
        info[488..496].fill(0xFF);
        info[508..512].copy_from_slice(&0xAA55_0000_u32.to_le_bytes());
        device.put(base + size, &info);
        for copy in 0..2 {
            let start = base + geometry.entry_offset(copy, 2).unwrap() - 8;
            for (index, low) in [0x0FFF_FFF8, 0x0FFF_FFFF, 0x0FFF_FFFF, 0x0FFF_FFFF].into_iter().enumerate() {
                let value = low | ((10 + u32::from(copy)) << 28);
                device.put(start + index as u64 * 4, &value.to_le_bytes());
            }
        }
        let mut entry = [0; 32];
        entry[..11].copy_from_slice(b"KEEP    BIN");
        entry[11] = 0x20;
        entry[26..28].copy_from_slice(&3_u16.to_le_bytes());
        entry[28..32].copy_from_slice(&4_u32.to_le_bytes());
        device.put(base + geometry.cluster_offset(2).unwrap(), &entry);
        device.put(base + geometry.cluster_offset(3).unwrap(), b"SAFE");
        device.put(0, &[0xA6; 512]);
        device.put(base + length, &[0x6A; 512]);
        let args = ImageArgs { image: "constructed-4k.fat".into(), offset: base, length: Some(length),
            oem_code_page: FatOemCodePage::Ascii, sidecar: None };
        let plan = BootPlan::prepare(&cx, Box::new(device.clone()), &args, 6 * size).unwrap();
        assert_eq!(*device.mutations.lock().unwrap(), 0);
        assert_eq!(plan.execute(&cx).unwrap()["verification"]["files"], 1);
        boot[65] |= 1;
        assert_eq!(device.read(base, size as usize), boot);
        assert_eq!(device.read(base + 6 * size, size as usize), boot);
        assert_eq!(device.read(base + geometry.cluster_offset(3).unwrap(), 4), b"SAFE");
        assert_eq!(device.read(0, 512), [0xA6; 512]);
        assert_eq!(device.read(base + length, 512), [0x6A; 512]);
        for copy in 0..2 {
            let at = base + geometry.entry_offset(copy, 2).unwrap() - 4;
            let expected = ((10 + u32::from(copy)) << 28) | 0x07FF_FFFF;
            assert_eq!(device.read(at, 4), expected.to_le_bytes());
        }
    }
}
}
