//! Exact native security metadata through validated file and $Secure catalogs.
//! No SID mapping, access decision, descriptor repair or backing mutation.

use super::attributes::{AttributeSet, read_list, resolve_catalog};
use super::{
    Cx, DATA, NtfsFileRecord, NtfsGeometry, NtfsReference, NtfsValue, NtfsVolume, Result, Storage,
    Stream, checkpoint, corrupt, data_read_admission, parse, standard_flags, unsupported,
};
use ffs_ondisk::ntfs_security::{
    MAX_SECURITY_DESCRIPTOR_BYTES, NtfsSecurityDescriptor, NtfsSecurityHeader,
    NtfsSecurityIndexEntry, NtfsSecurityIndexKind, NtfsSecurityIndexRoot, SDS_COPY_DISTANCE,
    parse_security_index_block_with_kind,
};
use std::collections::{BTreeMap, BTreeSet};

const SII: &[u16] = &[36, 83, 73, 73];
const SDH: &[u16] = &[36, 83, 68, 72];
const SDS: &[u16] = &[36, 83, 68, 83];
const MAX_INDEX_BLOCKS: usize = 16_384;
const MAX_INDEX_KEYS: usize = 65_536;
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;

/// Bounds for a complete $Secure audit, not permission to certify a prefix.
#[derive(Debug, Clone, Copy)]
pub struct SecurityCheckLimits {
    /// Maximum entries in each of the two native indexes.
    pub entries: usize,
    /// Total FILE, attribute-list, index, bitmap and paired-descriptor bytes.
    /// Resident metadata counts as work too. Charged before the corresponding read.
    pub metadata_bytes: u64,
}

impl Default for SecurityCheckLimits {
    fn default() -> Self {
        Self {
            entries: MAX_INDEX_KEYS,
            metadata_bytes: 512 * 1024 * 1024,
        }
    }
}

impl SecurityCheckLimits {
    pub fn validate(self) -> Result<()> {
        if !(1..=MAX_INDEX_KEYS).contains(&self.entries)
            || !(1..=(1_u64 << 40)).contains(&self.metadata_bytes)
        {
            return Err(super::FfsError::Format(
                "security checking requires 1..=65536 entries and 1..=1099511627776 metadata bytes"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Returned only after both entire indexes and every indexed SDS pair validate.
/// This does not check unindexed SDS bytes or the security references of files,
/// evaluate access, repair descriptors, or grant writable admission.
#[derive(Debug)]
pub struct SecurityCheckReport {
    pub secure_reference: NtfsReference,
    pub security_ids: usize,
    pub hash_entries: usize,
    pub index_blocks: usize,
    pub descriptor_bytes: u64,
    pub metadata_bytes: u64,
}

struct SecurityBudget {
    limits: SecurityCheckLimits,
    used: u64,
}

impl SecurityBudget {
    fn charge(&mut self, bytes: u64) -> Result<()> {
        if bytes > self.limits.metadata_bytes - self.used {
            return Err(unsupported(
                "security checking exceeds its metadata-work budget",
            ));
        }
        self.used += bytes;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SecurityDescriptorInfo {
    pub source: &'static str,
    pub security_id: Option<u32>,
    /// Exact extended STANDARD_INFORMATION field, including explicit zero.
    /// None denotes the legacy 48-byte form without that native field.
    pub standard_security_id: Option<u32>,
    pub legacy_attribute_present: bool,
    /// Native $Secure record identity and generation when the shared path wins.
    pub secure_reference: Option<NtfsReference>,
    pub hash: Option<u32>,
    pub sds_offset: Option<u64>,
    /// The descriptor alone, without the SDS header or allocation padding.
    pub bytes: Vec<u8>,
    pub descriptor: NtfsSecurityDescriptor,
}

impl NtfsVolume {
    /// Read this file's own security metadata, even when its DATA requires a
    /// separate reparse or encryption provider. Numeric identity never follows
    /// a link and security inspection never grants file-content access.
    pub fn security_descriptor(
        &self,
        cx: &Cx,
        record: &NtfsFileRecord,
    ) -> Result<SecurityDescriptorInfo> {
        checkpoint(cx)?;
        let catalog = self.attributes(cx, record)?;
        let attributes = catalog.all()?;
        if standard_flags(&attributes)?.is_none() {
            return Err(corrupt(
                0,
                "NTFS file has no STANDARD_INFORMATION security identity",
            ));
        }
        let standard = catalog.select(&self.geometry, 0x10, &[])?;
        let value = self.read(cx, &standard, 0, 72)?;
        let standard_security_id = if value.len() == 72 {
            Some(u32::from_le_bytes(
                value[52..56]
                    .try_into()
                    .map_err(|_| corrupt(0, "short NTFS security ID"))?,
            ))
        } else {
            None
        };
        let legacy_attribute_present = attributes.iter().any(|attribute| attribute.kind == 0x50);
        if let Some(security_id) = standard_security_id.filter(|id| *id != 0) {
            return self.shared_security_descriptor(cx, security_id, legacy_attribute_present);
        }

        // NTFS permits the legacy attribute on upgraded/repaired files,
        // including a 72-byte STANDARD_INFORMATION with security ID zero.
        for attribute in &attributes {
            if attribute.kind == 0x50 && (attribute.flags != 0 || !attribute.name.is_empty()) {
                return Err(corrupt(
                    0,
                    "named or transformed SECURITY_DESCRIPTOR attribute",
                ));
            }
        }
        let stream = catalog.select(&self.geometry, 0x50, &[])?;
        if !(20..=MAX_SECURITY_DESCRIPTOR_BYTES as u64).contains(&stream.size) {
            return Err(unsupported(
                "NTFS legacy security descriptor exceeds the read profile",
            ));
        }
        metadata_range(&self.geometry, &stream, 0, stream.size)?;
        let bytes = self.read(cx, &stream, 0, stream.size as usize)?;
        let descriptor = NtfsSecurityDescriptor::parse(&bytes).map_err(|error| parse(&error))?;
        checkpoint(cx)?;
        Ok(SecurityDescriptorInfo {
            source: "security_descriptor_attribute",
            security_id: None,
            standard_security_id,
            legacy_attribute_present,
            secure_reference: None,
            hash: None,
            sds_offset: None,
            bytes,
            descriptor,
        })
    }

    fn shared_security_descriptor(
        &self,
        cx: &Cx,
        security_id: u32,
        legacy_attribute_present: bool,
    ) -> Result<SecurityDescriptorInfo> {
        let secure = self.record(cx, 9, None)?;
        if secure.is_directory() {
            return Err(corrupt(0, "NTFS $Secure is a directory"));
        }
        let catalog = self.attributes(cx, &secure)?;
        let attributes = catalog.all()?;
        data_read_admission(&secure, &attributes)?;
        let stream = self.security_sds(&catalog)?;
        let mut budget = SecurityBudget {
            limits: SecurityCheckLimits::default(),
            used: 0,
        };
        let mut found = None;
        self.security_index(
            cx,
            &catalog,
            NtfsSecurityIndexKind::SecurityId,
            &mut budget,
            |header| {
                if header.security_id == security_id && found.replace(header).is_some() {
                    return Err(corrupt(0, "duplicate $SII security ID"));
                }
                Ok(())
            },
        )?;
        let header = found.ok_or_else(|| corrupt(0, "file security ID is missing from $SII"))?;
        let (bytes, descriptor) = self.security_pair(cx, &stream, header, &mut budget)?;
        Ok(SecurityDescriptorInfo {
            source: "secure_sds",
            security_id: Some(security_id),
            standard_security_id: Some(security_id),
            legacy_attribute_present,
            secure_reference: Some(NtfsReference {
                record: 9,
                sequence: secure.sequence,
            }),
            hash: Some(header.hash),
            sds_offset: Some(header.offset),
            bytes,
            descriptor,
        })
    }

    /// Audit both native $Secure indexes once, reconcile every complete header,
    /// and validate every referenced primary/duplicate SDS descriptor pair.
    /// Any corruption, unsupported metadata, I/O error, cancellation or exhausted
    /// budget fails the entire call; no partial scan is returned as consistent.
    pub fn check_security(
        &self,
        cx: &Cx,
        limits: SecurityCheckLimits,
    ) -> Result<SecurityCheckReport> {
        checkpoint(cx)?;
        limits.validate()?;
        if self.volume_flags != 0
            || self.logfile_recovery.is_some()
            || !self.source.overlay.is_empty()
        {
            return Err(unsupported(
                "security checking requires original clean-flag bytes without a recovery overlay",
            ));
        }
        let mut budget = SecurityBudget { limits, used: 0 };
        budget.charge(u64::from(self.geometry.record_bytes()))?;
        let secure = self.record(cx, 9, None)?;
        if secure.is_directory() {
            return Err(corrupt(0, "NTFS $Secure is a directory"));
        }
        let catalog = security_catalog(self, cx, &secure, &mut budget)?;
        data_read_admission(&secure, &catalog.all()?)?;
        let stream = self.security_sds(&catalog)?;
        let mut headers = BTreeMap::new();
        let (security_ids, sii_blocks) = self.security_index(
            cx,
            &catalog,
            NtfsSecurityIndexKind::SecurityId,
            &mut budget,
            |header| {
                if headers.insert(header.security_id, header).is_some() {
                    return Err(corrupt(0, "duplicate $SII security ID"));
                }
                Ok(())
            },
        )?;
        let mut hashed = BTreeSet::new();
        let (hash_entries, sdh_blocks) = self.security_index(
            cx,
            &catalog,
            NtfsSecurityIndexKind::SecurityHash,
            &mut budget,
            |header| {
                if headers.get(&header.security_id) != Some(&header)
                    || !hashed.insert(header.security_id)
                {
                    return Err(corrupt(
                        0,
                        "$SDH entry disagrees with $SII or repeats an ID",
                    ));
                }
                Ok(())
            },
        )?;
        if hashed.len() != headers.len() {
            return Err(corrupt(0, "$SII security ID is missing from $SDH"));
        }
        // Index order is not SDS-offset order. Check all physical descriptor
        // extents before reading any payload; two IDs cannot own overlapping
        // bytes, even if one carefully crafted header could parse inside another.
        let mut ordered: Vec<_> = headers.values().copied().collect();
        ordered.sort_unstable_by_key(|header| header.offset);
        let mut end = 0;
        for header in &ordered {
            checkpoint(cx)?;
            if header.offset < end {
                return Err(corrupt(header.offset, "indexed SDS descriptors overlap"));
            }
            end = header.offset + u64::from(header.length);
        }
        let mut descriptor_bytes = 0;
        for header in ordered {
            let (bytes, _) = self.security_pair(cx, &stream, header, &mut budget)?;
            descriptor_bytes += bytes.len() as u64;
        }
        checkpoint(cx)?;
        Ok(SecurityCheckReport {
            secure_reference: NtfsReference {
                record: 9,
                sequence: secure.sequence,
            },
            security_ids,
            hash_entries,
            index_blocks: sii_blocks + sdh_blocks,
            descriptor_bytes,
            metadata_bytes: budget.used,
        })
    }

    fn security_sds(&self, catalog: &AttributeSet<'_>) -> Result<Stream> {
        // Sparse gaps are legal, but each indexed descriptor must have physical
        // initialized storage. Compression/encryption is never metadata here.
        if catalog.all()?.iter().any(|attribute| {
            attribute.kind == DATA && attribute.name == SDS && attribute.flags & !super::SPARSE != 0
        }) {
            return Err(unsupported(
                "transformed NTFS security metadata is not admitted",
            ));
        }
        let stream = catalog.select(&self.geometry, DATA, SDS)?;
        if stream.resident() {
            return Err(corrupt(0, "$Secure:$SDS must be nonresident"));
        }
        Ok(stream)
    }

    fn security_pair(
        &self,
        cx: &Cx,
        stream: &Stream,
        header: NtfsSecurityHeader,
        budget: &mut SecurityBudget,
    ) -> Result<(Vec<u8>, NtfsSecurityDescriptor)> {
        checkpoint(cx)?;
        let length = u64::from(header.length);
        let duplicate = header.offset + SDS_COPY_DISTANCE;
        // Parsed headers guarantee addition bounds. Validate and charge both
        // copies before either read, including ranges crossing mapped runs.
        metadata_range(&self.geometry, stream, header.offset, length)?;
        metadata_range(&self.geometry, stream, duplicate, length)?;
        budget.charge(2 * length)?;
        let primary = self.read(cx, stream, header.offset, header.length as usize)?;
        let copy = self.read(cx, stream, duplicate, header.length as usize)?;
        if primary != copy {
            return Err(corrupt(header.offset, "SDS primary and duplicate disagree"));
        }
        let bytes = header
            .descriptor(&primary)
            .map_err(|error| parse(&error))?
            .to_vec();
        let descriptor = NtfsSecurityDescriptor::parse(&bytes).map_err(|error| parse(&error))?;
        checkpoint(cx)?;
        Ok((bytes, descriptor))
    }

    fn security_index(
        &self,
        cx: &Cx,
        catalog: &AttributeSet<'_>,
        kind: NtfsSecurityIndexKind,
        budget: &mut SecurityBudget,
        visit: impl FnMut(NtfsSecurityHeader) -> Result<()>,
    ) -> Result<(usize, usize)> {
        let name = match kind {
            NtfsSecurityIndexKind::SecurityId => SII,
            NtfsSecurityIndexKind::SecurityHash => SDH,
        };
        let attributes = catalog.all()?;
        for attribute in &attributes {
            let index = matches!(attribute.kind, 0x90 | 0xA0 | 0xB0) && attribute.name == name;
            if index && attribute.flags != 0 {
                return Err(unsupported(
                    "transformed NTFS security index is not admitted",
                ));
            }
        }
        let root = catalog.select(&self.geometry, 0x90, name)?;
        if !root.resident() {
            return Err(corrupt(0, "security INDEX_ROOT is nonresident"));
        }
        if root.size > 65_536 {
            return Err(unsupported("security INDEX_ROOT exceeds 65536 bytes"));
        }
        budget.charge(root.size)?;
        let bytes = self.read(cx, &root, 0, root.size as usize)?;
        let root =
            NtfsSecurityIndexRoot::parse_with_kind(&bytes, self.geometry.cluster_bytes(), kind)
                .map_err(|error| parse(&error))?;
        if root.block_bytes != self.geometry.index_bytes() {
            return Err(unsupported(
                "security index geometry differs from the boot profile",
            ));
        }
        let external = root.entries.iter().any(|entry| entry.child_vcn.is_some())
            || attributes
                .iter()
                .any(|attribute| matches!(attribute.kind, 0xA0 | 0xB0) && attribute.name == name);
        let (allocation, bitmap) = if external {
            let allocation = catalog.select(&self.geometry, 0xA0, name)?;
            let bitmap = catalog.select(&self.geometry, 0xB0, name)?;
            if allocation.resident()
                || allocation.initialized != allocation.size
                || !allocation.size.is_multiple_of(u64::from(root.block_bytes))
                || allocation.size / u64::from(root.block_bytes) > MAX_INDEX_BLOCKS as u64
                || bitmap.size > MAX_INDEX_BLOCKS.div_ceil(8) as u64
            {
                return Err(unsupported(
                    "security index allocation or bitmap exceeds the read profile",
                ));
            }
            if bitmap.size * 8 < allocation.size / u64::from(root.block_bytes) {
                return Err(corrupt(
                    0,
                    "security index bitmap does not cover its allocation blocks",
                ));
            }
            metadata_range(&self.geometry, &allocation, 0, allocation.size)?;
            metadata_range(&self.geometry, &bitmap, 0, bitmap.size)?;
            budget.charge(bitmap.size)?;
            let bitmap = self.read(cx, &bitmap, 0, bitmap.size as usize)?;
            (Some(allocation), bitmap)
        } else {
            (None, Vec::new())
        };
        let mut walker = SecurityWalker {
            volume: self,
            cx,
            kind,
            budget,
            block_bytes: root.block_bytes,
            vcn_bytes: root.vcn_bytes,
            allocation,
            bitmap,
            visited: BTreeSet::new(),
            keys: 0,
            bytes_read: 0,
        };
        walker.visit(root.entries, visit)?;
        for (index, &byte) in walker.bitmap.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) != 0 && !walker.visited.contains(&(index as u64 * 8 + bit)) {
                    return Err(corrupt(
                        0,
                        "security index bitmap has an unreachable allocated block",
                    ));
                }
            }
        }
        Ok((walker.keys, walker.visited.len()))
    }
}

fn security_catalog<'a>(
    volume: &NtfsVolume,
    cx: &Cx,
    base: &'a NtfsFileRecord,
    budget: &mut SecurityBudget,
) -> Result<AttributeSet<'a>> {
    for attribute in base.attributes().map_err(|error| parse(&error))? {
        if attribute.kind == super::ATTRIBUTE_LIST {
            let length = match attribute.value {
                NtfsValue::Resident(value) => value.len() as u64,
                NtfsValue::NonResident(value) => value.data_bytes,
            };
            budget.charge(length)?;
        }
    }
    let list = read_list(&volume.source, &volume.geometry, cx, base)?;
    resolve_catalog(cx, &volume.geometry, base, list.as_deref(), |reference| {
        budget.charge(u64::from(volume.geometry.record_bytes()))?;
        volume.record(cx, reference.record, Some(reference.sequence))
    })
}

/// Security metadata never acquires apparently valid zeroes from VDL tails,
/// missing mappings or a sparse hole. Unrelated sparse SDS gaps remain legal.
fn metadata_range(
    geometry: &NtfsGeometry,
    stream: &Stream,
    offset: u64,
    length: u64,
) -> Result<()> {
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= stream.size && *end <= stream.initialized)
        .ok_or_else(|| corrupt(offset, "security metadata range is not initialized"))?;
    match &stream.storage {
        Storage::Compressed(_) | Storage::Wof(_) => {
            return Err(unsupported("compressed security metadata is not admitted"));
        }
        Storage::Mapped(runs) if length != 0 => {
            let cluster = u64::from(geometry.cluster_bytes());
            let first_vcn = offset / cluster;
            let end_vcn = end.div_ceil(cluster);
            let first = runs
                .partition_point(|run| run.vcn <= first_vcn)
                .saturating_sub(1);
            if runs[first..]
                .iter()
                .take_while(|run| run.vcn < end_vcn)
                .any(|run| run.lcn.is_none())
            {
                return Err(corrupt(
                    offset,
                    "security metadata range contains a sparse hole",
                ));
            }
        }
        Storage::Resident(_) | Storage::Mapped(_) => {}
    }
    Ok(())
}

struct SecurityWalker<'a> {
    volume: &'a NtfsVolume,
    cx: &'a Cx,
    kind: NtfsSecurityIndexKind,
    budget: &'a mut SecurityBudget,
    block_bytes: u32,
    vcn_bytes: u32,
    allocation: Option<Stream>,
    bitmap: Vec<u8>,
    visited: BTreeSet<u64>,
    keys: usize,
    bytes_read: u64,
}

struct SecurityFrame {
    entries: std::vec::IntoIter<NtfsSecurityIndexEntry>,
    depth: usize,
    lower: Option<(u32, u32)>,
    upper: Option<(u32, u32)>,
}

impl SecurityWalker<'_> {
    fn visit(
        &mut self,
        entries: Vec<NtfsSecurityIndexEntry>,
        mut visit: impl FnMut(NtfsSecurityHeader) -> Result<()>,
    ) -> Result<()> {
        let mut stack = vec![SecurityFrame {
            entries: entries.into_iter(),
            depth: 0,
            lower: None,
            upper: None,
        }];
        // Keep only the current path's frames; sibling blocks are read when
        // visited, not prefetched into an attacker-sized queue or call stack.
        while let Some(frame) = stack.last_mut() {
            checkpoint(self.cx)?;
            let Some(entry) = frame.entries.next() else {
                stack.pop();
                continue;
            };
            let previous = frame.lower;
            let next = entry.header.map(|header| self.kind.key(header));
            if let Some(id) = next {
                self.keys += 1;
                if self.keys > self.budget.limits.entries {
                    return Err(unsupported("security index exceeds its entry budget"));
                }
                if previous.is_some_and(|bound| id <= bound)
                    || frame.upper.is_some_and(|bound| id >= bound)
                {
                    return Err(corrupt(0, "security index key violates its parent bounds"));
                }
            }
            if let Some(header) = entry.header {
                visit(header)?;
                frame.lower = next;
            }
            if let Some(vcn) = entry.child_vcn {
                let depth = frame.depth + 1;
                let upper = next.or(frame.upper);
                if depth > 32 {
                    return Err(unsupported("security index exceeds 32 child levels"));
                }
                let child = self.child(vcn)?;
                stack.push(SecurityFrame {
                    entries: child.into_iter(),
                    depth,
                    lower: previous,
                    upper,
                });
            }
        }
        checkpoint(self.cx)
    }

    fn child(&mut self, vcn: u64) -> Result<Vec<NtfsSecurityIndexEntry>> {
        checkpoint(self.cx)?;
        let offset = vcn
            .checked_mul(u64::from(self.vcn_bytes))
            .ok_or_else(|| corrupt(0, "security index child offset overflow"))?;
        if !offset.is_multiple_of(u64::from(self.block_bytes)) {
            return Err(corrupt(
                offset,
                "security index child is not index-block aligned",
            ));
        }
        let number = offset / u64::from(self.block_bytes);
        let byte = usize::try_from(number / 8)
            .ok()
            .and_then(|index| self.bitmap.get(index))
            .copied()
            .unwrap_or(0);
        if byte & (1 << (number % 8)) == 0
            || !self.visited.insert(number)
            || self.visited.len() > MAX_INDEX_BLOCKS
        {
            return Err(corrupt(
                offset,
                "security index child is free, repeated or over budget",
            ));
        }
        self.bytes_read += u64::from(self.block_bytes);
        if self.bytes_read > MAX_INDEX_BYTES {
            return Err(unsupported("security index traversal exceeds 64 MiB"));
        }
        let stream = self
            .allocation
            .as_ref()
            .ok_or_else(|| corrupt(offset, "security index child has no INDEX_ALLOCATION"))?;
        metadata_range(
            &self.volume.geometry,
            stream,
            offset,
            u64::from(self.block_bytes),
        )?;
        self.budget.charge(u64::from(self.block_bytes))?;
        let raw = self
            .volume
            .read(self.cx, stream, offset, self.block_bytes as usize)?;
        parse_security_index_block_with_kind(&raw, vcn, self.kind).map_err(|error| parse(&error))
    }
}
