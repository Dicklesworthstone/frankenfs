//! Exact native security metadata through validated file and $Secure catalogs.
//! No SID mapping, access decision, descriptor repair or backing mutation.

use super::{
    Cx, DATA, NtfsFileRecord, NtfsGeometry, NtfsValue, NtfsVolume, Result, Storage, Stream,
    checkpoint, corrupt, data_read_admission, parse, standard_flags, unsupported,
};
use ffs_ondisk::ntfs_security::{
    MAX_SECURITY_DESCRIPTOR_BYTES, NtfsSecurityDescriptor, NtfsSecurityHeader,
    NtfsSecurityIndexEntry, NtfsSecurityIndexRoot, SDS_COPY_DISTANCE,
    parse_security_index_block,
};
use std::collections::BTreeSet;

const SII: &[u16] = &[36, 83, 73, 73];
const SDS: &[u16] = &[36, 83, 68, 83];
const MAX_INDEX_BLOCKS: usize = 16_384;
const MAX_INDEX_KEYS: usize = 65_536;
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct SecurityDescriptorInfo {
    pub source: &'static str,
    pub security_id: Option<u32>,
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
            return Err(corrupt(0, "NTFS file has no STANDARD_INFORMATION security identity"));
        }
        let standard = catalog.select(&self.geometry, 0x10, &[])?;
        let value = self.read(cx, &standard, 0, 72)?;
        let security_id = if value.len() == 72 {
            u32::from_le_bytes(
                value[52..56]
                    .try_into()
                    .map_err(|_| corrupt(0, "short NTFS security ID"))?,
            )
        } else {
            0
        };
        if security_id != 0 {
            return self.shared_security_descriptor(cx, security_id);
        }

        // NTFS permits the legacy attribute on upgraded/repaired files,
        // including a 72-byte STANDARD_INFORMATION with security ID zero.
        for attribute in &attributes {
            if attribute.kind == 0x50
                && (attribute.flags != 0 || !attribute.name.is_empty())
            {
                return Err(corrupt(0, "named or transformed SECURITY_DESCRIPTOR attribute"));
            }
        }
        let stream = catalog.select(&self.geometry, 0x50, &[])?;
        if !(20..=MAX_SECURITY_DESCRIPTOR_BYTES as u64).contains(&stream.size) {
            return Err(unsupported("NTFS legacy security descriptor exceeds the read profile"));
        }
        metadata_range(&self.geometry, &stream, 0, stream.size)?;
        let bytes = self.read(cx, &stream, 0, stream.size as usize)?;
        let descriptor = NtfsSecurityDescriptor::parse(&bytes).map_err(|error| parse(&error))?;
        checkpoint(cx)?;
        Ok(SecurityDescriptorInfo {
            source: "security_descriptor_attribute",
            security_id: None,
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
    ) -> Result<SecurityDescriptorInfo> {
        let secure = self.record(cx, 9, None)?;
        if secure.is_directory() {
            return Err(corrupt(0, "NTFS $Secure is a directory"));
        }
        let catalog = self.attributes(cx, &secure)?;
        let attributes = catalog.all()?;
        data_read_admission(&secure, &attributes)?;
        // Sparse SDS gaps are legal; descriptor ranges themselves must have
        // physical initialized storage. INDEX_ROOT/ALLOCATION/BITMAP do not
        // admit transformed values in this read profile.
        for attribute in &attributes {
            let index = matches!(attribute.kind, 0x90 | 0xA0 | 0xB0)
                && attribute.name == SII;
            let sds = attribute.kind == DATA && attribute.name == SDS;
            if (index && attribute.flags != 0)
                || (sds && attribute.flags & !super::SPARSE != 0)
            {
                return Err(unsupported("transformed NTFS security metadata is not admitted"));
            }
            if index && attribute.kind == 0x90
                && !matches!(attribute.value, NtfsValue::Resident(_))
            {
                return Err(corrupt(0, "$SII INDEX_ROOT is nonresident"));
            }
        }
        let root = catalog.select(&self.geometry, 0x90, SII)?;
        if !root.resident() {
            return Err(corrupt(0, "$SII INDEX_ROOT is nonresident"));
        }
        let bytes = self.read(cx, &root, 0, 65_536)?;
        let root = NtfsSecurityIndexRoot::parse(&bytes, self.geometry.cluster_bytes())
            .map_err(|error| parse(&error))?;
        if root.block_bytes != self.geometry.index_bytes() {
            return Err(unsupported("$SII index geometry differs from the boot profile"));
        }
        let external = root.entries.iter().any(|entry| entry.child_vcn.is_some())
            || attributes.iter().any(|attribute| {
                matches!(attribute.kind, 0xA0 | 0xB0) && attribute.name == SII
            });
        let (allocation, bitmap) = if external {
            let allocation = catalog.select(&self.geometry, 0xA0, SII)?;
            let bitmap = catalog.select(&self.geometry, 0xB0, SII)?;
            if allocation.resident()
                || allocation.initialized != allocation.size
                || !allocation.size.is_multiple_of(u64::from(root.block_bytes))
                || allocation.size / u64::from(root.block_bytes) > MAX_INDEX_BLOCKS as u64
                || bitmap.size > MAX_INDEX_BLOCKS.div_ceil(8) as u64
            {
                return Err(unsupported("$SII allocation or bitmap exceeds the read profile"));
            }
            metadata_range(&self.geometry, &allocation, 0, allocation.size)?;
            metadata_range(&self.geometry, &bitmap, 0, bitmap.size)?;
            let bitmap = self.read(cx, &bitmap, 0, bitmap.size as usize)?;
            (Some(allocation), bitmap)
        } else {
            (None, Vec::new())
        };
        let mut walker = SecurityWalker {
            volume: self,
            cx,
            block_bytes: root.block_bytes,
            vcn_bytes: root.vcn_bytes,
            allocation,
            bitmap,
            visited: BTreeSet::new(),
            keys: 0,
            bytes_read: 0,
            wanted: security_id,
            found: None,
        };
        walker.visit(root.entries)?;
        for (index, &byte) in walker.bitmap.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) != 0
                    && !walker.visited.contains(&(index as u64 * 8 + bit))
                {
                    return Err(corrupt(0, "$SII bitmap has an unreachable allocated block"));
                }
            }
        }
        let header = walker
            .found
            .ok_or_else(|| corrupt(0, "file security ID is missing from $SII"))?;
        let stream = catalog.select(&self.geometry, DATA, SDS)?;
        if stream.resident() {
            return Err(corrupt(0, "$Secure:$SDS must be nonresident"));
        }
        let length = u64::from(header.length);
        let duplicate = header
            .offset
            .checked_add(SDS_COPY_DISTANCE)
            .ok_or_else(|| corrupt(0, "SDS duplicate offset overflow"))?;
        // Validate both ranges before issuing either payload read.
        metadata_range(&self.geometry, &stream, header.offset, length)?;
        metadata_range(&self.geometry, &stream, duplicate, length)?;
        let primary = self.read(cx, &stream, header.offset, header.length as usize)?;
        let copy = self.read(cx, &stream, duplicate, header.length as usize)?;
        if primary != copy {
            return Err(corrupt(header.offset, "SDS primary and duplicate disagree"));
        }
        let bytes = header
            .descriptor(&primary)
            .map_err(|error| parse(&error))?
            .to_vec();
        let descriptor = NtfsSecurityDescriptor::parse(&bytes).map_err(|error| parse(&error))?;
        checkpoint(cx)?;
        Ok(SecurityDescriptorInfo {
            source: "secure_sds",
            security_id: Some(security_id),
            hash: Some(header.hash),
            sds_offset: Some(header.offset),
            bytes,
            descriptor,
        })
    }
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
        Storage::Compressed(_) => {
            return Err(unsupported("compressed security metadata is not admitted"));
        }
        Storage::Resident(_) => {}
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
                return Err(corrupt(offset, "security metadata range contains a sparse hole"));
            }
        }
        Storage::Mapped(_) => {}
    }
    Ok(())
}

struct SecurityWalker<'a> {
    volume: &'a NtfsVolume,
    cx: &'a Cx,
    block_bytes: u32,
    vcn_bytes: u32,
    allocation: Option<Stream>,
    bitmap: Vec<u8>,
    visited: BTreeSet<u64>,
    keys: usize,
    bytes_read: u64,
    wanted: u32,
    found: Option<NtfsSecurityHeader>,
}

struct SecurityFrame {
    entries: std::vec::IntoIter<NtfsSecurityIndexEntry>,
    depth: usize,
    lower: Option<u32>,
    upper: Option<u32>,
}

impl SecurityWalker<'_> {
    fn visit(&mut self, entries: Vec<NtfsSecurityIndexEntry>) -> Result<()> {
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
            let next = entry.header.map(|header| header.security_id);
            if let Some(id) = next {
                self.keys += 1;
                if self.keys > MAX_INDEX_KEYS {
                    return Err(unsupported("$SII index exceeds 65,536 keys"));
                }
                if previous.is_some_and(|bound| id <= bound)
                    || frame.upper.is_some_and(|bound| id >= bound)
                {
                    return Err(corrupt(0, "$SII key violates its parent bounds"));
                }
            }
            if let Some(header) = entry.header {
                if header.security_id == self.wanted {
                    if self.found.is_some() {
                        return Err(corrupt(0, "duplicate $SII security ID"));
                    }
                    self.found = Some(header);
                }
                frame.lower = Some(header.security_id);
            }
            if let Some(vcn) = entry.child_vcn {
                let depth = frame.depth + 1;
                let upper = next.or(frame.upper);
                if depth > 32 {
                    return Err(unsupported("$SII index exceeds 32 child levels"));
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
            .ok_or_else(|| corrupt(0, "$SII child offset overflow"))?;
        if !offset.is_multiple_of(u64::from(self.block_bytes)) {
            return Err(corrupt(offset, "$SII child is not index-block aligned"));
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
            return Err(corrupt(offset, "$SII child is free, repeated or over budget"));
        }
        self.bytes_read += u64::from(self.block_bytes);
        if self.bytes_read > MAX_INDEX_BYTES {
            return Err(unsupported("$SII traversal exceeds 64 MiB"));
        }
        let stream = self
            .allocation
            .as_ref()
            .ok_or_else(|| corrupt(offset, "$SII child has no INDEX_ALLOCATION"))?;
        metadata_range(
            &self.volume.geometry,
            stream,
            offset,
            u64::from(self.block_bytes),
        )?;
        let raw = self
            .volume
            .read(self.cx, stream, offset, self.block_bytes as usize)?;
        parse_security_index_block(&raw, vcn).map_err(|error| parse(&error))
    }
}
