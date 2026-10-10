//! Complete attribute catalogs and nonresident extent assembly.
//!
//! The catalog is validated in both directions before any stream is published:
//! list entries must identify exact attributes, and loaded attributes must all
//! be represented in the list. Extension records never redirect to a new base.

use super::compression::CompressedStorage;
use super::{
    ATTRIBUTE_LIST, COMPRESSED, Cx, DATA, FfsError, NtfsAttribute, NtfsFileRecord, NtfsGeometry,
    NtfsReference, NtfsValue, NtfsVolume, Result, SPARSE, Source, Storage, Stream, checkpoint,
    corrupt, decode_mapping_pairs, parse, unsupported, validate_identity,
};
use ffs_ondisk::ntfs::attribute_list::{
    MAX_LIST_BYTES, NtfsAttributeListEntry, parse_attribute_list,
};
use std::collections::BTreeMap;

const MAX_EXTENSION_BYTES: usize = 16 * 1024 * 1024;
const MAX_STREAM_RUNS: usize = 65_536;
const BASE_REFERENCE: NtfsReference = NtfsReference {
    record: 0,
    sequence: 0,
};

pub(super) struct AttributeSet<'a> {
    base: &'a NtfsFileRecord,
    extensions: BTreeMap<u64, NtfsFileRecord>,
}

impl AttributeSet<'_> {
    pub(super) fn all(&self) -> Result<Vec<NtfsAttribute<'_>>> {
        let mut result = Vec::new();
        for record in std::iter::once(self.base).chain(self.extensions.values()) {
            result.extend(
                record
                    .attributes()
                    .map_err(|error| parse(&error))?
                    .into_iter()
                    .filter(|attr| attr.kind != ATTRIBUTE_LIST),
            );
        }
        Ok(result)
    }

    pub(super) fn select(
        &self,
        geometry: &NtfsGeometry,
        kind: u32,
        name: &[u16],
    ) -> Result<Stream> {
        let matches: Vec<_> = self
            .all()?
            .into_iter()
            .filter(|attr| attr.kind == kind && attr.name == name)
            .collect();
        Stream::from_attributes(geometry, &matches)
    }
}

impl NtfsVolume {
    pub(super) fn attributes<'a>(
        &self,
        cx: &Cx,
        base: &'a NtfsFileRecord,
    ) -> Result<AttributeSet<'a>> {
        let list = read_list(&self.source, &self.geometry, cx, base)?;
        resolve_catalog(cx, &self.geometry, base, list.as_deref(), |reference| {
            self.record(cx, reference.record, Some(reference.sequence))
        })
    }

    pub(super) fn select_stream(
        &self,
        cx: &Cx,
        base: &NtfsFileRecord,
        kind: u32,
        name: &[u16],
    ) -> Result<Stream> {
        let attributes = self.attributes(cx, base)?;
        let stream = attributes.select(&self.geometry, kind, name)?;
        checkpoint(cx)?;
        Ok(stream)
    }
}

fn read_list(
    source: &Source,
    geometry: &NtfsGeometry,
    cx: &Cx,
    base: &NtfsFileRecord,
) -> Result<Option<Vec<NtfsAttributeListEntry>>> {
    checkpoint(cx)?;
    validate_identity(base, u64::from(base.number), None)?;
    if base.base != BASE_REFERENCE {
        return Err(unsupported(
            "select NTFS attributes through their base record, not an extension",
        ));
    }
    let attributes = base.attributes().map_err(|error| parse(&error))?;
    let mut lists = attributes.iter().filter(|attr| attr.kind == ATTRIBUTE_LIST);
    let Some(list) = lists.next() else {
        return Ok(None);
    };
    if lists.next().is_some() || !list.name.is_empty() || list.flags != 0 {
        return Err(corrupt(0, "ambiguous, named or transformed ATTRIBUTE_LIST"));
    }
    // The list's own mapping must reside in the base record. It does not list
    // itself and cannot recursively discover additional list extents.
    let stream = Stream::from_attribute(geometry, list)?;
    if stream.size == 0 || stream.size > MAX_LIST_BYTES as u64 || stream.initialized != stream.size
    {
        return Err(corrupt(
            0,
            "ATTRIBUTE_LIST is empty, uninitialized or over budget",
        ));
    }
    let bytes = stream.read(source, geometry, cx, 0, stream.size as usize)?;
    let list = parse_attribute_list(&bytes).map_err(|error| parse(&error))?;
    checkpoint(cx)?;
    Ok(Some(list))
}

fn resolve_catalog<'a>(
    cx: &Cx,
    geometry: &NtfsGeometry,
    base: &'a NtfsFileRecord,
    list: Option<&[NtfsAttributeListEntry]>,
    mut load: impl FnMut(NtfsReference) -> Result<NtfsFileRecord>,
) -> Result<AttributeSet<'a>> {
    let mut result = AttributeSet {
        base,
        extensions: BTreeMap::new(),
    };
    let Some(list) = list else {
        return Ok(result);
    };
    let owner = NtfsReference {
        record: u64::from(base.number),
        sequence: base.sequence,
    };
    let mut catalog = BTreeMap::new();
    for entry in list {
        checkpoint(cx)?;
        if catalog
            .insert((entry.reference.record, entry.id), entry)
            .is_some()
        {
            return Err(corrupt(0, "duplicate ATTRIBUTE_LIST target"));
        }
        if entry.reference.record == owner.record {
            if entry.reference != owner {
                return Err(corrupt(0, "stale base reference in ATTRIBUTE_LIST"));
            }
        } else {
            let over_budget =
                result.extensions.len() >= MAX_EXTENSION_BYTES / geometry.record_bytes() as usize;
            if let std::collections::btree_map::Entry::Vacant(slot) =
                result.extensions.entry(entry.reference.record)
            {
                if over_budget {
                    return Err(unsupported("NTFS extension-record byte budget exceeded"));
                }
                let extension = load(entry.reference)?;
                if extension.base != owner {
                    return Err(corrupt(
                        0,
                        "NTFS extension belongs to a different base or generation",
                    ));
                }
                slot.insert(extension);
            }
        }
    }
    let mut matched = 0;
    for record in std::iter::once(base).chain(result.extensions.values()) {
        checkpoint(cx)?;
        for attr in record.attributes().map_err(|error| parse(&error))? {
            checkpoint(cx)?;
            if attr.kind == ATTRIBUTE_LIST {
                if record.number != base.number {
                    return Err(corrupt(
                        0,
                        "recursive ATTRIBUTE_LIST in an extension record",
                    ));
                }
                continue;
            }
            let target = (u64::from(record.number), attr.id);
            let entry = catalog
                .get(&target)
                .ok_or_else(|| corrupt(0, "attribute omitted from its ATTRIBUTE_LIST"))?;
            let vcn = match &attr.value {
                NtfsValue::Resident(_) => 0,
                NtfsValue::NonResident(value) => value.first_vcn,
            };
            if entry.reference.sequence != record.sequence
                || entry.kind != attr.kind
                || entry.name != attr.name
                || entry.first_vcn != vcn
            {
                return Err(corrupt(
                    0,
                    "ATTRIBUTE_LIST does not match its target attribute identity",
                ));
            }
            matched += 1;
        }
    }
    if matched != list.len() {
        return Err(corrupt(
            0,
            "ATTRIBUTE_LIST references a missing attribute instance",
        ));
    }
    checkpoint(cx)?;
    Ok(result)
}

impl Stream {
    /// Assemble one native value, not unrelated resident attributes sharing a
    /// type/name (FILE_NAME is enumerated separately). Sizes belong to VCN zero;
    /// continuation size fields are undefined and must not override them.
    pub(super) fn from_attributes(
        geometry: &NtfsGeometry,
        attributes: &[NtfsAttribute<'_>],
    ) -> Result<Self> {
        let first = attributes.first().ok_or_else(|| {
            FfsError::NotFound("NTFS stream has no matching attribute extents".into())
        })?;
        if first.flags & !(SPARSE | COMPRESSED) != 0 {
            return Err(unsupported(format!(
                "NTFS attribute flags {:#06x}: unsupported compression method, EFS or unknown flags",
                first.flags
            )));
        }
        let compressed = first.flags & COMPRESSED != 0;
        if compressed && first.kind != DATA {
            return Err(unsupported(
                "native compression is supported only for NTFS DATA",
            ));
        }
        if attributes.iter().any(|attr| {
            attr.kind != first.kind || attr.name != first.name || attr.flags != first.flags
        }) {
            return Err(corrupt(
                0,
                "inconsistent NTFS extent type, name or storage flags",
            ));
        }
        if let NtfsValue::Resident(value) = &first.value {
            if attributes.len() != 1 || first.flags != 0 {
                return Err(corrupt(
                    0,
                    "ambiguous resident value or nonresident storage flags",
                ));
            }
            return Ok(Self {
                size: value.len() as u64,
                initialized: value.len() as u64,
                allocated: value.len() as u64,
                storage: Storage::Resident(value.to_vec()),
            });
        }
        let mut extents = Vec::with_capacity(attributes.len());
        for attr in attributes {
            let NtfsValue::NonResident(value) = &attr.value else {
                return Err(corrupt(
                    0,
                    "resident and nonresident extents in one NTFS stream",
                ));
            };
            extents.push(value);
        }
        extents.sort_unstable_by_key(|value| value.first_vcn);
        let header = extents[0];
        if header.first_vcn != 0 {
            return Err(corrupt(0, "NTFS stream has no initial extent"));
        }
        if compressed {
            if header.compression_unit != 4 || geometry.cluster_bytes() > 4096 {
                return Err(unsupported(
                    "native NTFS compression requires 16-cluster units and clusters at most 4 KiB",
                ));
            }
        } else if header.compression_unit != 0
            && !(first.flags & SPARSE != 0 && header.compression_unit == 4)
        {
            return Err(unsupported("unsupported NTFS compression-unit encoding"));
        }
        if header.data_bytes > i64::MAX as u64
            || header.allocated_bytes > i64::MAX as u64
            || header.initialized_bytes > header.data_bytes
        {
            return Err(corrupt(0, "negative or inconsistent NTFS stream sizes"));
        }
        let mut runs = Vec::new();
        let mut next_vcn = 0;
        for extent in &extents {
            if extent.first_vcn != next_vcn || extent.compression_unit != header.compression_unit {
                return Err(corrupt(
                    0,
                    "NTFS extent gap, overlap or changed compression unit",
                ));
            }
            // LCN deltas restart at zero for each attribute's mapping pairs.
            let decoded = decode_mapping_pairs(
                extent.mapping_pairs,
                extent.first_vcn,
                extent.last_vcn,
                geometry.cluster_count(),
            )
            .map_err(|error| parse(&error))?;
            if decoded.is_empty() && extents.len() != 1 {
                return Err(corrupt(0, "empty continuation in NTFS extent list"));
            }
            if runs.len() + decoded.len() > MAX_STREAM_RUNS {
                return Err(unsupported("assembled NTFS stream exceeds the run budget"));
            }
            next_vcn = decoded.last().map_or(0, |run| run.vcn + run.clusters);
            runs.extend(decoded);
        }
        let cluster_bytes = u64::from(geometry.cluster_bytes());
        let coverage = next_vcn
            .checked_mul(cluster_bytes)
            .ok_or_else(|| corrupt(0, "NTFS mapping size overflow"))?;
        if header.data_bytes > coverage
            || !header.allocated_bytes.is_multiple_of(cluster_bytes)
            || header.allocated_bytes > coverage
        {
            return Err(corrupt(
                0,
                "NTFS stream size is not covered by its complete mapping",
            ));
        }
        if first.flags & (SPARSE | COMPRESSED) == 0
            && (header.allocated_bytes != coverage || runs.iter().any(|run| run.lcn.is_none()))
        {
            return Err(corrupt(
                0,
                "non-sparse NTFS stream has holes or incomplete allocation",
            ));
        }
        if compressed && header.allocated_bytes != coverage {
            return Err(corrupt(
                0,
                "compressed allocation length disagrees with mapped VCN coverage",
            ));
        }
        let mut physical: Vec<_> = runs
            .iter()
            .filter_map(|run| run.lcn.map(|lcn| (lcn, lcn + run.clusters)))
            .collect();
        physical.sort_unstable();
        if physical.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(corrupt(0, "NTFS stream aliases its own physical clusters"));
        }
        let allocated = physical.iter().try_fold(0_u64, |sum, (start, end)| {
            sum.checked_add((end - start) * cluster_bytes)
                .ok_or_else(|| corrupt(0, "NTFS allocation sum overflow"))
        })?;
        if allocated > header.allocated_bytes {
            return Err(corrupt(0, "NTFS mapped allocation exceeds its header"));
        }
        let storage = if compressed {
            Storage::Compressed(CompressedStorage::new(geometry, runs)?)
        } else {
            Storage::Mapped(runs)
        };
        Ok(Self {
            storage,
            size: header.data_bytes,
            initialized: header.initialized_bytes,
            allocated,
        })
    }
}

/// Discover a fragmented MFT without guessing physical record addresses. The
/// private map may have holes while bootstrapping; a record is read only after
/// its entire initialized byte range is covered. No partial map escapes here.
pub(super) fn bootstrap_mft(
    source: &Source,
    geometry: &NtfsGeometry,
    cx: &Cx,
    base: &NtfsFileRecord,
) -> Result<Stream> {
    validate_identity(base, 0, None)?;
    let list = read_list(source, geometry, cx, base)?;
    let Some(list) = list else {
        return resolve_catalog(cx, geometry, base, None, |reference| {
            Err(FfsError::NotFound(format!(
                "NTFS MFT record {} has no bootstrap catalog entry",
                reference.record
            )))
        })?
        .select(geometry, DATA, &[]);
    };
    let owner = NtfsReference {
        record: 0,
        sequence: base.sequence,
    };
    let data: Vec<_> = list
        .iter()
        .filter(|entry| entry.kind == DATA && entry.name.is_empty())
        .collect();
    let mut first = data.iter().filter(|entry| entry.first_vcn == 0);
    let initial = *first
        .next()
        .ok_or_else(|| corrupt(0, "MFT has no initial DATA extent"))?;
    if first.next().is_some() || initial.reference != owner {
        return Err(corrupt(
            0,
            "MFT initial DATA extent is ambiguous or outside record zero",
        ));
    }
    let attributes = base.attributes().map_err(|error| parse(&error))?;
    let initial_attr = attributes
        .iter()
        .find(|attr| attr.id == initial.id)
        .ok_or_else(|| corrupt(0, "missing MFT initial attribute instance"))?;
    let NtfsValue::NonResident(header) = &initial_attr.value else {
        return Err(corrupt(0, "MFT DATA must be nonresident"));
    };
    if header.data_bytes > header.allocated_bytes
        || header.initialized_bytes > header.data_bytes
        || header.allocated_bytes > geometry.volume_bytes()
        || header.data_bytes > i64::MAX as u64
    {
        return Err(corrupt(0, "invalid MFT bootstrap size fields"));
    }
    let mut map = Stream {
        storage: Storage::Mapped(Vec::new()),
        size: header.data_bytes,
        initialized: header.initialized_bytes,
        allocated: header.allocated_bytes,
    };
    let mut merge_work = 0;
    install_mft_extent(geometry, &mut map, initial, initial_attr, &mut merge_work)?;
    let Storage::Mapped(runs) = &map.storage else {
        return Err(corrupt(0, "invalid bootstrap storage"));
    };
    if runs.first().is_none_or(|run| {
        run.vcn != 0
            || run.lcn != Some(geometry.mft_cluster())
            || run.clusters * u64::from(geometry.cluster_bytes())
                < u64::from(geometry.record_bytes())
    }) {
        return Err(corrupt(
            0,
            "MFT initial extent does not cover its physical bootstrap record",
        ));
    }
    let mut records = BTreeMap::new();
    let mut pending: Vec<_> = data
        .into_iter()
        .filter(|entry| entry.first_vcn != 0)
        .collect();
    let mut probes = 0_usize;
    while !pending.is_empty() {
        let before = pending.len();
        let mut blocked = Vec::new();
        for entry in pending {
            checkpoint(cx)?;
            probes += 1;
            if probes > 131_072 {
                return Err(unsupported("MFT bootstrap dependency work budget exceeded"));
            }
            let record = if entry.reference.record == 0 {
                if entry.reference != owner {
                    return Err(corrupt(0, "stale MFT base reference"));
                }
                base
            } else {
                let over_budget =
                    records.len() >= MAX_EXTENSION_BYTES / geometry.record_bytes() as usize;
                match records.entry(entry.reference.record) {
                    std::collections::btree_map::Entry::Occupied(slot) => slot.into_mut(),
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        if over_budget {
                            return Err(unsupported("MFT extension-record byte budget exceeded"));
                        }
                        let Some(record) =
                            bootstrap_record(source, geometry, cx, &map, entry.reference)?
                        else {
                            blocked.push(entry);
                            continue;
                        };
                        if record.base != owner {
                            return Err(corrupt(0, "MFT extension has a foreign base generation"));
                        }
                        slot.insert(record)
                    }
                }
            };
            validate_identity(
                record,
                entry.reference.record,
                Some(entry.reference.sequence),
            )?;
            let attributes = record.attributes().map_err(|error| parse(&error))?;
            let attr = attributes
                .iter()
                .find(|attr| attr.id == entry.id)
                .ok_or_else(|| corrupt(0, "MFT list references a missing attribute instance"))?;
            install_mft_extent(geometry, &mut map, entry, attr, &mut merge_work)?;
        }
        if blocked.len() == before {
            return Err(corrupt(
                0,
                "MFT extent dependency cannot be resolved from known mappings",
            ));
        }
        pending = blocked;
    }
    // Now validate every catalog entry, including non-DATA attributes. Reuse
    // records already read, then assemble through the ordinary complete-stream
    // validator. Missing extents and undeclared attributes still fail here.
    let catalog = resolve_catalog(cx, geometry, base, Some(&list), |reference| {
        if let Some(record) = records.remove(&reference.record) {
            validate_identity(&record, reference.record, Some(reference.sequence))?;
            return Ok(record);
        }
        bootstrap_record(source, geometry, cx, &map, reference)?
            .ok_or_else(|| corrupt(0, "MFT catalog record lies in an unresolved mapping gap"))
    })?;
    let stream = catalog.select(geometry, DATA, &[])?;
    checkpoint(cx)?;
    Ok(stream)
}

fn install_mft_extent(
    geometry: &NtfsGeometry,
    map: &mut Stream,
    entry: &NtfsAttributeListEntry,
    attr: &NtfsAttribute<'_>,
    work: &mut usize,
) -> Result<()> {
    let NtfsValue::NonResident(value) = &attr.value else {
        return Err(corrupt(0, "resident MFT extent"));
    };
    if attr.id != entry.id
        || attr.kind != DATA
        || !attr.name.is_empty()
        || value.first_vcn != entry.first_vcn
    {
        return Err(corrupt(
            0,
            "MFT extent disagrees with its ATTRIBUTE_LIST entry",
        ));
    }
    if attr.flags != 0 || value.compression_unit != 0 {
        return Err(unsupported("transformed MFT DATA extent"));
    }
    let decoded = decode_mapping_pairs(
        value.mapping_pairs,
        value.first_vcn,
        value.last_vcn,
        geometry.cluster_count(),
    )
    .map_err(|error| parse(&error))?;
    if decoded.is_empty() || decoded.iter().any(|run| run.lcn.is_none()) {
        return Err(corrupt(0, "empty or sparse MFT DATA extent"));
    }
    let Storage::Mapped(runs) = &mut map.storage else {
        return Err(corrupt(0, "invalid MFT bootstrap storage"));
    };
    *work += runs.len() + decoded.len();
    if *work > 1_048_576 || runs.len() + decoded.len() > MAX_STREAM_RUNS {
        return Err(unsupported("MFT bootstrap mapping merge budget exceeded"));
    }
    runs.extend(decoded);
    runs.sort_unstable_by_key(|run| run.vcn);
    if runs
        .windows(2)
        .any(|pair| pair[0].vcn + pair[0].clusters > pair[1].vcn)
    {
        return Err(corrupt(0, "overlapping logical MFT extents"));
    }
    let mut physical: Vec<_> = runs
        .iter()
        .filter_map(|run| run.lcn.map(|lcn| (lcn, lcn + run.clusters)))
        .collect();
    physical.sort_unstable();
    if physical.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(corrupt(0, "aliased physical MFT extents"));
    }
    Ok(())
}

fn bootstrap_record(
    source: &Source,
    geometry: &NtfsGeometry,
    cx: &Cx,
    map: &Stream,
    reference: NtfsReference,
) -> Result<Option<NtfsFileRecord>> {
    checkpoint(cx)?;
    if reference.record > u64::from(u32::MAX) {
        return Err(corrupt(0, "MFT record identity exceeds the read profile"));
    }
    let start = reference.record * u64::from(geometry.record_bytes());
    let end = start + u64::from(geometry.record_bytes());
    if end > map.initialized {
        return Err(corrupt(start, "MFT extension lies beyond initialized data"));
    }
    let cluster_bytes = u64::from(geometry.cluster_bytes());
    let mut vcn = start / cluster_bytes;
    let end_vcn = end.div_ceil(cluster_bytes);
    let Storage::Mapped(runs) = &map.storage else {
        return Err(corrupt(start, "invalid bootstrap map"));
    };
    // Check the entire range before issuing even its first physical read.
    while vcn < end_vcn {
        let Some(index) = runs.partition_point(|run| run.vcn <= vcn).checked_sub(1) else {
            return Ok(None);
        };
        let run = &runs[index];
        if run.lcn.is_none() || vcn >= run.vcn + run.clusters {
            return Ok(None);
        }
        vcn = (run.vcn + run.clusters).min(end_vcn);
    }
    let raw = map.read(
        source,
        geometry,
        cx,
        start,
        geometry.record_bytes() as usize,
    )?;
    let record = NtfsFileRecord::parse(&raw).map_err(|error| parse(&error))?;
    validate_identity(&record, reference.record, Some(reference.sequence))?;
    checkpoint(cx)?;
    Ok(Some(record))
}
