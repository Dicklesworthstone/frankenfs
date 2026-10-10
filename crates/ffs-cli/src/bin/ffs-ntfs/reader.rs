//! Offline, native NTFS 3.1 MFT/stream reads. No mount, replay or device writes.

mod attributes;
mod namespace;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::{
    ATTRIBUTE_LIST, DATA, NtfsAttribute, NtfsFileRecord, NtfsGeometry, NtfsReference, NtfsRun,
    NtfsValue, SPARSE, VOLUME_INFORMATION, decode_mapping_pairs,
};
use ffs_types::{ByteOffset, ParseError};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

const MAX_READ: usize = 16 * 1024 * 1024;

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}
fn corrupt(offset: u64, detail: impl Into<String>) -> FfsError {
    FfsError::Corruption {
        block: offset / 512,
        detail: detail.into(),
    }
}
fn parse(error: ParseError) -> FfsError {
    corrupt(0, error.to_string())
}
fn unsupported(detail: impl Into<String>) -> FfsError {
    FfsError::UnsupportedFeature(detail.into())
}
fn buffer(size: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    data.try_reserve_exact(size)
        .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
    data.resize(size, 0);
    Ok(data)
}

struct ReadOnlyImage {
    file: File,
    length: u64,
}
impl ByteDevice for ReadOnlyImage {
    fn len_bytes(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, data: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.file.read_exact_at(data, offset.0)?;
        checkpoint(cx)
    }
    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _data: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }
    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)
    }
}

struct Source {
    device: Box<dyn ByteDevice>,
    base: u64,
    length: u64,
}
impl Source {
    fn read(&self, cx: &Cx, offset: u64, data: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        if offset
            .checked_add(data.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(corrupt(
                offset,
                "NTFS read outside the selected addressable volume",
            ));
        }
        let physical = self
            .base
            .checked_add(offset)
            .ok_or_else(|| corrupt(offset, "physical offset overflow"))?;
        self.device.read_exact_at(cx, ByteOffset(physical), data)?;
        checkpoint(cx)
    }
}

#[derive(Debug)]
enum Storage {
    Resident(Vec<u8>),
    Mapped(Vec<NtfsRun>),
}

/// Complete, validated stream. No public constructor permits bypassing the
/// bounds, flags, catalog and mapping checks performed during selection.
#[derive(Debug)]
pub struct Stream {
    storage: Storage,
    pub size: u64,
    pub initialized: u64,
    pub allocated: u64,
}
impl Stream {
    fn from_attribute(geometry: &NtfsGeometry, attr: &NtfsAttribute<'_>) -> Result<Self> {
        Self::from_attributes(geometry, std::slice::from_ref(attr))
    }

    #[must_use]
    pub fn resident(&self) -> bool {
        matches!(&self.storage, Storage::Resident(_))
    }

    fn read(
        &self,
        source: &Source,
        geometry: &NtfsGeometry,
        cx: &Cx,
        offset: u64,
        size: usize,
    ) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        if size > MAX_READ {
            return Err(unsupported("NTFS read request exceeds 16 MiB"));
        }
        let length = self.size.saturating_sub(offset).min(size as u64) as usize;
        let mut result = buffer(length)?;
        if length == 0 {
            return Ok(result);
        }
        match &self.storage {
            Storage::Resident(data) => {
                let at = usize::try_from(offset)
                    .map_err(|_| corrupt(0, "resident read offset overflow"))?;
                let slice = data
                    .get(at..at + length)
                    .ok_or_else(|| corrupt(0, "resident read beyond value"))?;
                result.copy_from_slice(slice);
            }
            Storage::Mapped(runs) => {
                let cluster_bytes = u64::from(geometry.cluster_bytes());
                // Everything after ValidDataLength stays zero without any disk read.
                let initialized =
                    self.initialized.saturating_sub(offset).min(length as u64) as usize;
                let mut done = 0;
                while done < initialized {
                    checkpoint(cx)?;
                    let logical = offset + done as u64;
                    let vcn = logical / cluster_bytes;
                    let index = runs
                        .partition_point(|run| run.vcn <= vcn)
                        .checked_sub(1)
                        .ok_or_else(|| corrupt(0, "missing NTFS mapping before read"))?;
                    let run = &runs[index];
                    let within = logical - run.vcn * cluster_bytes;
                    let available = (run.clusters * cluster_bytes)
                        .checked_sub(within)
                        .filter(|count| *count != 0)
                        .ok_or_else(|| corrupt(0, "gap in NTFS mapping"))?;
                    let count = available.min((initialized - done) as u64) as usize;
                    if let Some(lcn) = run.lcn {
                        let physical = geometry.cluster_offset(lcn).map_err(parse)? + within;
                        source.read(cx, physical, &mut result[done..done + count])?;
                    }
                    // Sparse runs intentionally remain zero; they do not trigger I/O.
                    done += count;
                }
            }
        }
        checkpoint(cx)?;
        Ok(result)
    }
}

pub struct NtfsVolume {
    source: Source,
    pub geometry: NtfsGeometry,
    mft: Stream,
}
impl NtfsVolume {
    pub fn open(cx: &Cx, path: &Path, base: u64, length: Option<u64>) -> Result<Self> {
        checkpoint(cx)?;
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(unsupported(
                "NTFS reader accepts only immutable offline regular images",
            ));
        }
        file.try_lock_shared()
            .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
        let size = metadata.len();
        Self::from_device(
            cx,
            Box::new(ReadOnlyImage { file, length: size }),
            base,
            length.unwrap_or(size.saturating_sub(base)),
        )
    }

    pub fn from_device(
        cx: &Cx,
        device: Box<dyn ByteDevice>,
        base: u64,
        length: u64,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if length < 512
            || base
                .checked_add(length)
                .is_none_or(|end| end > device.len_bytes())
        {
            return Err(FfsError::InvalidGeometry(
                "NTFS volume range exceeds backing".into(),
            ));
        }
        let mut source = Source {
            device,
            base,
            length,
        };
        let mut boot = [0_u8; 512];
        source.read(cx, 0, &mut boot)?;
        let geometry = NtfsGeometry::parse(&boot, length).map_err(parse)?;
        source.length = geometry.volume_bytes();
        let mut raw = buffer(geometry.record_bytes() as usize)?;
        source.read(
            cx,
            geometry
                .cluster_offset(geometry.mft_cluster())
                .map_err(parse)?,
            &mut raw,
        )?;
        let primary = NtfsFileRecord::parse(&raw).map_err(parse)?;
        validate_identity(&primary, 0, None)?;
        source.read(
            cx,
            geometry
                .cluster_offset(geometry.mirror_cluster())
                .map_err(parse)?,
            &mut raw,
        )?;
        let mirror = NtfsFileRecord::parse(&raw).map_err(parse)?;
        validate_identity(&mirror, 0, None)?;
        if primary.used_bytes() != mirror.used_bytes() {
            return Err(corrupt(
                0,
                "NTFS MFT bootstrap and MFTMirr disagree; no automatic recovery",
            ));
        }
        let mft = select_stream(&geometry, &primary, DATA, &[])?;
        let Storage::Mapped(runs) = &mft.storage else {
            return Err(corrupt(0, "MFT DATA must be nonresident"));
        };
        let record_bytes = u64::from(geometry.record_bytes());
        if runs.first().is_none_or(|run| {
            run.lcn != Some(geometry.mft_cluster())
                || run.clusters * u64::from(geometry.cluster_bytes()) < record_bytes
        }) || runs.iter().any(|run| run.lcn.is_none())
            || mft.initialized < 4 * record_bytes
            || !mft.initialized.is_multiple_of(record_bytes)
            || !mft.size.is_multiple_of(record_bytes)
        {
            return Err(corrupt(
                0,
                "invalid MFT bootstrap mapping or initialized record boundary",
            ));
        }
        let volume = Self {
            source,
            geometry,
            mft,
        };
        // Read record zero again through the actual MFT map, not boot arithmetic.
        if volume.record(cx, 0, None)?.used_bytes() != primary.used_bytes() {
            return Err(corrupt(
                0,
                "MFT mapping does not reproduce the bootstrap record",
            ));
        }
        let record = volume.record(cx, 3, None)?;
        let info = select_stream(&volume.geometry, &record, VOLUME_INFORMATION, &[])?;
        if !info.resident() || info.size < 12 || info.size > 4096 {
            return Err(corrupt(0, "invalid resident VOLUME_INFORMATION"));
        }
        let info = volume.read(cx, &info, 0, info.size as usize)?;
        if info[8..10] != [3, 1] {
            return Err(unsupported("NTFS reader currently admits version 3.1 only"));
        }
        let flags = u16::from_le_bytes([info[10], info[11]]);
        if flags != 0 {
            return Err(unsupported(format!(
                "NTFS volume flags {flags:#06x} require native investigation; replay is not implemented"
            )));
        }
        checkpoint(cx)?;
        Ok(volume)
    }

    #[must_use]
    pub fn record_count(&self) -> u64 {
        self.mft.initialized / u64::from(self.geometry.record_bytes())
    }

    pub fn record(&self, cx: &Cx, number: u64, sequence: Option<u16>) -> Result<NtfsFileRecord> {
        checkpoint(cx)?;
        if number >= self.record_count() || number > u64::from(u32::MAX) {
            return Err(FfsError::NotFound(format!(
                "NTFS MFT record {number} is outside the initialized record range"
            )));
        }
        let offset = number * u64::from(self.geometry.record_bytes());
        let raw = self.read(cx, &self.mft, offset, self.geometry.record_bytes() as usize)?;
        if raw.len() != self.geometry.record_bytes() as usize {
            return Err(corrupt(offset, "short MFT record"));
        }
        let record =
            NtfsFileRecord::parse(&raw).map_err(|error| corrupt(offset, error.to_string()))?;
        validate_identity(&record, number, sequence)?;
        checkpoint(cx)?;
        Ok(record)
    }

    pub fn data_stream(&self, cx: &Cx, record: &NtfsFileRecord, name: &[u16]) -> Result<Stream> {
        checkpoint(cx)?;
        if record.is_directory() && name.is_empty() {
            return Err(FfsError::IsDirectory);
        }
        let stream = self.select_stream(cx, record, DATA, name)?;
        checkpoint(cx)?;
        Ok(stream)
    }

    pub fn read(&self, cx: &Cx, stream: &Stream, offset: u64, size: usize) -> Result<Vec<u8>> {
        stream.read(&self.source, &self.geometry, cx, offset, size)
    }
}

fn validate_identity(record: &NtfsFileRecord, number: u64, sequence: Option<u16>) -> Result<()> {
    if !record.in_use() {
        return Err(FfsError::NotFound(format!(
            "NTFS MFT record {number} is not in use"
        )));
    }
    if u64::from(record.number) != number
        || record.sequence == 0
        || sequence.is_some_and(|expected| expected != record.sequence)
    {
        return Err(corrupt(0, "stale or mismatched NTFS file reference"));
    }
    Ok(())
}

fn select_stream(
    geometry: &NtfsGeometry,
    record: &NtfsFileRecord,
    kind: u32,
    name: &[u16],
) -> Result<Stream> {
    if record.base
        != (NtfsReference {
            record: 0,
            sequence: 0,
        })
    {
        return Err(unsupported(
            "NTFS extension record needs its base record and ATTRIBUTE_LIST",
        ));
    }
    let attributes = record.attributes().map_err(parse)?;
    if attributes.iter().any(|attr| attr.kind == ATTRIBUTE_LIST) {
        return Err(unsupported(
            "NTFS ATTRIBUTE_LIST assembly is not implemented; refusing a partial stream",
        ));
    }
    let mut matches = attributes
        .iter()
        .filter(|attr| attr.kind == kind && attr.name == name);
    let attr = matches.next().ok_or_else(|| {
        FfsError::NotFound(format!(
            "NTFS attribute {kind:#x} with UTF-16 name {name:?} in MFT record {}",
            record.number
        ))
    })?;
    if matches.next().is_some() {
        return Err(corrupt(
            0,
            "ambiguous NTFS stream or unassembled continuation extents",
        ));
    }
    Stream::from_attribute(geometry, attr)
}

#[cfg(test)]
mod tests;
