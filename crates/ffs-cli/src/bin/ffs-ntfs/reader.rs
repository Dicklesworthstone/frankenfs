//! Offline native NTFS 3.1 reads and explicit volatile recovery. No device writes.

mod attributes;
mod compression;
pub mod ea;
pub mod filesystem;
mod namespace;
mod recovery_apply;
pub mod security;
mod source;
mod wof;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::reparse::{MAX_REPARSE_BYTES, NtfsReparseData, NtfsReparsePoint};
use ffs_ondisk::ntfs::{
    ATTRIBUTE_LIST, COMPRESSED, DATA, NtfsAttribute, NtfsFileRecord, NtfsGeometry, NtfsReference,
    NtfsRun, NtfsValue, REPARSE_POINT, SPARSE, VOLUME_INFORMATION, decode_mapping_pairs,
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
fn parse(error: &ParseError) -> FfsError {
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
    overlay: std::collections::BTreeMap<u64, [u8; 512]>,
}

#[derive(Debug)]
enum Storage {
    Resident(Vec<u8>),
    Mapped(Vec<NtfsRun>),
    Compressed(compression::CompressedStorage),
    Wof(wof::WofStorage),
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
            Storage::Compressed(storage) => {
                storage.read_into(source, geometry, cx, self.initialized, offset, &mut result)?;
            }
            Storage::Wof(storage) => {
                storage.read_into(source, geometry, cx, self.initialized, offset, &mut result)?;
            }
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
                        let physical = geometry
                            .cluster_offset(lcn)
                            .map_err(|error| parse(&error))?
                            + within;
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

/// One logical DATA stream after assembling its attribute extents. Native
/// names remain UTF-16; inspection never replaces unrepresentable code units.
#[derive(Debug)]
pub struct DataStreamInfo {
    pub name: Vec<u16>,
    pub attribute_extents: usize,
    /// Metadata admission is not verification of every payload byte. Refused
    /// streams remain visible without opening their data or invoking a provider.
    pub read_profile: std::result::Result<DataStreamMetadata, String>,
}

#[derive(Debug)]
pub struct DataStreamMetadata {
    pub resident: bool,
    pub size: u64,
    pub initialized: u64,
    pub allocated: u64,
}

impl DataStreamMetadata {
    fn from_stream(stream: &Stream) -> Self {
        let resident = stream.resident();
        Self {
            resident,
            size: stream.size,
            initialized: stream.initialized,
            // Resident values occupy their FILE record, not separate clusters.
            allocated: if resident { 0 } else { stream.allocated },
        }
    }
}

pub struct NtfsVolume {
    source: Source,
    pub geometry: NtfsGeometry,
    mft: Stream,
    pub volume_flags: u16,
    pub logfile_recovery: Option<ffs_ondisk::ntfs::NtfsLogFilePlan>,
}
impl NtfsVolume {
    #[cfg(test)]
    pub fn open(cx: &Cx, path: &Path, base: u64, length: Option<u64>) -> Result<Self> {
        Self::open_with_options(cx, path, base, length, false)
    }

    pub fn open_with_options(
        cx: &Cx,
        path: &Path,
        base: u64,
        length: Option<u64>,
        recover_logfile: bool,
    ) -> Result<Self> {
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
        Self::from_device_with_options(
            cx,
            Box::new(ReadOnlyImage { file, length: size }),
            base,
            length.unwrap_or_else(|| size.saturating_sub(base)),
            recover_logfile,
        )
    }

    // ffs-protected-mount compiles this module through #[path] and opens
    // through here; the ffs-ntfs binary itself always passes recovery options.
    #[allow(dead_code)]
    pub fn from_device(
        cx: &Cx,
        device: Box<dyn ByteDevice>,
        base: u64,
        length: u64,
    ) -> Result<Self> {
        Self::from_device_with_options(cx, device, base, length, false)
    }

    pub fn from_device_with_options(
        cx: &Cx,
        device: Box<dyn ByteDevice>,
        base: u64,
        length: u64,
        recover_logfile: bool,
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
        let mut source = Source::bounded(cx, device, base, length)?;
        let mut boot = [0_u8; 512];
        source.read(cx, 0, &mut boot)?;
        let geometry = NtfsGeometry::parse(&boot, length).map_err(|error| parse(&error))?;
        source.length = geometry.volume_bytes();
        let mut raw = buffer(geometry.record_bytes() as usize)?;
        source.read(
            cx,
            geometry
                .cluster_offset(geometry.mft_cluster())
                .map_err(|error| parse(&error))?,
            &mut raw,
        )?;
        let primary = NtfsFileRecord::parse(&raw).map_err(|error| parse(&error))?;
        validate_identity(&primary, 0, None)?;
        source.read(
            cx,
            geometry
                .cluster_offset(geometry.mirror_cluster())
                .map_err(|error| parse(&error))?,
            &mut raw,
        )?;
        let mirror = NtfsFileRecord::parse(&raw).map_err(|error| parse(&error))?;
        validate_identity(&mirror, 0, None)?;
        if primary.used_bytes() != mirror.used_bytes() {
            return Err(corrupt(
                0,
                "NTFS MFT bootstrap and MFTMirr disagree; no automatic recovery",
            ));
        }
        let mft = attributes::bootstrap_mft(&source, &geometry, cx, &primary)?;
        validate_mft_stream(&mft, &geometry)?;
        let mut volume = Self {
            source,
            geometry,
            mft,
            volume_flags: 0,
            logfile_recovery: None,
        };
        // Read record zero again through the actual MFT map, not boot arithmetic.
        if volume.record(cx, 0, None)?.used_bytes() != primary.used_bytes() {
            return Err(corrupt(
                0,
                "MFT mapping does not reproduce the bootstrap record",
            ));
        }
        let record = volume.record(cx, 3, None)?;
        let info = volume.select_stream(cx, &record, VOLUME_INFORMATION, &[])?;
        if !info.resident() || info.size < 12 || info.size > 4096 {
            return Err(corrupt(0, "invalid resident VOLUME_INFORMATION"));
        }
        let info = volume.read(cx, &info, 0, info.size as usize)?;
        if info[8..10] != [3, 1] {
            return Err(unsupported("NTFS reader currently admits version 3.1 only"));
        }
        let flags = u16::from_le_bytes([info[10], info[11]]);
        volume.volume_flags = flags;
        if flags != 0 && !recover_logfile {
            return Err(unsupported(format!(
                "NTFS volume flags {flags:#06x} require native investigation; pass --recover-logfile to replay $LogFile into a read-only overlay"
            )));
        }
        if recover_logfile {
            // The dirty bit requests log handling. Other flags (resize,
            // upgrade, chkdsk and unknown state) are not permission to replay.
            if flags & !1 != 0 {
                return Err(unsupported(format!(
                    "NTFS volume flags {flags:#06x} require work beyond the admitted $LogFile overlay"
                )));
            }
            volume.apply_logfile_recovery(cx)?;
        }
        checkpoint(cx)?;
        Ok(volume)
    }

    fn apply_logfile_recovery(&mut self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        // Use the same protected tail and checkpoint-aware Analysis as native
        // preflight. Never fall back to a flat scan after a newer commit, table
        // or target cannot be read. None is a completely verified erased log.
        let Some(plan) = self.native_recovery_plan(cx)? else {
            return Ok(());
        };
        let overlay = recovery_apply::stage(cx, self, &plan)?;
        checkpoint(cx)?;
        // System records and changes to nonresident attributes are refused by
        // this executor. The admitted MFT bootstrap therefore remains valid.
        // No fallible work after publishing the complete volatile view.
        recovery_apply::publish(cx, &mut self.source, overlay)?;
        self.logfile_recovery = Some(plan);
        Ok(())
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
        let catalog = self.attributes(cx, record)?;
        let stream = self.data_from_catalog(cx, record, &catalog, name)?;
        checkpoint(cx)?;
        Ok(stream)
    }

    fn data_from_catalog(
        &self,
        cx: &Cx,
        record: &NtfsFileRecord,
        catalog: &attributes::AttributeSet<'_>,
        name: &[u16],
    ) -> Result<Stream> {
        let all = catalog.all()?;
        let provider = self.data_provider(cx, record, catalog, &all)?;
        if let Some(provider) = provider
            && name.is_empty()
        {
            return wof::open(self, cx, catalog, provider);
        }
        // An explicitly named DATA stream is its stored native value, including
        // WofCompressedData. Never apply the unnamed file's codec to an ADS.
        catalog.select(&self.geometry, DATA, name)
    }

    fn data_provider(
        &self,
        cx: &Cx,
        record: &NtfsFileRecord,
        catalog: &attributes::AttributeSet<'_>,
        all: &[NtfsAttribute<'_>],
    ) -> Result<Option<wof::FileProvider>> {
        checkpoint(cx)?;
        if all.iter().any(|attribute| attribute.kind == REPARSE_POINT) {
            let point = self
                .reparse_from_catalog(cx, catalog)?
                .ok_or_else(|| corrupt(0, "missing NTFS provider metadata"))?;
            let provider = wof::FileProvider::parse(&point)?;
            if record.is_directory() {
                return Err(unsupported(
                    "WOF individual-file provider cannot describe a directory",
                ));
            }
            if standard_flags(all)?.is_some_and(|flags| flags & 0x4000 != 0) {
                return Err(unsupported(
                    "NTFS EFS data requires an implemented key provider",
                ));
            }
            checkpoint(cx)?;
            return Ok(Some(provider));
        }
        data_read_admission(record, all)?;
        Ok(None)
    }

    /// Retrieve the actual native reparse metadata without following the target
    /// or interpreting an unknown provider's DATA. Works for resident and
    /// nonresident attributes, including validated attribute-list continuations.
    pub fn reparse_point(
        &self,
        cx: &Cx,
        record: &NtfsFileRecord,
    ) -> Result<Option<NtfsReparsePoint>> {
        let catalog = self.attributes(cx, record)?;
        self.reparse_from_catalog(cx, &catalog)
    }

    fn reparse_from_catalog(
        &self,
        cx: &Cx,
        catalog: &attributes::AttributeSet<'_>,
    ) -> Result<Option<NtfsReparsePoint>> {
        checkpoint(cx)?;
        let attributes = catalog.all()?;
        let mut present = false;
        for attribute in &attributes {
            if attribute.kind == REPARSE_POINT {
                present = true;
                if attribute.flags != 0 || !attribute.name.is_empty() {
                    return Err(corrupt(0, "named or transformed NTFS reparse attribute"));
                }
            }
        }
        if let Some(flags) = standard_flags(&attributes)?
            && (flags & 0x400 != 0) != present
        {
            return Err(corrupt(0, "NTFS reparse value and file attribute disagree"));
        }
        if !present {
            return Ok(None);
        }
        let stream = catalog.select(&self.geometry, REPARSE_POINT, &[])?;
        if !(8..=MAX_REPARSE_BYTES as u64).contains(&stream.size)
            || stream.initialized != stream.size
        {
            return Err(corrupt(0, "invalid NTFS reparse initialized value length"));
        }
        let value = self.read(cx, &stream, 0, stream.size as usize)?;
        let point = NtfsReparsePoint::parse(&value).map_err(|error| parse(&error))?;
        checkpoint(cx)?;
        Ok(Some(point))
    }

    pub fn readlink(&self, cx: &Cx, record: &NtfsFileRecord) -> Result<Vec<u8>> {
        let point = self
            .reparse_point(cx, record)?
            .ok_or_else(|| FfsError::Io(std::io::Error::from_raw_os_error(libc::EINVAL)))?;
        let target = relative_link_target(&point)?;
        checkpoint(cx)?;
        Ok(target.into_bytes())
    }

    pub fn read(&self, cx: &Cx, stream: &Stream, offset: u64, size: usize) -> Result<Vec<u8>> {
        stream.read(&self.source, &self.geometry, cx, offset, size)
    }
}

/// Validate the immutable MFT bootstrap. The public resident-only recovery
/// profile cannot change this map or silently retain a stale rebuilt view.
fn validate_mft_stream(mft: &Stream, geometry: &NtfsGeometry) -> Result<()> {
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
    Ok(())
}

/// Extraction and stream inspection share the complete catalog's file-level
/// admission. Unknown providers must not turn backing DATA into file contents.
fn data_read_admission(record: &NtfsFileRecord, attributes: &[NtfsAttribute<'_>]) -> Result<()> {
    if attributes.iter().any(|attr| attr.kind == REPARSE_POINT) {
        return Err(unsupported(
            "NTFS reparse DATA requires target resolution or an implemented provider",
        ));
    }
    if let Some(flags) = standard_flags(attributes)? {
        if flags & 0x400 != 0 {
            return Err(corrupt(0, "NTFS reparse attribute flag has no reparse value"));
        }
        // On directories ENCRYPTED is the default for newly created children.
        // A named directory stream retains its own ENCRYPTED attribute flag.
        if flags & 0x4000 != 0 && !record.is_directory() {
            return Err(unsupported(
                "NTFS EFS data requires an implemented key provider",
            ));
        }
    }
    Ok(())
}

fn standard_flags(attributes: &[NtfsAttribute<'_>]) -> Result<Option<u32>> {
    let mut flags = None;
    for attribute in attributes.iter().filter(|attribute| attribute.kind == 0x10) {
        let NtfsValue::Resident(value) = attribute.value else {
            return Err(corrupt(0, "nonresident NTFS STANDARD_INFORMATION"));
        };
        if flags.is_some()
            || attribute.flags != 0
            || !attribute.name.is_empty()
            || !matches!(value.len(), 48 | 72)
        {
            return Err(corrupt(0, "invalid NTFS STANDARD_INFORMATION identity"));
        }
        flags =
            Some(u32::from_le_bytes(value[32..36].try_into().map_err(
                |_| corrupt(0, "short NTFS file attribute flags"),
            )?));
    }
    Ok(flags)
}

/// Only native relative symbolic links have an unambiguous host representation.
/// Absolute NT/drive/UNC paths and stream-qualified targets need explicit volume
/// mapping/provider policy. The print name is never used for resolution.
fn relative_link_target(point: &NtfsReparsePoint) -> Result<String> {
    let NtfsReparseData::SymbolicLink {
        substitute,
        relative: true,
        ..
    } = &point.data
    else {
        return Err(unsupported(format!(
            "NTFS reparse tag {:#010x} has no admitted relative symbolic-link target",
            point.tag
        )));
    };
    let native = String::from_utf16(substitute).map_err(|_| {
        unsupported("NTFS symlink target cannot be represented losslessly as UTF-8")
    })?;
    if native.is_empty() || native.starts_with(['/', '\\']) || native.contains([':', '\0']) {
        return Err(unsupported(
            "NTFS relative symlink target is rooted or stream-qualified",
        ));
    }
    let target = native.replace('\\', "/");
    if target.len() > 4095 || target.split('/').any(|component| component.len() > 255) {
        return Err(FfsError::NameTooLong);
    }
    Ok(target)
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

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
