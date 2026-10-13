//! Create-only namespace publication for the ordered offline FAT writer.
//!
//! This initial profile admits portable ASCII 8.3 names in existing directory
//! storage. It never replaces an existing long name or short alias, grows a
//! directory, or silently converts a requested name. The successor end marker
//! is durable before an old end marker becomes a live file entry.

use super::super::{Directory, FatVolume, MAX_DIRECTORY_SLOTS};
use super::{
    Replacement, allocate, checkpoint, hash_device, modified_timestamp, reserve_clusters,
    validate_boot_state, write_volume,
};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_ondisk::fat::FatKind;

#[derive(Debug)]
struct Slot {
    offset: u64,
    bytes: [u8; 32],
}

/// Extra native state required when a free slot becomes a namespace entry.
#[derive(Debug)]
pub(super) struct Namespace {
    successor: Option<Slot>,
}

impl Namespace {
    pub(super) fn validate(&self, cx: &Cx, volume: &FatVolume) -> Result<()> {
        if let Some(slot) = &self.successor {
            let mut current = [0; 32];
            volume.read_exact(cx, slot.offset, &mut current)?;
            if current != slot.bytes {
                bail!("directory terminator successor changed after creation preflight");
            }
        }
        checkpoint(cx)?;
        Ok(())
    }

    pub(super) fn stage(&self, cx: &Cx, volume: &FatVolume) -> Result<()> {
        if let Some(slot) = &self.successor {
            let sector_bytes = u64::from(volume.geometry.sector_bytes());
            let start = slot.offset / sector_bytes * sector_bytes;
            let within = (slot.offset - start) as usize;
            let mut sector = allocate(sector_bytes as usize)?;
            volume.read_exact(cx, start, &mut sector)?;
            if sector[within..within + 32] != slot.bytes {
                bail!("directory successor changed before creation publication");
            }
            // Bytes beyond the previous end marker are not directory entries.
            // Retaining them after publishing a new entry can resurrect deleted
            // files. Clear the whole following slot without touching its peers.
            sector[within..within + 32].fill(0);
            write_volume(cx, volume, start, &sector)?;
            volume.device.sync(cx)?;
        }
        checkpoint(cx)?;
        Ok(())
    }
}

fn short_byte(byte: u8) -> bool {
    byte.is_ascii_uppercase()
        || byte.is_ascii_digit()
        || b"$%'-_@~`!(){}^#&".contains(&byte)
}

/// Return an exact representable short name; mixed case needs LFN storage and
/// is deliberately refused rather than silently changing the user's spelling.
fn short_name(name: &str) -> Result<([u8; 11], u8)> {
    let (base, extension) = name.rsplit_once('.').unwrap_or((name, ""));
    if base.is_empty()
        || base.len() > 8
        || extension.len() > 3
        || name.ends_with('.')
        || !base
            .bytes()
            .chain(extension.bytes())
            .all(|byte| short_byte(byte.to_ascii_uppercase()))
    {
        bail!("--create currently requires a portable ASCII 8.3 name without spaces or trailing dots");
    }
    let upper = base.to_ascii_uppercase();
    let numbered = upper.strip_prefix("COM").or_else(|| upper.strip_prefix("LPT"));
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || numbered.is_some_and(|suffix| matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
    {
        bail!("reserved DOS device name is not admitted for creation");
    }
    let mut flags = 0;
    for (part, bit) in [(base, 8), (extension, 16)] {
        let lower = part.bytes().any(|byte| byte.is_ascii_lowercase());
        let upper = part.bytes().any(|byte| byte.is_ascii_uppercase());
        if lower && upper {
            bail!("mixed-case short-name components require long-name creation support");
        }
        if lower {
            flags |= bit;
        }
    }
    let mut short = [b' '; 11];
    for (target, byte) in short[..8].iter_mut().zip(base.bytes()) {
        *target = byte.to_ascii_uppercase();
    }
    for (target, byte) in short[8..].iter_mut().zip(extension.bytes()) {
        *target = byte.to_ascii_uppercase();
    }
    Ok((short, flags))
}

fn parent(cx: &Cx, volume: &FatVolume, path: &str) -> Result<(Directory, String)> {
    if path.len() > 65_536
        || path.ends_with('/')
        || path.is_empty()
        || path.split('/').filter(|part| !part.is_empty() && *part != ".").take(257).count() > 256
    {
        bail!("creation requires a bounded non-root native file path");
    }
    let (parent_path, name) = path.rsplit_once('/').unwrap_or(("", path));
    let directory = match volume.resolve(cx, parent_path)? {
        None => Directory::Root,
        Some(entry) => {
            let directory = entry.directory()?;
            if entry.native.attributes & 0xC9 != 0 {
                bail!("creation parent has read-only or unsupported native attributes");
            }
            directory
        }
    };
    Ok((directory, name.to_owned()))
}

fn directory_offsets(cx: &Cx, volume: &FatVolume, directory: Directory) -> Result<Vec<u64>> {
    let mut offsets = Vec::new();
    if directory == Directory::Root
        && let Some((start, length)) = volume.geometry.fixed_root()
    {
        let count = usize::try_from(length / 32).context("FAT root slot count overflow")?;
        if count > MAX_DIRECTORY_SLOTS {
            bail!("creation parent exceeds the directory-slot budget");
        }
        offsets.try_reserve_exact(count).context("reserving bounded root slots")?;
        offsets.extend((start..start + length).step_by(32));
    } else {
        let first = match directory {
            Directory::Root => volume.geometry.root_cluster(),
            Directory::Cluster(first) => first,
        };
        let bytes = volume.geometry.cluster_bytes() as usize;
        let chain = volume.allocation_chain(
            cx,
            first,
            1,
            volume.cluster_offset(first)?,
            (MAX_DIRECTORY_SLOTS * 32).div_ceil(bytes),
        )?;
        let count = chain.len().checked_mul(bytes / 32).context("FAT directory slot overflow")?;
        if count > MAX_DIRECTORY_SLOTS {
            bail!("creation parent exceeds the directory-slot budget");
        }
        offsets.try_reserve_exact(count).context("reserving bounded directory slots")?;
        for cluster in chain {
            checkpoint(cx)?;
            let start = volume.cluster_offset(cluster)?;
            offsets.extend((start..start + bytes as u64).step_by(32));
        }
    }
    checkpoint(cx)?;
    Ok(offsets)
}

fn reserve_slot(cx: &Cx, volume: &FatVolume, directory: Directory) -> Result<(Slot, Namespace)> {
    let offsets = directory_offsets(cx, volume, directory)?;
    let mut preceding_lfn = false;
    for (index, offset) in offsets.iter().copied().enumerate() {
        checkpoint(cx)?;
        let mut bytes = [0; 32];
        volume.read_exact(cx, offset, &mut bytes)?;
        if bytes[0] == 0 || bytes[0] == 0xE5 {
            // An orphan long-name suffix must not adopt the newly created
            // short entry merely because its checksum happens to agree.
            if preceding_lfn {
                if bytes[0] == 0 {
                    bail!("orphan long-name records precede the directory end; native checking is required");
                }
                preceding_lfn = false;
                continue;
            }
            let successor = if bytes[0] == 0 {
                offsets.get(index + 1).map(|&offset| {
                    let mut bytes = [0; 32];
                    volume.read_exact(cx, offset, &mut bytes)?;
                    Ok::<_, anyhow::Error>(Slot { offset, bytes })
                }).transpose()?
            } else {
                None
            };
            return Ok((Slot { offset, bytes }, Namespace { successor }));
        }
        preceding_lfn = bytes[11] == 0x0F;
    }
    bail!("creation parent has no reusable directory slot; directory growth is not yet admitted")
}

pub(super) fn prepare(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    source: &dyn ByteDevice,
    now: u64,
) -> Result<Replacement> {
    checkpoint(cx)?;
    let size = u32::try_from(source.len_bytes()).context("FAT file size exceeds 2^32 - 1 bytes")?;
    let (date, time) = modified_timestamp(now)?;
    let (directory, name) = parent(cx, volume, path)?;
    let (short, flags) = short_name(&name)?;
    validate_boot_state(cx, volume)?;
    let before = volume.check(cx)?;
    if !before.clean || !before.complete || !before.namespace_complete {
        bail!("creation requires a complete clean allocation/namespace check: {}", serde_json::to_string(&before)?);
    }
    let key = volume.oem_code_page.name_key(&name);
    let conservative = name.to_uppercase().to_lowercase();
    for entry in volume.list(cx, directory)? {
        checkpoint(cx)?;
        let displayed = entry.name()?;
        let alias = entry.short_alias().context("creation requires representable native aliases")?;
        if entry.native.short_name == short
            || [displayed, alias].iter().any(|value| {
                volume.oem_code_page.name_key(value) == key
                    || value.to_uppercase().to_lowercase() == conservative
            })
        {
            bail!("--create never replaces an existing native name or short alias: {name:?}");
        }
    }
    let (slot, namespace) = reserve_slot(cx, volume, directory)?;
    let needed = u64::from(size).div_ceil(u64::from(volume.geometry.cluster_bytes())) as usize;
    let clusters = reserve_clusters(cx, volume, needed, before.free_clusters)?;
    let mut updated = [0; 32];
    updated[..11].copy_from_slice(&short);
    updated[11] = 0x20;
    updated[12] = flags;
    updated[13] = ((now % 2) * 100) as u8;
    updated[14..16].copy_from_slice(&time.to_le_bytes());
    updated[16..18].copy_from_slice(&date.to_le_bytes());
    updated[18..20].copy_from_slice(&date.to_le_bytes());
    updated[22..24].copy_from_slice(&time.to_le_bytes());
    updated[24..26].copy_from_slice(&date.to_le_bytes());
    let first = clusters.first().copied().unwrap_or(0);
    if volume.geometry.kind() == FatKind::Fat32 {
        updated[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
    }
    updated[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    updated[28..32].copy_from_slice(&size.to_le_bytes());
    let digest = hash_device(cx, source)?;
    checkpoint(cx)?;
    Ok(Replacement {
        path: path.to_owned(),
        entry_offset: slot.offset,
        old_size: 0,
        size,
        original: slot.bytes,
        updated,
        clusters,
        release: Vec::new(),
        digest,
        free_after: before.free_clusters - needed as u64,
        files: before.files.checked_add(1).context("FAT file count overflow")?,
        directories: before.directories,
        creation: Some(namespace),
    })
}

#[cfg(test)]
mod tests;
