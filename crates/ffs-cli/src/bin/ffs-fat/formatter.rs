//! Create a new empty FAT image; never open an existing image for mutation.
//!
//! The file is exclusively created and locked once. Verification uses a clone
//! of that same handle, so it neither reopens the path nor requests a second
//! advisory lock. Uncooperating writers are outside the advisory-lock contract.
//! Errors retain the new file, which may be incomplete; success requires file
//! and parent-directory synchronization plus the existing read-only checker.

#[cfg(test)]
mod tests;

use super::reader::{FatVolume, MAX_CHAIN_CLUSTERS, checkpoint};
use anyhow::{Context, Result, anyhow, bail};
use asupersync::Cx;
use clap::{Args, ValueEnum};
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_ondisk::fat::{FatGeometry, FatKind};
use ffs_types::ByteOffset;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SECTOR_BYTES: u64 = 512;
const FAT16_MIN_CLUSTERS: u64 = 4087;
const FAT16_MAX_CLUSTERS: u64 = 65_518;
const FAT32_MIN_CLUSTERS: u64 = 65_525;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FormatKind {
    Fat16,
    Fat32,
}

impl FormatKind {
    fn native(self) -> FatKind {
        match self {
            Self::Fat16 => FatKind::Fat16,
            Self::Fat32 => FatKind::Fat32,
        }
    }

    fn reserved_sectors(self) -> u64 {
        match self {
            Self::Fat16 => 1,
            Self::Fat32 => 32,
        }
    }

    fn fixed_root_sectors(self) -> u64 {
        match self {
            Self::Fat16 => 32,
            Self::Fat32 => 0,
        }
    }
}

#[derive(Debug, Args)]
pub struct FormatArgs {
    /// New regular image file. Existing files, symlinks and devices are refused.
    #[arg(value_name = "NEW_IMAGE")]
    image: PathBuf,
    /// Native dialect; geometry must fit this dialect and the checker budget.
    #[arg(long, value_enum)]
    kind: FormatKind,
    /// Exact logical image size in MiB (1048576 bytes); storage may be sparse.
    #[arg(long, value_name = "MIB")]
    size_mib: u64,
    /// 1..11 legal ASCII label bytes, uppercased; no leading or trailing space.
    #[arg(long)]
    label: Option<String>,
    /// Decimal 32-bit volume serial; defaults to a time-derived identifier.
    #[arg(long, value_name = "U32")]
    serial: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
    kind: FormatKind,
    total_sectors: u32,
    sectors_per_cluster: u8,
    fat_sectors: u32,
    data_clusters: u32,
    first_data_sector: u32,
}

impl Layout {
    fn calculate(kind: FormatKind, size_mib: u64) -> Result<Self> {
        let total = size_mib
            .checked_mul(2048)
            .filter(|total| *total != 0 && *total <= u64::from(u32::MAX))
            .ok_or_else(|| anyhow!("--size-mib must fit the nonzero 32-bit FAT sector count"))?;
        let width = u64::from(kind.native().entry_bytes());
        let headers = kind.reserved_sectors() + kind.fixed_root_sectors();
        for sectors_per_cluster in [1_u8, 2, 4, 8, 16, 32, 64, 128] {
            let cluster_sectors = u64::from(sectors_per_cluster);
            let mut low = 1_u64;
            let mut high = ((total / cluster_sectors + 2) * width).div_ceil(SECTOR_BYTES);
            // Increasing FAT size increases its capacity and reduces the data
            // clusters it must describe. Find the smallest sufficient copy.
            while low < high {
                let middle = low + (high - low) / 2;
                let clusters = total.saturating_sub(headers + 2 * middle) / cluster_sectors;
                if middle * SECTOR_BYTES >= (clusters + 2) * width {
                    high = middle;
                } else {
                    low = middle + 1;
                }
            }
            let first_data = headers + 2 * low;
            if first_data >= total {
                continue;
            }
            let clusters = (total - first_data) / cluster_sectors;
            let admitted = match kind {
                // 4085/4086 are formally FAT16 but some native implementations
                // classify them as FAT12. Never allocate reserved cluster IDs.
                FormatKind::Fat16 => {
                    (FAT16_MIN_CLUSTERS..=FAT16_MAX_CLUSTERS).contains(&clusters)
                        && low <= u64::from(u16::MAX)
                }
                FormatKind::Fat32 => {
                    (FAT32_MIN_CLUSTERS..=MAX_CHAIN_CLUSTERS as u64).contains(&clusters)
                }
            };
            if admitted {
                return Ok(Self {
                    kind,
                    total_sectors: total as u32,
                    sectors_per_cluster,
                    fat_sectors: low as u32,
                    data_clusters: clusters as u32,
                    first_data_sector: first_data as u32,
                });
            }
        }
        bail!(
            "size does not admit {:?} with 512-byte sectors, 1..128 sectors per cluster and the bounded FAT checker",
            kind.native()
        )
    }

    fn image_bytes(self) -> u64 {
        u64::from(self.total_sectors) * SECTOR_BYTES
    }

    fn root_sector(self) -> u64 {
        match self.kind {
            FormatKind::Fat16 => self.kind.reserved_sectors() + 2 * u64::from(self.fat_sectors),
            FormatKind::Fat32 => u64::from(self.first_data_sector),
        }
    }
}

struct Sector {
    offset: u64,
    bytes: [u8; 512],
}

struct FormatPlan {
    layout: Layout,
    label: Option<[u8; 11]>,
    serial: u32,
    boot: [u8; 512],
    before_boot: Vec<Sector>,
}

fn word(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn dword(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn volume_label(value: Option<&str>) -> Result<Option<[u8; 11]>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty()
        || value.len() > 11
        || value.starts_with(' ')
        || value.ends_with(' ')
        || value.bytes().any(|byte| {
            !(0x20..=0x7E).contains(&byte)
                || matches!(
                    byte,
                    b'"' | b'*' | b'+' | b',' | b'.' | b'/' | b':' | b';' | b'<'
                        | b'=' | b'>' | b'?' | b'[' | b'\\' | b']' | b'|'
                )
        })
    {
        bail!("--label requires 1..11 legal ASCII FAT label bytes without surrounding spaces");
    }
    let mut label = [b' '; 11];
    for (target, source) in label.iter_mut().zip(value.bytes()) {
        *target = source.to_ascii_uppercase();
    }
    Ok(Some(label))
}

impl FormatPlan {
    fn prepare(args: &FormatArgs) -> Result<Self> {
        if args.image.file_name().is_none() {
            bail!("format target must name a new regular file");
        }
        let layout = Layout::calculate(args.kind, args.size_mib)?;
        let label = volume_label(args.label.as_deref())?;
        let serial = if let Some(serial) = args.serial {
            serial
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("cannot derive FAT serial from the system clock; supply --serial")?;
            // A conventional volume identifier, not a uniqueness or security
            // guarantee. An explicit serial makes the image deterministic.
            (now.as_secs() as u32).rotate_left(16) ^ now.subsec_nanos()
        };
        let mut boot = [0_u8; 512];
        boot[..3].copy_from_slice(match layout.kind {
            FormatKind::Fat16 => &[0xEB, 0x3C, 0x90],
            FormatKind::Fat32 => &[0xEB, 0x58, 0x90],
        });
        boot[3..11].copy_from_slice(b"FRANKFS ");
        word(&mut boot, 11, 512);
        boot[13] = layout.sectors_per_cluster;
        word(&mut boot, 14, layout.kind.reserved_sectors() as u16);
        boot[16] = 2;
        boot[21] = 0xF8;
        word(&mut boot, 24, 63);
        word(&mut boot, 26, 255);
        let extension = match layout.kind {
            FormatKind::Fat16 => {
                word(&mut boot, 17, 512);
                word(&mut boot, 22, layout.fat_sectors as u16);
                if layout.total_sectors <= u32::from(u16::MAX) {
                    word(&mut boot, 19, layout.total_sectors as u16);
                } else {
                    dword(&mut boot, 32, layout.total_sectors);
                }
                boot[54..62].copy_from_slice(b"FAT16   ");
                boot[62..64].copy_from_slice(&[0xEB, 0xFE]);
                36
            }
            FormatKind::Fat32 => {
                dword(&mut boot, 32, layout.total_sectors);
                dword(&mut boot, 36, layout.fat_sectors);
                dword(&mut boot, 44, 2);
                word(&mut boot, 48, 1);
                word(&mut boot, 50, 6);
                boot[82..90].copy_from_slice(b"FAT32   ");
                boot[90..92].copy_from_slice(&[0xEB, 0xFE]);
                64
            }
        };
        boot[extension] = 0x80;
        boot[extension + 2] = 0x29;
        dword(&mut boot, extension + 3, serial);
        boot[extension + 7..extension + 18]
            .copy_from_slice(label.as_ref().unwrap_or(b"NO NAME    "));
        word(&mut boot, 510, 0xAA55);

        // Validate the finished BPB with the same parser used for real images,
        // before opening the output path at all.
        let geometry = FatGeometry::parse(&boot, layout.image_bytes())
            .map_err(|error| anyhow!("formatter produced invalid FAT geometry: {error}"))?;
        if geometry.kind() != layout.kind.native()
            || geometry.cluster_count() != layout.data_clusters
            || geometry.volume_bytes() != layout.image_bytes()
        {
            bail!("formatter geometry does not match its native BPB");
        }
        geometry
            .cluster_offset(layout.data_clusters + 1)
            .map_err(|error| anyhow!("formatter selected a reserved cluster identifier: {error}"))?;

        let mut fat = [0_u8; 512];
        match layout.kind {
            FormatKind::Fat16 => {
                word(&mut fat, 0, 0xFFF8);
                word(&mut fat, 2, 0xFFFF);
            }
            FormatKind::Fat32 => {
                dword(&mut fat, 0, 0x0FFF_FFF8);
                dword(&mut fat, 4, 0x0FFF_FFFF);
                dword(&mut fat, 8, 0x0FFF_FFFF);
            }
        }
        let mut root = [0_u8; 512];
        if let Some(label) = &label {
            root[..11].copy_from_slice(label);
            root[11] = 0x08;
            // Deterministic native 1980-01-01, including creation/access dates.
            word(&mut root, 16, 0x0021);
            word(&mut root, 18, 0x0021);
            word(&mut root, 24, 0x0021);
        }
        let mut before_boot = vec![
            Sector {
                offset: layout.kind.reserved_sectors() * SECTOR_BYTES,
                bytes: fat,
            },
            Sector {
                offset: (layout.kind.reserved_sectors() + u64::from(layout.fat_sectors))
                    * SECTOR_BYTES,
                bytes: fat,
            },
            Sector {
                offset: layout.root_sector() * SECTOR_BYTES,
                bytes: root,
            },
        ];
        if layout.kind == FormatKind::Fat32 {
            let mut info = [0_u8; 512];
            dword(&mut info, 0, 0x4161_5252);
            dword(&mut info, 484, 0x6141_7272);
            dword(&mut info, 488, layout.data_clusters - 1);
            dword(&mut info, 492, 3);
            dword(&mut info, 508, 0xAA55_0000);
            before_boot.extend([
                Sector {
                    offset: SECTOR_BYTES,
                    bytes: info,
                },
                Sector {
                    offset: 7 * SECTOR_BYTES,
                    bytes: info,
                },
                Sector {
                    offset: 6 * SECTOR_BYTES,
                    bytes: boot,
                },
            ]);
        }
        for sector in &before_boot {
            if sector.offset == 0
                || !sector.offset.is_multiple_of(SECTOR_BYTES)
                || sector.offset + SECTOR_BYTES > layout.image_bytes()
            {
                bail!("formatter metadata sector lies outside the new volume");
            }
        }
        Ok(Self {
            layout,
            label,
            serial,
            boot,
            before_boot,
        })
    }
}

/// Private injection boundary for initialization I/O and cancellation tests.
/// Production passes only the exclusively created, still-locked File.
trait ImageTarget {
    fn resize(&self, length: u64) -> io::Result<()>;
    fn write_sector(&self, offset: u64, bytes: &[u8; 512]) -> io::Result<()>;
    fn flush(&self) -> io::Result<()>;
}

impl ImageTarget for File {
    fn resize(&self, length: u64) -> io::Result<()> {
        self.set_len(length)
    }

    fn write_sector(&self, offset: u64, bytes: &[u8; 512]) -> io::Result<()> {
        self.write_all_at(bytes, offset)
    }

    fn flush(&self) -> io::Result<()> {
        self.sync_all()
    }
}

fn initialize(cx: &Cx, target: &impl ImageTarget, plan: &FormatPlan) -> Result<()> {
    checkpoint(cx)?;
    // create_new supplied a zero-length file. Extending it guarantees logical
    // zeros throughout both FATs, reserved areas, directories and free space;
    // no allocation or write scales with the image's logical byte length.
    target.resize(plan.layout.image_bytes())?;
    checkpoint(cx)?;
    for sector in &plan.before_boot {
        checkpoint(cx)?;
        target.write_sector(sector.offset, &sector.bytes)?;
        checkpoint(cx)?;
    }
    // The primary boot signature is published only after all other native
    // metadata is synchronized. Failure at any phase retains the new file.
    target.flush()?;
    checkpoint(cx)?;
    target.write_sector(0, &plan.boot)?;
    checkpoint(cx)?;
    target.flush()?;
    checkpoint(cx)?;
    Ok(())
}

/// Read-only capability over a clone of the already locked output handle.
/// Do not open the path again or ask for another advisory lock.
struct CreatedImage {
    file: File,
    length: u64,
}

impl ByteDevice for CreatedImage {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bytes: &mut [u8],
    ) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let end = offset
            .0
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| FfsError::InvalidGeometry("formatted-image read overflow".into()))?;
        if end > self.length {
            return Err(FfsError::InvalidGeometry(
                "formatted-image read exceeds the new file".into(),
            ));
        }
        self.file.read_exact_at(bytes, offset.0)?;
        checkpoint(cx)
    }

    fn write_all_at(
        &self,
        _cx: &Cx,
        _offset: ByteOffset,
        _bytes: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)
    }
}

fn verify_created(cx: &Cx, file: &File, plan: &FormatPlan) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    if file.metadata()?.len() != plan.layout.image_bytes() {
        bail!("new FAT image changed length during creation");
    }
    let boot_sector = Sector {
        offset: 0,
        bytes: plan.boot,
    };
    for sector in plan.before_boot.iter().chain(std::iter::once(&boot_sector)) {
        checkpoint(cx)?;
        let mut actual = [0_u8; 512];
        file.read_exact_at(&mut actual, sector.offset)?;
        checkpoint(cx)?;
        if actual != sector.bytes {
            bail!("new FAT metadata readback mismatch at byte {}", sector.offset);
        }
    }
    let volume = FatVolume::from_device(
        cx,
        Box::new(CreatedImage {
            file: file.try_clone()?,
            length: plan.layout.image_bytes(),
        }),
        0,
        plan.layout.image_bytes(),
    )?;
    let report = volume.check(cx)?;
    let allocated = u64::from(plan.layout.kind == FormatKind::Fat32);
    if !report.clean
        || report.files != 0
        || report.directories != 1
        || report.free_clusters != u64::from(plan.layout.data_clusters) - allocated
        || report.allocated_clusters != allocated
        || report.lost_clusters != Some(0)
    {
        bail!(
            "new FAT image failed empty-filesystem verification: {}",
            serde_json::to_string(&report)?
        );
    }
    checkpoint(cx)?;
    Ok(serde_json::to_value(report)?)
}

pub fn create(cx: &Cx, args: &FormatArgs) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    let plan = FormatPlan::prepare(args)?;
    let parent_path = args
        .image
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = File::open(parent_path)
        .with_context(|| format!("opening new-image parent {}", parent_path.display()))?;
    if !parent.metadata()?.is_dir() {
        bail!("new-image parent must be an existing directory");
    }
    checkpoint(cx)?;
    // O_EXCL creation is atomic and also refuses dangling symlinks. There is no
    // fallback open, truncate, overwrite, device path, or removal on error.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.image)
        .with_context(|| format!("exclusively creating new FAT image {}", args.image.display()))?;
    let finish = || -> Result<serde_json::Value> {
        checkpoint(cx)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != 0 {
            bail!("new FAT target is not an empty regular file");
        }
        file.try_lock()
            .map_err(|error| anyhow!("cannot exclusively lock new FAT image: {error}"))?;
        initialize(cx, &file, &plan)?;
        let verification = verify_created(cx, &file, &plan)?;
        checkpoint(cx)?;
        parent.sync_all().context("synchronizing the new-image directory entry")?;
        checkpoint(cx)?;
        let label = plan
            .label
            .as_ref()
            .map(|label| String::from_utf8_lossy(label).trim_end().to_owned());
        Ok(serde_json::json!({
            "operation": "create_new_image",
            "created_new_image": true,
            "image": args.image.display().to_string(),
            "format": format!("{:?}", plan.layout.kind.native()),
            "volume_bytes": plan.layout.image_bytes(),
            "sector_bytes": SECTOR_BYTES,
            "cluster_bytes": u64::from(plan.layout.sectors_per_cluster) * SECTOR_BYTES,
            "data_clusters": plan.layout.data_clusters,
            "fat_sectors": plan.layout.fat_sectors,
            "fat_copies": 2,
            "mirrored": true,
            "label": label,
            "serial": plan.serial,
            "storage": "logical zeros in a new file; physical storage may be sparse",
            "verification": verification
        }))
    };
    finish().with_context(|| {
        format!(
            "creating {}; the new file was retained and may be incomplete",
            args.image.display()
        )
    })
}
