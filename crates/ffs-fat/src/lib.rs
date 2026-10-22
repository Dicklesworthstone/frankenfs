#![forbid(unsafe_code)]
//! Experimental native FAT16/FAT32 image and filesystem operations.
//!
//! Callers supply their own capability context and own the runtime and signal
//! lifecycle. Read admission never grants write authority; offline mutation
//! retains its separate explicit options and exclusive-open checks.

macro_rules! companion_bin_tests {
    ($($item:item)*) => {
        $($item)*
    };
}

pub mod filesystem;
pub mod formatter;
pub mod reader;
pub mod resize;

use asupersync::Cx;
use clap::{Parser, Subcommand};
use ffs_error::FfsError;
use ffs_ondisk::fat::FatKind;
pub use filesystem::FatFs;
use reader::checkpoint;
pub use reader::{
    CheckIssue, Directory, Entry, FatCheckReport, FatVolume, FileChain, FileReader, ImageArgs,
};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "ffs-fat",
    about = "Read, create or explicitly replace files in offline FAT16/FAT32 images"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Root-to-entry chain of volume-relative native short-entry byte offsets.
/// These identify entries only while the selected image remains immutable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntrySlots(Vec<u64>);

impl EntrySlots {
    const MAX_COMPONENTS: usize = 256;
    const MAX_INPUT_BYTES: usize = 21 * Self::MAX_COMPONENTS - 1;

    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        if value.is_empty() || value.len() > Self::MAX_INPUT_BYTES {
            return Err("expected 1..256 comma-separated decimal entry offsets".into());
        }
        let mut slots = Vec::new();
        for component in value.split(',') {
            if slots.len() == Self::MAX_COMPONENTS
                || component.is_empty()
                || component.len() > 20
                || !component.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err("expected 1..256 comma-separated decimal entry offsets".into());
            }
            let offset = component
                .parse::<u64>()
                .map_err(|_| "FAT entry offset exceeds u64".to_owned())?;
            if !offset.is_multiple_of(32) {
                return Err("FAT entry offsets must be aligned to 32 bytes".into());
            }
            slots.push(offset);
        }
        Ok(Self(slots))
    }

    pub fn encoded(&self) -> String {
        self.0
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Each offset must belong to the complete validated directory reached by
    /// its preceding components. Never reinterpret arbitrary image bytes as an
    /// entry, nor stop parsing a directory when the requested slot is found.
    pub fn resolve(&self, cx: &Cx, volume: &FatVolume) -> ffs_error::Result<Option<Entry>> {
        checkpoint(cx)?;
        if self.0.len() > Self::MAX_COMPONENTS {
            return Err(FfsError::NameTooLong);
        }
        let mut directory = Directory::Root;
        let mut ancestors = BTreeSet::new();
        if volume.geometry.kind() == FatKind::Fat32 {
            ancestors.insert(volume.geometry.root_cluster());
        }
        let mut result = None;
        for (index, &offset) in self.0.iter().enumerate() {
            checkpoint(cx)?;
            let mut found = None;
            for entry in volume.list(cx, directory)? {
                checkpoint(cx)?;
                let _ = native_presentation(&entry)?;
                if entry.offset == offset {
                    if found.is_some() {
                        return Err(FfsError::Corruption {
                            block: offset / 512,
                            detail: "duplicate FAT directory-slot identity".into(),
                        });
                    }
                    found = Some(entry);
                }
            }
            let entry = found.ok_or_else(|| {
                FfsError::NotFound(format!(
                    "FAT entry slot {offset} is not in its selected parent"
                ))
            })?;
            if entry.native.is_directory() && !ancestors.insert(entry.native.first_cluster) {
                return Err(FfsError::Corruption {
                    block: offset / 512,
                    detail: "FAT directory links to an ancestor".into(),
                });
            }
            if index + 1 < self.0.len() {
                directory = entry.directory()?;
            }
            result = Some(entry);
        }
        checkpoint(cx)?;
        Ok(result)
    }
}

/// Lack of a host display spelling is not native corruption. Preserve the raw
/// name in the catalog, but keep structural name errors fatal.
fn native_presentation(entry: &Entry) -> ffs_error::Result<(Option<String>, Option<String>)> {
    // Inspect native units first: an unpaired surrogate must not hide a path
    // separator merely because UTF-16 display conversion fails before seeing it.
    let invalid_short = entry.native.short_name[..8]
        .iter()
        .all(|byte| *byte == b' ')
        || entry
            .native
            .short_name
            .iter()
            .any(|byte| matches!(*byte, 0 | b'/' | b'\\'));
    let invalid_long = entry.native.long_name.as_ref().is_some_and(|units| {
        units.is_empty()
            || matches!(units.as_slice(), [0x002E] | [0x002E, 0x002E])
            || units
                .iter()
                .any(|unit| matches!(*unit, 0 | 0x002F | 0x005C))
    });
    if invalid_short || invalid_long {
        return Err(FfsError::Corruption {
            block: entry.offset / 512,
            detail: "FAT native name is not a safe path component".into(),
        });
    }
    match entry.name() {
        Ok(name) => Ok((Some(name), None)),
        Err(error @ (FfsError::UnsupportedFeature(_) | FfsError::NameTooLong)) => {
            Ok((None, Some(error.to_string())))
        }
        Err(error) => Err(error),
    }
}

pub fn native_catalog(
    cx: &Cx,
    volume: &FatVolume,
    slots: &EntrySlots,
    volume_offset: u64,
) -> ffs_error::Result<serde_json::Value> {
    let directory = slots
        .resolve(cx, volume)?
        .map_or(Ok(Directory::Root), |entry| entry.directory())?;
    let entries = volume.list(cx, directory)?;
    if slots.0.len() == EntrySlots::MAX_COMPONENTS && !entries.is_empty() {
        return Err(FfsError::NameTooLong);
    }
    let mut report = Vec::with_capacity(entries.len());
    for entry in entries {
        checkpoint(cx)?;
        let (name, display_error) = native_presentation(&entry)?;
        let mut child = slots.clone();
        child.0.push(entry.offset);
        report.push(serde_json::json!({
            "entry_slots": child.encoded(),
            "entry_offset": entry.offset,
            "name": name,
            "display_error": display_error,
            "short_name_bytes": entry.native.short_name,
            "short_alias": entry.short_alias(),
            "long_name_utf16": entry.native.long_name,
            "case_flags": entry.native.case_flags,
            "attributes": entry.native.attributes,
            "directory": entry.native.is_directory(),
            "size": entry.native.size,
            "first_cluster": entry.native.first_cluster
        }));
    }
    checkpoint(cx)?;
    Ok(serde_json::json!({
        "format": format!("{:?}", volume.geometry.kind()),
        "read_only": true,
        "oem_code_page": volume.oem_code_page().label(),
        "volume_offset": volume_offset,
        "volume_bytes": volume.geometry.volume_bytes(),
        "entry_offset_origin": "selected_volume",
        "selector_scope": "current immutable image; not persistent file handles",
        "directory_entry_slots": (!slots.0.is_empty()).then(|| slots.encoded()),
        "entries": report
    }))
}

/// Validate allocation before emitting data. A later I/O or output failure may
/// leave an earlier streamed prefix, and is always returned as an error.
pub fn stream_file(
    cx: &Cx,
    volume: &FatVolume,
    entry: &Entry,
    output: &mut impl Write,
) -> ffs_error::Result<()> {
    let mut reader = volume.open_file_reader(cx, entry)?;
    let mut offset = 0_u64;
    while offset < reader.len_bytes() {
        let bytes = reader.read(cx, offset, 1024 * 1024)?;
        output.write_all(&bytes)?;
        offset += bytes.len() as u64;
    }
    checkpoint(cx)?;
    output.flush()?;
    Ok(())
}

pub fn extract_slots(
    cx: &Cx,
    volume: &FatVolume,
    slots: &EntrySlots,
    output: &mut impl Write,
) -> ffs_error::Result<()> {
    let entry = slots.resolve(cx, volume)?.ok_or(FfsError::IsDirectory)?;
    stream_file(cx, volume, &entry, output)
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Resize into a new standalone image without modifying the offline source.
    /// Preserves cluster numbers; shrinking requires a completely free tail.
    Resize {
        #[command(flatten)]
        options: resize::ResizeArgs,
    },
    /// Repair verified lost allocation, FSInfo hints and native dirty state offline.
    /// Does not restore interrupted file contents; keep a separate copy first.
    Recover {
        #[command(flatten)]
        options: reader::recovery::RecoverArgs,
    },
    /// Repair recognizable . and .. pointers from unique rooted directory ownership.
    /// Leaves changed images dirty; does not reclaim allocation or restore payload.
    RepairParents {
        #[command(flatten)]
        options: reader::recovery::RepairParentsArgs,
    },
    /// Rebuild declared FAT32 FSInfo from verified allocation, not old hint values.
    /// Leaves changed images dirty; never reclaims allocation or invents a sector.
    #[command(name = "repair-fsinfo")]
    RepairFsInfo {
        #[command(flatten)]
        options: reader::recovery::RepairFsInfoArgs,
    },
    /// Replace an existing regular file using initialized, separately allocated clusters.
    /// Requires exclusive offline ownership; --dry-run performs only preflight reads.
    Replace {
        #[command(flatten)]
        options: reader::replacement::ReplaceArgs,
    },
    /// Create one native directory with initialized . and .. entries.
    /// Requires exclusive offline ownership; --dry-run performs only preflight reads.
    Mkdir {
        #[command(flatten)]
        options: reader::replacement::MkdirArgs,
    },
    /// Unlink one native regular file and release its cluster chain.
    /// Requires exclusive offline ownership; --dry-run performs only preflight reads.
    Unlink {
        #[command(flatten)]
        options: reader::replacement::UnlinkArgs,
    },
    /// Remove one empty native directory and release its cluster chain.
    /// Requires exclusive offline ownership; --dry-run performs only preflight reads.
    Rmdir {
        #[command(flatten)]
        options: reader::replacement::RmdirArgs,
    },
    /// Rename or move one native file or directory.
    /// Requires exclusive offline ownership; --dry-run performs only preflight reads.
    Rename {
        #[command(flatten)]
        options: reader::replacement::RenameArgs,
    },
    /// Create a new FAT16/FAT32 image, optionally copy --source-dir, and verify it.
    /// Existing files and devices are never formatted.
    Format {
        #[command(flatten)]
        options: formatter::FormatArgs,
    },
    /// Validate boot geometry, clean-state admission and FAT reserved records.
    Inspect {
        #[command(flatten)]
        image: ImageArgs,
    },
    /// Check allocation ownership, chain sizes, directories and FAT32 hints.
    /// Emits JSON; findings or incomplete coverage cause a nonzero exit.
    Check {
        #[command(flatten)]
        image: ImageArgs,
    },
    /// List a directory as JSON, preserving safely representable native names.
    Ls {
        #[command(flatten)]
        image: ImageArgs,
        #[arg(default_value = "/")]
        path: String,
    },
    /// Stream a file's logical bytes to stdout; diagnostics go to stderr.
    Cat {
        #[command(flatten)]
        image: ImageArgs,
        path: String,
    },
    /// List native names and exact selectors, including names with no host spelling.
    Catalog {
        #[command(flatten)]
        image: ImageArgs,
        /// Directory selector from catalog: decimal volume-relative entry offsets.
        /// Omit for the root. Selectors require the same immutable image.
        #[arg(
            long,
            value_parser = EntrySlots::parse,
            value_name = "OFFSET[,OFFSET...]"
        )]
        entry_slots: Option<EntrySlots>,
    },
    /// Stream a native file selected from catalog, without converting its name.
    Extract {
        #[command(flatten)]
        image: ImageArgs,
        /// Root-to-file selector from catalog, relative to the selected volume.
        /// Every component must be a live entry in its selected parent directory.
        #[arg(
            long,
            value_parser = EntrySlots::parse,
            value_name = "OFFSET[,OFFSET...]"
        )]
        entry_slots: EntrySlots,
    },
    /// Mount an image through the existing FrankenFS FUSE adapter.
    Mount {
        #[command(flatten)]
        image: ImageArgs,
        /// Existing empty directory, outside the image's own path.
        mountpoint: PathBuf,
        /// Confirm the image will not be modified by a kernel mount or another program.
        #[arg(long, required = true)]
        offline_image: bool,
        /// Mount read-write instead of read-only.
        #[arg(long)]
        rw: bool,
        /// Synthetic Unix ownership; never written into native FAT metadata.
        #[arg(long, default_value_t = 0)]
        uid: u32,
        #[arg(long, default_value_t = 0)]
        gid: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::fat::FatOemCodePage;

    #[test]
    fn cli_requires_an_explicit_supported_oem_code_page() {
        for (value, page) in [
            ("ascii", FatOemCodePage::Ascii),
            ("437", FatOemCodePage::Cp437),
            ("850", FatOemCodePage::Cp850),
        ] {
            for command in ["ls", "check", "catalog"] {
                let cli =
                    Cli::try_parse_from(["ffs-fat", command, "disk.img", "--oem-code-page", value])
                        .unwrap();
                let (Command::Ls { image, .. }
                | Command::Check { image }
                | Command::Catalog { image, .. }) = cli.command
                else {
                    panic!("expected image command");
                };
                assert_eq!(image.oem_code_page, page);
            }
        }
        for invalid in ["auto", "utf8", "932", "", "CP850"] {
            assert!(
                Cli::try_parse_from(["ffs-fat", "ls", "disk.img", "--oem-code-page", invalid])
                    .is_err()
            );
        }
        let Command::Ls { image, .. } = Cli::try_parse_from(["ffs-fat", "ls", "disk.img"])
            .unwrap()
            .command
        else {
            panic!("expected ls");
        };
        assert_eq!(image.oem_code_page, FatOemCodePage::Ascii);
        assert!(
            Cli::try_parse_from([
                "ffs-fat",
                "mount",
                "disk.img",
                "/mnt/fat",
                "--offline-image",
                "--oem-code-page",
                "850"
            ])
            .is_ok()
        );
    }

    #[test]
    fn check_accepts_a_bounded_volume_and_refuses_repair_options() {
        let cli = Cli::try_parse_from([
            "ffs-fat", "check", "disk.img", "--offset", "1024", "--length", "4096",
        ])
        .unwrap();
        let Command::Check { image } = cli.command else {
            panic!("expected check");
        };
        assert_eq!((image.offset, image.length), (1024, Some(4096)));
        for option in ["--repair", "--rw"] {
            assert!(Cli::try_parse_from(["ffs-fat", "check", "disk.img", option]).is_err());
        }
    }

    #[test]
    fn clap_accepts_explicit_ranges_and_has_no_write_switch() {
        let cli = Cli::try_parse_from([
            "ffs-fat",
            "cat",
            "disk.img",
            "--offset",
            "1024",
            "--length",
            "4096",
            "/hello.txt",
        ])
        .unwrap();
        let Command::Cat { image, path } = cli.command else {
            panic!("expected cat");
        };
        assert_eq!((image.offset, image.length), (1024, Some(4096)));
        assert_eq!(path, "/hello.txt");
        assert!(matches!(
            Cli::try_parse_from(["ffs-fat", "check", "disk.img", "--offset", "1024"])
                .unwrap()
                .command,
            Command::Check { .. }
        ));
        assert!(Cli::try_parse_from(["ffs-fat", "check", "disk.img", "--repair"]).is_err());
        assert!(Cli::try_parse_from(["ffs-fat", "cat", "disk.img", "/hello.txt", "--rw"]).is_err());
        assert!(Cli::try_parse_from(["ffs-fat", "mount", "disk.img", "/mnt/fat"]).is_err());
        assert!(
            Cli::try_parse_from([
                "ffs-fat",
                "mount",
                "disk.img",
                "/mnt/fat",
                "--offline-image"
            ])
            .is_ok()
        );
    }

    #[test]
    fn native_slot_parser_is_exact_bounded_and_round_trips() {
        assert_eq!(
            EntrySlots::parse("20992,22592").unwrap().0,
            [20_992, 22_592]
        );
        let largest = !31_u64;
        let encoded = format!("0,32,{largest}");
        assert_eq!(EntrySlots::parse(&encoded).unwrap().encoded(), encoded);
        let maximum = vec!["32"; 256].join(",");
        assert_eq!(EntrySlots::parse(&maximum).unwrap().0.len(), 256);
        assert!(EntrySlots::parse(&vec!["32"; 257].join(",")).is_err());
        for value in [
            "",
            ",32",
            "32,",
            "32,,64",
            " 32",
            "32 ",
            "+32",
            "-32",
            "0x20",
            "1",
            "31",
            "33",
            "32/64",
            "18446744073709551616",
            "000000000000000000032",
        ] {
            assert!(EntrySlots::parse(value).is_err(), "{value:?}");
        }
        assert!(EntrySlots::parse(&"0".repeat(EntrySlots::MAX_INPUT_BYTES + 1)).is_err());
    }

    #[test]
    fn native_commands_use_typed_selectors_and_keep_explicit_volume_ranges() {
        let cli = Cli::try_parse_from(["ffs-fat", "catalog", "disk.img"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Catalog {
                entry_slots: None,
                ..
            }
        ));
        for command in ["catalog", "extract"] {
            let cli = Cli::try_parse_from([
                "ffs-fat",
                command,
                "disk.img",
                "--offset",
                "1024",
                "--length",
                "4096",
                "--entry-slots",
                "20992,22592",
            ])
            .unwrap();
            let (image, slots) = match cli.command {
                Command::Catalog { image, entry_slots } => (image, entry_slots.unwrap()),
                Command::Extract { image, entry_slots } => (image, entry_slots),
                _ => panic!("expected native command"),
            };
            assert_eq!((image.offset, image.length), (1024, Some(4096)));
            assert_eq!(slots.0, [20_992, 22_592]);
            for value in ["", "1", "32,", "32,,64"] {
                assert!(
                    Cli::try_parse_from(["ffs-fat", command, "disk.img", "--entry-slots", value])
                        .is_err()
                );
            }
            assert!(
                Cli::try_parse_from([
                    "ffs-fat",
                    command,
                    "disk.img",
                    "--entry-slots",
                    "32",
                    "--rw"
                ])
                .is_err()
            );
        }
        assert!(Cli::try_parse_from(["ffs-fat", "extract", "disk.img"]).is_err());
        assert!(
            Cli::try_parse_from([
                "ffs-fat",
                "extract",
                "disk.img",
                "--entry-slots",
                "32",
                "--entry-slots",
                "64"
            ])
            .is_err()
        );
    }

    #[test]
    fn native_names_reject_raw_separators_before_display_decoding() {
        use ffs_ondisk::fat::{FatDirectoryDecoder, short_name_checksum};

        for kind in [FatKind::Fat16, FatKind::Fat32] {
            let mut short = [0_u8; 32];
            short[..11].copy_from_slice(b"RAW     BIN");
            short[11] = 0x20;
            for (units, invalid) in [
                ([0xD800_u16, 0x0061], false),
                ([0xD800, 0x002F], true),
                ([0x005C, 0xD800], true),
                ([0x002E, 0x002E], true),
            ] {
                let mut long = [0_u8; 32];
                long[0] = 0x41;
                long[11] = 0x0F;
                long[13] = short_name_checksum(b"RAW     BIN");
                for (index, offset) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                    .into_iter()
                    .enumerate()
                {
                    let unit = units
                        .get(index)
                        .copied()
                        .unwrap_or(if index == units.len() { 0 } else { 0xFFFF });
                    long[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
                }
                let mut decoder = FatDirectoryDecoder::default();
                assert!(decoder.push(&long, kind).unwrap().is_none());
                let native = decoder.push(&short, kind).unwrap().unwrap();
                assert_eq!(native.long_name.as_deref(), Some(units.as_slice()));
                let entry = Entry {
                    offset: 4096,
                    native,
                    oem_code_page: FatOemCodePage::Ascii,
                };
                let result = native_presentation(&entry);
                if invalid {
                    assert!(matches!(result, Err(FfsError::Corruption { block: 8, .. })));
                } else {
                    let (name, error) = result.unwrap();
                    assert!(name.is_none());
                    assert!(error.is_some());
                }
            }
            for byte in [0, b'/', b'\\'] {
                short[0] = 0x82;
                short[1] = byte;
                let entry = Entry {
                    offset: 4096,
                    oem_code_page: FatOemCodePage::Ascii,
                    native: FatDirectoryDecoder::default()
                        .push(&short, kind)
                        .unwrap()
                        .unwrap(),
                };
                assert!(matches!(
                    native_presentation(&entry),
                    Err(FfsError::Corruption { block: 8, .. })
                ));
            }
            short[..8].fill(b' ');
            let entry = Entry {
                offset: 4096,
                oem_code_page: FatOemCodePage::Ascii,
                native: FatDirectoryDecoder::default()
                    .push(&short, kind)
                    .unwrap()
                    .unwrap(),
            };
            assert!(matches!(
                native_presentation(&entry),
                Err(FfsError::Corruption { block: 8, .. })
            ));
        }
    }

    #[test]
    fn fat_cli_mutations_refresh_raptorq_sidecar_and_repair_corruption_bd_q19uk() {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("volume.fat");
        let sidecar = dir.path().join("volume.ffs-rq");

        // 1. Format with --sidecar
        let cli = Cli::try_parse_from([
            "ffs-fat",
            "format",
            image.to_str().unwrap(),
            "--size-mib",
            "8",
            "--kind",
            "fat16",
            "--sidecar",
            sidecar.to_str().unwrap(),
        ])
        .unwrap();
        let Command::Format { options } = cli.command else {
            panic!("format");
        };
        let report = formatter::create(&cx, &options).unwrap();
        assert_eq!(report["sidecar_refreshed"], true);
        assert!(
            ffs_repair::sidecar::verify(&cx, &image, &sidecar)
                .unwrap()
                .is_healthy()
        );

        // 2. mkdir --sidecar refreshes sidecar
        let cli = Cli::try_parse_from([
            "ffs-fat",
            "mkdir",
            image.to_str().unwrap(),
            "/docs",
            "--offline-image",
            "--sidecar",
            sidecar.to_str().unwrap(),
        ])
        .unwrap();
        let Command::Mkdir { options } = cli.command else {
            panic!("mkdir");
        };
        let mkdir_rep = reader::replacement::run_mkdir(&cx, &options).unwrap();
        assert_eq!(mkdir_rep["sidecar_refreshed"], true);
        assert!(
            ffs_repair::sidecar::verify(&cx, &image, &sidecar)
                .unwrap()
                .is_healthy()
        );

        // 3. rename --sidecar refreshes sidecar
        let cli = Cli::try_parse_from([
            "ffs-fat",
            "rename",
            image.to_str().unwrap(),
            "/docs",
            "/archive",
            "--offline-image",
            "--sidecar",
            sidecar.to_str().unwrap(),
        ])
        .unwrap();
        let Command::Rename { options } = cli.command else {
            panic!("rename");
        };
        let rename_rep = reader::replacement::run_rename(&cx, &options).unwrap();
        assert_eq!(rename_rep["sidecar_refreshed"], true);
        assert!(
            ffs_repair::sidecar::verify(&cx, &image, &sidecar)
                .unwrap()
                .is_healthy()
        );

        // 4. rmdir --sidecar refreshes sidecar
        let cli = Cli::try_parse_from([
            "ffs-fat",
            "rmdir",
            image.to_str().unwrap(),
            "/archive",
            "--offline-image",
            "--sidecar",
            sidecar.to_str().unwrap(),
        ])
        .unwrap();
        let Command::Rmdir { options } = cli.command else {
            panic!("rmdir");
        };
        let rmdir_rep = reader::replacement::run_rmdir(&cx, &options).unwrap();
        assert_eq!(rmdir_rep["sidecar_refreshed"], true);
        assert!(
            ffs_repair::sidecar::verify(&cx, &image, &sidecar)
                .unwrap()
                .is_healthy()
        );
    }
}
