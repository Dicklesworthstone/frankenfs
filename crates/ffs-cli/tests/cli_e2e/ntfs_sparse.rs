//! Native ntfs-3g interoperability checks for logged sparse hole punching.

use super::ntfs_ea::{native_attribute_clusters, replace_owned_clusters};
use super::{command_available, run_cli_binary, sha256_file};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Output;

const CLUSTER_BYTES: u64 = 4096;
const VOLUME_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
struct NativeData {
    resident: bool,
    flags: u64,
    size: u64,
    initialized: u64,
    clusters: BTreeSet<u64>,
    holes: u64,
}

struct ExpectedData {
    unnamed: Vec<u8>,
    payload: Vec<u8>,
    resident: Vec<u8>,
    unnamed_clusters: usize,
    payload_clusters: usize,
    unnamed_sparse: bool,
    payload_sparse: bool,
}

fn checked(binary: &Path, arguments: &[&str]) -> Output {
    let output = run_cli_binary(binary, arguments);
    assert!(
        output.status.success(),
        "{} {arguments:?} failed: stdout={} stderr={}",
        binary.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn native_field<'a>(text: &'a str, label: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.trim().strip_prefix(label))
        .unwrap_or_else(|| panic!("native output is missing {label}"))
        .trim()
}

fn native_number(text: &str, label: &str) -> u64 {
    native_field(text, label)
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

fn native_hex(value: &str) -> u64 {
    u64::from_str_radix(value.strip_prefix("0x").expect("native hex field"), 16).unwrap()
}

fn native_data_streams(information: &[u8]) -> BTreeMap<String, NativeData> {
    let text = String::from_utf8_lossy(information);
    let mut streams = BTreeMap::new();
    for block in text.split("Dumping attribute ").skip(1) {
        if block.lines().next().unwrap().split_whitespace().nth(1) != Some("(0x80)") {
            continue;
        }
        let name = block
            .lines()
            .find_map(|line| line.trim().strip_prefix("Attribute name:"))
            .map_or_else(String::new, |name| {
                name.trim()
                    .strip_prefix('\'')
                    .and_then(|name| name.strip_suffix('\''))
                    .expect("native ASCII stream name")
                    .to_owned()
            });
        let resident = match native_field(block, "Resident:") {
            "Yes" => true,
            "No" => false,
            other => panic!("unexpected native residency {other}"),
        };
        let flags = native_hex(native_field(block, "Attribute flags:"));
        let size = native_number(block, "Data size:");
        let initialized = if resident {
            size
        } else {
            native_number(block, "Initialized size:")
        };
        let mut clusters = BTreeSet::new();
        let mut holes = 0_u64;
        if !resident {
            let (_, runlist) = block.split_once("Runlist:").expect("native DATA runlist");
            let mut next_vcn = 0_u64;
            for line in runlist.lines().skip(1) {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.first().is_none_or(|field| !field.starts_with("0x")) {
                    break;
                }
                assert_eq!(fields.len(), 3, "native VCN/LCN/length row");
                assert_eq!(native_hex(fields[0]), next_vcn, "contiguous native VCNs");
                let length = native_hex(fields[2]);
                assert!(length > 0);
                next_vcn = next_vcn.checked_add(length).unwrap();
                // ntfs-3g's ntfsinfo prints LCN_HOLE as <HOLE>, while other
                // negative LCN markers represent errors and must fail below.
                if fields[1] == "<HOLE>" {
                    holes = holes.checked_add(length).unwrap();
                } else {
                    let first = native_hex(fields[1]);
                    let end = first.checked_add(length).unwrap();
                    assert!(end <= VOLUME_BYTES / CLUSTER_BYTES);
                    for cluster in first..end {
                        assert!(clusters.insert(cluster), "DATA aliases cluster {cluster}");
                    }
                }
            }
            assert_eq!(next_vcn, size.div_ceil(CLUSTER_BYTES));
            assert_eq!(
                native_number(block, "Allocated size:"),
                next_vcn * CLUSTER_BYTES
            );
            if flags & 0x8000 != 0 {
                assert_eq!(
                    native_number(block, "Compressed size:"),
                    clusters.len() as u64 * CLUSTER_BYTES,
                    "native sparse physical size matches its allocated runs"
                );
            } else {
                assert_eq!(holes, 0, "ordinary DATA cannot contain sparse runs");
            }
        }
        assert!(
            streams
                .insert(
                    name,
                    NativeData {
                        resident,
                        flags,
                        size,
                        initialized,
                        clusters,
                        holes,
                    },
                )
                .is_none(),
            "fixture DATA must not require duplicate attribute extents"
        );
    }
    streams
}

fn add_owners(owners: &mut BTreeSet<u64>, clusters: &BTreeSet<u64>) {
    for &cluster in clusters {
        assert!(
            owners.insert(cluster),
            "native owners alias cluster {cluster}"
        );
    }
}

fn allocated_clusters(bitmap: &[u8]) -> u64 {
    bitmap.iter().map(|byte| u64::from(byte.count_ones())).sum()
}

fn data_metadata(record: &serde_json::Value, name: &str) -> serde_json::Value {
    let mut attribute = record["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|attribute| attribute["type"] == "0x80" && attribute["name"] == name)
        .expect("expected DATA attribute")
        .clone();
    // Catalog packing may renumber attribute instances, while all semantic
    // metadata of an unrelated stream must remain exactly unchanged.
    attribute.as_object_mut().unwrap().remove("instance");
    attribute
}

fn native_file_flags(image: &str, path: &str) -> u32 {
    let information = checked(Path::new("ntfscat"), &["-a", "16", image, path]).stdout;
    assert!(information.len() >= 36, "native STANDARD_INFORMATION");
    u32::from_le_bytes(information[32..36].try_into().unwrap())
}

#[test]
#[ignore = "requires ntfs-3g mkntfs, ntfscp, ntfscat, ntfsls, ntfsinfo and ntfsfix; checks native sparse reclamation and bounded writes"]
fn native_ntfs_hole_punch_cli_preserves_streams_allocation_and_volume_bounds() {
    for tool in [
        "mkntfs", "ntfscp", "ntfscat", "ntfsls", "ntfsinfo", "ntfsfix",
    ] {
        assert!(
            command_available(tool),
            "native NTFS sparse test requires {tool}; install ntfs-3g before explicitly running it"
        );
    }
    let directory = tempfile::tempdir().expect("native NTFS sparse test directory");
    let native_image = directory.path().join("native.img");
    let embedded_image = directory.path().join("embedded.img");
    let source_file = directory.path().join("source.bin");
    fs::File::create(&native_image)
        .unwrap()
        .set_len(VOLUME_BYTES)
        .unwrap();
    let native_path = native_image.to_str().unwrap();
    checked(
        Path::new("mkntfs"),
        &["-F", "-Q", "-s", "512", "-c", "4096", native_path],
    );

    let unnamed: Vec<u8> = (1_u8..=251).cycle().take(16 * 4096).collect();
    let payload: Vec<u8> = (3_u8..=253).cycle().take(12 * 4096).collect();
    let resident: Vec<u8> = (1_u8..=96).collect();
    let keep = b"immutable resident alternate DATA";
    let sentinel: Vec<u8> = (2_u8..=252).cycle().take(4096 + 211).collect();
    for (path, stream, bytes) in [
        ("/dense.bin", None, unnamed.as_slice()),
        ("/dense.bin", Some("Payload"), payload.as_slice()),
        ("/dense.bin", Some("Keep"), keep.as_slice()),
        ("/resident.bin", None, resident.as_slice()),
        ("/untouched.bin", None, sentinel.as_slice()),
    ] {
        fs::write(&source_file, bytes).unwrap();
        let mut arguments = Vec::new();
        if let Some(stream) = stream {
            arguments.extend(["-N", stream]);
        }
        arguments.extend([native_path, source_file.to_str().unwrap(), path]);
        checked(Path::new("ntfscp"), &arguments);
    }
    let listing = checked(Path::new("ntfsls"), &["-a", "-i", "-p", "/", native_path]);
    let listing = String::from_utf8(listing.stdout).unwrap();
    let number = |name: &str| {
        listing
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let number = fields.next()?.parse::<u64>().ok()?;
                (fields.next()? == name).then_some(number)
            })
            .unwrap_or_else(|| panic!("native directory is missing {name}"))
    };
    let dense_number = number("dense.bin").to_string();
    let resident_number = number("resident.bin").to_string();
    let original_bitmap = checked(Path::new("ntfscat"), &["-i", "6", native_path]).stdout;
    let original_mft_bitmap =
        checked(Path::new("ntfscat"), &["-i", "0", "-a", "176", native_path]).stdout;
    assert!(!original_bitmap.is_empty() && !original_mft_bitmap.is_empty());
    let original_root = checked(Path::new("ntfsinfo"), &["-v", "-i", "5", native_path]);
    let original_root_clusters = native_attribute_clusters(
        &original_root.stdout,
        "(0xa0)",
        VOLUME_BYTES / CLUSTER_BYTES,
    );
    assert!(
        !original_root_clusters.is_empty(),
        "native root has external I30"
    );
    let original_dense = native_data_streams(
        &checked(
            Path::new("ntfsinfo"),
            &["-v", "-F", "/dense.bin", native_path],
        )
        .stdout,
    );
    let original_resident = native_data_streams(
        &checked(
            Path::new("ntfsinfo"),
            &["-v", "-F", "/resident.bin", native_path],
        )
        .stdout,
    );
    assert_eq!(original_dense.len(), 3);
    assert_eq!(original_resident.len(), 1);
    assert_eq!(original_dense[""].clusters.len(), 16);
    assert_eq!(original_dense["Payload"].clusters.len(), 12);
    assert!(original_dense["Keep"].resident);
    assert!(original_resident[""].resident);
    let original_dense_flags = native_file_flags(native_path, "/dense.bin");
    let original_resident_flags = native_file_flags(native_path, "/resident.bin");
    assert_eq!(original_dense_flags & 0x200, 0);
    assert_eq!(original_resident_flags & 0x200, 0);
    let mut original_owners = original_root_clusters.clone();
    for data in original_dense.values().chain(original_resident.values()) {
        add_owners(&mut original_owners, &data.clusters);
    }

    let prefix = vec![0xA5; 1_048_576];
    let suffix = [0x5A; 4096];
    {
        let mut embedded = fs::File::create(&embedded_image).unwrap();
        embedded.write_all(&prefix).unwrap();
        std::io::copy(&mut fs::File::open(&native_image).unwrap(), &mut embedded).unwrap();
        embedded.write_all(&suffix).unwrap();
    }
    let binary = Path::new(env!("CARGO_BIN_EXE_ffs-ntfs"));
    let embedded_path = embedded_image.to_str().unwrap();
    let selection = ["--offset", "1048576", "--length", "67108864"];
    let record = |number: &str| {
        let mut arguments = vec!["record", embedded_path, number, "--offline-image"];
        arguments.extend(selection);
        serde_json::from_slice::<serde_json::Value>(&checked(binary, &arguments).stdout).unwrap()
    };
    let original_dense_record = record(&dense_number);
    let original_resident_record = record(&resident_number);
    let original_keep_metadata = data_metadata(&original_dense_record, "Keep");

    let transaction = |command: &str, path: &str, arguments: &[&str]| {
        let mut all = vec![
            command,
            embedded_path,
            path,
            "--offline-image",
            "--allow-write",
        ];
        all.extend(selection);
        all.extend_from_slice(arguments);
        let report: serde_json::Value =
            serde_json::from_slice(&checked(binary, &all).stdout).unwrap();
        let identity = match path {
            "/dense.bin" => &original_dense_record,
            "/resident.bin" => &original_resident_record,
            other => panic!("unexpected mutation target {other}"),
        };
        assert_eq!(report["format"], "NTFS");
        assert_eq!(report["operation"], command.replace('-', "_"));
        assert_eq!(report["outcome"], "committed");
        assert_eq!(report["token"]["storage"], report["storage_identity"]);
        assert_eq!(report["result"]["record"], identity["record"]);
        assert_eq!(report["result"]["sequence"], identity["sequence"]);
        report
    };
    let punch = |path: &str, name: &str, selectors: &[&str], start: u64, bytes: u64| {
        let start_text = start.to_string();
        let bytes_text = bytes.to_string();
        let mut arguments = vec!["--start", &start_text, "--bytes", &bytes_text];
        arguments.extend_from_slice(selectors);
        let report = transaction("tx-punch-hole", path, &arguments);
        assert_eq!(report["result"]["start"], start);
        assert_eq!(report["result"]["bytes"], bytes);
        assert_eq!(report["result"]["keep_size"], true);
        assert_eq!(
            report["result"]["stream_name_utf16"],
            serde_json::json!(name.encode_utf16().collect::<Vec<_>>())
        );
    };
    let verify = |expected: &ExpectedData| {
        let mut embedded = fs::File::open(&embedded_image).unwrap();
        let mut before_volume = vec![0; prefix.len()];
        embedded.read_exact(&mut before_volume).unwrap();
        assert_eq!(before_volume, prefix);
        let mut extracted = fs::File::create(&native_image).unwrap();
        assert_eq!(
            std::io::copy(&mut (&mut embedded).take(VOLUME_BYTES), &mut extracted).unwrap(),
            VOLUME_BYTES
        );
        extracted.sync_all().unwrap();
        let mut after_volume = [0; 4096];
        embedded.read_exact(&mut after_volume).unwrap();
        assert_eq!(after_volume, suffix);
        assert_eq!(embedded.read(&mut [0; 1]).unwrap(), 0);
        let unchanged = sha256_file(&embedded_image);
        let native_unchanged = sha256_file(&native_image);

        for (path, stream, bytes) in [
            ("/dense.bin", "", expected.unnamed.as_slice()),
            ("/dense.bin", "Payload", expected.payload.as_slice()),
            ("/dense.bin", "Keep", keep.as_slice()),
            ("/resident.bin", "", expected.resident.as_slice()),
            ("/untouched.bin", "", sentinel.as_slice()),
        ] {
            let mut arguments = vec![native_path, path];
            if !stream.is_empty() {
                arguments.extend(["-n", stream]);
            }
            assert_eq!(
                checked(Path::new("ntfscat"), &arguments).stdout,
                bytes,
                "independent native read of {path}:{stream}"
            );
            let mut arguments = vec!["read", embedded_path, path, "--offline-image"];
            arguments.extend(selection);
            if !stream.is_empty() {
                arguments.extend(["--stream", stream]);
            }
            assert_eq!(checked(binary, &arguments).stdout, bytes);
        }

        let root = checked(Path::new("ntfsinfo"), &["-v", "-i", "5", native_path]);
        let root_clusters =
            native_attribute_clusters(&root.stdout, "(0xa0)", VOLUME_BYTES / CLUSTER_BYTES);
        assert_eq!(root_clusters.len(), original_root_clusters.len());
        let dense_info = checked(
            Path::new("ntfsinfo"),
            &["-v", "-F", "/dense.bin", native_path],
        );
        let resident_info = checked(
            Path::new("ntfsinfo"),
            &["-v", "-F", "/resident.bin", native_path],
        );
        let dense = native_data_streams(&dense_info.stdout);
        let resident = native_data_streams(&resident_info.stdout);
        assert_eq!(dense.len(), 3);
        assert_eq!(resident.len(), 1);
        for (name, bytes, count, sparse) in [
            (
                "",
                expected.unnamed.as_slice(),
                expected.unnamed_clusters,
                expected.unnamed_sparse,
            ),
            (
                "Payload",
                expected.payload.as_slice(),
                expected.payload_clusters,
                expected.payload_sparse,
            ),
        ] {
            let data = &dense[name];
            assert!(
                !data.resident,
                "nonresident DATA must not collapse into a value"
            );
            assert_eq!(data.size, bytes.len() as u64);
            assert_eq!(
                data.initialized,
                bytes.len() as u64,
                "ValidDataLength is preserved"
            );
            assert_eq!(data.clusters.len(), count);
            assert_eq!(data.flags, if sparse { 0x8000 } else { 0 });
            assert_eq!(
                data.holes + data.clusters.len() as u64,
                data.size / CLUSTER_BYTES
            );
        }
        assert_eq!(dense["Keep"], original_dense["Keep"]);
        assert!(resident[""].resident, "resident DATA stays resident");
        assert_eq!(resident[""].size, original_resident[""].size);
        assert_eq!(resident[""].initialized, original_resident[""].initialized);
        assert_eq!(resident[""].flags, original_resident[""].flags);
        assert_eq!(resident[""].clusters, BTreeSet::<u64>::new());
        if expected.unnamed == unnamed {
            assert_eq!(
                dense[""], original_dense[""],
                "unselected unnamed DATA runs remain intact"
            );
        }
        if expected.payload == payload {
            assert_eq!(
                dense["Payload"], original_dense["Payload"],
                "unselected ADS runs remain intact"
            );
        }
        assert_eq!(
            native_file_flags(native_path, "/dense.bin"),
            original_dense_flags | if expected.unnamed_sparse { 0x200 } else { 0 },
            "only unnamed sparse conversion changes the base FILE sparse flag"
        );
        assert_eq!(
            native_file_flags(native_path, "/resident.bin"),
            original_resident_flags,
            "resident hole punching preserves FILE flags"
        );

        let mut owners = root_clusters;
        for data in dense.values().chain(resident.values()) {
            add_owners(&mut owners, &data.clusters);
        }
        let bitmap = checked(Path::new("ntfscat"), &["-i", "6", native_path]).stdout;
        let mut expected_bitmap = original_bitmap.clone();
        // Parent I30 pages and boundary DATA clusters may move during COW.
        // Every other owner is fixed, and every resulting bit must be explained.
        replace_owned_clusters(&mut expected_bitmap, &original_owners, &owners);
        assert_eq!(
            bitmap, expected_bitmap,
            "native allocation has no leaks or aliases"
        );
        assert_eq!(
            allocated_clusters(&bitmap),
            allocated_clusters(&original_bitmap) - original_owners.len() as u64
                + owners.len() as u64
        );
        assert_eq!(
            checked(Path::new("ntfscat"), &["-i", "0", "-a", "176", native_path]).stdout,
            original_mft_bitmap,
            "hole punching preserves FILE allocation"
        );

        for (number, original, information) in [
            (&dense_number, &original_dense_record, &dense_info.stdout),
            (
                &resident_number,
                &original_resident_record,
                &resident_info.stdout,
            ),
        ] {
            let current = record(number);
            assert_eq!(current["record"], original["record"]);
            assert_eq!(current["sequence"], original["sequence"]);
            assert_eq!(current["hard_links"], original["hard_links"]);
            assert_eq!(
                native_number(
                    &String::from_utf8_lossy(information),
                    "MFT Record Seq. Numb.:"
                ),
                original["sequence"].as_u64().unwrap(),
                "native FILE sequence remains intact"
            );
        }
        assert_eq!(
            data_metadata(&record(&dense_number), "Keep"),
            original_keep_metadata,
            "the unrelated resident ADS retains every semantic DATA field"
        );
        checked(Path::new("ntfsfix"), &["-n", native_path]);
        let mut arguments = vec![
            "check-allocation",
            embedded_path,
            "--offline-image",
            "--verify-record-ownership",
            "--verify-namespace",
            "--verify-mft-mirror",
        ];
        arguments.extend(selection);
        let report: serde_json::Value =
            serde_json::from_slice(&checked(binary, &arguments).stdout).unwrap();
        assert_eq!(report["complete"], true);
        assert_eq!(report["allocation_consistent"], true);
        assert_eq!(report["requested_checks_consistent"], true);
        for check in ["record_ownership", "namespace", "mft_mirror"] {
            assert_eq!(report[check]["complete"], true, "{check}: {report}");
            assert_eq!(report[check]["consistent"], true, "{check}: {report}");
        }
        assert_eq!(sha256_file(&embedded_image), unchanged);
        assert_eq!(sha256_file(&native_image), native_unchanged);
    };

    let mut expected = ExpectedData {
        unnamed: unnamed.clone(),
        payload: payload.clone(),
        resident,
        unnamed_clusters: 16,
        payload_clusters: 12,
        unnamed_sparse: false,
        payload_sparse: false,
    };
    verify(&expected);

    punch("/resident.bin", "", &[], 7, 19);
    expected.resident[7..26].fill(0);
    verify(&expected);
    punch("/resident.bin", "", &[], 0, 1_u64 << 40);
    expected.resident.fill(0);
    verify(&expected);

    // Sparse ADS conversion must leave unnamed DATA and the base FILE flags alone.
    punch(
        "/dense.bin",
        "Payload",
        &["--stream-utf16", "0050,0061,0079,006c,006f,0061,0064"],
        4096 + 29,
        2 * 4096 + 43,
    );
    expected.payload[4096 + 29..3 * 4096 + 72].fill(0);
    expected.payload_clusters = 11;
    expected.payload_sparse = true;
    verify(&expected);
    punch(
        "/dense.bin",
        "Payload",
        &["--stream", "Payload"],
        0,
        1_u64 << 40,
    );
    expected.payload.fill(0);
    expected.payload_clusters = 0;
    verify(&expected);

    // A partial cluster is zeroed without becoming a sparse allocation.
    punch("/dense.bin", "", &[], 17, 29);
    expected.unnamed[17..46].fill(0);
    verify(&expected);
    punch("/dense.bin", "", &[], 4096 - 37, 3 * 4096 + 89);
    expected.unnamed[4096 - 37..4 * 4096 + 52].fill(0);
    expected.unnamed_clusters = 13;
    expected.unnamed_sparse = true;
    verify(&expected);
    punch("/dense.bin", "", &[], 0, 1_u64 << 40);
    expected.unnamed.fill(0);
    expected.unnamed_clusters = 0;
    verify(&expected);

    // Reopen the all-hole stream, allocate one zero-filled cluster for a write,
    // and reclaim it again without changing EOF or the independent ADS.
    transaction(
        "tx-write-range",
        "/dense.bin",
        &["--start", "4099", "--data", "REUSE"],
    );
    expected.unnamed[4099..4104].copy_from_slice(b"REUSE");
    expected.unnamed_clusters = 1;
    verify(&expected);
    punch("/dense.bin", "", &[], 4096, 4096);
    expected.unnamed[4096..8192].fill(0);
    expected.unnamed_clusters = 0;
    verify(&expected);
    punch(
        "/dense.bin",
        "",
        &[],
        2 * expected.unnamed.len() as u64,
        1_u64 << 40,
    );
    verify(&expected);

    let refuse = |path: &str, arguments: &[&str], authorize: bool, bounds: &[&str]| {
        let unchanged = sha256_file(&embedded_image);
        let mut all = vec!["tx-punch-hole", embedded_path, path, "--offline-image"];
        if authorize {
            all.push("--allow-write");
        }
        all.extend_from_slice(bounds);
        all.extend_from_slice(arguments);
        assert!(!run_cli_binary(binary, &all).status.success(), "{all:?}");
        assert_eq!(sha256_file(&embedded_image), unchanged);
    };
    let invalid: &[&[&str]] = &[
        &["--start", "0", "--bytes", "0"],
        &["--start", "9223372036854775807", "--bytes", "1"],
        &["--start", "18446744073709551615", "--bytes", "1"],
        &["--start", "0", "--bytes", "1", "--stream", "payload"],
        &["--start", "0", "--bytes", "1", "--stream", "missing"],
        &["--start", "999999", "--bytes", "1", "--stream", "missing"],
        &["--start", "0", "--bytes", "1", "--stream-utf16", "0000"],
        &[
            "--start",
            "0",
            "--bytes",
            "1",
            "--stream",
            "Payload",
            "--stream-utf16",
            "0050",
        ],
    ];
    for arguments in invalid {
        refuse("/dense.bin", arguments, true, &selection);
    }
    refuse(
        "/dense.bin",
        &["--start", "0", "--bytes", "1"],
        false,
        &selection,
    );
    for path in ["/", "/$Bitmap"] {
        refuse(path, &["--start", "0", "--bytes", "1"], true, &selection);
    }
    for bounds in [
        &["--offset", "1048577", "--length", "67108864"][..],
        &["--offset", "1048576", "--length", "4096"][..],
        &[][..],
    ] {
        refuse(
            "/dense.bin",
            &["--start", "0", "--bytes", "1"],
            true,
            bounds,
        );
    }
    verify(&expected);
}
