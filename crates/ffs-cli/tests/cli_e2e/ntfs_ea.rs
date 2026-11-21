//! Native ntfs-3g interoperability checks for logged NTFS EA mutations.

use super::{command_available, run_cli_binary, sha256_file};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Output;

struct ExpectedEa {
    name: &'static [u8],
    value: Vec<u8>,
    need_ea: bool,
}

fn checked(binary: &Path, args: &[&str]) -> Output {
    let output = run_cli_binary(binary, args);
    assert!(
        output.status.success(),
        "{} {args:?} failed: stdout={} stderr={}",
        binary.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn data_stream_metadata(record: &serde_json::Value) -> Vec<serde_json::Value> {
    record["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|attribute| attribute["type"] == "0x80")
        .map(|attribute| {
            let mut metadata = attribute.clone();
            // Repacking assigns new per-record attribute instance numbers.
            // FILE identity and every semantic DATA field must still agree.
            metadata.as_object_mut().unwrap().remove("instance");
            metadata
        })
        .collect()
}

pub fn native_attribute_clusters(
    information: &[u8],
    attribute_type: &str,
    cluster_limit: u64,
) -> BTreeSet<u64> {
    // EA names may contain arbitrary OEM bytes; only ASCII runlist fields are
    // interpreted here. The separate raw EA oracle verifies all exact bytes.
    let text = String::from_utf8_lossy(information);
    let mut selected = false;
    let mut runlist = false;
    let mut clusters = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("Dumping attribute ") {
            selected = line.split_whitespace().nth(3) == Some(attribute_type);
            runlist = false;
        } else if selected && line.starts_with("Runlist:") {
            runlist = true;
        } else if runlist && !line.is_empty() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 3 || !fields.iter().all(|field| field.starts_with("0x")) {
                runlist = false;
                continue;
            }
            let numbers: Vec<_> = fields
                .iter()
                .map(|field| u64::from_str_radix(&field[2..], 16).unwrap())
                .collect();
            let first = numbers[1];
            let length = numbers[2];
            assert!(length > 0);
            let end = first.checked_add(length).unwrap();
            assert!(end <= cluster_limit, "native run escapes the volume");
            for cluster in first..end {
                assert!(
                    clusters.insert(cluster),
                    "native attribute aliases cluster {cluster}"
                );
            }
        }
    }
    clusters
}

pub fn replace_owned_clusters(
    bitmap: &mut [u8],
    removed: &BTreeSet<u64>,
    replacement: &BTreeSet<u64>,
) {
    for cluster in removed {
        let index = usize::try_from(cluster / 8).unwrap();
        let mask = 1_u8 << (cluster % 8);
        assert_ne!(
            bitmap[index] & mask,
            0,
            "original native owner was unallocated"
        );
        bitmap[index] &= !mask;
    }
    for cluster in replacement {
        let index = usize::try_from(cluster / 8).unwrap();
        let mask = 1_u8 << (cluster % 8);
        assert_eq!(
            bitmap[index] & mask,
            0,
            "native allocation aliases an unchanged owner"
        );
        bitmap[index] |= mask;
    }
}

// Decode the bytes returned by the independent native reader without using
// FrankenFS's EA codec. Native entry sizes include their four-byte offsets
// and alignment, while PackedEaSize excludes both.
fn assert_native_eas(information: &[u8], bytes: &[u8], expected: &[ExpectedEa]) {
    assert_eq!(information.len(), 8);
    let packed = usize::from(u16::from_le_bytes(information[..2].try_into().unwrap()));
    let need_ea = usize::from(u16::from_le_bytes(information[2..4].try_into().unwrap()));
    let unpacked = u32::from_le_bytes(information[4..].try_into().unwrap());
    assert_eq!(
        packed,
        expected
            .iter()
            .map(|entry| 5 + entry.name.len() + entry.value.len())
            .sum::<usize>()
    );
    assert_eq!(
        need_ea,
        expected.iter().filter(|entry| entry.need_ea).count()
    );
    assert_eq!(u64::from(unpacked), bytes.len() as u64);
    let mut offset = 0;
    let mut seen = BTreeSet::new();
    while offset < bytes.len() {
        let row = &bytes[offset..];
        assert!(row.len() >= 8);
        let next = usize::try_from(u32::from_le_bytes(row[..4].try_into().unwrap())).unwrap();
        let flags = row[4];
        let name_len = usize::from(row[5]);
        let value_len = usize::from(u16::from_le_bytes(row[6..8].try_into().unwrap()));
        let name_end = 8 + name_len;
        let value_start = name_end + 1;
        let used = value_start + value_len;
        assert!(name_len > 0 && used <= row.len());
        assert_eq!(flags & !0x80, 0);
        assert_eq!(row[name_end], 0);
        let name = &row[8..name_end];
        assert!(seen.insert(name), "duplicate native EA name {name:?}");
        let entry = expected
            .iter()
            .find(|entry| entry.name == name)
            .expect("the native reader returned an expected EA name");
        assert_eq!(flags == 0x80, entry.need_ea);
        assert_eq!(&row[value_start..used], entry.value);
        let consumed = if next == 0 {
            assert!(row.len() <= used.next_multiple_of(4));
            row.len()
        } else {
            assert!(next.is_multiple_of(4) && next >= used && next <= row.len());
            next
        };
        assert!(row[used..consumed].iter().all(|byte| *byte == 0));
        offset += consumed;
    }
    assert_eq!(seen.len(), expected.len());
}

#[test]
#[ignore = "requires ntfs-3g mkntfs, ntfscp, ntfscat, ntfsls, ntfsinfo and ntfsfix; checks native EA promotion, reclamation and bounded writes"]
fn native_ntfs_ea_cli_preserves_data_allocation_and_volume_bounds() {
    for tool in [
        "mkntfs", "ntfscp", "ntfscat", "ntfsls", "ntfsinfo", "ntfsfix",
    ] {
        assert!(
            command_available(tool),
            "native NTFS EA test requires {tool}; install ntfs-3g before explicitly running it"
        );
    }
    const VOLUME_BYTES: u64 = 64 * 1024 * 1024;
    let directory = tempfile::tempdir().expect("native NTFS EA test directory");
    let native_image = directory.path().join("native.img");
    let embedded_image = directory.path().join("embedded.img");
    let payload_file = directory.path().join("payload.bin");
    fs::File::create(&native_image)
        .unwrap()
        .set_len(VOLUME_BYTES)
        .unwrap();
    let native_path = native_image.to_str().unwrap();
    checked(
        Path::new("mkntfs"),
        &["-F", "-Q", "-s", "512", "-c", "4096", native_path],
    );
    let base_data = b"native unnamed DATA survives every EA mutation";
    let stream_data = b"native named DATA remains unchanged";
    let sentinel_data = b"this other native file is never modified";
    for (path, stream, bytes) in [
        ("/notes", None, base_data.as_slice()),
        ("/notes", Some("Sibling"), stream_data.as_slice()),
        ("/untouched", None, sentinel_data.as_slice()),
    ] {
        fs::write(&payload_file, bytes).unwrap();
        let mut args = Vec::new();
        if let Some(stream) = stream {
            args.extend(["-N", stream]);
        }
        args.extend([native_path, payload_file.to_str().unwrap(), path]);
        checked(Path::new("ntfscp"), &args);
    }
    let listing = checked(Path::new("ntfsls"), &["-a", "-i", "-p", "/", native_path]);
    let native_record = String::from_utf8(listing.stdout)
        .unwrap()
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let record = fields.next()?.parse::<u64>().ok()?;
            (fields.next()? == "notes").then_some(record)
        })
        .expect("native directory contains notes");
    let record_number = native_record.to_string();
    let original_bitmap = checked(Path::new("ntfscat"), &["-i", "6", native_path]).stdout;
    let original_mft_bitmap =
        checked(Path::new("ntfscat"), &["-i", "0", "-a", "176", native_path]).stdout;
    assert!(!original_bitmap.is_empty() && !original_mft_bitmap.is_empty());
    let original_root_information = checked(Path::new("ntfsinfo"), &["-v", "-i", "5", native_path]);
    let original_root_clusters = native_attribute_clusters(
        &original_root_information.stdout,
        "(0xa0)",
        VOLUME_BYTES / 4096,
    );
    assert!(
        !original_root_clusters.is_empty(),
        "native root uses external I30 storage"
    );
    let allocated = |bitmap: &[u8]| {
        bitmap
            .iter()
            .map(|byte| u64::from(byte.count_ones()))
            .sum::<u64>()
    };
    let original_allocated = allocated(&original_bitmap);
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
    let mut record_args = vec!["record", embedded_path, &record_number, "--offline-image"];
    record_args.extend(selection);
    let original_record: serde_json::Value =
        serde_json::from_slice(&checked(binary, &record_args).stdout).unwrap();
    assert_eq!(original_record["record"], native_record);
    assert_eq!(original_record["hard_links"], 1);
    let original_data_attributes = data_stream_metadata(&original_record);

    let mut last_commit_lsn = 0;
    let mut transaction = |command: &str, arguments: &[&str]| {
        let mut args = vec![
            command,
            embedded_path,
            "/notes",
            "--offline-image",
            "--allow-write",
        ];
        args.extend(selection);
        args.extend_from_slice(arguments);
        let report: serde_json::Value =
            serde_json::from_slice(&checked(binary, &args).stdout).unwrap();
        assert_eq!(report["format"], "NTFS");
        assert_eq!(report["operation"], command.replace('-', "_"));
        assert_eq!(report["outcome"], "committed");
        assert_eq!(report["token"]["storage"], report["storage_identity"]);
        assert_eq!(report["result"]["record"], native_record);
        assert_eq!(report["result"]["sequence"], original_record["sequence"]);
        let commit_lsn = report["token"]["commit_lsn"].as_u64().unwrap();
        assert!(commit_lsn > last_commit_lsn);
        last_commit_lsn = commit_lsn;
        report
    };
    let verify = |expected: &[ExpectedEa], resident: Option<bool>, extra_clusters: u64| {
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
        for (path, stream, expected_data) in [
            ("/notes", None, base_data.as_slice()),
            ("/notes", Some("Sibling"), stream_data.as_slice()),
            ("/untouched", None, sentinel_data.as_slice()),
        ] {
            let mut args = vec![native_path, path];
            if let Some(stream) = stream {
                args.extend(["-n", stream]);
            }
            assert_eq!(checked(Path::new("ntfscat"), &args).stdout, expected_data);
        }
        let bitmap = checked(Path::new("ntfscat"), &["-i", "6", native_path]).stdout;
        assert_eq!(allocated(&bitmap), original_allocated + extra_clusters);
        let root_information = checked(Path::new("ntfsinfo"), &["-v", "-i", "5", native_path]);
        let file_information = checked(Path::new("ntfsinfo"), &["-v", "-F", "/notes", native_path]);
        let root_clusters =
            native_attribute_clusters(&root_information.stdout, "(0xa0)", VOLUME_BYTES / 4096);
        let ea_clusters =
            native_attribute_clusters(&file_information.stdout, "(0xe0)", VOLUME_BYTES / 4096);
        assert_eq!(root_clusters.len(), original_root_clusters.len());
        assert_eq!(ea_clusters.len() as u64, extra_clusters);
        assert!(
            root_clusters.is_disjoint(&ea_clusters),
            "EA and parent I30 ownership overlap"
        );
        let mut replacement = root_clusters;
        replacement.extend(ea_clusters);
        let mut expected_bitmap = original_bitmap.clone();
        // Parent I30 pages are copy-on-write too. Permit their verified native
        // relocation while still checking every allocation bit and rejecting
        // leaks, missing allocations, and aliases of all unchanged owners.
        replace_owned_clusters(&mut expected_bitmap, &original_root_clusters, &replacement);
        assert_eq!(
            bitmap, expected_bitmap,
            "native ownership exactly matches allocation"
        );
        assert_eq!(
            checked(Path::new("ntfscat"), &["-i", "0", "-a", "176", native_path]).stdout,
            original_mft_bitmap,
            "EA mutations preserve native FILE allocation"
        );
        let mut native_values = Vec::new();
        for attribute in ["208", "224"] {
            let output = run_cli_binary(
                Path::new("ntfscat"),
                &["-a", attribute, native_path, "/notes"],
            );
            if expected.is_empty() {
                assert!(!output.status.success(), "native EA attribute still exists");
            } else {
                assert!(
                    output.status.success(),
                    "native EA read failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                native_values.push(output.stdout);
            }
        }
        if !expected.is_empty() {
            assert_native_eas(&native_values[0], &native_values[1], expected);
        }
        let record: serde_json::Value =
            serde_json::from_slice(&checked(binary, &record_args).stdout).unwrap();
        assert_eq!(record["sequence"], original_record["sequence"]);
        assert_eq!(record["hard_links"], 1);
        let attributes = record["attributes"].as_array().unwrap();
        assert_eq!(data_stream_metadata(&record), original_data_attributes);
        let ea = attributes
            .iter()
            .find(|attribute| attribute["type"] == "0xe0");
        if let Some(resident) = resident {
            assert_eq!(ea.expect("EA attribute is present")["resident"], resident);
        } else {
            assert!(ea.is_none());
            assert!(
                attributes
                    .iter()
                    .all(|attribute| attribute["type"] != "0xd0")
            );
        }
        checked(Path::new("ntfsfix"), &["-n", native_path]);
        let mut args = vec![
            "check-allocation",
            embedded_path,
            "--offline-image",
            "--verify-record-ownership",
            "--verify-namespace",
            "--verify-mft-mirror",
        ];
        args.extend(selection);
        let report: serde_json::Value =
            serde_json::from_slice(&checked(binary, &args).stdout).unwrap();
        assert_eq!(report["complete"], true);
        assert_eq!(report["allocation_consistent"], true);
        assert_eq!(report["requested_checks_consistent"], true);
        assert_eq!(sha256_file(&embedded_image), unchanged);
        assert_eq!(sha256_file(&native_image), native_unchanged);
    };

    verify(&[], None, 0);
    let mut expected = vec![ExpectedEa {
        name: b"user.note",
        value: b"seed".to_vec(),
        need_ea: true,
    }];
    let created = transaction(
        "tx-set-ea",
        &[
            "--name",
            "user.note",
            "--data",
            "seed",
            "--create",
            "--need-ea=true",
        ],
    );
    assert_eq!(created["result"]["bytes"], 4);
    assert_eq!(created["result"]["need_ea"], true);
    verify(&expected, Some(true), 0);
    transaction(
        "tx-set-ea",
        &["--name-hex", "757365722eff", "--empty", "--create"],
    );
    expected.push(ExpectedEa {
        name: b"user.\xff",
        value: Vec::new(),
        need_ea: false,
    });
    verify(&expected, Some(true), 0);

    let bulk: Vec<u8> = (0_u8..=u8::MAX).cycle().take(6_001).collect();
    fs::write(&payload_file, &bulk).unwrap();
    let grown = transaction(
        "tx-set-ea",
        &[
            "--name",
            "user.note",
            "--data-file",
            payload_file.to_str().unwrap(),
            "--replace",
        ],
    );
    assert_eq!(grown["result"]["bytes"], bulk.len());
    assert_eq!(
        grown["result"]["need_ea"], true,
        "omission preserves NEED_EA"
    );
    expected[0].value = bulk;
    verify(&expected, Some(false), 2);

    let oversized_file = directory.path().join("oversized.bin");
    fs::write(&oversized_file, vec![0xC3; 65_536]).unwrap();
    for (command, arguments) in [
        (
            "tx-set-ea",
            vec!["--name", "user.note", "--empty", "--create"],
        ),
        (
            "tx-set-ea",
            vec!["--name", "missing", "--empty", "--replace"],
        ),
        ("tx-remove-ea", vec!["--name", "missing"]),
        ("tx-set-ea", vec!["--name-hex", "7573657200", "--empty"]),
        (
            "tx-set-ea",
            vec!["--name", "user.note", "--empty", "--create", "--replace"],
        ),
        (
            "tx-set-ea",
            vec![
                "--name",
                "user.note",
                "--data-file",
                oversized_file.to_str().unwrap(),
            ],
        ),
    ] {
        let unchanged = sha256_file(&embedded_image);
        let mut args = vec![
            command,
            embedded_path,
            "/notes",
            "--offline-image",
            "--allow-write",
        ];
        args.extend(selection);
        args.extend(arguments);
        assert!(!run_cli_binary(binary, &args).status.success());
        assert_eq!(sha256_file(&embedded_image), unchanged);
    }
    let unchanged = sha256_file(&embedded_image);
    let mut unauthorized = vec![
        "tx-set-ea",
        embedded_path,
        "/notes",
        "--offline-image",
        "--name",
        "user.note",
        "--empty",
    ];
    unauthorized.extend(selection);
    assert!(!run_cli_binary(binary, &unauthorized).status.success());
    assert_eq!(sha256_file(&embedded_image), unchanged);
    verify(&expected, Some(false), 2);

    let shrunk = transaction(
        "tx-set-ea",
        &["--name", "user.note", "--data", "tiny", "--need-ea=false"],
    );
    assert_eq!(shrunk["result"]["need_ea"], false);
    expected[0].value = b"tiny".to_vec();
    expected[0].need_ea = false;
    verify(&expected, Some(true), 0);
    transaction("tx-remove-ea", &["--name-hex", "757365722eff"]);
    expected.pop();
    verify(&expected, Some(true), 0);
    transaction("tx-remove-ea", &["--name", "user.note"]);
    verify(&[], None, 0);
}
