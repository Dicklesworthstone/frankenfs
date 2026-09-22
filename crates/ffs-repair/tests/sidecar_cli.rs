//! Execute the shipped binary against real files and the actual RaptorQ codec.

use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::process::{Command, Output};

fn run(args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ffs-image-repair"))
        .args(args)
        .output()
        .expect("run ffs-image-repair")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn sidecar_binary_protect_verify_restore_round_trip_and_no_clobber() {
    let dir = tempfile::tempdir().expect("directory");
    let image = dir.path().join("image.img");
    let sidecar = dir.path().join("image.ffs-rq");
    let restored = dir.path().join("restored.img");
    let bytes: Vec<u8> = (0..12 * 512 + 17)
        .map(|index| ((index * 29 + index / 512) % 251) as u8)
        .collect();
    std::fs::write(&image, &bytes).expect("image");

    let output = run(&[
        OsStr::new("protect"),
        image.as_os_str(),
        sidecar.as_os_str(),
        OsStr::new("--offline"),
        OsStr::new("--block-size"),
        OsStr::new("512"),
        OsStr::new("--group-blocks"),
        OsStr::new("8"),
        OsStr::new("--repair-symbols"),
        OsStr::new("6"),
    ]);
    assert_success(&output);
    let protected: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(protected["image_bytes"], bytes.len() as u64);
    assert_eq!(std::fs::read(&image).expect("source unchanged"), bytes);

    assert_success(&run(&[
        OsStr::new("verify"),
        image.as_os_str(),
        sidecar.as_os_str(),
    ]));
    File::options()
        .write(true)
        .open(&image)
        .expect("image")
        .write_all_at(&[255], 516)
        .expect("corrupt image");
    let damaged = std::fs::read(&image).expect("damaged source");
    let output = run(&[
        OsStr::new("verify"),
        image.as_os_str(),
        sidecar.as_os_str(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(report["changed_blocks"], 1);
    assert_eq!(report["matches_snapshot"], false);

    let args = [
        OsStr::new("restore"),
        image.as_os_str(),
        sidecar.as_os_str(),
        restored.as_os_str(),
        OsStr::new("--offline"),
    ];
    let output = run(&args);
    assert_success(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(report["recovered_blocks"], 1);
    assert_eq!(std::fs::read(&restored).expect("restored bytes"), bytes);
    assert_eq!(std::fs::read(&image).expect("evidence retained"), damaged);
    assert_eq!(
        run(&args).status.code(),
        Some(4),
        "output must not be replaced"
    );
    assert_eq!(std::fs::read(&restored).expect("retained output"), bytes);
}

#[test]
fn sidecar_binary_restores_ext4_superblock_and_file_data_with_independent_fsck() {
    let dir = tempfile::tempdir().expect("directory");
    let image = dir.path().join("filesystem.ext4");
    let sidecar = dir.path().join("filesystem.ffs-rq");
    let output = dir.path().join("restored.ext4");
    let seed = dir.path().join("payload.txt");
    let payload = b"external RaptorQ restores filesystem metadata and user data\n".repeat(40);
    std::fs::write(&seed, &payload).expect("payload");
    File::create(&image)
        .expect("image")
        .set_len(4 * 1024 * 1024)
        .expect("image length");
    let formatted = Command::new("mkfs.ext4")
        .args([
            "-F",
            "-q",
            "-b",
            "1024",
            "-O",
            "^has_journal",
            "-U",
            "11111111-2222-3333-4444-555555555555",
            "-E",
            "lazy_itable_init=0",
        ])
        .arg(&image)
        .output()
        .expect("mkfs.ext4 is required for this executed filesystem regression");
    assert_success(&formatted);
    let seeded = Command::new("debugfs")
        .args(["-w", "-R"])
        .arg(format!("write {} /payload", seed.display()))
        .arg(&image)
        .output()
        .expect("debugfs");
    assert_success(&seeded);
    let mapping = Command::new("debugfs")
        .args(["-R", "bmap /payload 0"])
        .arg(&image)
        .output()
        .expect("debugfs bmap");
    assert_success(&mapping);
    let data_block = String::from_utf8_lossy(&mapping.stdout)
        .lines()
        .find_map(|line| line.trim().parse::<u64>().ok())
        .expect("independent file data block mapping");
    assert!(data_block > 1);
    let original = std::fs::read(&image).expect("original image");
    assert_eq!(&original[1080..1082], &[0x53, 0xef], "ext4 superblock magic");

    assert_success(&run(&[
        OsStr::new("protect"),
        image.as_os_str(),
        sidecar.as_os_str(),
        OsStr::new("--offline"),
        OsStr::new("--block-size"),
        OsStr::new("1024"),
        OsStr::new("--group-blocks"),
        OsStr::new("64"),
        OsStr::new("--repair-symbols"),
        OsStr::new("8"),
    ]));
    let damaged_file = File::options().write(true).open(&image).expect("image");
    damaged_file.write_all_at(&[0, 0], 1080).expect("damage superblock magic");
    damaged_file.write_all_at(&[255], data_block * 1024).expect("damage file data");
    let damaged = std::fs::read(&image).expect("damaged evidence");
    assert_ne!(damaged, original);

    let restored = run(&[
        OsStr::new("restore"),
        image.as_os_str(),
        sidecar.as_os_str(),
        output.as_os_str(),
        OsStr::new("--offline"),
    ]);
    assert_success(&restored);
    let report: serde_json::Value = serde_json::from_slice(&restored.stdout).expect("JSON");
    assert_eq!(report["recovered_blocks"], 2);
    assert_eq!(std::fs::read(&output).expect("restored image"), original);
    assert_eq!(std::fs::read(&image).expect("source retained"), damaged);
    let checked = Command::new("e2fsck")
        .args(["-f", "-n"])
        .arg(&output)
        .output()
        .expect("e2fsck");
    assert_success(&checked);
    let readback = Command::new("debugfs")
        .args(["-R", "cat /payload"])
        .arg(&output)
        .output()
        .expect("debugfs readback");
    assert_success(&readback);
    assert_eq!(readback.stdout, payload);
}
