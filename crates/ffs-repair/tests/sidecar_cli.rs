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
    assert_eq!(run(&args).status.code(), Some(4), "output must not be replaced");
    assert_eq!(std::fs::read(&restored).expect("retained output"), bytes);
}
