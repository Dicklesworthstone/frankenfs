#![forbid(unsafe_code)]

//! Same-host fsync latency workload probe.
//!
//! This is a bench-only comparator for the journal-commit/fdatasync class. It
//! creates new scratch artifacts under `/data/tmp` and intentionally leaves
//! them in place to comply with the repository no-delete rule.

use asupersync::Cx;
use ffs_core::OpenFs;
use ffs_types::InodeNumber;
use std::ffi::OsStr;
use std::fs::{OpenOptions, create_dir};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BATCHES: usize = 4;
const OPS_PER_BATCH: usize = 8;
const COUNT: usize = BATCHES * OPS_PER_BATCH;
const IMAGE_SIZE: u64 = 64 * 1024 * 1024;
const PAYLOAD_SIZE: usize = 4096;

struct FfsRun {
    samples: Vec<u64>,
    image: PathBuf,
    e2fsck_status: Option<i32>,
}

fn unique_path(prefix: &str, suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |dur| dur.as_nanos());
    PathBuf::from(format!(
        "/data/tmp/{prefix}_{}_{}{}",
        std::process::id(),
        nanos,
        suffix
    ))
}

fn percentile(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = sorted.len().saturating_mul(pct).saturating_add(99) / 100;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

fn print_summary(label: &str, samples: &[u64], artifact: &str) {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let mean = if sorted.is_empty() {
        0.0
    } else {
        sorted.iter().map(|v| *v as f64).sum::<f64>() / sorted.len() as f64
    };
    let variance = if sorted.len() <= 1 {
        0.0
    } else {
        sorted
            .iter()
            .map(|v| {
                let d = *v as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / (sorted.len() as f64 - 1.0)
    };
    let cv_pct = if mean == 0.0 {
        0.0
    } else {
        variance.sqrt() / mean * 100.0
    };
    println!(
        "{label},count={},median_us={:.3},p95_us={:.3},p99_us={:.3},min_us={:.3},max_us={:.3},mean_us={:.3},cv_pct={:.2},artifact={artifact}",
        sorted.len(),
        percentile(&sorted, 50) as f64 / 1000.0,
        percentile(&sorted, 95) as f64 / 1000.0,
        percentile(&sorted, 99) as f64 / 1000.0,
        sorted.first().copied().unwrap_or(0) as f64 / 1000.0,
        sorted.last().copied().unwrap_or(0) as f64 / 1000.0,
        mean / 1000.0,
        cv_pct,
    );
}

fn batch_medians(samples: &[u64]) -> Vec<u64> {
    samples
        .chunks(OPS_PER_BATCH)
        .map(|chunk| {
            let mut sorted = chunk.to_vec();
            sorted.sort_unstable();
            percentile(&sorted, 50)
        })
        .collect()
}

fn create_ext4_image() -> Option<PathBuf> {
    let image = unique_path("cod_ffs_fsync_ext4", ".img");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&image)
        .ok()?;
    file.set_len(IMAGE_SIZE).ok()?;
    drop(file);

    let mkfs = Command::new("mkfs.ext4")
        .args(["-F", "-q", "-b", "4096"])
        .arg(&image)
        .status()
        .ok()?;
    if !mkfs.success() {
        println!(
            "ffs_ext4_write_fsync,skip=mkfs_failed,artifact={}",
            image.display()
        );
        return None;
    }

    let _ = Command::new("debugfs")
        .args(["-w", "-R", "set_inode_field / mode 040777"])
        .arg(&image)
        .status();

    Some(image)
}

fn run_e2fsck(image: &PathBuf) -> Option<i32> {
    let mut child = Command::new("e2fsck")
        .args(["-fn"])
        .arg(image)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    for _ in 0..100 {
        if let Some(status) = child.try_wait().ok()? {
            return status.code();
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    None
}

fn run_ffs() -> Option<FfsRun> {
    let image = create_ext4_image()?;
    let cx = Cx::for_testing();
    let mut fs = OpenFs::open(&cx, &image).ok()?;
    fs.enable_writes(&cx).ok()?;
    let attr = fs
        .create(&cx, InodeNumber(2), OsStr::new("fsync.bin"), 0o644, 0, 0)
        .ok()?;
    let mut samples = Vec::with_capacity(COUNT);
    for idx in 0..COUNT {
        let payload = vec![u8::try_from(idx).expect("sample count fits u8"); PAYLOAD_SIZE];
        let start = Instant::now();
        fs.write(&cx, attr.ino, 0, &payload).ok()?;
        fs.fsync(&cx, attr.ino, 0, false).ok()?;
        samples.push(u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    fs.sync_all_to_device(&cx).ok()?;
    drop(fs);
    let e2fsck_status = run_e2fsck(&image);
    Some(FfsRun {
        samples,
        image,
        e2fsck_status,
    })
}

fn run_kernel() -> Option<(Vec<u64>, String)> {
    let dir = unique_path("cod_ffs_fsync_kernel", "");
    create_dir(&dir).ok()?;
    let path = dir.join("fsync.bin");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .ok()?;
    let mut samples = Vec::with_capacity(COUNT);
    for idx in 0..COUNT {
        let payload = vec![u8::try_from(idx).expect("sample count fits u8"); PAYLOAD_SIZE];
        let start = Instant::now();
        file.write_at(&payload, 0).ok()?;
        file.sync_all().ok()?;
        samples.push(u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    if samples.is_empty() {
        println!(
            "kernel_ext4_write_fsync,skip=no_samples,artifact={}",
            dir.display()
        );
        return None;
    }
    Some((samples, dir.display().to_string()))
}

fn main() {
    let Some(ffs_run) = run_ffs() else {
        println!("ffs_ext4_write_fsync,skip=unavailable");
        return;
    };
    let Some((kernel_samples, kernel_dir)) = run_kernel() else {
        println!("kernel_ext4_write_fsync,skip=unavailable");
        return;
    };
    print_summary(
        "ffs_ext4_write_fsync",
        &ffs_run.samples,
        &ffs_run.image.display().to_string(),
    );
    let ffs_batch_medians = batch_medians(&ffs_run.samples);
    print_summary(
        "ffs_ext4_write_fsync_batch_medians",
        &ffs_batch_medians,
        &ffs_run.image.display().to_string(),
    );
    println!(
        "ffs_ext4_write_fsync_e2fsck,status={:?},clean={},artifact={}",
        ffs_run.e2fsck_status,
        ffs_run.e2fsck_status == Some(0),
        ffs_run.image.display(),
    );
    print_summary("kernel_ext4_write_fsync", &kernel_samples, &kernel_dir);
    let kernel_batch_medians = batch_medians(&kernel_samples);
    print_summary(
        "kernel_ext4_write_fsync_batch_medians",
        &kernel_batch_medians,
        &kernel_dir,
    );
    let ffs_med = {
        let mut v = ffs_batch_medians;
        v.sort_unstable();
        percentile(&v, 50)
    };
    let kernel_med = {
        let mut v = kernel_batch_medians;
        v.sort_unstable();
        percentile(&v, 50)
    };
    if kernel_med > 0 {
        println!(
            "fsync_ratio_batch_medians,ffs_over_kernel={:.3},kernel_over_ffs={:.3}",
            ffs_med as f64 / kernel_med as f64,
            kernel_med as f64 / ffs_med.max(1) as f64
        );
    }
}
