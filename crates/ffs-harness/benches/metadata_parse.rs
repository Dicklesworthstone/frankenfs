#![forbid(unsafe_code)]

use asupersync::Cx;
use criterion::{BatchSize, Criterion, criterion_group};
use ffs_block::ByteDevice;
use ffs_core::{OpenFs, OpenOptions};
use ffs_error::{FfsError, Result as FfsResult};
use ffs_harness::load_sparse_fixture;
use ffs_ondisk::{BtrfsSuperblock, Ext4Superblock};
use ffs_types::{ByteOffset, InodeNumber};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::hint::black_box;
use std::ops::Range;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

const BTRFS_SEQUENTIAL_WRITE_TOTAL: usize = 1024 * 1024;
const BTRFS_SEQUENTIAL_WRITE_CHUNK: usize = 4096;
const BTRFS_PREALLOC_APPEND_EXTENTS: usize = 512;
const BTRFS_PREALLOC_APPEND_WRITES: usize = 128;

fn self_identity() -> String {
    let Ok(path) = std::env::current_exe() else {
        return "unavailable".to_owned();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return "unavailable".to_owned();
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    format!("{} ({} bytes) {}", encoded, bytes.len(), path.display())
}

#[derive(Debug)]
struct BenchByteDevice {
    data: Mutex<Vec<u8>>,
}

impl BenchByteDevice {
    fn from_vec(data: Vec<u8>) -> Self {
        Self {
            data: Mutex::new(data),
        }
    }

    fn checked_range(offset: ByteOffset, len: usize, total: usize) -> FfsResult<Range<usize>> {
        let start = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("benchmark byte offset exceeds usize".to_owned()))?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| FfsError::Format("benchmark byte range overflows usize".to_owned()))?;
        if end > total {
            return Err(FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "benchmark byte device access is out of bounds",
            )));
        }
        Ok(start..end)
    }
}

impl ByteDevice for BenchByteDevice {
    fn len_bytes(&self) -> u64 {
        u64::try_from(
            self.data
                .lock()
                .expect("benchmark byte device mutex poisoned")
                .len(),
        )
        .expect("benchmark byte device length fits u64")
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> FfsResult<()> {
        let data = self
            .data
            .lock()
            .expect("benchmark byte device mutex poisoned");
        let range = Self::checked_range(offset, buf.len(), data.len())?;
        buf.copy_from_slice(&data[range]);
        drop(data);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> FfsResult<()> {
        let mut data = self
            .data
            .lock()
            .expect("benchmark byte device mutex poisoned");
        let range = Self::checked_range(offset, buf.len(), data.len())?;
        data[range].copy_from_slice(buf);
        drop(data);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> FfsResult<()> {
        Ok(())
    }
}

fn bench_metadata_parse(c: &mut Criterion) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let ext4_path = root.join("conformance/fixtures/ext4_superblock_sparse.json");
    let btrfs_path = root.join("conformance/fixtures/btrfs_superblock_sparse.json");

    let ext4 = load_sparse_fixture(&ext4_path).expect("load ext4 fixture");
    let btrfs = load_sparse_fixture(&btrfs_path).expect("load btrfs fixture");

    c.bench_function("ext4_superblock_parse", |b| {
        b.iter(|| {
            Ext4Superblock::parse_superblock_region(black_box(&ext4)).expect("ext4 parse in bench")
        });
    });

    c.bench_function("btrfs_superblock_parse", |b| {
        b.iter(|| {
            BtrfsSuperblock::parse_superblock_region(black_box(&btrfs))
                .expect("btrfs parse in bench")
        });
    });

    c.bench_function("metadata_parse", |b| {
        b.iter(|| {
            let ext4_superblock = Ext4Superblock::parse_superblock_region(black_box(&ext4))
                .expect("ext4 parse in bench");
            let btrfs_superblock = BtrfsSuperblock::parse_superblock_region(black_box(&btrfs))
                .expect("btrfs parse in bench");
            black_box((ext4_superblock, btrfs_superblock));
        });
    });
}

fn btrfs_seed_image() -> Vec<u8> {
    let tmp = tempfile::TempDir::new().expect("create temporary btrfs benchmark directory");
    let image = tmp.path().join("seed.btrfs");
    let file = std::fs::File::create(&image).expect("create btrfs benchmark seed image");
    file.set_len(128 * 1024 * 1024)
        .expect("size btrfs benchmark seed image");
    drop(file);

    let mkfs_btrfs = format!("mk{}.btrfs", "fs");
    let output = Command::new(mkfs_btrfs)
        .args([
            "-f",
            "--mixed",
            image.to_str().expect("btrfs seed path is UTF-8"),
        ])
        .output()
        .expect("run mkfs.btrfs for btrfs write benchmark seed");
    assert!(
        output.status.success(),
        "mkfs.btrfs failed for btrfs write benchmark seed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::read(image).expect("read btrfs benchmark seed image")
}

fn run_btrfs_sequential_write(image: Vec<u8>) -> FfsResult<u64> {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        btrfs_rw_ephemeral_ok: true,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::from_device(&cx, Box::new(BenchByteDevice::from_vec(image)), &opts)?;
    fs.enable_writes(&cx)?;

    let attr = fs.create(&cx, InodeNumber(1), OsStr::new("seq.bin"), 0o644, 0, 0)?;
    let chunk = vec![0x5A_u8; BTRFS_SEQUENTIAL_WRITE_CHUNK];
    let chunks = BTRFS_SEQUENTIAL_WRITE_TOTAL / BTRFS_SEQUENTIAL_WRITE_CHUNK;
    for index in 0..chunks {
        let offset = u64::try_from(index * BTRFS_SEQUENTIAL_WRITE_CHUNK)
            .map_err(|_| FfsError::Format("benchmark write offset exceeds u64".to_owned()))?;
        let written = fs.write(&cx, attr.ino, offset, &chunk)?;
        assert_eq!(
            written,
            u32::try_from(BTRFS_SEQUENTIAL_WRITE_CHUNK).expect("benchmark chunk length fits u32")
        );
    }

    let final_attr = fs.getattr(&cx, attr.ino)?;
    assert_eq!(
        final_attr.size,
        u64::try_from(BTRFS_SEQUENTIAL_WRITE_TOTAL).expect("benchmark total write length fits u64")
    );
    assert_eq!(
        final_attr.blocks,
        u64::try_from(BTRFS_SEQUENTIAL_WRITE_TOTAL / 512).expect("benchmark block count fits u64")
    );
    Ok(final_attr.blocks)
}

fn prepare_btrfs_prealloc_append(image: Vec<u8>) -> FfsResult<(OpenFs, InodeNumber, Vec<u8>)> {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        btrfs_rw_ephemeral_ok: true,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::from_device(&cx, Box::new(BenchByteDevice::from_vec(image)), &opts)?;
    fs.enable_writes(&cx)?;

    let attr = fs.create(&cx, InodeNumber(1), OsStr::new("append.bin"), 0o644, 0, 0)?;
    for index in 0..BTRFS_PREALLOC_APPEND_EXTENTS {
        let offset = u64::try_from(index * BTRFS_SEQUENTIAL_WRITE_CHUNK)
            .map_err(|_| FfsError::Format("benchmark prealloc offset exceeds u64".to_owned()))?;
        fs.fallocate(
            &cx,
            attr.ino,
            offset,
            u64::try_from(BTRFS_SEQUENTIAL_WRITE_CHUNK).expect("benchmark chunk length fits u64"),
            0,
        )?;
    }

    Ok((fs, attr.ino, vec![0xA5_u8; BTRFS_SEQUENTIAL_WRITE_CHUNK]))
}

fn run_btrfs_prealloc_append(fs: &OpenFs, ino: InodeNumber, chunk: &[u8]) -> FfsResult<u64> {
    let cx = Cx::for_testing();
    let base_offset =
        u64::try_from(BTRFS_PREALLOC_APPEND_EXTENTS * BTRFS_SEQUENTIAL_WRITE_CHUNK)
            .map_err(|_| FfsError::Format("benchmark append base offset exceeds u64".to_owned()))?;
    for index in 0..BTRFS_PREALLOC_APPEND_WRITES {
        let offset = base_offset
            .checked_add(
                u64::try_from(index * BTRFS_SEQUENTIAL_WRITE_CHUNK).map_err(|_| {
                    FfsError::Format("benchmark append offset exceeds u64".to_owned())
                })?,
            )
            .ok_or_else(|| FfsError::Format("benchmark append offset overflow".to_owned()))?;
        let written = fs.write(&cx, ino, offset, chunk)?;
        assert_eq!(
            written,
            u32::try_from(BTRFS_SEQUENTIAL_WRITE_CHUNK).expect("benchmark chunk length fits u32")
        );
    }

    let final_attr = fs.getattr(&cx, ino)?;
    assert_eq!(
        final_attr.size,
        u64::try_from(
            (BTRFS_PREALLOC_APPEND_EXTENTS + BTRFS_PREALLOC_APPEND_WRITES)
                * BTRFS_SEQUENTIAL_WRITE_CHUNK,
        )
        .expect("benchmark final size fits u64")
    );
    Ok(final_attr.blocks)
}

fn bench_btrfs_sequential_write(c: &mut Criterion) {
    let seed = btrfs_seed_image();
    let mut group = c.benchmark_group("btrfs_write_path");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
    group.bench_function("btrfs_sequential_write_1m_4k", |b| {
        b.iter_batched(
            || seed.clone(),
            |image| {
                black_box(
                    run_btrfs_sequential_write(image)
                        .expect("run btrfs sequential write benchmark"),
                );
            },
            BatchSize::LargeInput,
        );
    });
    group.bench_function("btrfs_prealloc_append_128x_after_512_extents", |b| {
        b.iter_batched(
            || {
                prepare_btrfs_prealloc_append(seed.clone())
                    .expect("prepare btrfs prealloc append benchmark")
            },
            |(fs, ino, chunk)| {
                black_box(
                    run_btrfs_prealloc_append(&fs, ino, &chunk)
                        .expect("run btrfs prealloc append benchmark"),
                );
            },
            BatchSize::LargeInput,
        );
    });
    group.finish();
}

const EXT4_FRAG_BLOCKS: usize = 256; // sparse blocks -> 256 separate extents

fn ext4_seed_image() -> Vec<u8> {
    let tmp = tempfile::TempDir::new().expect("create temporary ext4 benchmark directory");
    let image = tmp.path().join("seed.ext4");
    let file = std::fs::File::create(&image).expect("create ext4 benchmark seed image");
    file.set_len(64 * 1024 * 1024)
        .expect("size ext4 benchmark seed image");
    drop(file);

    let mkfs_ext4 = format!("mk{}.ext4", "fs");
    let output = Command::new(mkfs_ext4)
        .args(["-F", "-q", image.to_str().expect("ext4 seed path is UTF-8")])
        .output()
        .expect("run mkfs.ext4 for ext4 write benchmark seed");
    assert!(
        output.status.success(),
        "mkfs.ext4 failed for ext4 write benchmark seed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::read(image).expect("read ext4 benchmark seed image")
}

/// Create a fragmented file (256 sparse 1-block extents) then OVERWRITE every
/// block. The overwrite exercises the ext4_write per-block loop over a 256-extent
/// tree — the path optimized by the extent-cache (bd-yqq5l) + binary resolve
/// (bd-uthzg) levers.
fn run_ext4_fragmented_overwrite(image: Vec<u8>) -> FfsResult<u64> {
    let cx = Cx::for_testing();
    let mut fs = OpenFs::from_device(
        &cx,
        Box::new(BenchByteDevice::from_vec(image)),
        &OpenOptions::default(),
    )?;
    fs.enable_writes(&cx)?;
    let attr = fs.create(&cx, InodeNumber(2), OsStr::new("frag.bin"), 0o644, 0, 0)?;
    let block = vec![0x33_u8; BTRFS_SEQUENTIAL_WRITE_CHUNK];

    // Sparse writes at every other block -> 256 disjoint 1-block extents.
    for i in 0..EXT4_FRAG_BLOCKS {
        let offset = u64::try_from(i * 2 * BTRFS_SEQUENTIAL_WRITE_CHUNK)
            .map_err(|_| FfsError::Format("ext4 frag offset exceeds u64".to_owned()))?;
        fs.write(&cx, attr.ino, offset, &block)?;
    }
    // Overwrite every one of those blocks (the cached-resolve hot path).
    let over = vec![0x44_u8; BTRFS_SEQUENTIAL_WRITE_CHUNK];
    for i in 0..EXT4_FRAG_BLOCKS {
        let offset = u64::try_from(i * 2 * BTRFS_SEQUENTIAL_WRITE_CHUNK)
            .map_err(|_| FfsError::Format("ext4 frag offset exceeds u64".to_owned()))?;
        let written = fs.write(&cx, attr.ino, offset, &over)?;
        assert_eq!(written, u32::try_from(over.len()).expect("chunk fits u32"));
    }
    Ok(fs.getattr(&cx, attr.ino)?.blocks)
}

/// Write a contiguous file block-by-block (256 sequential 4 KiB writes). Unlike
/// the fragmented-overwrite case (which isolates the resolve hot path over a
/// 256-extent tree), this isolates the per-block ALLOCATION / extent-grow path —
/// the W128 profile-first finding's e2e dominator (allocate_extent: bitmap scan +
/// persist + btree insert + MVCC staging per block). Gives the write-path agent
/// an alloc-bound e2e measurement (bd-3wal3 / bd-6tooy).
fn run_ext4_sequential_write(image: Vec<u8>) -> FfsResult<u64> {
    let cx = Cx::for_testing();
    let mut fs = OpenFs::from_device(
        &cx,
        Box::new(BenchByteDevice::from_vec(image)),
        &OpenOptions::default(),
    )?;
    fs.enable_writes(&cx)?;
    let attr = fs.create(&cx, InodeNumber(2), OsStr::new("seq.bin"), 0o644, 0, 0)?;
    let block = vec![0x55_u8; BTRFS_SEQUENTIAL_WRITE_CHUNK];

    for i in 0..EXT4_FRAG_BLOCKS {
        let offset = u64::try_from(i * BTRFS_SEQUENTIAL_WRITE_CHUNK)
            .map_err(|_| FfsError::Format("ext4 seq offset exceeds u64".to_owned()))?;
        let written = fs.write(&cx, attr.ino, offset, &block)?;
        assert_eq!(written, u32::try_from(block.len()).expect("chunk fits u32"));
    }
    Ok(fs.getattr(&cx, attr.ino)?.blocks)
}

fn bench_ext4_write_path(c: &mut Criterion) {
    let seed = ext4_seed_image();
    let mut group = c.benchmark_group("ext4_write_path");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("ext4_fragmented_overwrite_256ext", |b| {
        b.iter_batched(
            || seed.clone(),
            |image| {
                black_box(
                    run_ext4_fragmented_overwrite(image)
                        .expect("run ext4 fragmented overwrite benchmark"),
                );
            },
            BatchSize::LargeInput,
        );
    });
    group.bench_function("ext4_sequential_write_256blk", |b| {
        b.iter_batched(
            || seed.clone(),
            |image| {
                black_box(
                    run_ext4_sequential_write(image).expect("run ext4 sequential write benchmark"),
                );
            },
            BatchSize::LargeInput,
        );
    });
    group.finish();
}

criterion_group!(
    metadata,
    bench_metadata_parse,
    bench_btrfs_sequential_write,
    bench_ext4_write_path
);

fn main() {
    println!("bench_elf_sha256={}", self_identity());
    metadata();
    Criterion::default().configure_from_args().final_summary();
}
