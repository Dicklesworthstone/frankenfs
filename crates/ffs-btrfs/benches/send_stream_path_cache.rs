#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Whole-stream benchmark for btrfs send path construction (bd-h3087).
//!
//! The fixture is a deep directory chain with many regular files at the leaf.
//! It exercises `generate_send_stream` exactly where parent-chain PATH and
//! directory-depth reconstruction used to walk the same ancestors per inode.

use criterion::{Criterion, criterion_group};
#[cfg(feature = "bench-instrumentation")]
use ffs_btrfs::generate_send_stream_materialized_parent_index_control;
use ffs_btrfs::{
    BTRFS_FIRST_FREE_OBJECTID, BTRFS_ITEM_INODE_ITEM, BTRFS_ITEM_INODE_REF,
    BTRFS_SEND_STREAM_MAGIC, BTRFS_SEND_STREAM_VERSION, BtrfsKey, BtrfsLeafEntry, SendAttr,
    SendCommand, build_chmod_command, build_chown_command, build_link_command, build_mkdir_command,
    build_mkfile_command, build_subvol_command, build_truncate_command, build_utimes_command,
    generate_send_stream, parse_inode_item, parse_inode_refs,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::fs::File;
use std::hint::black_box;
use std::io::Read;
use std::process::Command;
use std::time::Instant;

const DEPTH: u64 = 128;
const FILES: u64 = 768;
const ROOT_INO: u64 = BTRFS_FIRST_FREE_OBJECTID;
const FIRST_DIR_INO: u64 = ROOT_INO + 1;
const FIRST_FILE_INO: u64 = FIRST_DIR_INO + DEPTH;
const BTRFS_SEND_CRC32C_POLY: u32 = 0x82F6_3B78;

#[derive(Clone, Copy)]
struct BootstrapMedianCi {
    median: f64,
    low: f64,
    high: f64,
}

fn median(mut values: Vec<f64>) -> f64 {
    assert!(!values.is_empty(), "median requires at least one sample");
    values.sort_by(f64::total_cmp);
    let midpoint = values.len() / 2;
    if values.len() % 2 == 0 {
        values[midpoint - 1].midpoint(values[midpoint])
    } else {
        values[midpoint]
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

fn bootstrap_median_ci(log_ratios: &[f64]) -> BootstrapMedianCi {
    const RESAMPLES: usize = 20_000;
    assert!(
        !log_ratios.is_empty(),
        "bootstrap median CI requires paired samples"
    );
    let mut state =
        0xB7F5_5EAD_2026_0726_u64 ^ u64::try_from(log_ratios.len()).expect("sample count fits u64");
    let mut bootstrapped = Vec::with_capacity(RESAMPLES);
    for _ in 0..RESAMPLES {
        let mut sample = Vec::with_capacity(log_ratios.len());
        for _ in log_ratios {
            let draw = splitmix64(&mut state)
                % u64::try_from(log_ratios.len()).expect("sample count fits u64");
            sample.push(log_ratios[usize::try_from(draw).expect("draw fits usize")]);
        }
        bootstrapped.push(median(sample));
    }
    bootstrapped.sort_by(f64::total_cmp);
    let low_index = RESAMPLES.saturating_mul(25) / 1000;
    let high_index = RESAMPLES
        .saturating_mul(975)
        .div_ceil(1000)
        .saturating_sub(1);
    BootstrapMedianCi {
        median: median(log_ratios.to_vec()).exp(),
        low: bootstrapped[low_index].exp(),
        high: bootstrapped[high_index].exp(),
    }
}

fn print_bench_evidence_metadata() {
    let exe = std::env::current_exe().expect("bench executable");
    let mut file = File::open(&exe).expect("open bench executable for hashing");
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer).expect("hash bench executable");
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let worker = Command::new("hostname")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let digest = hasher.finalize();
    let mut sha256 = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        write!(&mut sha256, "{byte:02x}").expect("format bench executable hash");
    }
    println!("bench_evidence,binary_sha256={sha256},worker={worker}");
}

#[cfg(target_arch = "x86_64")]
fn print_codegen_isa() {
    println!(
        "codegen_isa,target_arch=x86_64,compile_sse2={},compile_sse4_2={},compile_avx2={},compile_fma={},runtime_sse4_2={},runtime_avx2={},runtime_fma={}",
        cfg!(target_feature = "sse2"),
        cfg!(target_feature = "sse4.2"),
        cfg!(target_feature = "avx2"),
        cfg!(target_feature = "fma"),
        std::is_x86_feature_detected!("sse4.2"),
        std::is_x86_feature_detected!("avx2"),
        std::is_x86_feature_detected!("fma"),
    );
}

#[cfg(not(target_arch = "x86_64"))]
fn print_codegen_isa() {
    println!("codegen_isa,target_arch=non_x86_64");
}

#[derive(Debug, Clone, Default)]
struct LegacySendStreamBuilder {
    buffer: Vec<u8>,
    has_header: bool,
    finalized: bool,
}

impl LegacySendStreamBuilder {
    fn new() -> Self {
        Self::default()
    }

    fn write_header(&mut self) {
        assert!(!self.has_header, "header already written");
        self.buffer.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
        self.buffer
            .extend_from_slice(&BTRFS_SEND_STREAM_VERSION.to_le_bytes());
        self.has_header = true;
    }

    fn add_command(&mut self, cmd: SendCommand, attrs: &[(SendAttr, &[u8])]) {
        assert!(self.has_header, "must write header first");
        assert!(!self.finalized, "stream already finalized");

        let mut payload = Vec::new();
        for (atype, adata) in attrs {
            assert!(
                u16::try_from(adata.len()).is_ok(),
                "send-stream attribute data exceeds u16 TLV limit"
            );
            payload.extend_from_slice(&(*atype as u16).to_le_bytes());
            payload.extend_from_slice(&(adata.len() as u16).to_le_bytes());
            payload.extend_from_slice(adata);
        }

        let payload_len = payload.len() as u32;
        let full_len = 10 + payload.len();
        let mut frame = Vec::with_capacity(full_len);
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.extend_from_slice(&(cmd as u16).to_le_bytes());
        frame.extend_from_slice(&[0_u8; 4]);
        frame.extend_from_slice(&payload);

        let crc = send_stream_command_crc32c(&frame);
        frame[6..10].copy_from_slice(&crc.to_le_bytes());
        self.buffer.extend_from_slice(&frame);
    }

    fn finalize(&mut self) {
        assert!(!self.finalized, "stream already finalized");
        self.add_command(SendCommand::End, &[]);
        self.finalized = true;
    }

    fn finish(self) -> Vec<u8> {
        assert!(self.finalized, "must call finalize() before finish()");
        self.buffer
    }
}

fn btrfs_send_crc32c(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ BTRFS_SEND_CRC32C_POLY
            };
        }
    }
    crc
}

fn send_stream_command_crc32c(command: &[u8]) -> u32 {
    let mut crc = btrfs_send_crc32c(0, &command[..6]);
    crc = btrfs_send_crc32c(crc, &[0_u8; 4]);
    btrfs_send_crc32c(crc, &command[10..])
}

fn btrfs_send_crc32c_accelerated(seed: u32, data: &[u8]) -> u32 {
    !ffs_types::crc32c_append(!seed, data)
}

fn send_stream_command_crc32c_accelerated(command: &[u8]) -> u32 {
    let mut crc = btrfs_send_crc32c_accelerated(0, &command[..6]);
    crc = btrfs_send_crc32c_accelerated(crc, &[0_u8; 4]);
    btrfs_send_crc32c_accelerated(crc, &command[10..])
}

fn legacy_add_command(
    builder: &mut LegacySendStreamBuilder,
    command: (SendCommand, Vec<(SendAttr, Vec<u8>)>),
) {
    let (cmd, attrs) = command;
    let refs: Vec<(SendAttr, &[u8])> = attrs.iter().map(|(a, d)| (*a, d.as_slice())).collect();
    builder.add_command(cmd, &refs);
}

fn make_inode_item(mode: u32, size: u64, nlink: u32) -> Vec<u8> {
    let mut buf = vec![0_u8; 160];
    buf[0..8].copy_from_slice(&1_u64.to_le_bytes());
    buf[16..24].copy_from_slice(&size.to_le_bytes());
    buf[24..32].copy_from_slice(&size.to_le_bytes());
    buf[40..44].copy_from_slice(&nlink.to_le_bytes());
    buf[52..56].copy_from_slice(&mode.to_le_bytes());
    buf
}

fn make_inode_ref(index: u64, name: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + name.len());
    buf.extend_from_slice(&index.to_le_bytes());
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(name);
    buf
}

fn push_inode(
    items: &mut Vec<BtrfsLeafEntry>,
    objectid: u64,
    mode: u32,
    nlink: u32,
    parent: u64,
    name: &[u8],
) {
    items.push(BtrfsLeafEntry {
        key: BtrfsKey {
            objectid,
            item_type: BTRFS_ITEM_INODE_ITEM,
            offset: 0,
        },
        data: make_inode_item(mode, 0, nlink),
    });
    items.push(BtrfsLeafEntry {
        key: BtrfsKey {
            objectid,
            item_type: BTRFS_ITEM_INODE_REF,
            offset: parent,
        },
        data: make_inode_ref(1, name),
    });
}

fn build_deep_send_items() -> Vec<BtrfsLeafEntry> {
    let mut items = Vec::with_capacity(((DEPTH + FILES) * 2 + FILES / 4 + 2) as usize);
    let dir_mode = u32::from(ffs_types::S_IFDIR | 0o755);
    let file_mode = u32::from(ffs_types::S_IFREG | 0o644);

    items.push(BtrfsLeafEntry {
        key: BtrfsKey {
            objectid: ROOT_INO,
            item_type: BTRFS_ITEM_INODE_ITEM,
            offset: 0,
        },
        data: make_inode_item(dir_mode, 0, 1),
    });

    let mut parent = ROOT_INO;
    for depth in 0..DEPTH {
        let ino = FIRST_DIR_INO + depth;
        let name = format!("d{depth:03}");
        push_inode(&mut items, ino, dir_mode, 1, parent, name.as_bytes());
        parent = ino;
    }

    for idx in 0..FILES {
        let ino = FIRST_FILE_INO + idx;
        let name = format!("f{idx:04}");
        let nlink = if idx % 4 == 0 { 2 } else { 1 };
        push_inode(&mut items, ino, file_mode, nlink, parent, name.as_bytes());
        if nlink > 1 {
            let link_name = format!("l{idx:04}");
            items.push(BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: ino,
                    item_type: BTRFS_ITEM_INODE_REF,
                    offset: parent,
                },
                data: make_inode_ref(2, link_name.as_bytes()),
            });
        }
    }

    items
}

fn collect_inode_links(items: &[BtrfsLeafEntry]) -> BTreeMap<u64, Vec<(u64, Vec<u8>)>> {
    let mut inode_links: BTreeMap<u64, Vec<(u64, Vec<u8>)>> = BTreeMap::new();
    for entry in items {
        if entry.key.item_type == BTRFS_ITEM_INODE_REF {
            if let Ok(refs) = parse_inode_refs(&entry.data) {
                let links = inode_links.entry(entry.key.objectid).or_default();
                for inode_ref in refs {
                    links.push((entry.key.offset, inode_ref.name.clone()));
                }
            }
        }
    }
    inode_links
}

/// Exact source-neutral copy of the production projection under review. This is
/// the complete allocation/clone stage the proposed lever would remove.
fn project_primary_parents(
    inode_links: &BTreeMap<u64, Vec<(u64, Vec<u8>)>>,
) -> BTreeMap<u64, (u64, Vec<u8>)> {
    inode_links
        .iter()
        .filter_map(|(&ino, links)| {
            links
                .first()
                .map(|(parent, name)| (ino, (*parent, name.clone())))
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("format SHA-256");
    }
    hex
}

fn primary_parent_digest(parents: &BTreeMap<u64, (u64, Vec<u8>)>) -> String {
    let mut hasher = Sha256::new();
    for (ino, (parent, name)) in parents {
        hasher.update(ino.to_le_bytes());
        hasher.update(parent.to_le_bytes());
        hasher.update(
            u64::try_from(name.len())
                .expect("name length fits u64")
                .to_le_bytes(),
        );
        hasher.update(name);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("format parent-index SHA-256");
    }
    hex
}

fn observe_ns_per_iteration(mut operation: impl FnMut(), iterations: u32) -> f64 {
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    started.elapsed().as_secs_f64() * 1e9 / f64::from(iterations)
}

/// Retry-predicate gate for bd-btrfs-send-parent-index-azojl. This invocation
/// does not contain a candidate production path: it only counts the exact
/// projection stage against duplicate executions of the current whole stream.
fn parent_index_attribution_only() {
    const PAIRS: usize = 31;
    const WHOLE_REPEATS: u32 = 2;
    const STAGE_REPEATS: u32 = 16;
    const MIN_ATTRIBUTION_FRACTION: f64 = 0.001;

    let items = build_deep_send_items();
    let uuid = [0x5a_u8; 16];
    let subvol: &[u8] = b"bench_subvol";
    let inode_links = collect_inode_links(&items);
    let parents = project_primary_parents(&inode_links);
    assert_eq!(parents.len(), inode_links.len());
    for (ino, links) in &inode_links {
        let (expected_parent, expected_name) =
            links.first().expect("fixture inode has at least one link");
        let (actual_parent, actual_name) = &parents[ino];
        assert_eq!(actual_parent, expected_parent, "primary parent changed");
        assert_eq!(actual_name, expected_name, "primary name changed");
    }

    let stream_a = generate_send_stream(&items, subvol, &uuid, 1, |_bytenr, _len, _ram, _comp| {
        Ok(Vec::new())
    })
    .expect("generate first current stream");
    let stream_b = generate_send_stream(&items, subvol, &uuid, 1, |_bytenr, _len, _ram, _comp| {
        Ok(Vec::new())
    })
    .expect("generate duplicate current stream");
    assert_eq!(stream_a, stream_b, "duplicate current streams differ");
    println!(
        "parent_index_attribution_parity,inodes={},links={},primary_name_bytes={},parent_index_sha256={},stream_bytes={},stream_sha256={},result=identical",
        parents.len(),
        inode_links.values().map(Vec::len).sum::<usize>(),
        parents.values().map(|(_, name)| name.len()).sum::<usize>(),
        primary_parent_digest(&parents),
        stream_a.len(),
        sha256_hex(&stream_a),
    );

    for _ in 0..4 {
        black_box(project_primary_parents(black_box(&inode_links)));
        black_box(
            generate_send_stream(
                black_box(&items),
                black_box(subvol),
                black_box(&uuid),
                black_box(1),
                |_bytenr, _len, _ram, _comp| Ok(Vec::new()),
            )
            .expect("warm current whole stream"),
        );
    }

    let mut whole_lhs_ns = Vec::with_capacity(PAIRS);
    let mut whole_rhs_ns = Vec::with_capacity(PAIRS);
    let mut projection_ns = Vec::with_capacity(PAIRS);
    let mut raw_pairs = String::with_capacity(PAIRS.saturating_mul(72));
    for pair_index in 0..PAIRS {
        let observe_whole = || {
            observe_ns_per_iteration(
                || {
                    let stream = generate_send_stream(
                        black_box(&items),
                        black_box(subvol),
                        black_box(&uuid),
                        black_box(1),
                        |_bytenr, _len, _ram, _comp| Ok(Vec::new()),
                    )
                    .expect("generate current whole stream");
                    black_box(stream.len());
                },
                WHOLE_REPEATS,
            )
        };
        let observe_projection = || {
            observe_ns_per_iteration(
                || {
                    let primary = project_primary_parents(black_box(&inode_links));
                    black_box(primary.len());
                },
                STAGE_REPEATS,
            )
        };
        let (lhs, rhs, projection, order) = if pair_index % 2 == 0 {
            (
                observe_whole(),
                observe_whole(),
                observe_projection(),
                "AAS",
            )
        } else {
            let projection = observe_projection();
            let rhs = observe_whole();
            let lhs = observe_whole();
            (lhs, rhs, projection, "SAA")
        };
        whole_lhs_ns.push(lhs);
        whole_rhs_ns.push(rhs);
        projection_ns.push(projection);
        if pair_index > 0 {
            raw_pairs.push(';');
        }
        write!(&mut raw_pairs, "{order}:{lhs:.3}:{rhs:.3}:{projection:.3}")
            .expect("format attribution pair");
    }

    let null_log_ratios = whole_lhs_ns
        .iter()
        .zip(&whole_rhs_ns)
        .map(|(lhs, rhs)| (lhs / rhs).ln())
        .collect::<Vec<_>>();
    let attribution_log_ratios = projection_ns
        .iter()
        .zip(whole_lhs_ns.iter().zip(&whole_rhs_ns))
        .map(|(projection, (lhs, rhs))| (projection / lhs.midpoint(*rhs)).ln())
        .collect::<Vec<_>>();
    let null_summary = bootstrap_median_ci(&null_log_ratios);
    let attribution_summary = bootstrap_median_ci(&attribution_log_ratios);
    let null_log_radius = null_summary
        .low
        .ln()
        .abs()
        .max(null_summary.high.ln().abs());
    let null_floor_ratio = null_log_radius.exp();
    let admitted = null_floor_ratio < 1.10 && attribution_summary.low >= MIN_ATTRIBUTION_FRACTION;
    let verdict = if admitted {
        "ADMITTED_FOR_AB"
    } else if null_floor_ratio >= 1.10 {
        "BLOCKED_NULL_FLOOR"
    } else {
        "NOT_ADMITTED_BELOW_0_1_PERCENT"
    };
    println!(
        "parent_index_attribution_pairs,pairs={PAIRS},whole_repeats={WHOLE_REPEATS},projection_repeats={STAGE_REPEATS},format=order:whole_lhs_ns:whole_rhs_ns:projection_ns,values={raw_pairs}"
    );
    println!(
        "parent_index_attribution,whole_aa_median={:.6},whole_aa_ci_low={:.6},whole_aa_ci_high={:.6},whole_aa_null_floor_ratio={null_floor_ratio:.6},projection_fraction_median={:.8},projection_fraction_ci_low={:.8},projection_fraction_ci_high={:.8},projection_pct_median={:.4},minimum_fraction={MIN_ATTRIBUTION_FRACTION:.4},admitted={admitted},verdict={verdict},gate_basis=bootstrap_median_ci,bootstrap_resamples=20000,cv_used=false",
        null_summary.median,
        null_summary.low,
        null_summary.high,
        attribution_summary.median,
        attribution_summary.low,
        attribution_summary.high,
        attribution_summary.median * 100.0,
    );
}

fn group_send_inode_entries(items: &[BtrfsLeafEntry]) -> BTreeMap<u64, Vec<&BtrfsLeafEntry>> {
    let mut inodes: BTreeMap<u64, Vec<&BtrfsLeafEntry>> = BTreeMap::new();
    for entry in items {
        inodes.entry(entry.key.objectid).or_default().push(entry);
    }
    inodes
}

/// Source-neutral copy of the second full inode-item parse pass in
/// `generate_send_stream`. Classification has already parsed these same items;
/// retaining that result would remove exactly this work.
fn reparse_send_inode_items(inodes: &BTreeMap<u64, Vec<&BtrfsLeafEntry>>) -> (usize, u64) {
    let mut parsed = 0_usize;
    let mut digest = 0_u64;
    for (&ino, entries) in inodes {
        if ino < BTRFS_FIRST_FREE_OBJECTID {
            continue;
        }
        let Some(inode) = entries
            .iter()
            .find(|entry| entry.key.item_type == BTRFS_ITEM_INODE_ITEM)
            .and_then(|entry| parse_inode_item(&entry.data).ok())
        else {
            continue;
        };
        parsed += 1;
        digest = digest
            .rotate_left(7)
            .wrapping_add(ino)
            .wrapping_add(inode.generation)
            .wrapping_add(inode.size)
            .wrapping_add(u64::from(inode.mode))
            .wrapping_add(inode.mtime_sec)
            .wrapping_add(u64::from(inode.mtime_nsec));
    }
    (parsed, digest)
}

/// Retry-predicate gate for the prior broad `generate_send_stream` parse row.
/// There is no candidate path in this invocation: it attributes the exact
/// redundant parse pass against duplicate current whole-stream executions.
fn inode_reparse_attribution_only() {
    const PAIRS: usize = 31;
    const WHOLE_REPEATS: u32 = 2;
    const STAGE_REPEATS: u32 = 64;
    const MIN_ATTRIBUTION_FRACTION: f64 = 0.05;

    let items = build_deep_send_items();
    let inodes = group_send_inode_entries(&items);
    let uuid = [0x5a_u8; 16];
    let subvol: &[u8] = b"bench_subvol";
    let (parsed_inodes, parse_digest) = reparse_send_inode_items(&inodes);
    assert_eq!(
        parsed_inodes,
        usize::try_from(DEPTH + FILES + 1).expect("fixture inode count fits usize"),
        "source-neutral parse pass did not cover every fixture inode"
    );

    let stream_a = generate_send_stream(&items, subvol, &uuid, 1, |_bytenr, _len, _ram, _comp| {
        Ok(Vec::new())
    })
    .expect("generate first current stream");
    let stream_b = generate_send_stream(&items, subvol, &uuid, 1, |_bytenr, _len, _ram, _comp| {
        Ok(Vec::new())
    })
    .expect("generate duplicate current stream");
    assert_eq!(stream_a, stream_b, "duplicate current streams differ");
    println!(
        "inode_reparse_attribution_parity,parsed_inodes={parsed_inodes},parse_digest={parse_digest:016x},stream_bytes={},stream_sha256={},result=identical",
        stream_a.len(),
        sha256_hex(&stream_a),
    );

    for _ in 0..4 {
        black_box(reparse_send_inode_items(black_box(&inodes)));
        black_box(
            generate_send_stream(
                black_box(&items),
                black_box(subvol),
                black_box(&uuid),
                black_box(1),
                |_bytenr, _len, _ram, _comp| Ok(Vec::new()),
            )
            .expect("warm current whole stream"),
        );
    }

    let mut whole_lhs_ns = Vec::with_capacity(PAIRS);
    let mut whole_rhs_ns = Vec::with_capacity(PAIRS);
    let mut reparse_ns = Vec::with_capacity(PAIRS);
    let mut raw_pairs = String::with_capacity(PAIRS.saturating_mul(72));
    for pair_index in 0..PAIRS {
        let observe_whole = || {
            observe_ns_per_iteration(
                || {
                    let stream = generate_send_stream(
                        black_box(&items),
                        black_box(subvol),
                        black_box(&uuid),
                        black_box(1),
                        |_bytenr, _len, _ram, _comp| Ok(Vec::new()),
                    )
                    .expect("generate current whole stream");
                    black_box(stream.len());
                },
                WHOLE_REPEATS,
            )
        };
        let observe_reparse = || {
            observe_ns_per_iteration(
                || {
                    let observation = reparse_send_inode_items(black_box(&inodes));
                    black_box(observation);
                },
                STAGE_REPEATS,
            )
        };
        let (lhs, rhs, reparse, order) = if pair_index % 2 == 0 {
            (observe_whole(), observe_whole(), observe_reparse(), "AAS")
        } else {
            let reparse = observe_reparse();
            let rhs = observe_whole();
            let lhs = observe_whole();
            (lhs, rhs, reparse, "SAA")
        };
        whole_lhs_ns.push(lhs);
        whole_rhs_ns.push(rhs);
        reparse_ns.push(reparse);
        if pair_index > 0 {
            raw_pairs.push(';');
        }
        write!(&mut raw_pairs, "{order}:{lhs:.3}:{rhs:.3}:{reparse:.3}")
            .expect("format inode-reparse attribution pair");
    }

    let null_log_ratios = whole_lhs_ns
        .iter()
        .zip(&whole_rhs_ns)
        .map(|(lhs, rhs)| (lhs / rhs).ln())
        .collect::<Vec<_>>();
    let attribution_log_ratios = reparse_ns
        .iter()
        .zip(whole_lhs_ns.iter().zip(&whole_rhs_ns))
        .map(|(reparse, (lhs, rhs))| (reparse / lhs.midpoint(*rhs)).ln())
        .collect::<Vec<_>>();
    let null_summary = bootstrap_median_ci(&null_log_ratios);
    let attribution_summary = bootstrap_median_ci(&attribution_log_ratios);
    let null_log_radius = null_summary
        .low
        .ln()
        .abs()
        .max(null_summary.high.ln().abs());
    let null_floor_ratio = null_log_radius.exp();
    let admitted = null_floor_ratio < 1.10 && attribution_summary.low >= MIN_ATTRIBUTION_FRACTION;
    let verdict = if admitted {
        "ADMITTED_FOR_AB"
    } else if null_floor_ratio >= 1.10 {
        "BLOCKED_NULL_FLOOR"
    } else {
        "NOT_ADMITTED_BELOW_5_PERCENT"
    };
    println!(
        "inode_reparse_attribution_pairs,pairs={PAIRS},whole_repeats={WHOLE_REPEATS},reparse_repeats={STAGE_REPEATS},format=order:whole_lhs_ns:whole_rhs_ns:reparse_ns,values={raw_pairs}"
    );
    println!(
        "inode_reparse_attribution,whole_aa_median={:.6},whole_aa_ci_low={:.6},whole_aa_ci_high={:.6},whole_aa_null_floor_ratio={null_floor_ratio:.6},reparse_fraction_median={:.8},reparse_fraction_ci_low={:.8},reparse_fraction_ci_high={:.8},reparse_pct_median={:.4},minimum_fraction={MIN_ATTRIBUTION_FRACTION:.2},admitted={admitted},verdict={verdict},gate_basis=bootstrap_median_ci,bootstrap_resamples=20000,cv_used=false",
        null_summary.median,
        null_summary.low,
        null_summary.high,
        attribution_summary.median,
        attribution_summary.low,
        attribution_summary.high,
        attribution_summary.median * 100.0,
    );
}

#[cfg(feature = "bench-instrumentation")]
fn parent_index_ab_only() {
    const PAIRS: usize = 31;
    const WHOLE_REPEATS: u32 = 2;

    let items = build_deep_send_items();
    let uuid = [0x5a_u8; 16];
    let subvol: &[u8] = b"bench_subvol";
    let inode_links = collect_inode_links(&items);

    let control_stream = generate_send_stream_materialized_parent_index_control(
        &items,
        subvol,
        &uuid,
        1,
        |_bytenr, _len, _ram, _comp| Ok(Vec::new()),
    )
    .expect("generate materialized-primary-parent control stream");
    let candidate_stream =
        generate_send_stream(&items, subvol, &uuid, 1, |_bytenr, _len, _ram, _comp| {
            Ok(Vec::new())
        })
        .expect("generate direct-primary-link candidate stream");
    assert_eq!(
        control_stream, candidate_stream,
        "direct primary-link lookup changed the complete send stream"
    );
    println!(
        "parent_index_ab_parity,inodes={},links={},primary_name_bytes={},stream_bytes={},control_sha256={},candidate_sha256={},result=identical",
        inode_links.len(),
        inode_links.values().map(Vec::len).sum::<usize>(),
        inode_links
            .values()
            .filter_map(|links| links.first())
            .map(|(_, name)| name.len())
            .sum::<usize>(),
        control_stream.len(),
        sha256_hex(&control_stream),
        sha256_hex(&candidate_stream),
    );

    for _ in 0..4 {
        black_box(
            generate_send_stream_materialized_parent_index_control(
                black_box(&items),
                black_box(subvol),
                black_box(&uuid),
                black_box(1),
                |_bytenr, _len, _ram, _comp| Ok(Vec::new()),
            )
            .expect("warm materialized-primary-parent control stream"),
        );
        black_box(
            generate_send_stream(
                black_box(&items),
                black_box(subvol),
                black_box(&uuid),
                black_box(1),
                |_bytenr, _len, _ram, _comp| Ok(Vec::new()),
            )
            .expect("warm direct-primary-link candidate stream"),
        );
    }

    let mut control_lhs_ns = Vec::with_capacity(PAIRS);
    let mut control_rhs_ns = Vec::with_capacity(PAIRS);
    let mut candidate_ns = Vec::with_capacity(PAIRS);
    let mut raw_pairs = String::with_capacity(PAIRS.saturating_mul(72));
    for pair_index in 0..PAIRS {
        let observe_control = || {
            observe_ns_per_iteration(
                || {
                    let stream = generate_send_stream_materialized_parent_index_control(
                        black_box(&items),
                        black_box(subvol),
                        black_box(&uuid),
                        black_box(1),
                        |_bytenr, _len, _ram, _comp| Ok(Vec::new()),
                    )
                    .expect("generate materialized-primary-parent control stream");
                    black_box(stream.len());
                },
                WHOLE_REPEATS,
            )
        };
        let observe_candidate = || {
            observe_ns_per_iteration(
                || {
                    let stream = generate_send_stream(
                        black_box(&items),
                        black_box(subvol),
                        black_box(&uuid),
                        black_box(1),
                        |_bytenr, _len, _ram, _comp| Ok(Vec::new()),
                    )
                    .expect("generate direct-primary-link candidate stream");
                    black_box(stream.len());
                },
                WHOLE_REPEATS,
            )
        };
        let (lhs, rhs, candidate, order) = if pair_index % 2 == 0 {
            (
                observe_control(),
                observe_control(),
                observe_candidate(),
                "AAB",
            )
        } else {
            let candidate = observe_candidate();
            let rhs = observe_control();
            let lhs = observe_control();
            (lhs, rhs, candidate, "BAA")
        };
        control_lhs_ns.push(lhs);
        control_rhs_ns.push(rhs);
        candidate_ns.push(candidate);
        if pair_index > 0 {
            raw_pairs.push(';');
        }
        write!(&mut raw_pairs, "{order}:{lhs:.3}:{rhs:.3}:{candidate:.3}")
            .expect("format parent-index A/A+B pair");
    }

    let null_log_ratios = control_lhs_ns
        .iter()
        .zip(&control_rhs_ns)
        .map(|(lhs, rhs)| (lhs / rhs).ln())
        .collect::<Vec<_>>();
    let speedup_log_ratios = control_lhs_ns
        .iter()
        .zip(&control_rhs_ns)
        .zip(&candidate_ns)
        .map(|((lhs, rhs), candidate)| (lhs.midpoint(*rhs) / candidate).ln())
        .collect::<Vec<_>>();
    let null_summary = bootstrap_median_ci(&null_log_ratios);
    let speedup_summary = bootstrap_median_ci(&speedup_log_ratios);
    let null_log_radius = null_summary
        .low
        .ln()
        .abs()
        .max(null_summary.high.ln().abs());
    let null_floor_ratio = null_log_radius.exp();
    let twice_null_ratio = (2.0 * null_log_radius).exp();
    let admitted = null_floor_ratio < 1.10
        && speedup_summary.low > twice_null_ratio
        && speedup_summary.low > 1.0;
    let verdict = if admitted {
        "KEEP"
    } else if null_floor_ratio >= 1.10 {
        "REJECT_NULL_FLOOR"
    } else {
        "REJECT_BELOW_TWICE_NULL"
    };
    println!(
        "parent_index_ab_pairs,pairs={PAIRS},whole_repeats={WHOLE_REPEATS},format=order:control_lhs_ns:control_rhs_ns:candidate_ns,values={raw_pairs}"
    );
    println!(
        "parent_index_ab,control_aa_median={:.6},control_aa_ci_low={:.6},control_aa_ci_high={:.6},control_aa_null_floor_ratio={null_floor_ratio:.6},twice_null_ratio={twice_null_ratio:.6},control_over_candidate_median={:.6},control_over_candidate_ci_low={:.6},control_over_candidate_ci_high={:.6},admitted={admitted},verdict={verdict},gate_basis=bootstrap_median_ci,bootstrap_resamples=20000,cv_used=false",
        null_summary.median,
        null_summary.low,
        null_summary.high,
        speedup_summary.median,
        speedup_summary.low,
        speedup_summary.high,
    );
}

fn legacy_generate_send_stream_for_fixture(
    items: &[BtrfsLeafEntry],
    subvol_name: &[u8],
    subvol_uuid: &[u8; 16],
    ctransid: u64,
) -> Vec<u8> {
    let mut builder = LegacySendStreamBuilder::new();
    builder.write_header();
    legacy_add_command(
        &mut builder,
        build_subvol_command(subvol_name, subvol_uuid, ctransid),
    );

    let mut inode_links: BTreeMap<u64, Vec<(u64, Vec<u8>)>> = BTreeMap::new();
    for entry in items {
        if entry.key.item_type == BTRFS_ITEM_INODE_REF {
            if let Ok(refs) = parse_inode_refs(&entry.data) {
                let links = inode_links.entry(entry.key.objectid).or_default();
                for inode_ref in refs {
                    links.push((entry.key.offset, inode_ref.name));
                }
            }
        }
    }
    let inode_parents: BTreeMap<u64, (u64, Vec<u8>)> = inode_links
        .iter()
        .filter_map(|(&ino, links)| links.first().map(|(p, n)| (ino, (*p, n.clone()))))
        .collect();

    let mut path_cache: HashMap<u64, Vec<u8>> =
        HashMap::with_capacity(inode_parents.len().saturating_add(1));
    path_cache.insert(BTRFS_FIRST_FREE_OBJECTID, Vec::new());
    let mut build_path = |ino: u64| -> Vec<u8> {
        if let Some(path) = path_cache.get(&ino) {
            return path.clone();
        }

        let mut trail = Vec::new();
        let mut current = ino;
        let mut base_path = Vec::new();
        loop {
            if let Some(path) = path_cache.get(&current) {
                base_path.clone_from(path);
                break;
            }
            let Some((parent, name)) = inode_parents.get(&current) else {
                break;
            };
            trail.push((current, name.clone()));
            if *parent == current || *parent == BTRFS_FIRST_FREE_OBJECTID {
                break;
            }
            current = *parent;
        }

        let mut path = base_path;
        for (node, name) in trail.iter().rev() {
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(name);
            path_cache.insert(*node, path.clone());
        }
        if trail.is_empty() {
            path_cache.insert(ino, path.clone());
        }
        path
    };

    let mut inodes: BTreeMap<u64, Vec<&BtrfsLeafEntry>> = BTreeMap::new();
    for entry in items {
        inodes.entry(entry.key.objectid).or_default().push(entry);
    }

    let mut dir_inos = Vec::new();
    let mut other_inos = Vec::new();
    for (&ino, entries) in &inodes {
        let Some(inode) = entries
            .iter()
            .find(|e| e.key.item_type == BTRFS_ITEM_INODE_ITEM)
            .and_then(|e| parse_inode_item(&e.data).ok())
        else {
            continue;
        };
        if (inode.mode as u16) & ffs_types::S_IFMT == ffs_types::S_IFDIR {
            dir_inos.push(ino);
        } else {
            other_inos.push(ino);
        }
    }

    let mut depth_cache: HashMap<u64, usize> =
        HashMap::with_capacity(inode_parents.len().saturating_add(1));
    depth_cache.insert(BTRFS_FIRST_FREE_OBJECTID, 0);
    let mut dir_depth = |start: u64| -> usize {
        if let Some(&depth) = depth_cache.get(&start) {
            return depth;
        }

        let mut trail = Vec::new();
        let mut cur = start;
        let mut base_depth = 0usize;
        loop {
            if let Some(&depth) = depth_cache.get(&cur) {
                base_depth = depth;
                break;
            }
            let Some((parent, _)) = inode_parents.get(&cur) else {
                break;
            };
            if *parent == cur || *parent == BTRFS_FIRST_FREE_OBJECTID {
                break;
            }
            trail.push(cur);
            cur = *parent;
            if trail.len() > inodes.len() {
                let depth = trail.len();
                depth_cache.insert(start, depth);
                return depth;
            }
        }

        let mut depth = base_depth;
        for node in trail.iter().rev() {
            depth += 1;
            depth_cache.insert(*node, depth);
        }
        let depth = depth_cache.get(&start).copied().unwrap_or(base_depth);
        depth_cache.insert(start, depth);
        depth
    };
    dir_inos.sort_by_key(|&ino| (dir_depth(ino), ino));
    let emit_order: Vec<u64> = dir_inos.into_iter().chain(other_inos).collect();

    for &ino in &emit_order {
        let entries = &inodes[&ino];
        let Some(inode) = entries
            .iter()
            .find(|e| e.key.item_type == BTRFS_ITEM_INODE_ITEM)
            .and_then(|e| parse_inode_item(&e.data).ok())
        else {
            continue;
        };

        let path = build_path(ino);
        let file_type = (inode.mode as u16) & ffs_types::S_IFMT;

        match file_type {
            ffs_types::S_IFDIR => {
                if ino != BTRFS_FIRST_FREE_OBJECTID {
                    legacy_add_command(&mut builder, build_mkdir_command(&path, ino));
                }
            }
            ffs_types::S_IFREG => {
                legacy_add_command(&mut builder, build_mkfile_command(&path, ino));
                legacy_add_command(&mut builder, build_truncate_command(&path, inode.size));
            }
            _ => continue,
        }

        if file_type != ffs_types::S_IFDIR {
            if let Some(links) = inode_links.get(&ino) {
                for (parent, name) in links.iter().skip(1) {
                    let mut link_path = build_path(*parent);
                    if !link_path.is_empty() {
                        link_path.push(b'/');
                    }
                    link_path.extend_from_slice(name);
                    legacy_add_command(&mut builder, build_link_command(&link_path, &path));
                }
            }
        }

        let mode_bits = u64::from(inode.mode & 0o7777);
        legacy_add_command(&mut builder, build_chmod_command(&path, mode_bits));
        legacy_add_command(
            &mut builder,
            build_chown_command(&path, u64::from(inode.uid), u64::from(inode.gid)),
        );
        legacy_add_command(
            &mut builder,
            build_utimes_command(
                &path,
                inode.atime_sec as i64,
                inode.atime_nsec as i32,
                inode.mtime_sec as i64,
                inode.mtime_nsec as i32,
                inode.ctime_sec as i64,
                inode.ctime_nsec as i32,
            ),
        );
    }

    builder.finalize();
    builder.finish()
}

fn bench_send_stream_path_cache(c: &mut Criterion) {
    let items = build_deep_send_items();
    let uuid = [0x5a_u8; 16];
    let subvol: &[u8] = b"bench_subvol";

    let stream = generate_send_stream(&items, subvol, &uuid, 1, |_bytenr, _len, _ram, _comp| {
        Ok(Vec::new())
    })
    .expect("generate send stream");
    let legacy_stream = legacy_generate_send_stream_for_fixture(&items, subvol, &uuid, 1);
    assert_eq!(
        stream, legacy_stream,
        "fused send stream must be byte-identical to legacy materialized construction"
    );
    assert!(
        stream.len() > 1_000_000,
        "fixture should emit enough PATH bytes to stress parent-chain work"
    );

    let mut group = c.benchmark_group("btrfs_send_stream_deep_paths");
    group.sample_size(10);
    group.bench_function("legacy_materialized_commands", |b| {
        b.iter(|| {
            let out = legacy_generate_send_stream_for_fixture(
                black_box(&items),
                black_box(subvol),
                black_box(&uuid),
                black_box(1),
            );
            black_box(out.len())
        });
    });
    group.bench_function("fused_direct_commands", |b| {
        b.iter(|| {
            let out = generate_send_stream(
                black_box(&items),
                black_box(subvol),
                black_box(&uuid),
                black_box(1),
                |_bytenr, _len, _ram, _comp| Ok(Vec::new()),
            )
            .expect("generate send stream");
            black_box(out.len())
        });
    });
    group.finish();
}

fn bench_send_stream_crc32c(c: &mut Criterion) {
    const DATA_LEN: usize = 48 * 1024;

    let mut frame = vec![0_u8; 10 + 4 + DATA_LEN];
    frame[..4].copy_from_slice(&((4 + DATA_LEN) as u32).to_le_bytes());
    frame[4..6].copy_from_slice(&(SendCommand::Write as u16).to_le_bytes());
    frame[10..12].copy_from_slice(&(SendAttr::Data as u16).to_le_bytes());
    frame[12..14].copy_from_slice(&(DATA_LEN as u16).to_le_bytes());
    for (idx, byte) in frame[14..].iter_mut().enumerate() {
        *byte = (idx as u8).wrapping_mul(37).wrapping_add(11);
    }

    for seed in [0, u32::MAX, 0x1234_5678] {
        for data in [&[][..], b"btrfs-stream".as_slice(), frame.as_slice()] {
            assert_eq!(
                btrfs_send_crc32c(seed, data),
                btrfs_send_crc32c_accelerated(seed, data),
                "accelerated raw-seed CRC32C changed the checksum"
            );
        }
    }
    assert_eq!(
        send_stream_command_crc32c(&frame),
        send_stream_command_crc32c_accelerated(&frame),
        "accelerated command CRC32C changed the framed checksum"
    );

    let mut group = c.benchmark_group("btrfs_send_crc32c_48k_command");
    group.bench_function("bitwise_a", |b| {
        b.iter(|| black_box(send_stream_command_crc32c(black_box(&frame))));
    });
    group.bench_function("bitwise_b", |b| {
        b.iter(|| black_box(send_stream_command_crc32c(black_box(&frame))));
    });
    group.bench_function("accelerated", |b| {
        b.iter(|| black_box(send_stream_command_crc32c_accelerated(black_box(&frame))));
    });
    group.finish();
}

criterion_group!(
    send_stream_path_cache,
    bench_send_stream_path_cache,
    bench_send_stream_crc32c
);

fn main() {
    if std::env::args().any(|arg| arg == "--inode-reparse-attribution-only") {
        print_bench_evidence_metadata();
        print_codegen_isa();
        inode_reparse_attribution_only();
        return;
    }
    if std::env::args().any(|arg| arg == "--parent-index-attribution-only") {
        print_bench_evidence_metadata();
        print_codegen_isa();
        parent_index_attribution_only();
        return;
    }
    if std::env::args().any(|arg| arg == "--parent-index-ab-only") {
        print_bench_evidence_metadata();
        print_codegen_isa();
        #[cfg(feature = "bench-instrumentation")]
        {
            parent_index_ab_only();
            return;
        }
        #[cfg(not(feature = "bench-instrumentation"))]
        panic!("--parent-index-ab-only requires --features bench-instrumentation");
    }
    send_stream_path_cache();
}
