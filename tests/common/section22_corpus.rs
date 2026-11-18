//! Shared Spec §22.3 10-image real `mkfs.ext4` conformance corpus builder.
//!
//! Included via `#[path = ...]` in Gate 1 (`ffs-ondisk`), Gate 2 (`ffs-extent`),
//! Gate 3 (`ffs-dir`), and Gate 5 (`ffs-fuse`) so all canonical §22 gates
//! validate FrankenFS against identical upstream `e2fsprogs`-produced images
//! without introducing cyclic Cargo `[dev-dependencies]`.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CORPUS_CACHE_VERSION: &str = "v3";

#[derive(Debug, Clone)]
pub struct Section22ImageSpec {
    pub name: &'static str,
    pub path: PathBuf,
    pub block_size: u32,
    pub size_bytes: u64,
    pub has_extents: bool,
    pub has_dir_index: bool,
    pub has_metadata_csum: bool,
    pub is_64bit: bool,
    pub has_flex_bg: bool,
}

struct CorpusRecipe {
    name: &'static str,
    label: &'static str,
    block_size: u32,
    inode_size: u16,
    size_bytes: u64,
    features: &'static str,
    extra_args: &'static [&'static str],
    has_extents: bool,
    has_dir_index: bool,
    has_metadata_csum: bool,
    is_64bit: bool,
    has_flex_bg: bool,
}

const RECIPES: &[CorpusRecipe] = &[
    CorpusRecipe {
        name: "img01_minimal.ext4",
        label: "img01_minimal",
        block_size: 4096,
        inode_size: 256,
        size_bytes: 1024 * 1024,
        features: "none,ext_attr,sparse_super,filetype,extent",
        extra_args: &[],
        has_extents: true,
        has_dir_index: false,
        has_metadata_csum: false,
        is_64bit: false,
        has_flex_bg: false,
    },
    CorpusRecipe {
        name: "img02_1k_blocks.ext4",
        label: "img02_1k",
        block_size: 1024,
        inode_size: 256,
        size_bytes: 10 * 1024 * 1024,
        features: "none,ext_attr,sparse_super,filetype,extent,dir_index",
        extra_args: &[],
        has_extents: true,
        has_dir_index: true,
        has_metadata_csum: false,
        is_64bit: false,
        has_flex_bg: false,
    },
    CorpusRecipe {
        name: "img03_2k_blocks.ext4",
        label: "img03_2k",
        block_size: 2048,
        inode_size: 256,
        size_bytes: 10 * 1024 * 1024,
        features: "none,ext_attr,sparse_super,filetype,extent",
        extra_args: &[],
        has_extents: true,
        has_dir_index: false,
        has_metadata_csum: false,
        is_64bit: false,
        has_flex_bg: false,
    },
    CorpusRecipe {
        name: "img04_metadata_csum.ext4",
        label: "img04_csum64",
        block_size: 4096,
        inode_size: 256,
        size_bytes: 100 * 1024 * 1024,
        features: "none,ext_attr,sparse_super,filetype,extent,64bit,metadata_csum,has_journal",
        extra_args: &["-E", "lazy_itable_init=0,lazy_journal_init=0"],
        has_extents: true,
        has_dir_index: false,
        has_metadata_csum: true,
        is_64bit: true,
        has_flex_bg: false,
    },
    CorpusRecipe {
        name: "img05_flex_bg.ext4",
        label: "img05_flexbg",
        block_size: 4096,
        inode_size: 256,
        size_bytes: 100 * 1024 * 1024,
        features: "none,ext_attr,sparse_super,filetype,extent,flex_bg,64bit,metadata_csum",
        extra_args: &["-G", "16", "-E", "lazy_itable_init=0"],
        has_extents: true,
        has_dir_index: false,
        has_metadata_csum: true,
        is_64bit: true,
        has_flex_bg: true,
    },
    CorpusRecipe {
        name: "img06_no_extents.ext4",
        label: "img06_indirect",
        block_size: 4096,
        inode_size: 128,
        size_bytes: 10 * 1024 * 1024,
        features: "none,ext_attr,sparse_super,filetype,uninit_bg",
        extra_args: &[],
        has_extents: false,
        has_dir_index: false,
        has_metadata_csum: false,
        is_64bit: false,
        has_flex_bg: false,
    },
    CorpusRecipe {
        name: "img07_large_dirs.ext4",
        label: "img07_largedir",
        block_size: 4096,
        inode_size: 256,
        size_bytes: 1024 * 1024 * 1024,
        features: "none,ext_attr,sparse_super,filetype,extent,dir_index,dir_nlink,large_dir,64bit,metadata_csum",
        extra_args: &["-E", "lazy_itable_init=0"],
        has_extents: true,
        has_dir_index: true,
        has_metadata_csum: true,
        is_64bit: true,
        has_flex_bg: false,
    },
    CorpusRecipe {
        name: "img08_deep_tree.ext4",
        label: "img08_deeptree",
        block_size: 4096,
        inode_size: 256,
        size_bytes: 1024 * 1024 * 1024,
        features: "none,ext_attr,sparse_super,filetype,extent,huge_file,64bit,metadata_csum",
        extra_args: &["-E", "lazy_itable_init=0"],
        has_extents: true,
        has_dir_index: false,
        has_metadata_csum: true,
        is_64bit: true,
        has_flex_bg: false,
    },
    CorpusRecipe {
        name: "img09_sparse.ext4",
        label: "img09_sparse",
        block_size: 4096,
        inode_size: 256,
        size_bytes: 100 * 1024 * 1024,
        features: "none,ext_attr,sparse_super,filetype,extent,uninit_bg",
        extra_args: &[],
        has_extents: true,
        has_dir_index: false,
        has_metadata_csum: false,
        is_64bit: false,
        has_flex_bg: false,
    },
    CorpusRecipe {
        name: "img10_xattrs.ext4",
        label: "img10_xattrs",
        block_size: 4096,
        inode_size: 256,
        size_bytes: 100 * 1024 * 1024,
        features: "none,ext_attr,sparse_super,filetype,extent,extra_isize,64bit,metadata_csum",
        extra_args: &["-E", "lazy_itable_init=0"],
        has_extents: true,
        has_dir_index: false,
        has_metadata_csum: true,
        is_64bit: true,
        has_flex_bg: false,
    },
];

pub fn command_exists(program: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    for mut base in std::env::split_paths(&paths) {
        base.push(program);
        if let Ok(meta) = fs::metadata(&base)
            && meta.is_file()
            && (meta.permissions().mode() & 0o111) != 0
        {
            return true;
        }
    }
    ["/sbin", "/usr/sbin"]
        .iter()
        .map(|dir| Path::new(dir).join(program))
        .any(|p| {
            fs::metadata(&p).is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        })
}

pub fn find_e2fs_tool(program: &str) -> Option<PathBuf> {
    if let Some(paths) = std::env::var_os("PATH") {
        for mut base in std::env::split_paths(&paths) {
            base.push(program);
            if fs::metadata(&base)
                .is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
            {
                return Some(base);
            }
        }
    }
    for dir in ["/sbin", "/usr/sbin"] {
        let candidate = Path::new(dir).join(program);
        if fs::metadata(&candidate)
            .is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        {
            return Some(candidate);
        }
    }
    None
}

pub fn require_oracles_enabled() -> bool {
    std::env::var_os("FFS_REQUIRE_ORACLES")
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

pub fn require_fuse_enabled() -> bool {
    std::env::var_os("FFS_REQUIRE_FUSE").is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn corpus_cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("FFS_SECTION22_CORPUS_DIR") {
        return PathBuf::from(dir);
    }
    let meta_uid = fs::metadata("/proc/self").map_or(0, |m| m.uid());
    std::env::temp_dir().join(format!(
        "ffs-section22-corpus-{CORPUS_CACHE_VERSION}-u{meta_uid}"
    ))
}

fn corpus_is_complete(dir: &Path) -> bool {
    if !dir.join(format!(".ready-{CORPUS_CACHE_VERSION}")).is_file() {
        return false;
    }
    RECIPES.iter().all(|r| {
        fs::metadata(dir.join(r.name)).is_ok_and(|m| m.is_file() && m.len() == r.size_bytes)
    })
}

fn deterministic_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = vec![0_u8; len];
    for byte in &mut out {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state & 0xFF) as u8;
        if *byte == 0 {
            *byte = 0xA5;
        }
    }
    out
}

fn populate_staging_tree(recipe_name: &str, root: &Path) {
    fs::set_permissions(root, fs::Permissions::from_mode(0o755)).expect("chmod staging root");
    match recipe_name {
        "img01_minimal.ext4" => {
            fs::write(root.join("hello.txt"), b"hello frankenfs minimal\n")
                .expect("write hello.txt");
        }
        "img02_1k_blocks.ext4" => {
            let htree = root.join("htree_dir");
            fs::create_dir_all(&htree).expect("mkdir htree_dir");
            for i in 0..250_u32 {
                let name = format!("entry_{i:04}_hash_probe.txt");
                let body = format!("1k-block-entry-{i:04}\n");
                fs::write(htree.join(name), body.as_bytes()).expect("write htree file");
            }
        }
        "img03_2k_blocks.ext4" => {
            let nested = root.join("alpha").join("beta");
            fs::create_dir_all(&nested).expect("mkdir alpha/beta");
            fs::write(nested.join("note.txt"), b"two-kilobyte-block-note\n")
                .expect("write note.txt");
            symlink("beta/note.txt", root.join("alpha").join("note_link")).expect("create symlink");
            fs::write(root.join("multi.bin"), deterministic_bytes(3, 20 * 1024))
                .expect("write multi.bin");
        }
        "img04_metadata_csum.ext4" => {
            let sub = root.join("docs");
            fs::create_dir_all(&sub).expect("mkdir docs");
            fs::write(sub.join("readme.txt"), b"metadata_csum + 64bit + journal\n")
                .expect("write readme");
            fs::write(root.join("payload.bin"), deterministic_bytes(4, 96 * 1024))
                .expect("write payload.bin");
            symlink("docs/readme.txt", root.join("readme.link")).expect("symlink");
        }
        "img05_flex_bg.ext4" => {
            for g in 0..4_u64 {
                let d = root.join(format!("group_dir_{g}"));
                fs::create_dir_all(&d).expect("mkdir group_dir");
                fs::write(d.join("chunk.bin"), deterministic_bytes(50 + g, 64 * 1024))
                    .expect("write chunk.bin");
            }
        }
        "img06_no_extents.ext4" => {
            fs::write(root.join("small.txt"), b"legacy indirect inode\n").expect("write small.txt");
            fs::write(root.join("indirect.bin"), deterministic_bytes(6, 16 * 4096))
                .expect("write indirect.bin");
        }
        "img07_large_dirs.ext4" => {
            let big = root.join("bigdir");
            fs::create_dir_all(&big).expect("mkdir bigdir");
            let mut seeds = Vec::with_capacity(64);
            for s in 0..64_u32 {
                let p = big.join(format!("f_{s:06}.dat"));
                fs::write(&p, format!("seed-{s:06}\n").as_bytes()).expect("write seed file");
                seeds.push(p);
            }
            for i in 64..100_005_u32 {
                let src = &seeds[(i as usize) & 63];
                let dst = big.join(format!("f_{i:06}.dat"));
                fs::hard_link(src, dst).expect("hard_link bigdir entry");
            }
        }
        "img08_deep_tree.ext4" => {
            fs::write(root.join("depth0.bin"), deterministic_bytes(80, 12 * 1024))
                .expect("write depth0.bin");

            let d1 = File::create(root.join("depth1.bin")).expect("create depth1.bin");
            let blk = deterministic_bytes(81, 4096);
            for i in 0..16_u64 {
                d1.write_all_at(&blk, (i * 2) * 4096)
                    .expect("write depth1 block");
            }

            // 1,408 separated 4 KiB blocks exceed 4 * 340 = 1,360 max depth-1
            // leaf entries, forcing a genuine eh_depth == 2 tree in 5.5 MiB.
            let d2 = File::create(root.join("depth2.bin")).expect("create depth2.bin");
            let blk2 = deterministic_bytes(82, 4096);
            for i in 0..1_408_u64 {
                d2.write_all_at(&blk2, (i * 2) * 4096)
                    .expect("write depth2 block");
            }
        }
        "img09_sparse.ext4" => {
            let sp = File::create(root.join("sparse_holes.bin")).expect("create sparse_holes.bin");
            let seg_a = deterministic_bytes(90, 8192);
            let seg_b = deterministic_bytes(91, 8192);
            sp.write_all_at(&seg_a, 16 * 1024)
                .expect("write sparse seg_a");
            sp.write_all_at(&seg_b, 64 * 1024)
                .expect("write sparse seg_b");
            sp.set_len(128 * 1024).expect("set trailing hole len");
        }
        "img10_xattrs.ext4" => {
            fs::write(root.join("attr_inline.txt"), b"inline xattr carrier\n")
                .expect("write attr_inline.txt");
            fs::write(
                root.join("attr_block.txt"),
                b"external block xattr carrier\n",
            )
            .expect("write attr_block.txt");
        }
        other => panic!("unknown Section 22 recipe {other}"),
    }
}

fn run_checked(cmd: &mut Command, context: &str) {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("{context}: spawn failed: {e}"));
    assert!(
        out.status.success(),
        "{context} failed (status={:?}):\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn apply_post_mkfs_population(
    recipe_name: &str,
    image: &Path,
    debugfs_bin: &Path,
    e2fsck_bin: &Path,
    work_dir: &Path,
    (uid, gid): (u32, u32),
) {
    // Ensure `lost+found` is owned by the test runner uid/gid so non-root
    // `ls -laRn` over both kernel ext4 (`default_permissions`) and FrankenFS
    // FUSE (`MountOption::DefaultPermissions`) traverses it cleanly without EACCES.
    let lf_out = Command::new(debugfs_bin)
        .arg("-w")
        .args([
            "-R",
            &format!("set_inode_field lost+found uid {uid}"),
            "-R",
            &format!("set_inode_field lost+found gid {gid}"),
        ])
        .arg(image)
        .output()
        .expect("spawn debugfs -w lost+found chown");
    assert!(
        lf_out.status.success(),
        "debugfs lost+found uid/gid update failed on {}: {}",
        image.display(),
        String::from_utf8_lossy(&lf_out.stderr)
    );

    if matches!(
        recipe_name,
        "img02_1k_blocks.ext4" | "img07_large_dirs.ext4"
    ) {
        // Force htree directory indexing (`-D`) on dir_index directories.
        let out = Command::new(e2fsck_bin)
            .args(["-f", "-y", "-D"])
            .arg(image)
            .output()
            .expect("spawn e2fsck -fyD");
        let code = out.status.code().unwrap_or(99);
        assert!(
            code == 0 || code == 1,
            "e2fsck -fyD failed on {}: code={code} stderr={}",
            image.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    } else if recipe_name == "img10_xattrs.ext4" {
        let large_val_path = work_dir.join("large_xattr.bin");
        fs::write(&large_val_path, vec![b'X'; 1024]).expect("write large_xattr.bin");
        let script = format!(
            "ea_set /attr_inline.txt user.author frankenfs\n\
             ea_set /attr_inline.txt security.selinux system_u:object_r:unlabeled_t:s0\n\
             ea_set /attr_block.txt user.tag block_carrier\n\
             ea_set /attr_block.txt security.capability cap_net_raw\n\
             ea_set -f {} /attr_block.txt user.large_payload\n",
            large_val_path.display()
        );
        let mut child = Command::new(debugfs_bin)
            .arg("-w")
            .arg(image)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn debugfs -w");
        child
            .stdin
            .take()
            .expect("debugfs stdin")
            .write_all(script.as_bytes())
            .expect("write debugfs script");
        let out = child.wait_with_output().expect("wait debugfs -w");
        assert!(
            out.status.success(),
            "debugfs -w xattr setup failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

pub fn ensure_section22_corpus(suite_name: &str) -> Option<Vec<Section22ImageSpec>> {
    let Some(mkfs_bin) = find_e2fs_tool("mkfs.ext4") else {
        assert!(
            !require_oracles_enabled(),
            "FFS_REQUIRE_ORACLES=1 but mkfs.ext4 is missing"
        );
        println!("SKIP|suite={suite_name}|reason=mkfs_ext4_unavailable");
        return None;
    };
    let Some(debugfs_bin) = find_e2fs_tool("debugfs") else {
        assert!(
            !require_oracles_enabled(),
            "FFS_REQUIRE_ORACLES=1 but debugfs is missing"
        );
        println!("SKIP|suite={suite_name}|reason=debugfs_unavailable");
        return None;
    };
    let Some(_dumpe2fs_bin) = find_e2fs_tool("dumpe2fs") else {
        assert!(
            !require_oracles_enabled(),
            "FFS_REQUIRE_ORACLES=1 but dumpe2fs is missing"
        );
        println!("SKIP|suite={suite_name}|reason=dumpe2fs_unavailable");
        return None;
    };
    let Some(e2fsck_bin) = find_e2fs_tool("e2fsck") else {
        assert!(
            !require_oracles_enabled(),
            "FFS_REQUIRE_ORACLES=1 but e2fsck is missing"
        );
        println!("SKIP|suite={suite_name}|reason=e2fsck_unavailable");
        return None;
    };

    let dir = corpus_cache_dir();
    fs::create_dir_all(&dir).expect("create section22 corpus cache dir");
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(dir.join(".corpus.lock"))
        .expect("open section22 corpus lock");
    lock_file.lock().expect("acquire section22 corpus lock");

    if !corpus_is_complete(&dir) {
        let uid = fs::metadata("/proc/self").map_or(0, |m| m.uid());
        let gid = fs::metadata("/proc/self").map_or(0, |m| m.gid());
        let owner_opt = format!("root_owner={uid}:{gid}");

        for recipe in RECIPES {
            let final_path = dir.join(recipe.name);
            let tmp_img = dir.join(format!(".building-{}", recipe.name));
            let unique_staging = dir.join(format!(
                ".staging-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
                recipe.label
            ));
            fs::create_dir_all(&unique_staging).expect("create unique staging dir");
            populate_staging_tree(recipe.name, &unique_staging);

            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_img)
                .expect("create sparse tmp image");
            f.set_len(recipe.size_bytes).expect("set sparse image size");
            drop(f);

            let mut cmd = Command::new(&mkfs_bin);
            cmd.args([
                "-F",
                "-q",
                "-b",
                &recipe.block_size.to_string(),
                "-I",
                &recipe.inode_size.to_string(),
                "-L",
                recipe.label,
                "-O",
                recipe.features,
                "-E",
                &owner_opt,
            ]);
            cmd.args(recipe.extra_args);
            cmd.arg("-d").arg(&unique_staging).arg(&tmp_img);
            run_checked(&mut cmd, &format!("mkfs.ext4 {}", recipe.name));

            apply_post_mkfs_population(
                recipe.name,
                &tmp_img,
                &debugfs_bin,
                &e2fsck_bin,
                &unique_staging,
                (uid, gid),
            );

            run_checked(
                Command::new(&e2fsck_bin).args(["-f", "-n"]).arg(&tmp_img),
                &format!("e2fsck -fn {}", recipe.name),
            );

            fs::rename(&tmp_img, &final_path).expect("publish built corpus image");
        }
        fs::write(dir.join(format!(".ready-{CORPUS_CACHE_VERSION}")), b"ok\n")
            .expect("write corpus ready marker");
    }

    Some(
        RECIPES
            .iter()
            .map(|r| Section22ImageSpec {
                name: r.name,
                path: dir.join(r.name),
                block_size: r.block_size,
                size_bytes: r.size_bytes,
                has_extents: r.has_extents,
                has_dir_index: r.has_dir_index,
                has_metadata_csum: r.has_metadata_csum,
                is_64bit: r.is_64bit,
                has_flex_bg: r.has_flex_bg,
            })
            .collect(),
    )
}

/// Parse `dumpe2fs -h <image>` key-value output into a lookup map.
pub fn dumpe2fs_header_fields(image: &Path) -> BTreeMap<String, String> {
    let bin = find_e2fs_tool("dumpe2fs").expect("dumpe2fs available");
    let out = Command::new(bin)
        .arg("-h")
        .arg(image)
        .output()
        .expect("run dumpe2fs -h");
    assert!(
        out.status.success(),
        "dumpe2fs -h failed on {}: {}",
        image.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let mut map = BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some((k, v)) = line.split_once(':') {
            map.insert(k.trim().to_owned(), v.trim().to_owned());
        }
    }
    map
}

/// Batch-query `debugfs` `blocks <ino>` for a list of inode numbers in a single
/// `debugfs` process, returning the ordered physical block list per inode.
pub fn debugfs_blocks_for_inodes(image: &Path, inodes: &[u32]) -> BTreeMap<u32, Vec<u64>> {
    if inodes.is_empty() {
        return BTreeMap::new();
    }
    let bin = find_e2fs_tool("debugfs").expect("debugfs available");
    let mut script = String::new();
    for &ino in inodes {
        script.push_str(&format!(
            "!echo __INO_START_{ino}__\nblocks <{ino}>\n!echo __INO_END_{ino}__\n"
        ));
    }
    let mut child = Command::new(bin)
        .arg(image)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn debugfs batch");
    child
        .stdin
        .take()
        .expect("debugfs stdin")
        .write_all(script.as_bytes())
        .expect("write debugfs batch script");
    let out = child.wait_with_output().expect("wait debugfs batch");
    assert!(
        out.status.success(),
        "debugfs batch failed on {}: {}",
        image.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut result = BTreeMap::new();
    let mut current_ino: Option<u32> = None;
    let mut current_blocks: Vec<u64> = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("__INO_START_")
            && let Some(num) = rest.strip_suffix("__")
            && let Ok(ino) = num.parse::<u32>()
        {
            current_ino = Some(ino);
            current_blocks.clear();
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("__INO_END_")
            && let Some(num) = rest.strip_suffix("__")
            && let Ok(ino) = num.parse::<u32>()
        {
            if current_ino == Some(ino) {
                result.insert(ino, std::mem::take(&mut current_blocks));
                current_ino = None;
            }
            continue;
        }
        if current_ino.is_some() {
            for tok in trimmed.split_whitespace() {
                if let Ok(blk) = tok.parse::<u64>() {
                    current_blocks.push(blk);
                }
            }
        }
    }
    result
}
