//! Read-only lost-chain export to a separate, private host directory.
//!
//! Reuse the recovery ownership proof, but never free a cluster or clear native
//! dirty state. An orphan has no trustworthy filename, type or logical EOF:
//! exported bytes are whole clusters and may include sensitive deleted data.
//! This is raw salvage, not undeletion, native repair or payload reconstruction.

use super::{
    FatEntry, FatKind, FatTable, FatVolume, MAX_CHAIN_CLUSTERS, Plan, allocate, checkpoint,
    hex_digest,
};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_FILES: usize = 10_000;
const MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const BUFFER_BYTES: usize = 64 * 1024;

/// Follow only disjoint, acyclic chains with native end markers. Sorting cluster
/// IDs is NOT file order. Merges, cycles and links into reachable allocation have
/// no unique original ownership, so refuse the whole export before output I/O.
fn chains(cx: &Cx, kind: FatKind, lost: &[(u32, u32)]) -> Result<Vec<Vec<u32>>> {
    checkpoint(cx)?;
    if lost.len() > MAX_CHAIN_CLUSTERS {
        bail!("salvage exceeds the native allocation work budget");
    }
    let mut inbound = allocate(lost.len())?;
    let mut visited = allocate(lost.len())?;
    let locate = |cluster| {
        lost.binary_search_by_key(&cluster, |&(id, _)| id)
            .map_err(|_| anyhow::anyhow!("lost chain points outside proven unreachable allocation"))
    };
    for (index, &(cluster, raw)) in lost.iter().enumerate() {
        checkpoint(cx)?;
        if cluster < 2 || (index != 0 && lost[index - 1].0 >= cluster) {
            bail!("salvage requires strictly ordered, unique data-cluster identities");
        }
        match kind.decode_entry(raw) {
            FatEntry::End => {}
            FatEntry::Next(next) => {
                let target = locate(next)?;
                if inbound[target] != 0 {
                    bail!("lost chains merge at cluster {next}; refusing to guess ownership");
                }
                inbound[target] = 1;
            }
            _ => bail!("lost chain includes a free, bad, reserved or invalid successor"),
        }
    }
    let mut result = Vec::new();
    let mut count = 0;
    for head in 0..lost.len() {
        checkpoint(cx)?;
        if inbound[head] != 0 {
            continue;
        }
        if result.len() == MAX_FILES {
            bail!("salvage exceeds 10000 recovered files");
        }
        let mut chain = Vec::new();
        let mut at = head;
        loop {
            checkpoint(cx)?;
            if visited[at] != 0 {
                bail!("lost chain revisits an already assigned cluster");
            }
            visited[at] = 1;
            count += 1;
            chain
                .try_reserve(1)
                .context("reserving bounded salvage chain")?;
            chain.push(lost[at].0);
            match kind.decode_entry(lost[at].1) {
                FatEntry::End => break,
                FatEntry::Next(next) => at = locate(next)?,
                _ => bail!("invalid salvage chain successor"),
            }
        }
        result
            .try_reserve(1)
            .context("reserving bounded salvage file list")?;
        result.push(chain);
    }
    if count != lost.len() {
        bail!("lost allocation contains a cycle without a unique head");
    }
    Ok(result)
}

pub(super) struct Salvage {
    evidence: Plan,
    chains: Vec<Vec<u32>>,
    output: PathBuf,
    bytes: u64,
}

#[derive(Serialize)]
struct ExportedFile {
    name: String,
    /// Native allocation order, not ascending physical cluster IDs.
    clusters: Vec<u32>,
    bytes: u64,
    sha256: String,
}

impl Salvage {
    pub(super) fn prepare(
        cx: &Cx,
        volume: &FatVolume,
        evidence: Plan,
        output: &Path,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let bytes = (evidence.lost.len() as u64)
            .checked_mul(u64::from(volume.geometry.cluster_bytes()))
            .filter(|bytes| *bytes <= MAX_BYTES)
            .context("salvage exceeds the 64 GiB export budget")?;
        let chains = chains(cx, volume.geometry.kind(), &evidence.lost)?;
        // Resolve the operator-selected parent once, and require a fresh leaf.
        // The caller must keep this host directory namespace exclusively owned.
        let leaf = output
            .file_name()
            .context("salvage requires a new output directory name")?;
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .canonicalize()
            .context("resolve existing salvage output parent")?;
        let output = parent.join(leaf);
        match fs::symlink_metadata(&output) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => bail!(
                "salvage output must not already exist: {}",
                output.display()
            ),
        }
        for chain in &chains {
            for &cluster in chain {
                checkpoint(cx)?;
                volume.cluster_offset(cluster)?;
            }
        }
        Ok(Self {
            evidence,
            chains,
            output,
            bytes,
        })
    }

    pub(super) fn report(&self, dry_run: bool) -> serde_json::Value {
        serde_json::json!({
            "operation": "salvage_lost_chains", "dry_run": dry_run,
            "image_changed": false, "image_repaired": false,
            "format": self.evidence.before.format,
            "volume_offset": self.evidence.before.volume_offset,
            "volume_bytes": self.evidence.before.volume_bytes,
            "output_directory": self.output.to_string_lossy(),
            "output_directory_bytes": self.output.as_os_str().as_encoded_bytes(),
            "planned_files": self.chains.len(), "planned_bytes": self.bytes,
            "planned_clusters": self.evidence.lost.len(),
            "original_names_known": false, "original_lengths_known": false,
            "warning": "whole-cluster exports include slack, may contain sensitive deleted data or directory records, and are not proof of original file integrity",
            "before": self.evidence.before,
        })
    }

    fn validate_links(&self, cx: &Cx, volume: &FatVolume) -> Result<()> {
        let mut table = FatTable::new(volume);
        for &(cluster, expected) in &self.evidence.lost {
            checkpoint(cx)?;
            for copy in volume.copies() {
                if table.raw_entry(cx, copy, cluster)? != expected {
                    bail!("lost allocation changed after salvage preflight in FAT copy {copy}");
                }
            }
        }
        Ok(())
    }

    pub(super) fn execute(
        &self,
        cx: &Cx,
        volume: &FatVolume,
        mut source_stable: impl FnMut() -> Result<()>,
    ) -> Result<serde_json::Value> {
        checkpoint(cx)?;
        source_stable()?;
        self.validate_links(cx, volume)?;
        // Reserve buffers and reporting capacity BEFORE creating output.
        let mut buffer = allocate(BUFFER_BYTES)?;
        let mut files = Vec::new();
        files
            .try_reserve_exact(self.chains.len())
            .context("reserving salvage manifest")?;
        let mut report = self.report(false);
        if self.chains.is_empty() {
            report["output_created"] = false.into();
            report["exported_files"] = 0.into();
            report["exported_bytes"] = 0.into();
            source_stable()?;
            checkpoint(cx)?;
            return Ok(report);
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(
                self.output
                    .parent()
                    .context("salvage output has no parent")?,
            )?;
        DirBuilder::new()
            .mode(0o700)
            .create(&self.output)
            .context("create new private salvage directory; existing targets are never reused")?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&self.output)?;
        let identity = directory.metadata()?;
        let result = (|| -> Result<serde_json::Value> {
            for (index, chain) in self.chains.iter().enumerate() {
                checkpoint(cx)?;
                source_stable()?;
                same_directory(&self.output, &identity)?;
                let name = format!("FILE{index:04}.CHK");
                let mut target = new_file(&self.output.join(&name))?;
                let digest = stream_chain(cx, volume, chain, &mut target, &mut buffer)?;
                target.sync_all()?;
                let length = chain.len() as u64 * u64::from(volume.geometry.cluster_bytes());
                verify_output(cx, &mut target, length, &digest, &mut buffer)?;
                source_stable()?;
                let mut retained_chain = Vec::new();
                retained_chain
                    .try_reserve_exact(chain.len())
                    .context("retaining salvage provenance")?;
                retained_chain.extend_from_slice(chain);
                files.push(ExportedFile {
                    name,
                    clusters: retained_chain,
                    bytes: length,
                    sha256: hex_digest(&digest),
                });
            }
            self.validate_links(cx, volume)?;
            source_stable()?;
            same_directory(&self.output, &identity)?;
            checkpoint(cx)?;
            report["output_created"] = true.into();
            report["exported_files"] = files.len().into();
            report["exported_bytes"] = self.bytes.into();
            report["files"] = serde_json::to_value(&files)?;
            // Publish the manifest only after every output has been synchronized
            // and read back. Failure retains partial artifacts but never reports
            // success or deletes the operator's evidence to disguise the failure.
            let mut manifest = new_file(&self.output.join("manifest.json"))?;
            serde_json::to_writer_pretty(&mut manifest, &report)?;
            manifest.write_all(b"\n")?;
            manifest.sync_all()?;
            directory.sync_all()?;
            parent.sync_all()?;
            same_directory(&self.output, &identity)?;
            source_stable()?;
            checkpoint(cx)?;
            Ok(report)
        })();
        result.with_context(|| {
            format!(
                "FAT salvage failed; image was not modified; partial output retained at {}",
                self.output.display()
            )
        })
    }
}

fn new_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?)
}

fn same_directory(path: &Path, original: &Metadata) -> Result<()> {
    let current = fs::symlink_metadata(path)?;
    if !current.is_dir()
        || current.file_type().is_symlink()
        || current.dev() != original.dev()
        || current.ino() != original.ino()
    {
        bail!("salvage output directory identity changed");
    }
    Ok(())
}

fn stream_chain(
    cx: &Cx,
    volume: &FatVolume,
    chain: &[u32],
    output: &mut impl Write,
    buffer: &mut [u8],
) -> Result<[u8; 32]> {
    if buffer.is_empty() {
        bail!("salvage streaming buffer is empty");
    }
    let mut hash = Sha256::new();
    for &cluster in chain {
        let base = volume.cluster_offset(cluster)?;
        let length = u64::from(volume.geometry.cluster_bytes());
        let mut offset = 0;
        while offset < length {
            checkpoint(cx)?;
            let count = (length - offset).min(buffer.len() as u64) as usize;
            volume.read_exact(cx, base + offset, &mut buffer[..count])?;
            // An I/O failure never emits bytes from a partially filled buffer.
            checkpoint(cx)?;
            output.write_all(&buffer[..count])?;
            hash.update(&buffer[..count]);
            offset += count as u64;
        }
    }
    checkpoint(cx)?;
    output.flush()?;
    Ok(hash.finalize().into())
}

fn verify_output(
    cx: &Cx,
    file: &mut File,
    length: u64,
    expected: &[u8; 32],
    buffer: &mut [u8],
) -> Result<()> {
    if buffer.is_empty() {
        bail!("salvage readback buffer is empty");
    }
    if file.metadata()?.len() != length {
        bail!("salvaged file length failed readback");
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut left = length;
    while left != 0 {
        checkpoint(cx)?;
        let count = left.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        left -= count as u64;
    }
    let actual: [u8; 32] = hash.finalize().into();
    if &actual != expected {
        bail!("salvaged file SHA-256 failed readback");
    }
    checkpoint(cx)?;
    Ok(())
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
