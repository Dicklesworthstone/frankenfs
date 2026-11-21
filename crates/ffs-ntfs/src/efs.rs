//! Explicit key-scoped NTFS EFS (`0x4000`, `$EFS` `0x100`) credentials, raw
//! ciphertext access, and authenticated plaintext reading.
//!
//! Security contract:
//! - Unauthorized callers NEVER receive fabricated plaintext; `NtfsVolume::data_stream`
//!   and `NtfsFs::read`/`write` keep refusing `FILE_ATTRIBUTE_ENCRYPTED` (`0x4000`).
//! - Raw ciphertext inspection (`read_raw_efs_ciphertext`) is a distinct explicit API.
//! - Plaintext decryption/encryption requires an explicit [`NtfsEfsKeyScope`] supplying
//!   the exact 32-byte FEK matching the `$EFS` SHA-256 key commitment.
//! - [`NtfsEfsKey`] redacts its key bytes in `Debug`/`Display` and scrubs key memory
//!   on `Drop` in pure safe Rust (`#![forbid(unsafe_code)]`).

use std::collections::BTreeMap;
use std::fmt;

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::efs::{
    EFS_ALG_AES_256, EFS_SECTOR_BYTES, EFS_STREAM_NAME, NtfsEfsMetadata,
    compute_efs_key_commitment, derive_efs_key_id, efs_decrypt_sector,
};
use ffs_ondisk::ntfs::{DATA, ENCRYPTED, LOGGED_UTILITY_STREAM, NtfsFileRecord};
use serde::Serialize;

use crate::NtfsVolume;
use crate::reader::checkpoint;

/// Scoped 256-bit File Encryption Key (FEK).
///
/// Key bytes are never printed by `Debug`/`Display` and are actively zero-scrubbed
/// on `Drop` using `std::hint::black_box` (pure safe Rust).
#[derive(Clone, PartialEq, Eq)]
pub struct NtfsEfsKey {
    fek: [u8; 32],
    key_id: [u8; 32],
}

impl NtfsEfsKey {
    /// Construct a scoped EFS key from explicit 32-byte FEK material.
    #[must_use]
    pub fn from_raw_bytes(fek: [u8; 32]) -> Self {
        let key_id = derive_efs_key_id(&fek);
        Self { fek, key_id }
    }

    /// Parse a scoped EFS key from a 64-character hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let trimmed = hex_str.trim();
        if trimmed.len() != 64 {
            return Err(FfsError::Format(
                "NTFS EFS FEK must be exactly 64 hex characters (32 bytes)".into(),
            ));
        }
        let mut fek = [0_u8; 32];
        for (idx, dst) in fek.iter_mut().enumerate() {
            let pair = &trimmed[idx * 2..idx * 2 + 2];
            *dst = u8::from_str_radix(pair, 16)
                .map_err(|_| FfsError::Format("invalid hex byte in NTFS EFS FEK".into()))?;
        }
        Ok(Self::from_raw_bytes(fek))
    }

    #[must_use]
    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    #[must_use]
    pub fn key_id_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for b in &self.key_id {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    #[must_use]
    pub(crate) const fn raw_fek(&self) -> &[u8; 32] {
        &self.fek
    }
}

impl Drop for NtfsEfsKey {
    fn drop(&mut self) {
        for b in &mut self.fek {
            *b = std::hint::black_box(0);
        }
    }
}

impl fmt::Debug for NtfsEfsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtfsEfsKey")
            .field("key_id", &self.key_id_hex())
            .field("fek", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for NtfsEfsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NtfsEfsKey(key_id={}, fek=[REDACTED])",
            self.key_id_hex()
        )
    }
}

/// Explicit per-operation credential provider for authorized NTFS EFS transforms.
pub trait NtfsEfsKeyScope: Send + Sync {
    /// Resolve the explicit FEK for `key_id`, or `None` if unauthorized/unloaded.
    fn resolve_key(&self, key_id: &[u8; 32]) -> Option<NtfsEfsKey>;
}

/// In-memory scoped key ring holding explicitly loaded [`NtfsEfsKey`]s.
/// All keys are scrubbed on `Drop`.
#[derive(Default)]
pub struct StaticEfsKeyScope {
    keys: BTreeMap<[u8; 32], NtfsEfsKey>,
}

impl StaticEfsKeyScope {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: NtfsEfsKey) -> [u8; 32] {
        let id = key.key_id();
        self.keys.insert(id, key);
        id
    }

    pub fn remove(&mut self, key_id: &[u8; 32]) -> bool {
        self.keys.remove(key_id).is_some()
    }
}

impl fmt::Debug for StaticEfsKeyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticEfsKeyScope")
            .field("loaded_keys", &self.keys.len())
            .finish()
    }
}

impl NtfsEfsKeyScope for StaticEfsKeyScope {
    fn resolve_key(&self, key_id: &[u8; 32]) -> Option<NtfsEfsKey> {
        self.keys.get(key_id).cloned()
    }
}

/// Redacted, serializable inspection report for a file's `$EFS` (`0x100`) stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NtfsEfsMetadataInfo {
    pub record: u32,
    pub sequence: u16,
    pub encrypted_flag_set: bool,
    pub version: u32,
    pub algorithm_id: u32,
    pub key_id_hex: String,
    pub ddf_count: u32,
    pub drf_count: u32,
    pub explicit_fek_profile: bool,
    pub stream_bytes: usize,
}

impl NtfsVolume {
    /// Inspect an encrypted file's `$EFS` (`0x100`) metadata without requiring keys
    /// and without exposing any secret material.
    pub fn efs_metadata(
        &self,
        cx: &Cx,
        record: &NtfsFileRecord,
    ) -> Result<Option<(NtfsEfsMetadata, NtfsEfsMetadataInfo)>> {
        checkpoint(cx)?;
        let catalog = self.attributes(cx, record)?;
        let all = catalog.all()?;
        let has_efs_stream = all
            .iter()
            .any(|a| a.kind == LOGGED_UTILITY_STREAM && a.name == EFS_STREAM_NAME);
        if !has_efs_stream {
            return Ok(None);
        }
        let efs_stream = catalog.select(&self.geometry, LOGGED_UTILITY_STREAM, &EFS_STREAM_NAME)?;
        if efs_stream.size == 0 || efs_stream.size > 65_536 {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "invalid $EFS stream length".into(),
            });
        }
        let raw = self.read(cx, &efs_stream, 0, efs_stream.size as usize)?;
        let meta = NtfsEfsMetadata::parse(&raw).map_err(|err| FfsError::Corruption {
            block: 0,
            detail: err.to_string(),
        })?;
        let std_attr = catalog.select(&self.geometry, 0x10, &[])?;
        let std_raw = self.read(cx, &std_attr, 0, std_attr.size.min(72) as usize)?;
        let encrypted_flag_set = std_raw.len() >= 36
            && (u32::from_le_bytes([std_raw[32], std_raw[33], std_raw[34], std_raw[35]]) & 0x4000)
                != 0;
        let mut key_id_hex = String::with_capacity(64);
        for b in &meta.key_id {
            key_id_hex.push_str(&format!("{b:02x}"));
        }
        let info = NtfsEfsMetadataInfo {
            record: record.number,
            sequence: record.sequence,
            encrypted_flag_set,
            version: meta.version,
            algorithm_id: meta.algorithm_id,
            key_id_hex,
            ddf_count: meta.ddf_count,
            drf_count: meta.drf_count,
            explicit_fek_profile: meta.explicit_fek_profile,
            stream_bytes: raw.len(),
        };
        Ok(Some((meta, info)))
    }

    /// Explicitly read raw stored ciphertext bytes of an EFS-encrypted unnamed `$DATA`
    /// stream (without decrypting or masquerading as plaintext).
    pub fn read_raw_efs_ciphertext(
        &self,
        cx: &Cx,
        record: &NtfsFileRecord,
        offset: u64,
        bytes: usize,
    ) -> Result<(u64, Vec<u8>)> {
        checkpoint(cx)?;
        if record.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        let catalog = self.attributes(cx, record)?;
        let all = catalog.all()?;
        let is_encrypted_attr = all
            .iter()
            .any(|a| a.kind == DATA && a.name.is_empty() && (a.flags & ENCRYPTED != 0));
        if !is_encrypted_attr {
            return Err(FfsError::UnsupportedFeature(
                "raw EFS ciphertext read requires an encrypted unnamed $DATA stream".into(),
            ));
        }
        let stream = catalog.select_raw_encrypted(&self.geometry, DATA, &[])?;
        let data = self.read(cx, &stream, offset, bytes)?;
        Ok((stream.size, data))
    }

    /// Decrypt and read plaintext bytes of an EFS-encrypted file using an explicit
    /// authorized [`NtfsEfsKeyScope`]. Refuses wrong/missing keys or opaque third-party
    /// DPAPI-wrapped headers before returning any byte.
    pub fn read_efs_plaintext(
        &self,
        cx: &Cx,
        record: &NtfsFileRecord,
        key_scope: &dyn NtfsEfsKeyScope,
        offset: u64,
        bytes: usize,
    ) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        if record.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        let Some((meta, info)) = self.efs_metadata(cx, record)? else {
            return Err(FfsError::UnsupportedFeature(
                "file does not carry an $EFS metadata stream".into(),
            ));
        };
        if !info.encrypted_flag_set
            || !meta.explicit_fek_profile
            || meta.algorithm_id != EFS_ALG_AES_256
        {
            return Err(FfsError::UnsupportedFeature(
                "EFS plaintext access requires explicit AES-256 FEK profile (Windows DPAPI unwrapping is not fabricated on Linux)".into(),
            ));
        }
        let key = key_scope
            .resolve_key(&meta.key_id)
            .ok_or(FfsError::PermissionDenied)?;
        let expected =
            compute_efs_key_commitment(key.raw_fek(), &meta.key_id, self.geometry.serial());
        if expected != meta.key_commitment {
            return Err(FfsError::PermissionDenied);
        }

        let catalog = self.attributes(cx, record)?;
        let stream = catalog.select_raw_encrypted(&self.geometry, DATA, &[])?;
        if offset >= stream.size || bytes == 0 {
            return Ok(Vec::new());
        }
        let readable = usize::try_from((stream.size - offset).min(bytes as u64))
            .map_err(|_| FfsError::Format("EFS read length overflow".into()))?;
        let aligned_start = (offset / EFS_SECTOR_BYTES as u64) * EFS_SECTOR_BYTES as u64;
        let aligned_end = (offset + readable as u64).next_multiple_of(EFS_SECTOR_BYTES as u64);
        let read_span = usize::try_from(aligned_end - aligned_start)
            .map_err(|_| FfsError::Format("EFS aligned span overflow".into()))?;
        // Read full 512-byte encrypted sectors covering [offset .. offset + readable).
        let mut cipher = self.read_raw_aligned_encrypted(cx, &stream, aligned_start, read_span)?;
        for (idx, sector) in cipher
            .as_chunks_mut::<EFS_SECTOR_BYTES>()
            .0
            .iter_mut()
            .enumerate()
        {
            checkpoint(cx)?;
            let sec_off = aligned_start + (idx as u64) * (EFS_SECTOR_BYTES as u64);
            efs_decrypt_sector(key.raw_fek(), sec_off, sector).map_err(|err| {
                FfsError::Corruption {
                    block: sec_off / 512,
                    detail: err.to_string(),
                }
            })?;
        }
        let rel = (offset - aligned_start) as usize;
        Ok(cipher[rel..rel + readable].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn efs_key_redacts_debug_and_display() {
        let hex = "00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef";
        let key = NtfsEfsKey::from_hex(hex).unwrap();
        let dbg = format!("{key:?}");
        let disp = format!("{key}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(disp.contains("[REDACTED]"));
        assert!(!dbg.contains("00112233"));
        assert!(!disp.contains("00112233"));
    }
}
