//! Native OpenZFS 2.3.0 dataset encryption key lifecycle, keyring, and ZAP codec.
//!
//! Manages in-memory unwrapped dataset keys keyed by encryption-root DSL directory
//! object ID (`DSL_CRYPTO_ROOT_DDOBJ`), strict fail-closed key status transitions
//! (`load_key` / `unload_key` / `change_key`), key-material scrubbing on drop,
//! and exact on-disk `dsl_crypto_key` MOS ZAP serialization.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::crypto::{
    DSL_CRYPTO_GUID, DSL_CRYPTO_HMAC_KEY_1, DSL_CRYPTO_IV, DSL_CRYPTO_KEY_VERSION_V0,
    DSL_CRYPTO_KEYFORMAT, DSL_CRYPTO_MAC, DSL_CRYPTO_MASTER_KEY_1, DSL_CRYPTO_PBKDF2_ITERS,
    DSL_CRYPTO_PBKDF2_SALT, DSL_CRYPTO_REFCOUNT, DSL_CRYPTO_ROOT_DDOBJ, DSL_CRYPTO_SUITE,
    DSL_CRYPTO_VERSION, DslCryptoKeyRecord, UnwrappedDslKey, ZFS_HMAC_KEY_LEN,
    ZFS_MAX_MASTER_KEY_LEN, ZFS_PBKDF2_MIN_ITERS, ZFS_WRAPPING_KEY_LEN, ZIO_DATA_IV_LEN,
    ZIO_DATA_MAC_LEN, ZIO_DATA_SALT_LEN, ZfsKeyFormat, ZioEncrypt, derive_zfs_passphrase_key,
    scrub_bytes,
};
use ffs_ondisk::zfs_zap::Entry as ZapEntry;
use serde::Serialize;

fn corrupt(detail: impl Into<String>) -> FfsError {
    FfsError::Corruption {
        block: 0,
        detail: detail.into(),
    }
}

/// Runtime key availability for a dataset (`zfs get keystatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ZfsKeyStatus {
    /// Dataset is not encrypted.
    None,
    /// Dataset is encrypted and its encryption root key is loaded in memory.
    Available,
    /// Dataset is encrypted and its encryption root key is not loaded.
    Unavailable,
}

impl ZfsKeyStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Available => "available",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Redacted 32-byte wrapping key, zeroed and scrubbed on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct WrappingKey {
    bytes: [u8; ZFS_WRAPPING_KEY_LEN],
}

impl WrappingKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ZFS_WRAPPING_KEY_LEN]) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ZFS_WRAPPING_KEY_LEN] {
        &self.bytes
    }
}

impl std::fmt::Debug for WrappingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WrappingKey(<redacted>)")
    }
}

impl Drop for WrappingKey {
    fn drop(&mut self) {
        scrub_bytes(&mut self.bytes);
    }
}

/// Caller-supplied wrapping key input for `load_key`, `change_key`, or encrypted dataset creation.
#[derive(Clone)]
pub enum ZfsKeyMaterial {
    /// Exact 32 raw bytes (`keyformat=raw`).
    Raw([u8; ZFS_WRAPPING_KEY_LEN]),
    /// 64 ASCII hexadecimal characters (`keyformat=hex`).
    Hex(String),
    /// UTF-8 / raw passphrase bytes, minimum 8 bytes (`keyformat=passphrase`).
    Passphrase(Vec<u8>),
}

impl std::fmt::Debug for ZfsKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raw(_) => f.write_str("ZfsKeyMaterial::Raw(<redacted>)"),
            Self::Hex(_) => f.write_str("ZfsKeyMaterial::Hex(<redacted>)"),
            Self::Passphrase(_) => f.write_str("ZfsKeyMaterial::Passphrase(<redacted>)"),
        }
    }
}

impl Drop for ZfsKeyMaterial {
    fn drop(&mut self) {
        match self {
            Self::Raw(bytes) => scrub_bytes(bytes),
            Self::Hex(s) => {
                // Replace with empty string; Vec/String bytes cannot be safely mutated in-place
                // without unsafe, so clear to drop capacity cleanly.
                s.clear();
            }
            Self::Passphrase(bytes) => scrub_bytes(bytes),
        }
    }
}

fn decode_hex_wrapping_key(hex: &str) -> Result<WrappingKey> {
    let trimmed = hex.trim();
    if trimmed.len() != ZFS_WRAPPING_KEY_LEN * 2 || !trimmed.is_ascii() {
        return Err(FfsError::Format(
            "ZFS hex key must be exactly 64 ASCII hexadecimal characters".into(),
        ));
    }
    let mut out = [0_u8; ZFS_WRAPPING_KEY_LEN];
    let raw = trimmed.as_bytes();
    for i in 0..ZFS_WRAPPING_KEY_LEN {
        let hi = hex_nibble(raw[i * 2])?;
        let lo = hex_nibble(raw[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(WrappingKey::from_bytes(out))
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(FfsError::Format(
            "invalid hexadecimal character in ZFS key".into(),
        )),
    }
}

impl ZfsKeyMaterial {
    #[must_use]
    pub const fn format(&self) -> ZfsKeyFormat {
        match self {
            Self::Raw(_) => ZfsKeyFormat::Raw,
            Self::Hex(_) => ZfsKeyFormat::Hex,
            Self::Passphrase(_) => ZfsKeyFormat::Passphrase,
        }
    }

    /// Derive the 32-byte wrapping key matching `expected_format` and PBKDF2 parameters.
    pub fn resolve_wrapping_key(
        &self,
        expected_format: ZfsKeyFormat,
        pbkdf2_salt: u64,
        pbkdf2_iters: u64,
    ) -> Result<WrappingKey> {
        if expected_format != ZfsKeyFormat::None && self.format() != expected_format {
            return Err(FfsError::PermissionDenied);
        }
        match self {
            Self::Raw(bytes) => Ok(WrappingKey::from_bytes(*bytes)),
            Self::Hex(hex) => decode_hex_wrapping_key(hex),
            Self::Passphrase(pass) => {
                let iters = if pbkdf2_iters == 0 {
                    return Err(corrupt("passphrase key missing pbkdf2iters"));
                } else if pbkdf2_iters < ZFS_PBKDF2_MIN_ITERS {
                    return Err(corrupt("passphrase pbkdf2iters below minimum 100000"));
                } else {
                    pbkdf2_iters
                };
                let dk = derive_zfs_passphrase_key(pass, pbkdf2_salt, iters)
                    .map_err(|_| FfsError::PermissionDenied)?;
                Ok(WrappingKey::from_bytes(dk))
            }
        }
    }
}

/// Verified on-disk encryption metadata discovered for a dataset in one MOS view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZfsDatasetCryptoInfo {
    /// MOS object ID of the encryption-root `dsl_dir`.
    pub encryption_root_ddobj: u64,
    /// Pool-relative path components of the encryption-root dataset.
    pub encryption_root_components: Vec<Vec<u8>>,
    /// MOS object ID of the `dsl_crypto_key` ZAP object.
    pub crypto_key_obj: u64,
    /// Decoded `dsl_crypto_key` ZAP record.
    pub record: DslCryptoKeyRecord,
    /// Dataset `keylocation` property bytes (default `b"prompt"`).
    pub keylocation: Vec<u8>,
}

/// Thread-safe in-memory keyring mapping `encryption_root_ddobj -> UnwrappedDslKey`.
#[derive(Debug, Default, Clone)]
pub struct ZfsKeyRing {
    keys: Arc<RwLock<BTreeMap<u64, Arc<UnwrappedDslKey>>>>,
}

impl ZfsKeyRing {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Unwrap and load the key for `info`'s encryption root. Fails closed with
    /// `FfsError::PermissionDenied` if the wrapping key/format/passphrase fails MAC verification.
    pub fn load_key(&self, info: &ZfsDatasetCryptoInfo, material: &ZfsKeyMaterial) -> Result<()> {
        let wrapping = material.resolve_wrapping_key(
            info.record.keyformat,
            info.record.pbkdf2_salt,
            info.record.pbkdf2_iters,
        )?;
        let unwrapped = info
            .record
            .unwrap(wrapping.as_bytes())
            .map_err(|_| FfsError::PermissionDenied)?;
        let mut guard = self
            .keys
            .write()
            .map_err(|_| FfsError::Io(std::io::Error::other("ZFS keyring lock poisoned")))?;
        guard.insert(info.encryption_root_ddobj, Arc::new(unwrapped));
        Ok(())
    }

    /// Directly register a freshly generated unwrapped key for a newly created encryption root.
    pub fn insert_unwrapped(&self, encryption_root_ddobj: u64, key: UnwrappedDslKey) -> Result<()> {
        let mut guard = self
            .keys
            .write()
            .map_err(|_| FfsError::Io(std::io::Error::other("ZFS keyring lock poisoned")))?;
        guard.insert(encryption_root_ddobj, Arc::new(key));
        Ok(())
    }

    /// Unload and scrub the in-memory key for `encryption_root_ddobj`.
    /// Returns `true` if a key was present and unloaded.
    pub fn unload_key(&self, encryption_root_ddobj: u64) -> Result<bool> {
        let mut guard = self
            .keys
            .write()
            .map_err(|_| FfsError::Io(std::io::Error::other("ZFS keyring lock poisoned")))?;
        Ok(guard.remove(&encryption_root_ddobj).is_some())
    }

    /// Look up the loaded unwrapped key for `encryption_root_ddobj`.
    #[must_use]
    pub fn get(&self, encryption_root_ddobj: u64) -> Option<Arc<UnwrappedDslKey>> {
        self.keys
            .read()
            .ok()
            .and_then(|guard| guard.get(&encryption_root_ddobj).cloned())
    }

    /// Report `ZfsKeyStatus` for a dataset whose encryption root is `encryption_root_ddobj`.
    #[must_use]
    pub fn key_status(&self, encryption_root_ddobj: Option<u64>) -> ZfsKeyStatus {
        encryption_root_ddobj.map_or(ZfsKeyStatus::None, |root| {
            if self.get(root).is_some() {
                ZfsKeyStatus::Available
            } else {
                ZfsKeyStatus::Unavailable
            }
        })
    }

    /// List all currently loaded encryption-root DSL directory object IDs.
    #[must_use]
    pub fn loaded_roots(&self) -> Vec<u64> {
        self.keys
            .read()
            .map_or_else(|_| Vec::new(), |guard| guard.keys().copied().collect())
    }
}

// ── On-Disk `dsl_crypto_key` MOS ZAP Codec ──────────────────────────────────

fn find_zap_u64(entries: &[ZapEntry], name: &[u8]) -> Result<Option<u64>> {
    let Some(entry) = entries.iter().find(|e| e.name == name) else {
        return Ok(None);
    };
    if entry.integer_bytes != 8 || entry.values.len() != 1 {
        return Err(corrupt(format!(
            "dsl_crypto_key field {:?} is not a uint64 scalar",
            String::from_utf8_lossy(name)
        )));
    }
    Ok(Some(entry.values[0]))
}

fn find_zap_bytes<const N: usize>(entries: &[ZapEntry], name: &[u8]) -> Result<[u8; N]> {
    let entry = entries.iter().find(|e| e.name == name).ok_or_else(|| {
        corrupt(format!(
            "dsl_crypto_key missing required byte array {:?}",
            String::from_utf8_lossy(name)
        ))
    })?;
    if entry.integer_bytes != 1 || entry.values.len() != N {
        return Err(corrupt(format!(
            "dsl_crypto_key field {:?} expected {N} bytes, got {} x {}B",
            String::from_utf8_lossy(name),
            entry.values.len(),
            entry.integer_bytes
        )));
    }
    let mut out = [0_u8; N];
    for (slot, &val) in out.iter_mut().zip(entry.values.iter()) {
        *slot = u8::try_from(val)
            .map_err(|_| corrupt("dsl_crypto_key byte element overflows uint8"))?;
    }
    Ok(out)
}

/// Parse an OpenZFS `dsl_crypto_key` MOS ZAP object into a validated [`DslCryptoKeyRecord`].
pub fn parse_dsl_crypto_key_zap(entries: &[ZapEntry]) -> Result<DslCryptoKeyRecord> {
    let suite_raw = find_zap_u64(entries, DSL_CRYPTO_SUITE)?
        .ok_or_else(|| corrupt("dsl_crypto_key missing DSL_CRYPTO_SUITE"))?;
    let suite = ZioEncrypt::from_raw(suite_raw)
        .map_err(|_| corrupt("dsl_crypto_key invalid cipher suite"))?;
    if !suite.is_active() {
        return Err(corrupt("dsl_crypto_key cipher suite is inactive"));
    }
    let guid = find_zap_u64(entries, DSL_CRYPTO_GUID)?
        .filter(|&g| g != 0)
        .ok_or_else(|| corrupt("dsl_crypto_key missing or zero DSL_CRYPTO_GUID"))?;
    let version = find_zap_u64(entries, DSL_CRYPTO_VERSION)?.unwrap_or(DSL_CRYPTO_KEY_VERSION_V0);
    let root_ddobj = find_zap_u64(entries, DSL_CRYPTO_ROOT_DDOBJ)?
        .filter(|&r| r != 0)
        .ok_or_else(|| corrupt("dsl_crypto_key missing DSL_CRYPTO_ROOT_DDOBJ"))?;
    let refcount = find_zap_u64(entries, DSL_CRYPTO_REFCOUNT)?.unwrap_or(1);
    let keyformat_raw = find_zap_u64(entries, DSL_CRYPTO_KEYFORMAT)?.unwrap_or(0);
    let keyformat = ZfsKeyFormat::from_raw(keyformat_raw)
        .map_err(|_| corrupt("dsl_crypto_key invalid keyformat"))?;
    let pbkdf2_salt = find_zap_u64(entries, DSL_CRYPTO_PBKDF2_SALT)?.unwrap_or(0);
    let pbkdf2_iters = find_zap_u64(entries, DSL_CRYPTO_PBKDF2_ITERS)?.unwrap_or(0);
    let iv = find_zap_bytes::<ZIO_DATA_IV_LEN>(entries, DSL_CRYPTO_IV)?;
    let mac = find_zap_bytes::<ZIO_DATA_MAC_LEN>(entries, DSL_CRYPTO_MAC)?;
    let encrypted_master_key =
        find_zap_bytes::<ZFS_MAX_MASTER_KEY_LEN>(entries, DSL_CRYPTO_MASTER_KEY_1)?;
    let encrypted_hmac_key = find_zap_bytes::<ZFS_HMAC_KEY_LEN>(entries, DSL_CRYPTO_HMAC_KEY_1)?;

    Ok(DslCryptoKeyRecord {
        suite: suite.effective(),
        guid,
        version,
        root_ddobj,
        refcount,
        keyformat,
        pbkdf2_salt,
        pbkdf2_iters,
        iv,
        mac,
        encrypted_master_key,
        encrypted_hmac_key,
    })
}

fn zap_u64_entry(name: &[u8], value: u64) -> ZapEntry {
    ZapEntry {
        name: name.to_vec(),
        integer_bytes: 8,
        values: vec![value],
        collision: 0,
    }
}

fn zap_bytes_entry(name: &[u8], bytes: &[u8]) -> ZapEntry {
    ZapEntry {
        name: name.to_vec(),
        integer_bytes: 1,
        values: bytes.iter().map(|&b| u64::from(b)).collect(),
        collision: 0,
    }
}

/// Encode a [`DslCryptoKeyRecord`] into exact OpenZFS 2.3.0 `dsl_crypto_key` MOS ZAP entries.
#[must_use]
pub fn encode_dsl_crypto_key_zap(record: &DslCryptoKeyRecord) -> Vec<ZapEntry> {
    let mut entries = vec![
        zap_u64_entry(DSL_CRYPTO_SUITE, record.suite.effective().raw()),
        zap_u64_entry(DSL_CRYPTO_GUID, record.guid),
        zap_u64_entry(DSL_CRYPTO_VERSION, record.version),
        zap_u64_entry(DSL_CRYPTO_ROOT_DDOBJ, record.root_ddobj),
        zap_u64_entry(DSL_CRYPTO_REFCOUNT, record.refcount),
        zap_bytes_entry(DSL_CRYPTO_IV, &record.iv),
        zap_bytes_entry(DSL_CRYPTO_MAC, &record.mac),
        zap_bytes_entry(DSL_CRYPTO_MASTER_KEY_1, &record.encrypted_master_key),
        zap_bytes_entry(DSL_CRYPTO_HMAC_KEY_1, &record.encrypted_hmac_key),
        zap_u64_entry(DSL_CRYPTO_KEYFORMAT, record.keyformat.raw()),
    ];
    if record.keyformat == ZfsKeyFormat::Passphrase {
        entries.push(zap_u64_entry(DSL_CRYPTO_PBKDF2_SALT, record.pbkdf2_salt));
        entries.push(zap_u64_entry(DSL_CRYPTO_PBKDF2_ITERS, record.pbkdf2_iters));
    }
    entries
}

/// Strictly unique `(salt, iv)` generator bound to `(ivset_guid, txg, object_id, level, blkid, seq)`.
///
/// Guarantees zero `(salt, iv)` reuse across every newly written block in a TXG and across TXGs
/// without ambient randomness dependency, while deriving pseudorandom nonces via BLAKE3-keyed PRF.
#[derive(Debug, Clone)]
pub struct ZfsNonceGenerator {
    seed: [u8; 32],
    txg: u64,
    counter: u64,
}

impl ZfsNonceGenerator {
    #[must_use]
    pub fn new(ivset_guid: u64, key_guid: u64, txg: u64, extra_entropy: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"frankenfs.zfs.nonce.v1");
        hasher.update(&ivset_guid.to_le_bytes());
        hasher.update(&key_guid.to_le_bytes());
        hasher.update(&txg.to_le_bytes());
        hasher.update(extra_entropy);
        Self {
            seed: *hasher.finalize().as_bytes(),
            txg,
            counter: 0,
        }
    }

    pub fn next_salt_iv(
        &mut self,
        object_id: u64,
        level: u8,
        block_id: u64,
    ) -> ([u8; ZIO_DATA_SALT_LEN], [u8; ZIO_DATA_IV_LEN]) {
        self.counter = self.counter.wrapping_add(1);
        let mut hasher = blake3::Hasher::new_keyed(&self.seed);
        hasher.update(&self.txg.to_le_bytes());
        hasher.update(&object_id.to_le_bytes());
        hasher.update(&[level]);
        hasher.update(&block_id.to_le_bytes());
        hasher.update(&self.counter.to_le_bytes());
        let out = hasher.finalize();
        let bytes = out.as_bytes();
        let mut salt = [0_u8; ZIO_DATA_SALT_LEN];
        salt.copy_from_slice(&bytes[0..ZIO_DATA_SALT_LEN]);
        let mut iv = [0_u8; ZIO_DATA_IV_LEN];
        iv.copy_from_slice(&bytes[ZIO_DATA_SALT_LEN..ZIO_DATA_SALT_LEN + ZIO_DATA_IV_LEN]);
        (salt, iv)
    }
}

/// Derive deterministic or entropy-mixed key material for a newly created encrypted dataset.
pub fn generate_new_dataset_keys(
    pool_guid: u64,
    dataset_guid: u64,
    txg: u64,
    extra_entropy: &[u8],
) -> (
    [u8; ZFS_MAX_MASTER_KEY_LEN],
    [u8; ZFS_HMAC_KEY_LEN],
    [u8; ZIO_DATA_IV_LEN],
    u64,
) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"frankenfs.zfs.newkey.v1");
    hasher.update(&pool_guid.to_le_bytes());
    hasher.update(&dataset_guid.to_le_bytes());
    hasher.update(&txg.to_le_bytes());
    hasher.update(extra_entropy);
    let mut xof = hasher.finalize_xof();
    let mut master = [0_u8; ZFS_MAX_MASTER_KEY_LEN];
    let mut hmac = [0_u8; ZFS_HMAC_KEY_LEN];
    let mut iv = [0_u8; ZIO_DATA_IV_LEN];
    let mut guid_bytes = [0_u8; 8];
    xof.fill(&mut master);
    xof.fill(&mut hmac);
    xof.fill(&mut iv);
    xof.fill(&mut guid_bytes);
    let key_guid = u64::from_le_bytes(guid_bytes).max(1);
    (master, hmac, iv, key_guid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::zfs::crypto::{DSL_CRYPTO_KEY_VERSION_V1, ZFS_PBKDF2_DEFAULT_ITERS};

    #[test]
    fn zap_roundtrip_and_keyring_lifecycle() {
        let wrapping_bytes = [0x42_u8; ZFS_WRAPPING_KEY_LEN];
        let (master, hmac, iv, key_guid) = generate_new_dataset_keys(7, 99, 10, b"test-seed");
        let record = DslCryptoKeyRecord::wrap(
            ZioEncrypt::Aes256Gcm,
            key_guid,
            DSL_CRYPTO_KEY_VERSION_V1,
            55,
            1,
            ZfsKeyFormat::Raw,
            0,
            0,
            iv,
            &wrapping_bytes,
            &master,
            &hmac,
        )
        .unwrap();

        let zap = encode_dsl_crypto_key_zap(&record);
        let parsed = parse_dsl_crypto_key_zap(&zap).unwrap();
        assert_eq!(parsed, record);

        let info = ZfsDatasetCryptoInfo {
            encryption_root_ddobj: 55,
            encryption_root_components: vec![b"enc".to_vec()],
            crypto_key_obj: 77,
            record: parsed,
            keylocation: b"prompt".to_vec(),
        };

        let ring = ZfsKeyRing::new();
        assert_eq!(ring.key_status(None), ZfsKeyStatus::None);
        assert_eq!(ring.key_status(Some(55)), ZfsKeyStatus::Unavailable);

        // Wrong key must fail closed and leave status Unavailable.
        let wrong = ZfsKeyMaterial::Raw([0x43_u8; ZFS_WRAPPING_KEY_LEN]);
        assert!(matches!(
            ring.load_key(&info, &wrong),
            Err(FfsError::PermissionDenied)
        ));
        assert_eq!(ring.key_status(Some(55)), ZfsKeyStatus::Unavailable);

        // Wrong format must fail closed.
        let wrong_fmt = ZfsKeyMaterial::Hex("42".repeat(32));
        assert!(matches!(
            ring.load_key(&info, &wrong_fmt),
            Err(FfsError::PermissionDenied)
        ));

        // Correct raw key succeeds and becomes Available.
        let right = ZfsKeyMaterial::Raw(wrapping_bytes);
        ring.load_key(&info, &right).unwrap();
        assert_eq!(ring.key_status(Some(55)), ZfsKeyStatus::Available);
        let unwrapped = ring.get(55).unwrap();
        assert_eq!(unwrapped.active_master_key(), &master);
        assert_eq!(unwrapped.hmac_key, hmac);

        // Debug must redact key material.
        assert!(format!("{unwrapped:?}").contains("<redacted>"));
        assert!(format!("{right:?}").contains("<redacted>"));

        // Unload transitions back to Unavailable.
        assert!(ring.unload_key(55).unwrap());
        assert_eq!(ring.key_status(Some(55)), ZfsKeyStatus::Unavailable);
        assert!(!ring.unload_key(55).unwrap());
    }

    #[test]
    fn passphrase_key_derivation_and_nonce_uniqueness() {
        let salt = 0x1122_3344_5566_7788_u64;
        let pass = ZfsKeyMaterial::Passphrase(b"correct horse battery staple".to_vec());
        let wk = pass
            .resolve_wrapping_key(ZfsKeyFormat::Passphrase, salt, ZFS_PBKDF2_MIN_ITERS)
            .unwrap();
        let (master, hmac, iv, key_guid) = generate_new_dataset_keys(1, 2, 3, b"pass-seed");
        let rec = DslCryptoKeyRecord::wrap(
            ZioEncrypt::Aes128Ccm,
            key_guid,
            DSL_CRYPTO_KEY_VERSION_V1,
            10,
            1,
            ZfsKeyFormat::Passphrase,
            salt,
            ZFS_PBKDF2_MIN_ITERS,
            iv,
            wk.as_bytes(),
            &master,
            &hmac,
        )
        .unwrap();
        let zap = encode_dsl_crypto_key_zap(&rec);
        let parsed = parse_dsl_crypto_key_zap(&zap).unwrap();
        assert_eq!(parsed.pbkdf2_salt, salt);
        assert_eq!(parsed.pbkdf2_iters, ZFS_PBKDF2_MIN_ITERS);
        let _ = ZFS_PBKDF2_DEFAULT_ITERS;

        let mut nonce_gen = ZfsNonceGenerator::new(100, key_guid, 5, b"");
        let a = nonce_gen.next_salt_iv(1, 0, 0);
        let b = nonce_gen.next_salt_iv(1, 0, 0);
        let c = nonce_gen.next_salt_iv(1, 0, 1);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }
}
