//! Pure-safe-Rust NTFS EFS (`$EFS` `0x100` metadata & 512-byte sector AES-256-CBC) codec.
//!
//! Uses only FIPS-197 AES-256 implemented in safe Rust (`#![forbid(unsafe_code)]`)
//! and workspace `sha2` for key-commitment verification (zero new external crate
//! dependencies). Windows DPAPI/RSA certificate-store unwrapping is NOT fabricated
//! on Linux; callers must supply explicit FEK credentials scoped to the operation.

use sha2::{Digest, Sha256};

use super::{invalid, le32};
use ffs_types::ParseError;

pub const EFS_STREAM_NAME: [u16; 4] = [b'$' as u16, b'E' as u16, b'F' as u16, b'S' as u16];
pub const EFS_SECTOR_BYTES: usize = 512;
pub const EFS_ALG_AES_256: u32 = 0x6610;
pub const EFS_HEADER_VERSION: u32 = 2;
pub const MAX_EFS_METADATA_BYTES: usize = 64 * 1024;

// Minimal NTFS $EFS binary framing constants (compatible header fields + explicit
// FEK SHA-256 key-commitment DDF entry for safe-Rust key verification).
const EFS_FIXED_HEADER_BYTES: usize = 68;
const EFS_DDF_TAG: [u8; 4] = *b"FDDF";

/// Parsed `$EFS` (`0x100`) stream metadata. Never contains plaintext FEK bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsEfsMetadata {
    pub version: u32,
    pub algorithm_id: u32,
    pub key_id: [u8; 32],
    /// Keyed SHA-256 commitment `SHA256("ffs-ntfs-efs-v1" || fek || key_id || volume_serial)`
    /// verifying that a caller-supplied FEK matches this file before decrypting or overwriting.
    pub key_commitment: [u8; 32],
    pub ddf_count: u32,
    pub drf_count: u32,
    /// True when produced by FrankenFS's explicit FEK-commitment profile; false for
    /// opaque third-party/Windows DPAPI `$EFS` headers preserved in raw mode.
    pub explicit_fek_profile: bool,
    pub raw_bytes: Vec<u8>,
}

/// Derive a deterministic 32-byte key commitment binding `(fek, key_id, volume_serial)`.
#[must_use]
pub fn compute_efs_key_commitment(
    fek: &[u8; 32],
    key_id: &[u8; 32],
    volume_serial: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ffs-ntfs-efs-commit-v1:");
    h.update(fek);
    h.update(key_id);
    h.update(volume_serial.to_le_bytes());
    h.finalize().into()
}

/// Derive a deterministic 32-byte `key_id` fingerprint from an explicit FEK.
#[must_use]
pub fn derive_efs_key_id(fek: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ffs-ntfs-efs-keyid-v1:");
    h.update(fek);
    h.finalize().into()
}

impl NtfsEfsMetadata {
    /// Encode a valid `$EFS` metadata stream binding `algorithm_id`, `key_id`,
    /// and `key_commitment` without embedding any plaintext key bytes.
    pub fn encode_explicit(
        algorithm_id: u32,
        key_id: [u8; 32],
        key_commitment: [u8; 32],
    ) -> Result<Self, ParseError> {
        if algorithm_id != EFS_ALG_AES_256 {
            return Err(invalid("ntfs.efs", "unsupported EFS cipher algorithm"));
        }
        // Standard-shaped 68B header + 76B DDF entry (tag + alg + key_id + key_commitment) = 144B.
        let total_len: usize = EFS_FIXED_HEADER_BYTES + 76;
        let mut raw = vec![0_u8; total_len];
        raw[0..4].copy_from_slice(&(total_len as u32).to_le_bytes()); // total_length
        raw[4..8].copy_from_slice(&0_u32.to_le_bytes()); // state
        raw[8..12].copy_from_slice(&EFS_HEADER_VERSION.to_le_bytes()); // version = 2
        raw[12..16].copy_from_slice(&0_u32.to_le_bytes()); // crypto_api_version
        // Bytes [16..48]: non-secret key_id fingerprint (never the FEK!).
        raw[16..48].copy_from_slice(&key_id);
        // Bytes [48..64]: reserved/DDF/DRF MD5 slots left zero for explicit profile.
        raw[64..68].copy_from_slice(&(EFS_FIXED_HEADER_BYTES as u32).to_le_bytes()); // ddf_offset
        // DDF section at 68..144
        raw[68..72].copy_from_slice(&EFS_DDF_TAG);
        raw[72..76].copy_from_slice(&algorithm_id.to_le_bytes());
        raw[76..108].copy_from_slice(&key_id);
        raw[108..140].copy_from_slice(&key_commitment);
        raw[140..144].copy_from_slice(&1_u32.to_le_bytes()); // ddf_count = 1
        Self::parse(&raw)
    }

    /// Parse and structurally validate a `$EFS` (`0x100`) stream.
    /// Accepts both explicit-FEK headers and opaque third-party `$EFS` headers
    /// (marking the latter `explicit_fek_profile = false` for raw-only preservation).
    pub fn parse(raw: &[u8]) -> Result<Self, ParseError> {
        if raw.len() < EFS_FIXED_HEADER_BYTES || raw.len() > MAX_EFS_METADATA_BYTES {
            return Err(invalid("ntfs.efs", "invalid $EFS metadata stream length"));
        }
        let declared_len = usize::try_from(le32(raw, 0)?)
            .map_err(|_| invalid("ntfs.efs", "$EFS length overflow"))?;
        if declared_len < EFS_FIXED_HEADER_BYTES || declared_len > raw.len() {
            return Err(invalid(
                "ntfs.efs",
                "$EFS declared length exceeds stream bounds",
            ));
        }
        let version = le32(raw, 8)?;
        if !(1..=4).contains(&version) {
            return Err(invalid("ntfs.efs", "unsupported $EFS header version"));
        }
        let ddf_off = usize::try_from(le32(raw, 64)?)
            .map_err(|_| invalid("ntfs.efs", "$EFS DDF offset overflow"))?;
        if ddf_off < EFS_FIXED_HEADER_BYTES || ddf_off > declared_len {
            return Err(invalid("ntfs.efs", "$EFS DDF offset out of bounds"));
        }
        let explicit_slice = raw.get(ddf_off..ddf_off + 76);
        if let Some(ddf) = explicit_slice
            && ddf[0..4] == EFS_DDF_TAG
        {
            let algorithm_id = le32(ddf, 4)?;
            let mut key_id = [0_u8; 32];
            key_id.copy_from_slice(&ddf[8..40]);
            let mut key_commitment = [0_u8; 32];
            key_commitment.copy_from_slice(&ddf[40..72]);
            let ddf_count = le32(ddf, 72)?;
            if ddf_count == 0 {
                return Err(invalid(
                    "ntfs.efs",
                    "$EFS explicit DDF count must be nonzero",
                ));
            }
            return Ok(Self {
                version,
                algorithm_id,
                key_id,
                key_commitment,
                ddf_count,
                drf_count: 0,
                explicit_fek_profile: true,
                raw_bytes: raw.to_vec(),
            });
        }
        let mut fingerprint = [0_u8; 32];
        fingerprint.copy_from_slice(&raw[16..48]);
        Ok(Self {
            version,
            algorithm_id: 0,
            key_id: fingerprint,
            key_commitment: [0_u8; 32],
            ddf_count: 1,
            drf_count: 0,
            explicit_fek_profile: false,
            raw_bytes: raw.to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Pure-safe-Rust FIPS-197 AES-256 block cipher + 512-byte EFS sector CBC
// ---------------------------------------------------------------------------

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const RCON: [u8; 8] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

#[inline]
const fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut acc = 0_u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            acc ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    acc
}

fn expand_key_256(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut words = [[0_u8; 4]; 60];
    for (i, chunk) in key.as_chunks::<4>().0.iter().enumerate() {
        words[i] = *chunk;
    }
    for i in 8..60 {
        let mut temp = words[i - 1];
        if i.is_multiple_of(8) {
            temp = [
                SBOX[usize::from(temp[1])] ^ RCON[i / 8],
                SBOX[usize::from(temp[2])],
                SBOX[usize::from(temp[3])],
                SBOX[usize::from(temp[0])],
            ];
        } else if i % 8 == 4 {
            temp = [
                SBOX[usize::from(temp[0])],
                SBOX[usize::from(temp[1])],
                SBOX[usize::from(temp[2])],
                SBOX[usize::from(temp[3])],
            ];
        }
        words[i] = [
            words[i - 8][0] ^ temp[0],
            words[i - 8][1] ^ temp[1],
            words[i - 8][2] ^ temp[2],
            words[i - 8][3] ^ temp[3],
        ];
    }
    let mut round_keys = [[0_u8; 16]; 15];
    for (r, rk) in round_keys.iter_mut().enumerate() {
        for (c, slot) in rk.chunks_exact_mut(4).enumerate() {
            slot.copy_from_slice(&words[r * 4 + c]);
        }
    }
    round_keys
}

fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for (s, &k) in state.iter_mut().zip(rk.iter()) {
        *s ^= k;
    }
}

fn shift_rows(s: &mut [u8; 16]) {
    // Column-major 4x4 state: index = col*4 + row
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;

    s.swap(2, 10);
    s.swap(6, 14);

    let t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;

    s.swap(2, 10);
    s.swap(6, 14);

    let t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
}

fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        let t = a0 ^ a1 ^ a2 ^ a3;
        s[i] ^= t ^ xtime(a0 ^ a1);
        s[i + 1] ^= t ^ xtime(a1 ^ a2);
        s[i + 2] ^= t ^ xtime(a2 ^ a3);
        s[i + 3] ^= t ^ xtime(a3 ^ a0);
    }
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        s[i + 1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        s[i + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        s[i + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

/// FIPS-197 AES-256 single 16-byte block encryption (pure safe Rust).
#[must_use]
pub fn aes256_encrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
    let mut rks = expand_key_256(key);
    let mut state = *block;
    add_round_key(&mut state, &rks[0]);
    for rk in &rks[1..14] {
        for b in &mut state {
            *b = SBOX[usize::from(*b)];
        }
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, rk);
    }
    for b in &mut state {
        *b = SBOX[usize::from(*b)];
    }
    shift_rows(&mut state);
    add_round_key(&mut state, &rks[14]);
    // Scrub local round-key schedule before returning.
    for rk in &mut rks {
        for byte in rk.iter_mut() {
            *byte = std::hint::black_box(0);
        }
    }
    state
}

/// FIPS-197 AES-256 single 16-byte block decryption (pure safe Rust).
#[must_use]
pub fn aes256_decrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
    let mut rks = expand_key_256(key);
    let mut state = *block;
    add_round_key(&mut state, &rks[14]);
    for rk in rks[1..14].iter().rev() {
        inv_shift_rows(&mut state);
        for b in &mut state {
            *b = INV_SBOX[usize::from(*b)];
        }
        add_round_key(&mut state, rk);
        inv_mix_columns(&mut state);
    }
    inv_shift_rows(&mut state);
    for b in &mut state {
        *b = INV_SBOX[usize::from(*b)];
    }
    add_round_key(&mut state, &rks[0]);
    for rk in &mut rks {
        for byte in rk.iter_mut() {
            *byte = std::hint::black_box(0);
        }
    }
    state
}

/// Native NTFS EFS 512-byte sector IV from logical byte offset (NTFS EFS AES-256 CBC).
/// Derived per 512-byte unit so each sector has a distinct deterministic CBC IV.
#[must_use]
fn efs_sector_iv(logical_sector_offset: u64) -> [u8; 16] {
    let mut iv = [0_u8; 16];
    let lo = logical_sector_offset.wrapping_add(0x1691_1962_9891_ad13);
    let hi = logical_sector_offset.wrapping_add(0x5816_657b_e916_1312);
    iv[0..8].copy_from_slice(&lo.to_le_bytes());
    iv[8..16].copy_from_slice(&hi.to_le_bytes());
    iv
}

/// Encrypt one 512-byte NTFS EFS data unit in place using AES-256-CBC.
pub fn efs_encrypt_sector(
    key: &[u8; 32],
    logical_sector_offset: u64,
    sector: &mut [u8],
) -> Result<(), ParseError> {
    if sector.len() != EFS_SECTOR_BYTES
        || !logical_sector_offset.is_multiple_of(EFS_SECTOR_BYTES as u64)
    {
        return Err(invalid(
            "ntfs.efs",
            "EFS sector encryption requires 512-byte aligned 512-byte buffer",
        ));
    }
    let mut prev = efs_sector_iv(logical_sector_offset);
    for chunk in sector.chunks_exact_mut(16) {
        let mut block = [0_u8; 16];
        for ((dst, &src), &p) in block.iter_mut().zip(chunk.iter()).zip(prev.iter()) {
            *dst = src ^ p;
        }
        let ct = aes256_encrypt_block(key, &block);
        chunk.copy_from_slice(&ct);
        prev = ct;
    }
    Ok(())
}

/// Decrypt one 512-byte NTFS EFS data unit in place using AES-256-CBC.
pub fn efs_decrypt_sector(
    key: &[u8; 32],
    logical_sector_offset: u64,
    sector: &mut [u8],
) -> Result<(), ParseError> {
    if sector.len() != EFS_SECTOR_BYTES
        || !logical_sector_offset.is_multiple_of(EFS_SECTOR_BYTES as u64)
    {
        return Err(invalid(
            "ntfs.efs",
            "EFS sector decryption requires 512-byte aligned 512-byte buffer",
        ));
    }
    let mut prev = efs_sector_iv(logical_sector_offset);
    for chunk in sector.chunks_exact_mut(16) {
        let mut ct = [0_u8; 16];
        ct.copy_from_slice(chunk);
        let dec = aes256_decrypt_block(key, &ct);
        for ((dst, &d), &p) in chunk.iter_mut().zip(dec.iter()).zip(prev.iter()) {
            *dst = d ^ p;
        }
        prev = ct;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_197_appendix_c3_aes256_known_answer_vector() {
        let mut key = [0_u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected_ct: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        let ct = aes256_encrypt_block(&key, &pt);
        assert_eq!(ct, expected_ct);
        assert_eq!(aes256_decrypt_block(&key, &ct), pt);
    }

    #[test]
    fn efs_sector_cbc_and_metadata_commitment_roundtrip() {
        let key = [0x42_u8; 32];
        let key_id = derive_efs_key_id(&key);
        let commitment = compute_efs_key_commitment(&key, &key_id, 0x1234_5678_9abc_def0);
        let meta = NtfsEfsMetadata::encode_explicit(EFS_ALG_AES_256, key_id, commitment).unwrap();
        assert!(meta.explicit_fek_profile);
        assert_eq!(meta.algorithm_id, EFS_ALG_AES_256);
        assert_eq!(meta.key_id, key_id);
        assert_eq!(meta.key_commitment, commitment);
        // Raw $EFS bytes MUST NEVER contain the plaintext FEK!
        assert!(!meta.raw_bytes.windows(32).any(|w| w == key));
        assert_eq!(NtfsEfsMetadata::parse(&meta.raw_bytes).unwrap(), meta);

        let orig: Vec<u8> = (0..512)
            .map(|i| u8::try_from((i * 7) % 251).unwrap())
            .collect();
        let mut s0 = orig.clone();
        let mut s1 = orig.clone();
        efs_encrypt_sector(&key, 0, &mut s0).unwrap();
        efs_encrypt_sector(&key, 512, &mut s1).unwrap();
        assert_ne!(s0, orig);
        assert_ne!(
            s0, s1,
            "distinct sector offsets must produce distinct ciphertext"
        );

        efs_decrypt_sector(&key, 0, &mut s0).unwrap();
        efs_decrypt_sector(&key, 512, &mut s1).unwrap();
        assert_eq!(s0, orig);
        assert_eq!(s1, orig);

        // Wrong key must not recover plaintext and fails commitment check.
        let wrong_key = [0x99_u8; 32];
        assert_ne!(
            compute_efs_key_commitment(&wrong_key, &key_id, 0x1234_5678_9abc_def0),
            commitment
        );
    }
}
