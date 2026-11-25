//! Native OpenZFS 2.3.0 authenticated encryption primitives and wire formats.
//!
//! Pure safe Rust (`#![forbid(unsafe_code)]`) with zero new external crates.
//! Wire layouts, AAD ordering, key derivation, and MAC rules match upstream
//! OpenZFS `zfs-2.3.0`:
//! - `module/zfs/zio_crypt.c` & `include/sys/zio_crypt.h`
//! - `module/zfs/dsl_crypt.c` & `module/zfs/hkdf.c`
//! - `module/zfs/zio_checksum.c` (`zio_checksum_handle_crypt`)
//! - `lib/libzfs/libzfs_crypto.c` (PBKDF2-HMAC-SHA1 wrapping key derivation)

use crate::zfs::{BlockPointer, Endian, MAX_BLOCK_BYTES, checksum, decompress};
use crate::zfs_dmu::{
    DMU_OT_DNODE, DMU_OT_OBJSET, DNODE_BLOCK_BYTES, DNODE_BYTES, DNODE_FLAG_SPILL_BLKPTR,
    OBJSET_GROUPUSED_OFFSET, OBJSET_PROJECTUSED_OFFSET, OBJSET_USERUSED_OFFSET,
};
use ffs_types::ParseError;
use flate2::{Compress, Compression, FlushCompress, Status};
use sha2::{Digest, Sha512};

pub const ZIO_DATA_SALT_LEN: usize = 8;
pub const ZIO_DATA_IV_LEN: usize = 12;
pub const ZIO_DATA_MAC_LEN: usize = 16;
pub const ZIO_OBJSET_MAC_LEN: usize = 32;
pub const ZFS_WRAPPING_KEY_LEN: usize = 32;
pub const ZFS_HMAC_KEY_LEN: usize = 64;
pub const ZFS_MAX_MASTER_KEY_LEN: usize = 32;
pub const ZFS_PBKDF2_MIN_ITERS: u64 = 100_000;
pub const ZFS_PBKDF2_DEFAULT_ITERS: u64 = 350_000;
pub const DSL_CRYPTO_KEY_VERSION_V0: u64 = 0;
pub const DSL_CRYPTO_KEY_VERSION_V1: u64 = 1;

/// OpenZFS `dsl_dir` ZAP key naming the MOS `dsl_crypto_key` ZAP object.
pub const DSL_DIR_CRYPTO_KEY_OBJ: &[u8] = b"com.datto:crypto_key_obj";
/// OpenZFS `dsl_dataset` ZAP key storing the IV-set GUID.
pub const DSL_DATASET_IVSET_GUID: &[u8] = b"com.datto:ivset_guid";

/// Standard `dsl_crypto_key` MOS ZAP attribute names.
pub const DSL_CRYPTO_SUITE: &[u8] = b"DSL_CRYPTO_SUITE";
pub const DSL_CRYPTO_GUID: &[u8] = b"DSL_CRYPTO_GUID";
pub const DSL_CRYPTO_VERSION: &[u8] = b"DSL_CRYPTO_VERSION";
pub const DSL_CRYPTO_ROOT_DDOBJ: &[u8] = b"DSL_CRYPTO_ROOT_DDOBJ";
pub const DSL_CRYPTO_REFCOUNT: &[u8] = b"DSL_CRYPTO_REFCOUNT";
pub const DSL_CRYPTO_IV: &[u8] = b"DSL_CRYPTO_IV";
pub const DSL_CRYPTO_MAC: &[u8] = b"DSL_CRYPTO_MAC";
pub const DSL_CRYPTO_MASTER_KEY_1: &[u8] = b"DSL_CRYPTO_MASTER_KEY_1";
pub const DSL_CRYPTO_HMAC_KEY_1: &[u8] = b"DSL_CRYPTO_HMAC_KEY_1";
pub const DSL_CRYPTO_KEYFORMAT: &[u8] = b"keyformat";
pub const DSL_CRYPTO_PBKDF2_SALT: &[u8] = b"pbkdf2salt";
pub const DSL_CRYPTO_PBKDF2_ITERS: &[u8] = b"pbkdf2iters";

const fn invalid(reason: &'static str) -> ParseError {
    ParseError::InvalidField {
        field: "zfs.crypto",
        reason,
    }
}

/// Overwrite sensitive key/plaintext bytes and inhibit dead-store elimination.
pub fn scrub_bytes(buf: &mut [u8]) {
    buf.fill(0);
    std::hint::black_box(buf);
}

/// Constant-time slice equality check for authentication tags and MACs.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Native OpenZFS `zio_encrypt` cipher suite selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ZioEncrypt {
    Inherit = 0,
    On = 1,
    Off = 2,
    Aes128Ccm = 3,
    Aes192Ccm = 4,
    Aes256Ccm = 5,
    Aes128Gcm = 6,
    Aes192Gcm = 7,
    Aes256Gcm = 8,
}

impl ZioEncrypt {
    pub const fn from_raw(raw: u64) -> Result<Self, ParseError> {
        match raw {
            0 => Ok(Self::Inherit),
            1 => Ok(Self::On),
            2 => Ok(Self::Off),
            3 => Ok(Self::Aes128Ccm),
            4 => Ok(Self::Aes192Ccm),
            5 => Ok(Self::Aes256Ccm),
            6 => Ok(Self::Aes128Gcm),
            7 => Ok(Self::Aes192Gcm),
            8 => Ok(Self::Aes256Gcm),
            _ => Err(invalid("unsupported ZFS encryption cipher suite")),
        }
    }

    pub fn from_name(name: &str) -> Result<Self, ParseError> {
        match name {
            "off" => Ok(Self::Off),
            "on" => Ok(Self::On),
            "aes-128-ccm" => Ok(Self::Aes128Ccm),
            "aes-192-ccm" => Ok(Self::Aes192Ccm),
            "aes-256-ccm" => Ok(Self::Aes256Ccm),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-192-gcm" => Ok(Self::Aes192Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            _ => Err(invalid("unknown ZFS encryption suite name")),
        }
    }

    /// Resolve `On` to OpenZFS default `Aes256Gcm`.
    #[must_use]
    pub const fn effective(self) -> Self {
        match self {
            Self::On => Self::Aes256Gcm,
            other => other,
        }
    }

    /// Raw numeric identifier stored in `DSL_CRYPTO_SUITE` / `encryption` property.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self as u64
    }

    /// Data/master key byte length for concrete cipher suites (`16`, `24`, or `32`).
    pub const fn key_len(self) -> Result<usize, ParseError> {
        match self.effective() {
            Self::Aes128Ccm | Self::Aes128Gcm => Ok(16),
            Self::Aes192Ccm | Self::Aes192Gcm => Ok(24),
            Self::Aes256Ccm | Self::Aes256Gcm => Ok(32),
            Self::Inherit | Self::Off | Self::On => Err(invalid("cipher suite is not active")),
        }
    }

    #[must_use]
    pub const fn is_active(self) -> bool {
        !matches!(self, Self::Inherit | Self::Off)
    }

    #[must_use]
    pub const fn is_gcm(self) -> bool {
        matches!(
            self.effective(),
            Self::Aes128Gcm | Self::Aes192Gcm | Self::Aes256Gcm
        )
    }

    #[must_use]
    pub const fn is_ccm(self) -> bool {
        matches!(
            self.effective(),
            Self::Aes128Ccm | Self::Aes192Ccm | Self::Aes256Ccm
        )
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::On => "on",
            Self::Off => "off",
            Self::Aes128Ccm => "aes-128-ccm",
            Self::Aes192Ccm => "aes-192-ccm",
            Self::Aes256Ccm => "aes-256-ccm",
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes192Gcm => "aes-192-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
        }
    }
}

/// Native OpenZFS `zfs_keyformat_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ZfsKeyFormat {
    None = 0,
    Raw = 1,
    Hex = 2,
    Passphrase = 3,
}

impl ZfsKeyFormat {
    pub const fn from_raw(raw: u64) -> Result<Self, ParseError> {
        match raw {
            0 => Ok(Self::None),
            1 => Ok(Self::Raw),
            2 => Ok(Self::Hex),
            3 => Ok(Self::Passphrase),
            _ => Err(invalid("unsupported ZFS keyformat")),
        }
    }

    pub fn from_name(name: &str) -> Result<Self, ParseError> {
        match name {
            "none" => Ok(Self::None),
            "raw" => Ok(Self::Raw),
            "hex" => Ok(Self::Hex),
            "passphrase" => Ok(Self::Passphrase),
            _ => Err(invalid("unknown ZFS keyformat name")),
        }
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self as u64
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Raw => "raw",
            Self::Hex => "hex",
            Self::Passphrase => "passphrase",
        }
    }
}

/// Exact OpenZFS `DMU_OT_IS_ENCRYPTED(ot)` classification (`dmu.h` + `dmu.c`).
///
/// New-style object types (`ot & 0x80 != 0`) carry `DMU_OT_ENCRYPTED = 0x20`.
/// Legacy object types (`ot < 54`) follow `dmu_ot[]` in OpenZFS `zfs-2.3.0`.
#[must_use]
pub const fn dmu_ot_is_encrypted(ot: u8) -> bool {
    if ot & 0x80 != 0 {
        return (ot & 0x20) != 0;
    }
    matches!(
        ot,
        9 | 10 | 18 | 19 | 20 | 22 | 23 | 25 | 26 | 33 | 34 | 35 | 39 | 40 | 44 | 45 | 46 | 47 | 49
    )
}

// ── Pure Safe Rust AES-128 / AES-192 / AES-256 (FIPS 197 forward cipher) ────

#[rustfmt::skip]
const AES_SBOX: [u8; 256] = [
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

const AES_RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

#[inline]
const fn xtime(x: u8) -> u8 {
    let hi = (x >> 7) & 1;
    (x << 1) ^ (hi * 0x1b)
}

struct AesKeySchedule {
    round_keys: [[u8; 16]; 15],
    rounds: usize,
}

impl Drop for AesKeySchedule {
    fn drop(&mut self) {
        for rk in &mut self.round_keys {
            scrub_bytes(rk);
        }
    }
}

impl AesKeySchedule {
    fn new(key: &[u8]) -> Result<Self, ParseError> {
        let (nk, rounds) = match key.len() {
            16 => (4_usize, 10_usize),
            24 => (6_usize, 12_usize),
            32 => (8_usize, 14_usize),
            _ => return Err(invalid("AES key must be 16, 24, or 32 bytes")),
        };
        let total_words = 4 * (rounds + 1);
        let mut w = [[0_u8; 4]; 60];
        for i in 0..nk {
            w[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
        }
        for i in nk..total_words {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                temp = [
                    AES_SBOX[usize::from(temp[1])] ^ AES_RCON[i / nk - 1],
                    AES_SBOX[usize::from(temp[2])],
                    AES_SBOX[usize::from(temp[3])],
                    AES_SBOX[usize::from(temp[0])],
                ];
            } else if nk == 8 && i % nk == 4 {
                temp = [
                    AES_SBOX[usize::from(temp[0])],
                    AES_SBOX[usize::from(temp[1])],
                    AES_SBOX[usize::from(temp[2])],
                    AES_SBOX[usize::from(temp[3])],
                ];
            }
            for b in 0..4 {
                w[i][b] = w[i - nk][b] ^ temp[b];
            }
        }
        let mut round_keys = [[0_u8; 16]; 15];
        for r in 0..=rounds {
            for col in 0..4 {
                round_keys[r][col * 4..col * 4 + 4].copy_from_slice(&w[r * 4 + col]);
            }
        }
        for word in &mut w {
            scrub_bytes(word);
        }
        Ok(Self { round_keys, rounds })
    }

    fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut s = *input;
        for i in 0..16 {
            s[i] ^= self.round_keys[0][i];
        }
        for rk in self.round_keys.iter().take(self.rounds).skip(1) {
            // SubBytes
            for b in &mut s {
                *b = AES_SBOX[usize::from(*b)];
            }
            // ShiftRows (column-major layout: index = col*4 + row)
            let t1 = s[1];
            s[1] = s[5];
            s[5] = s[9];
            s[9] = s[13];
            s[13] = t1;

            s.swap(2, 10);
            s.swap(6, 14);

            let t3 = s[15];
            s[15] = s[11];
            s[11] = s[7];
            s[7] = s[3];
            s[3] = t3;

            // MixColumns
            for col in 0..4 {
                let c = col * 4;
                let a0 = s[c];
                let a1 = s[c + 1];
                let a2 = s[c + 2];
                let a3 = s[c + 3];
                let xor_all = a0 ^ a1 ^ a2 ^ a3;
                s[c] = a0 ^ xor_all ^ xtime(a0 ^ a1);
                s[c + 1] = a1 ^ xor_all ^ xtime(a1 ^ a2);
                s[c + 2] = a2 ^ xor_all ^ xtime(a2 ^ a3);
                s[c + 3] = a3 ^ xor_all ^ xtime(a3 ^ a0);
            }
            // AddRoundKey
            for i in 0..16 {
                s[i] ^= rk[i];
            }
        }
        // Final round (SubBytes + ShiftRows + AddRoundKey, no MixColumns)
        for b in &mut s {
            *b = AES_SBOX[usize::from(*b)];
        }
        let t1 = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = t1;
        s.swap(2, 10);
        s.swap(6, 14);
        let t3 = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = s[3];
        s[3] = t3;
        let rk = &self.round_keys[self.rounds];
        for i in 0..16 {
            s[i] ^= rk[i];
        }
        s
    }
}

// ── AES-GCM (NIST SP 800-38D, 96-bit IV, 128-bit tag) ───────────────────────

fn ghash_mul(x: u128, h: u128) -> u128 {
    let mut z = 0_u128;
    let mut v = h;
    for bit in 0..128 {
        if ((x >> (127 - bit)) & 1) != 0 {
            z ^= v;
        }
        let lsb = v & 1;
        v >>= 1;
        if lsb != 0 {
            v ^= 0xE100_0000_0000_0000_0000_0000_0000_0000_u128;
        }
    }
    z
}

fn ghash(h_bytes: [u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let h = u128::from_be_bytes(h_bytes);
    let mut y = 0_u128;
    for chunk in aad.chunks(16) {
        let mut block = [0_u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        y = ghash_mul(y ^ u128::from_be_bytes(block), h);
    }
    for chunk in ciphertext.chunks(16) {
        let mut block = [0_u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        y = ghash_mul(y ^ u128::from_be_bytes(block), h);
    }
    let aad_bits = (aad.len() as u64).wrapping_mul(8);
    let ct_bits = (ciphertext.len() as u64).wrapping_mul(8);
    let mut len_block = [0_u8; 16];
    len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());
    y = ghash_mul(y ^ u128::from_be_bytes(len_block), h);
    y.to_be_bytes()
}

fn inc32(counter: &mut [u8; 16]) {
    let val = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    counter[12..16].copy_from_slice(&val.wrapping_add(1).to_be_bytes());
}

fn aes_gcm_crypt_in_place(aes: &AesKeySchedule, iv: &[u8; 12], data: &mut [u8]) -> [u8; 16] {
    let mut j0 = [0_u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let mut ctr = j0;
    for chunk in data.chunks_mut(16) {
        inc32(&mut ctr);
        let stream = aes.encrypt_block(&ctr);
        for (b, s) in chunk.iter_mut().zip(stream.iter()) {
            *b ^= *s;
        }
    }
    aes.encrypt_block(&j0)
}

pub fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8; ZIO_DATA_IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; ZIO_DATA_MAC_LEN]), ParseError> {
    let aes = AesKeySchedule::new(key)?;
    let h = aes.encrypt_block(&[0_u8; 16]);
    let mut ct = plaintext.to_vec();
    let e_j0 = aes_gcm_crypt_in_place(&aes, iv, &mut ct);
    let s = ghash(h, aad, &ct);
    let mut tag = [0_u8; 16];
    for i in 0..16 {
        tag[i] = s[i] ^ e_j0[i];
    }
    Ok((ct, tag))
}

pub fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8; ZIO_DATA_IV_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; ZIO_DATA_MAC_LEN],
) -> Result<Vec<u8>, ParseError> {
    let aes = AesKeySchedule::new(key)?;
    let h = aes.encrypt_block(&[0_u8; 16]);
    let s = ghash(h, aad, ciphertext);
    let mut j0 = [0_u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let e_j0 = aes.encrypt_block(&j0);
    let mut expected = [0_u8; 16];
    for i in 0..16 {
        expected[i] = s[i] ^ e_j0[i];
    }
    if !ct_eq(&expected, tag) {
        return Err(invalid("AES-GCM authentication tag mismatch"));
    }
    let mut pt = ciphertext.to_vec();
    let _ = aes_gcm_crypt_in_place(&aes, iv, &mut pt);
    Ok(pt)
}

// ── AES-CCM (RFC 3610, L = 3, M = 16, 12-byte nonce) ────────────────────────

fn ccm_cbcmac(
    aes: &AesKeySchedule,
    nonce: &[u8; ZIO_DATA_IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<[u8; 16], ParseError> {
    if plaintext.len() >= (1_usize << 24) {
        return Err(invalid("AES-CCM payload exceeds L=3 16 MiB-1 bound"));
    }
    let mut b0 = [0_u8; 16];
    // L = 3 -> L' = 2; M = 16 -> M' = (16 - 2) / 2 = 7 -> (7 << 3) | 2 = 0x3A
    b0[0] = if aad.is_empty() { 0x3A } else { 0x7A };
    b0[1..13].copy_from_slice(nonce);
    let len_be = (plaintext.len() as u32).to_be_bytes();
    b0[13..16].copy_from_slice(&len_be[1..4]);

    let mut x = aes.encrypt_block(&b0);
    let mut feed_block = |block: &[u8; 16]| {
        for i in 0..16 {
            x[i] ^= block[i];
        }
        x = aes.encrypt_block(&x);
    };

    if !aad.is_empty() {
        let mut hdr = [0_u8; 10];
        let hdr_len = if aad.len() < 0xFF00 {
            let l = u16::try_from(aad.len()).map_err(|_| invalid("CCM AAD length overflow"))?;
            hdr[0..2].copy_from_slice(&l.to_be_bytes());
            2
        } else if let Ok(l) = u32::try_from(aad.len()) {
            hdr[0] = 0xFF;
            hdr[1] = 0xFE;
            hdr[2..6].copy_from_slice(&l.to_be_bytes());
            6
        } else {
            hdr[0] = 0xFF;
            hdr[1] = 0xFF;
            hdr[2..10].copy_from_slice(&(aad.len() as u64).to_be_bytes());
            10
        };
        let mut block = [0_u8; 16];
        let first_take = (16 - hdr_len).min(aad.len());
        block[..hdr_len].copy_from_slice(&hdr[..hdr_len]);
        block[hdr_len..hdr_len + first_take].copy_from_slice(&aad[..first_take]);
        feed_block(&block);
        for chunk in aad[first_take..].chunks(16) {
            let mut blk = [0_u8; 16];
            blk[..chunk.len()].copy_from_slice(chunk);
            feed_block(&blk);
        }
    }

    for chunk in plaintext.chunks(16) {
        let mut blk = [0_u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        feed_block(&blk);
    }

    Ok(x)
}

fn ccm_ctr_in_place(
    aes: &AesKeySchedule,
    nonce: &[u8; ZIO_DATA_IV_LEN],
    data: &mut [u8],
) -> [u8; 16] {
    let mut a = [0_u8; 16];
    a[0] = 2; // L - 1 = 2
    a[1..13].copy_from_slice(nonce);
    let s0 = aes.encrypt_block(&a);

    let mut ctr = 1_u32;
    for chunk in data.chunks_mut(16) {
        let ctr_be = ctr.to_be_bytes();
        a[13..16].copy_from_slice(&ctr_be[1..4]);
        let stream = aes.encrypt_block(&a);
        for (b, k) in chunk.iter_mut().zip(stream.iter()) {
            *b ^= *k;
        }
        ctr = ctr.wrapping_add(1);
    }
    s0
}

pub fn aes_ccm_encrypt(
    key: &[u8],
    iv: &[u8; ZIO_DATA_IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; ZIO_DATA_MAC_LEN]), ParseError> {
    let aes = AesKeySchedule::new(key)?;
    let mac = ccm_cbcmac(&aes, iv, aad, plaintext)?;
    let mut ct = plaintext.to_vec();
    let s0 = ccm_ctr_in_place(&aes, iv, &mut ct);
    let mut tag = [0_u8; 16];
    for i in 0..16 {
        tag[i] = mac[i] ^ s0[i];
    }
    Ok((ct, tag))
}

pub fn aes_ccm_decrypt(
    key: &[u8],
    iv: &[u8; ZIO_DATA_IV_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; ZIO_DATA_MAC_LEN],
) -> Result<Vec<u8>, ParseError> {
    let aes = AesKeySchedule::new(key)?;
    let mut pt = ciphertext.to_vec();
    let s0 = ccm_ctr_in_place(&aes, iv, &mut pt);
    let mac = ccm_cbcmac(&aes, iv, aad, &pt)?;
    let mut expected = [0_u8; 16];
    for i in 0..16 {
        expected[i] = mac[i] ^ s0[i];
    }
    if !ct_eq(&expected, tag) {
        scrub_bytes(&mut pt);
        return Err(invalid("AES-CCM authentication tag mismatch"));
    }
    Ok(pt)
}

/// Dispatch AEAD encryption by `ZioEncrypt` suite.
pub fn aead_encrypt(
    suite: ZioEncrypt,
    key: &[u8],
    iv: &[u8; ZIO_DATA_IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; ZIO_DATA_MAC_LEN]), ParseError> {
    if suite.is_gcm() {
        aes_gcm_encrypt(key, iv, aad, plaintext)
    } else if suite.is_ccm() {
        aes_ccm_encrypt(key, iv, aad, plaintext)
    } else {
        Err(invalid("cipher suite does not support AEAD"))
    }
}

/// Dispatch AEAD decryption by `ZioEncrypt` suite.
pub fn aead_decrypt(
    suite: ZioEncrypt,
    key: &[u8],
    iv: &[u8; ZIO_DATA_IV_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; ZIO_DATA_MAC_LEN],
) -> Result<Vec<u8>, ParseError> {
    if suite.is_gcm() {
        aes_gcm_decrypt(key, iv, aad, ciphertext, tag)
    } else if suite.is_ccm() {
        aes_ccm_decrypt(key, iv, aad, ciphertext, tag)
    } else {
        Err(invalid("cipher suite does not support AEAD"))
    }
}

// ── SHA-1 + PBKDF2-HMAC-SHA1 (OpenZFS passphrase key derivation) ────────────

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity((data.len() + 9).next_multiple_of(64));
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut schedule = [0_u32; 80];
    for block in padded.as_chunks::<64>().0 {
        for i in 0..16 {
            schedule[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            schedule[i] = (schedule[i - 3] ^ schedule[i - 8] ^ schedule[i - 14] ^ schedule[i - 16])
                .rotate_left(1);
        }
        let [mut va, mut vb, mut vc, mut vd, mut ve] = state;
        for (i, &wi) in schedule.iter().enumerate() {
            let (func, k_const) = match i {
                0..=19 => ((vb & vc) | ((!vb) & vd), 0x5A82_7999_u32),
                20..=39 => (vb ^ vc ^ vd, 0x6ED9_EBA1_u32),
                40..=59 => ((vb & vc) | (vb & vd) | (vc & vd), 0x8F1B_BCDC_u32),
                _ => (vb ^ vc ^ vd, 0xCA62_C1D6_u32),
            };
            let temp = va
                .rotate_left(5)
                .wrapping_add(func)
                .wrapping_add(ve)
                .wrapping_add(k_const)
                .wrapping_add(wi);
            ve = vd;
            vd = vc;
            vc = vb.rotate_left(30);
            vb = va;
            va = temp;
        }
        state[0] = state[0].wrapping_add(va);
        state[1] = state[1].wrapping_add(vb);
        state[2] = state[2].wrapping_add(vc);
        state[3] = state[3].wrapping_add(vd);
        state[4] = state[4].wrapping_add(ve);
    }
    let mut out = [0_u8; 20];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut k_block = [0_u8; 64];
    if key.len() > 64 {
        k_block[..20].copy_from_slice(&sha1_digest(key));
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    for &b in &k_block {
        inner.push(b ^ 0x36);
    }
    inner.extend_from_slice(data);
    let inner_hash = sha1_digest(&inner);

    let mut outer = [0_u8; 64 + 20];
    for i in 0..64 {
        outer[i] = k_block[i] ^ 0x5c;
    }
    outer[64..84].copy_from_slice(&inner_hash);
    let out = sha1_digest(&outer);
    scrub_bytes(&mut k_block);
    scrub_bytes(&mut inner);
    scrub_bytes(&mut outer);
    out
}

/// Derive a 32-byte OpenZFS wrapping key via PBKDF2-HMAC-SHA1 (RFC 2898 / `libzfs_crypto.c`).
///
/// OpenZFS stores `pbkdf2salt` as a `uint64_t` in the `dsl_crypto_key` ZAP and passes
/// `&salt` (little-endian 8 bytes on x86_64/arm64, or `salt.to_le_bytes()`) directly to
/// `PKCS5_PBKDF2_HMAC_SHA1`. Callers needing raw arbitrary salt bytes (e.g. RFC 6070 tests)
/// can call [`pbkdf2_hmac_sha1`].
pub fn pbkdf2_hmac_sha1(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u64,
    out: &mut [u8],
) -> Result<(), ParseError> {
    if iterations == 0 {
        return Err(invalid("PBKDF2 iteration count must be positive"));
    }
    if out.is_empty() {
        return Ok(());
    }
    let mut block_idx = 1_u32;
    for chunk in out.chunks_mut(20) {
        let mut msg = Vec::with_capacity(salt.len() + 4);
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&block_idx.to_be_bytes());
        let mut u = hmac_sha1(passphrase, &msg);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha1(passphrase, &u);
            for i in 0..20 {
                t[i] ^= u[i];
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
        scrub_bytes(&mut u);
        scrub_bytes(&mut t);
        block_idx = block_idx
            .checked_add(1)
            .ok_or_else(|| invalid("PBKDF2 output length overflow"))?;
    }
    Ok(())
}

/// OpenZFS native passphrase wrapping-key derivation (`libzfs_crypto.c`).
pub fn derive_zfs_passphrase_key(
    passphrase: &[u8],
    pbkdf2_salt: u64,
    pbkdf2_iters: u64,
) -> Result<[u8; ZFS_WRAPPING_KEY_LEN], ParseError> {
    if passphrase.len() < 8 {
        return Err(invalid("ZFS passphrase must be at least 8 bytes"));
    }
    if pbkdf2_iters < ZFS_PBKDF2_MIN_ITERS {
        return Err(invalid("ZFS pbkdf2iters below minimum 100000"));
    }
    let mut dk = [0_u8; ZFS_WRAPPING_KEY_LEN];
    pbkdf2_hmac_sha1(
        passphrase,
        &pbkdf2_salt.to_le_bytes(),
        pbkdf2_iters,
        &mut dk,
    )?;
    Ok(dk)
}

// ── HMAC-SHA512 & HKDF-SHA512 (OpenZFS `module/zfs/hkdf.c`) ─────────────────

#[must_use]
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut k_block = [0_u8; 128];
    if key.len() > 128 {
        let digest = Sha512::digest(key);
        k_block[..64].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0_u8; 128];
    let mut opad = [0_u8; 128];
    for i in 0..128 {
        ipad[i] = k_block[i] ^ 0x36;
        opad[i] = k_block[i] ^ 0x5c;
    }
    let mut inner = Sha512::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(inner_digest);
    let outer_digest = outer.finalize();
    let mut out = [0_u8; 64];
    out.copy_from_slice(&outer_digest);
    scrub_bytes(&mut k_block);
    scrub_bytes(&mut ipad);
    scrub_bytes(&mut opad);
    out
}

/// RFC 5869 HKDF-SHA512 matching OpenZFS `hkdf_sha512` (`module/zfs/hkdf.c`).
pub fn hkdf_sha512(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<Vec<u8>, ParseError> {
    if okm_len == 0 || okm_len > 255 * 64 {
        return Err(invalid("invalid HKDF-SHA512 output length"));
    }
    let zero_salt = [0_u8; 64];
    let extract_salt = if salt.is_empty() {
        &zero_salt[..]
    } else {
        salt
    };
    let mut prk = hmac_sha512(extract_salt, ikm);

    let mut okm = Vec::with_capacity(okm_len);
    let mut prev = [0_u8; 64];
    let mut has_prev = false;
    let mut counter = 1_u8;
    while okm.len() < okm_len {
        let mut msg = Vec::with_capacity(64 + info.len() + 1);
        if has_prev {
            msg.extend_from_slice(&prev);
        }
        msg.extend_from_slice(info);
        msg.push(counter);
        prev = hmac_sha512(&prk, &msg);
        has_prev = true;
        let take = (okm_len - okm.len()).min(64);
        okm.extend_from_slice(&prev[..take]);
        scrub_bytes(&mut msg);
        counter = counter
            .checked_add(1)
            .ok_or_else(|| invalid("HKDF counter overflow"))?;
    }
    scrub_bytes(&mut prk);
    scrub_bytes(&mut prev);
    Ok(okm)
}

/// Derive the per-block data encryption key via OpenZFS `zio_crypt_key_get_keydata`:
/// `HKDF-SHA512(ikm = master_key[..key_len], salt = [], info = block_salt[..8], len = key_len)`.
pub fn derive_block_data_key(
    master_key: &[u8],
    suite: ZioEncrypt,
    block_salt: &[u8; ZIO_DATA_SALT_LEN],
) -> Result<Vec<u8>, ParseError> {
    let key_len = suite.key_len()?;
    if master_key.len() < key_len {
        return Err(invalid("master key shorter than cipher suite key length"));
    }
    hkdf_sha512(&master_key[..key_len], &[], block_salt, key_len)
}

// ── On-Disk `dsl_crypto_key` Record & Key Wrapping ──────────────────────────

/// On-disk representation of an OpenZFS `dsl_crypto_key` MOS ZAP object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DslCryptoKeyRecord {
    pub suite: ZioEncrypt,
    pub guid: u64,
    pub version: u64,
    pub root_ddobj: u64,
    pub refcount: u64,
    pub keyformat: ZfsKeyFormat,
    pub pbkdf2_salt: u64,
    pub pbkdf2_iters: u64,
    pub iv: [u8; ZIO_DATA_IV_LEN],
    pub mac: [u8; ZIO_DATA_MAC_LEN],
    /// Ciphertext master key (stored in 32-byte field; first `suite.key_len()` bytes active).
    pub encrypted_master_key: [u8; ZFS_MAX_MASTER_KEY_LEN],
    /// Ciphertext 64-byte HMAC-SHA512 key.
    pub encrypted_hmac_key: [u8; ZFS_HMAC_KEY_LEN],
}

/// Unwrapped in-memory dataset encryption key pair (`master_key` + `hmac_key`).
/// Automatically scrubbed on drop; `Debug` redacts key material.
#[derive(Clone, PartialEq, Eq)]
pub struct UnwrappedDslKey {
    pub suite: ZioEncrypt,
    pub guid: u64,
    pub version: u64,
    pub master_key: [u8; ZFS_MAX_MASTER_KEY_LEN],
    pub master_key_len: usize,
    pub hmac_key: [u8; ZFS_HMAC_KEY_LEN],
}

impl std::fmt::Debug for UnwrappedDslKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnwrappedDslKey")
            .field("suite", &self.suite)
            .field("guid", &self.guid)
            .field("version", &self.version)
            .field("master_key", &"<redacted>")
            .field("hmac_key", &"<redacted>")
            .finish()
    }
}

impl Drop for UnwrappedDslKey {
    fn drop(&mut self) {
        scrub_bytes(&mut self.master_key);
        scrub_bytes(&mut self.hmac_key);
    }
}

impl UnwrappedDslKey {
    #[must_use]
    pub fn active_master_key(&self) -> &[u8] {
        &self.master_key[..self.master_key_len]
    }
}

fn key_wrap_aad(guid: u64, suite: ZioEncrypt, version: u64) -> Vec<u8> {
    if version == DSL_CRYPTO_KEY_VERSION_V0 {
        guid.to_le_bytes().to_vec()
    } else {
        let mut aad = Vec::with_capacity(24);
        aad.extend_from_slice(&guid.to_le_bytes());
        aad.extend_from_slice(&suite.effective().raw().to_le_bytes());
        aad.extend_from_slice(&version.to_le_bytes());
        aad
    }
}

impl DslCryptoKeyRecord {
    /// Wrap `(master_key[..key_len], hmac_key)` under a 32-byte wrapping key using
    /// OpenZFS `zio_crypt_key_wrap` (AES-256-GCM for GCM suites, AES-256-CCM for CCM suites).
    #[allow(clippy::too_many_arguments)]
    pub fn wrap(
        suite: ZioEncrypt,
        guid: u64,
        version: u64,
        root_ddobj: u64,
        refcount: u64,
        keyformat: ZfsKeyFormat,
        pbkdf2_salt: u64,
        pbkdf2_iters: u64,
        iv: [u8; ZIO_DATA_IV_LEN],
        wrapping_key: &[u8; ZFS_WRAPPING_KEY_LEN],
        master_key: &[u8],
        hmac_key: &[u8; ZFS_HMAC_KEY_LEN],
    ) -> Result<Self, ParseError> {
        let suite = suite.effective();
        let key_len = suite.key_len()?;
        if master_key.len() < key_len {
            return Err(invalid("master key shorter than suite key length"));
        }
        if version > DSL_CRYPTO_KEY_VERSION_V1 {
            return Err(invalid("unsupported dsl_crypto_key version"));
        }
        let wrap_suite = if suite.is_gcm() {
            ZioEncrypt::Aes256Gcm
        } else {
            ZioEncrypt::Aes256Ccm
        };
        let aad = key_wrap_aad(guid, suite, version);
        let mut plain = Vec::with_capacity(key_len + ZFS_HMAC_KEY_LEN);
        plain.extend_from_slice(&master_key[..key_len]);
        plain.extend_from_slice(hmac_key);
        let (ct, mac) = aead_encrypt(wrap_suite, wrapping_key, &iv, &aad, &plain)?;
        scrub_bytes(&mut plain);

        let mut encrypted_master_key = [0_u8; ZFS_MAX_MASTER_KEY_LEN];
        encrypted_master_key[..key_len].copy_from_slice(&ct[..key_len]);
        let mut encrypted_hmac_key = [0_u8; ZFS_HMAC_KEY_LEN];
        encrypted_hmac_key.copy_from_slice(&ct[key_len..key_len + ZFS_HMAC_KEY_LEN]);
        Ok(Self {
            suite,
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

    /// Unwrap `(master_key, hmac_key)` verifying the AEAD MAC over the wrapping key & AAD.
    pub fn unwrap(
        &self,
        wrapping_key: &[u8; ZFS_WRAPPING_KEY_LEN],
    ) -> Result<UnwrappedDslKey, ParseError> {
        let suite = self.suite.effective();
        let key_len = suite.key_len()?;
        if self.version > DSL_CRYPTO_KEY_VERSION_V1 {
            return Err(invalid("unsupported dsl_crypto_key version"));
        }
        let wrap_suite = if suite.is_gcm() {
            ZioEncrypt::Aes256Gcm
        } else {
            ZioEncrypt::Aes256Ccm
        };
        let aad = key_wrap_aad(self.guid, suite, self.version);
        let mut ct = Vec::with_capacity(key_len + ZFS_HMAC_KEY_LEN);
        ct.extend_from_slice(&self.encrypted_master_key[..key_len]);
        ct.extend_from_slice(&self.encrypted_hmac_key);
        let mut plain = aead_decrypt(wrap_suite, wrapping_key, &self.iv, &aad, &ct, &self.mac)?;

        let mut master_key = [0_u8; ZFS_MAX_MASTER_KEY_LEN];
        master_key[..key_len].copy_from_slice(&plain[..key_len]);
        let mut hmac_key = [0_u8; ZFS_HMAC_KEY_LEN];
        hmac_key.copy_from_slice(&plain[key_len..key_len + ZFS_HMAC_KEY_LEN]);
        scrub_bytes(&mut plain);
        Ok(UnwrappedDslKey {
            suite,
            guid: self.guid,
            version: self.version,
            master_key,
            master_key_len: key_len,
            hmac_key,
        })
    }
}

// ── BlockPointer Protected-Block Wire Layout & Checksum Verification ────────

/// Extract the 8-byte encryption salt from an encrypted L0 `BlockPointer` (`words[4]`).
#[must_use]
pub fn bp_crypt_salt(bp: &BlockPointer) -> [u8; ZIO_DATA_SALT_LEN] {
    bp.payload_order().encode(bp.raw_word(4))
}

/// Extract the 12-byte encryption IV from an encrypted L0 `BlockPointer`:
/// `IV[0..8] = words[5]` and `IV[8..12] = (words[11] >> 32) as u32` in `bp.payload_order()`.
#[must_use]
pub fn bp_crypt_iv(bp: &BlockPointer) -> [u8; ZIO_DATA_IV_LEN] {
    let order = bp.payload_order();
    let iv1 = order.encode(bp.raw_word(5));
    let iv2_u32 = (bp.raw_word(11) >> 32) as u32;
    let iv2 = match order {
        Endian::Little => iv2_u32.to_le_bytes(),
        Endian::Big => iv2_u32.to_be_bytes(),
    };
    let mut iv = [0_u8; ZIO_DATA_IV_LEN];
    iv[0..8].copy_from_slice(&iv1);
    iv[8..12].copy_from_slice(&iv2);
    iv
}

/// Extract the 16-byte MAC from a protected `BlockPointer` (`words[14..16]`) in `bp.payload_order()`.
#[must_use]
pub fn bp_crypt_mac(bp: &BlockPointer) -> [u8; ZIO_DATA_MAC_LEN] {
    let order = bp.payload_order();
    let mut mac = [0_u8; ZIO_DATA_MAC_LEN];
    mac[0..8].copy_from_slice(&order.encode(bp.raw_word(14)));
    mac[8..16].copy_from_slice(&order.encode(bp.raw_word(15)));
    mac
}

/// Encode `(salt, iv)` into `(word4, word5, iv2_upper_32)` using `order`.
#[must_use]
pub fn encode_crypt_salt_iv(
    salt: &[u8; ZIO_DATA_SALT_LEN],
    iv: &[u8; ZIO_DATA_IV_LEN],
    order: Endian,
) -> (u64, u64, u32) {
    let w4 = match order {
        Endian::Little => u64::from_le_bytes(*salt),
        Endian::Big => u64::from_be_bytes(*salt),
    };
    let iv1: [u8; 8] = [iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7]];
    let w5 = match order {
        Endian::Little => u64::from_le_bytes(iv1),
        Endian::Big => u64::from_be_bytes(iv1),
    };
    let iv2_bytes = [iv[8], iv[9], iv[10], iv[11]];
    let iv2 = match order {
        Endian::Little => u32::from_le_bytes(iv2_bytes),
        Endian::Big => u32::from_be_bytes(iv2_bytes),
    };
    (w4, w5, iv2)
}

/// Encode a 16-byte MAC into two `u64` words (`words[14..16]`) using `order`.
#[must_use]
pub fn encode_crypt_mac_words(mac: &[u8; ZIO_DATA_MAC_LEN], order: Endian) -> [u64; 2] {
    let lo = [
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7],
    ];
    let hi = [
        mac[8], mac[9], mac[10], mac[11], mac[12], mac[13], mac[14], mac[15],
    ];
    match order {
        Endian::Little => [u64::from_le_bytes(lo), u64::from_le_bytes(hi)],
        Endian::Big => [u64::from_be_bytes(lo), u64::from_be_bytes(hi)],
    }
}

/// Compute `blk_cksum` (`words[12..16]`) for a protected block per OpenZFS `zio_checksum_handle_crypt`.
///
/// - `DMU_OT_OBJSET (11)`: preserves all 4 physical checksum words (its 64-byte MACs live inside `objset_phys_t`).
/// - All other protected blocks store the 16-byte MAC in `words[14..16]`; weak checksums
///   (`Fletcher2=6`, `Fletcher4=7`) fold `cksum[0] ^= cksum[2]` and `cksum[1] ^= cksum[3]`,
///   while cryptographic checksums (`SHA256=8`, `SHA512/256=11`) keep `cksum[0..2]` unmodified.
pub fn compute_protected_checksum_words(
    physical: &[u8],
    checksum_type: u8,
    order: Endian,
    object_type: u8,
    mac: [u8; ZIO_DATA_MAC_LEN],
) -> Result<[u64; 4], ParseError> {
    let mut cksum = checksum(physical, checksum_type, order)?;
    if object_type == DMU_OT_OBJSET {
        return Ok(cksum);
    }
    if matches!(checksum_type, 6 | 7) {
        cksum[0] ^= cksum[2];
        cksum[1] ^= cksum[3];
    }
    let mac_words = encode_crypt_mac_words(&mac, order);
    cksum[2] = mac_words[0];
    cksum[3] = mac_words[1];
    Ok(cksum)
}

/// Verify the physical disk checksum of a protected `BlockPointer` (keylessly!).
pub fn verify_protected_physical_checksum(
    bp: &BlockPointer,
    physical: &[u8],
) -> Result<(), ParseError> {
    if !bp.protected() {
        return Err(invalid("expected protected block pointer"));
    }
    if physical.len() != bp.physical_bytes() {
        return Err(invalid("protected physical block length mismatch"));
    }
    let actual = checksum(physical, bp.checksum_type(), bp.payload_order())?;
    let expected = bp.checksum_words();
    if bp.object_type() == DMU_OT_OBJSET {
        if actual != expected {
            return Err(invalid("protected objset physical checksum mismatch"));
        }
        return Ok(());
    }
    let (w0, w1) = if matches!(bp.checksum_type(), 6 | 7) {
        (actual[0] ^ actual[2], actual[1] ^ actual[3])
    } else {
        (actual[0], actual[1])
    };
    if w0 != expected[0] || w1 != expected[1] {
        return Err(invalid("protected block physical checksum mismatch"));
    }
    Ok(())
}

// ── OpenZFS `blkptr_auth_buf_t` & Indirect-Block MAC Tree ───────────────────

/// Build OpenZFS `blkptr_auth_buf_t` for a single child `BlockPointer` (`zio_crypt.c:915-990`).
///
/// Always little-endian `portable_blk_prop` (`LE64`) followed by the 16-byte MAC
/// (`bp.words[14..16]` in `bp.payload_order()`, zero for holes/embedded), and for
/// key version >= 1 an 8-byte zero padding word (`bab_pad`, 32 bytes total vs 24 bytes for v0).
#[must_use]
pub fn blkptr_auth_buf(bp: &BlockPointer, version: u64) -> Vec<u8> {
    let mut prop = bp.raw_word(6);
    if version == DSL_CRYPTO_KEY_VERSION_V0 {
        // v0: clear dedup (bit 62), checksum (bits 40..48), set psize=512 (bits 16..32 = 0)
        prop &= !((1_u64 << 62) | (0xff_u64 << 40) | (0xffff_u64 << 16));
    } else {
        // v1 (`zio_crypt_bp_do_indrect_checksum` / `zio_crypt_init_uios_dnode`):
        if bp.hole() {
            prop = 0;
        } else {
            // Clear dedup (62), checksum (40..48)
            prop &= !((1_u64 << 62) | (0xff_u64 << 40));
            if bp.level() > 0 {
                // Indirect BPs also mask byteorder (63), compress (32..39), psize (16..32 -> 0)
                prop &= !((1_u64 << 63) | (0x7f_u64 << 32) | (0xffff_u64 << 16));
            }
        }
    }
    let mac = if bp.hole() || bp.embedded() {
        [0_u8; ZIO_DATA_MAC_LEN]
    } else {
        bp_crypt_mac(bp)
    };
    let len = if version == DSL_CRYPTO_KEY_VERSION_V0 {
        24
    } else {
        32
    };
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&prop.to_le_bytes());
    out.extend_from_slice(&mac);
    if version != DSL_CRYPTO_KEY_VERSION_V0 {
        out.extend_from_slice(&0_u64.to_le_bytes());
    }
    out
}

/// Compute the 16-byte MAC of a protected indirect block (`level > 0`) keylessly:
/// `SHA512(concat of blkptr_auth_buf(child_bp, version) for all 128B child BPs)[..16]`.
pub fn compute_indirect_block_mac(
    uncompressed_indirect: &[u8],
    order: Endian,
    version: u64,
) -> Result<[u8; ZIO_DATA_MAC_LEN], ParseError> {
    if uncompressed_indirect.is_empty() || !uncompressed_indirect.len().is_multiple_of(128) {
        return Err(invalid("indirect block length is not a multiple of 128"));
    }
    let mut hasher = Sha512::new();
    for chunk in uncompressed_indirect.as_chunks::<128>().0 {
        let bp = BlockPointer::parse(chunk, order)?;
        hasher.update(blkptr_auth_buf(&bp, version));
    }
    let digest = hasher.finalize();
    let mut mac = [0_u8; ZIO_DATA_MAC_LEN];
    mac.copy_from_slice(&digest[..ZIO_DATA_MAC_LEN]);
    Ok(mac)
}

// ── Level-0 Regular Encrypted & Authenticated Blocks ────────────────────────

/// Encrypt a compressed (and ashift zero-padded) L0 regular data block.
pub fn encrypt_regular_block(
    key: &UnwrappedDslKey,
    salt: &[u8; ZIO_DATA_SALT_LEN],
    iv: &[u8; ZIO_DATA_IV_LEN],
    plaintext_psize: &[u8],
) -> Result<(Vec<u8>, [u8; ZIO_DATA_MAC_LEN]), ParseError> {
    let mut dk = derive_block_data_key(key.active_master_key(), key.suite, salt)?;
    let result = aead_encrypt(key.suite, &dk, iv, &[], plaintext_psize);
    scrub_bytes(&mut dk);
    result
}

/// Decrypt and authenticate a compressed L0 regular data block, then decompress to `lsize`.
pub fn decrypt_regular_block(
    key: &UnwrappedDslKey,
    bp: &BlockPointer,
    ciphertext_psize: &[u8],
) -> Result<Vec<u8>, ParseError> {
    if !bp.protected() || bp.level() != 0 || !dmu_ot_is_encrypted(bp.object_type()) {
        return Err(invalid("block pointer is not an encrypted level-0 block"));
    }
    if bp.object_type() == DMU_OT_DNODE {
        return decrypt_dnode_block(key, bp, ciphertext_psize);
    }
    let salt = bp_crypt_salt(bp);
    let iv = bp_crypt_iv(bp);
    let mac = bp_crypt_mac(bp);
    let mut dk = derive_block_data_key(key.active_master_key(), key.suite, &salt)?;
    let mut decrypted = aead_decrypt(key.suite, &dk, &iv, &[], ciphertext_psize, &mac)?;
    scrub_bytes(&mut dk);
    let logical = decompress(&decrypted, bp.compression(), bp.logical_bytes());
    scrub_bytes(&mut decrypted);
    logical
}

/// Compute the 16-byte HMAC-SHA512 authentication tag for an authenticated-only
/// (non-encrypted, non-objset) L0 block (`zio_crypt_do_hmac`).
#[must_use]
pub fn compute_authenticated_block_mac(
    hmac_key: &[u8; ZFS_HMAC_KEY_LEN],
    physical_psize: &[u8],
) -> [u8; ZIO_DATA_MAC_LEN] {
    let full = hmac_sha512(hmac_key, physical_psize);
    let mut mac = [0_u8; ZIO_DATA_MAC_LEN];
    mac.copy_from_slice(&full[..ZIO_DATA_MAC_LEN]);
    mac
}

// ── `DMU_OT_DNODE` Authenticated Encryption (`zio_crypt_init_uios_dnode`) ───

struct DnodeCryptParts {
    aad: Vec<u8>,
    enc_spans: Vec<(usize, usize)>,
}

fn split_dnode_block_for_crypt(
    raw: &[u8],
    order: Endian,
    version: u64,
) -> Result<DnodeCryptParts, ParseError> {
    if raw.len() != DNODE_BLOCK_BYTES {
        return Err(invalid("encrypted dnode block must be 16 KiB"));
    }
    let total_slots = DNODE_BLOCK_BYTES / DNODE_BYTES;
    let mut aad = Vec::with_capacity(DNODE_BLOCK_BYTES);
    let mut enc_spans = Vec::new();
    let mut i = 0_usize;
    while i < total_slots {
        let base = i * DNODE_BYTES;
        let dn_type = raw[base];
        let extra_slots = if dn_type == 0 {
            0_usize
        } else {
            usize::from(raw[base + 12])
        };
        if i + 1 + extra_slots > total_slots {
            return Err(invalid("dnode extra_slots exceeds 16 KiB dnode block"));
        }
        let dnode_size = (1 + extra_slots) * DNODE_BYTES;

        // 1. 64-byte core in the block's on-disk byte order, with dn_flags &= SPILL and dn_used = 0.
        let mut core = [0_u8; 64];
        core.copy_from_slice(&raw[base..base + 64]);
        core[7] &= DNODE_FLAG_SPILL_BLKPTR;
        core[24..32].fill(0);
        aad.extend_from_slice(&core);

        if dn_type == 0 {
            // Free dnode slot: remaining 448 bytes stay plaintext in AAD (`zio_crypt_init_uios_dnode`).
            aad.extend_from_slice(&raw[base + 64..base + DNODE_BYTES]);
            i += 1;
            continue;
        }

        let nblkptr = usize::from(raw[base + 3]);
        let has_spill = (raw[base + 7] & DNODE_FLAG_SPILL_BLKPTR) != 0;
        let bonus_start = 64 + nblkptr * 128;
        let bonus_end = dnode_size - if has_spill { 128 } else { 0 };
        if nblkptr == 0 || nblkptr > 3 || bonus_start > bonus_end {
            return Err(invalid("invalid dnode nblkptr or bonus geometry"));
        }

        // 2. Child block pointers (`dn_nblkptr` entries) as `blkptr_auth_buf_t`.
        for p in 0..nblkptr {
            let off = base + 64 + p * 128;
            let bp = BlockPointer::parse(&raw[off..off + 128], order)?;
            aad.extend_from_slice(&blkptr_auth_buf(&bp, version));
        }

        // 3. Optional spill block pointer BEFORE bonus bytes (exact OpenZFS order!).
        if has_spill {
            let spill_off = base + dnode_size - 128;
            let spill_bp = BlockPointer::parse(&raw[spill_off..spill_off + 128], order)?;
            aad.extend_from_slice(&blkptr_auth_buf(&spill_bp, version));
        }

        // 4. Bonus region (`DN_MAX_BONUS_LEN`): encrypted if bonus type is encrypted and bonus_len != 0,
        //    otherwise authenticated as plaintext in AAD.
        let bonus_type = raw[base + 4];
        let bonus_len = match order {
            Endian::Little => u16::from_le_bytes([raw[base + 10], raw[base + 11]]),
            Endian::Big => u16::from_be_bytes([raw[base + 10], raw[base + 11]]),
        };
        let bonus_abs_start = base + bonus_start;
        let bonus_abs_end = base + bonus_end;
        if dmu_ot_is_encrypted(bonus_type) && bonus_len != 0 {
            enc_spans.push((bonus_abs_start, bonus_abs_end));
        } else {
            aad.extend_from_slice(&raw[bonus_abs_start..bonus_abs_end]);
        }

        i += 1 + extra_slots;
    }
    Ok(DnodeCryptParts { aad, enc_spans })
}

/// Encrypt an uncompressed 16 KiB `DMU_OT_DNODE` block per OpenZFS `zio_crypt_init_uios_dnode`.
pub fn encrypt_dnode_block(
    key: &UnwrappedDslKey,
    salt: &[u8; ZIO_DATA_SALT_LEN],
    iv: &[u8; ZIO_DATA_IV_LEN],
    plaintext: &[u8],
    order: Endian,
) -> Result<(Vec<u8>, [u8; ZIO_DATA_MAC_LEN]), ParseError> {
    let parts = split_dnode_block_for_crypt(plaintext, order, key.version)?;
    let mut enc_plain = Vec::new();
    for &(lo, hi) in &parts.enc_spans {
        enc_plain.extend_from_slice(&plaintext[lo..hi]);
    }
    let mut dk = derive_block_data_key(key.active_master_key(), key.suite, salt)?;
    let (enc_ct, mac) = aead_encrypt(key.suite, &dk, iv, &parts.aad, &enc_plain)?;
    scrub_bytes(&mut dk);
    scrub_bytes(&mut enc_plain);

    let mut out = plaintext.to_vec();
    let mut cursor = 0_usize;
    for &(lo, hi) in &parts.enc_spans {
        let len = hi - lo;
        out[lo..hi].copy_from_slice(&enc_ct[cursor..cursor + len]);
        cursor += len;
    }
    Ok((out, mac))
}

/// Decrypt and authenticate a 16 KiB `DMU_OT_DNODE` block per OpenZFS `zio_crypt_init_uios_dnode`.
pub fn decrypt_dnode_block(
    key: &UnwrappedDslKey,
    bp: &BlockPointer,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ParseError> {
    if bp.object_type() != DMU_OT_DNODE || bp.level() != 0 || !bp.protected() {
        return Err(invalid("expected protected level-0 DMU_OT_DNODE pointer"));
    }
    if bp.compression() != 2 || ciphertext.len() != DNODE_BLOCK_BYTES {
        return Err(invalid(
            "encrypted DMU_OT_DNODE block must be uncompressed 16 KiB",
        ));
    }
    let order = bp.payload_order();
    let parts = split_dnode_block_for_crypt(ciphertext, order, key.version)?;
    let mut enc_ct = Vec::new();
    for &(lo, hi) in &parts.enc_spans {
        enc_ct.extend_from_slice(&ciphertext[lo..hi]);
    }
    let salt = bp_crypt_salt(bp);
    let iv = bp_crypt_iv(bp);
    let mac = bp_crypt_mac(bp);
    let mut dk = derive_block_data_key(key.active_master_key(), key.suite, &salt)?;
    let mut plain_spans = aead_decrypt(key.suite, &dk, &iv, &parts.aad, &enc_ct, &mac)?;
    scrub_bytes(&mut dk);

    let mut out = ciphertext.to_vec();
    let mut cursor = 0_usize;
    for &(lo, hi) in &parts.enc_spans {
        let len = hi - lo;
        out[lo..hi].copy_from_slice(&plain_spans[cursor..cursor + len]);
        cursor += len;
    }
    scrub_bytes(&mut plain_spans);
    Ok(out)
}

/// Extract raw on-disk bonus bytes (still encrypted when `bonus_type` is an encrypted
/// object type) for a single dnode slot inside a 16 KiB `DMU_OT_DNODE` block, supporting
/// keyless raw (`zfs send -w`) stream generation.
pub fn extract_raw_dnode_bonus(
    raw_block: &[u8],
    slot: usize,
    order: Endian,
) -> Result<Option<(usize, Vec<u8>)>, ParseError> {
    if raw_block.len() != DNODE_BLOCK_BYTES || slot >= DNODE_BLOCK_BYTES / DNODE_BYTES {
        return Err(invalid("invalid dnode block or slot index"));
    }
    let base = slot * DNODE_BYTES;
    if raw_block[base] == 0 {
        return Ok(None);
    }
    let extra_slots = usize::from(raw_block[base + 12]);
    let total_slots = DNODE_BLOCK_BYTES / DNODE_BYTES;
    if slot + 1 + extra_slots > total_slots {
        return Err(invalid("dnode extra_slots exceeds 16 KiB dnode block"));
    }
    let dnode_size = (1 + extra_slots) * DNODE_BYTES;
    let nblkptr = usize::from(raw_block[base + 3]);
    let has_spill = (raw_block[base + 7] & DNODE_FLAG_SPILL_BLKPTR) != 0;
    let bonus_start = 64 + nblkptr * 128;
    let bonus_end = dnode_size - if has_spill { 128 } else { 0 };
    if nblkptr == 0 || nblkptr > 3 || bonus_start > bonus_end {
        return Err(invalid("invalid dnode nblkptr or bonus geometry"));
    }
    let bonus_len = usize::from(match order {
        Endian::Little => u16::from_le_bytes([raw_block[base + 10], raw_block[base + 11]]),
        Endian::Big => u16::from_be_bytes([raw_block[base + 10], raw_block[base + 11]]),
    });
    if bonus_len == 0 {
        return Ok(Some((0, Vec::new())));
    }
    let bonus_type = raw_block[base + 4];
    let raw_len = if dmu_ot_is_encrypted(bonus_type) {
        bonus_end - bonus_start
    } else {
        bonus_len.min(bonus_end - bonus_start)
    };
    Ok(Some((
        raw_len,
        raw_block[base + bonus_start..base + bonus_start + raw_len].to_vec(),
    )))
}

/// Write exact raw (possibly encrypted) bonus bytes into a dnode slot inside a 16 KiB
/// `DMU_OT_DNODE` block during keyless raw (`zfs recv`) stream ingestion.
pub fn write_raw_dnode_bonus(
    raw_block: &mut [u8],
    slot: usize,
    raw_bonus: &[u8],
) -> Result<(), ParseError> {
    if raw_block.len() != DNODE_BLOCK_BYTES || slot >= DNODE_BLOCK_BYTES / DNODE_BYTES {
        return Err(invalid("invalid dnode block or slot index"));
    }
    let base = slot * DNODE_BYTES;
    if raw_block[base] == 0 {
        return Err(invalid("cannot write raw bonus into free dnode slot"));
    }
    let extra_slots = usize::from(raw_block[base + 12]);
    let total_slots = DNODE_BLOCK_BYTES / DNODE_BYTES;
    if slot + 1 + extra_slots > total_slots {
        return Err(invalid("dnode extra_slots exceeds 16 KiB dnode block"));
    }
    let dnode_size = (1 + extra_slots) * DNODE_BYTES;
    let nblkptr = usize::from(raw_block[base + 3]);
    let has_spill = (raw_block[base + 7] & DNODE_FLAG_SPILL_BLKPTR) != 0;
    let bonus_start = 64 + nblkptr * 128;
    let bonus_end = dnode_size - if has_spill { 128 } else { 0 };
    if nblkptr == 0 || nblkptr > 3 || bonus_start > bonus_end {
        return Err(invalid("invalid dnode nblkptr or bonus geometry"));
    }
    let capacity = bonus_end - bonus_start;
    if raw_bonus.len() > capacity {
        return Err(invalid("raw bonus payload exceeds dnode bonus capacity"));
    }
    raw_block[base + bonus_start..base + bonus_end].fill(0);
    raw_block[base + bonus_start..base + bonus_start + raw_bonus.len()].copy_from_slice(raw_bonus);
    Ok(())
}

// ── `objset_phys_t` Portable & Local HMACs (`zio_crypt_do_objset_hmacs`) ────

fn append_objset_dnode_hmac_input(
    dnode_raw: &[u8],
    order: Endian,
    version: u64,
    buf: &mut Vec<u8>,
) -> Result<(), ParseError> {
    if dnode_raw.len() != DNODE_BYTES {
        return Err(invalid("objset embedded dnode must be 512 bytes"));
    }
    let mut core = [0_u8; 64];
    core.copy_from_slice(&dnode_raw[..64]);
    // Convert multi-byte fields in dnode_phys_t core to little-endian (`zio_crypt_do_dnode_hmac_updates`).
    if order == Endian::Big {
        let blksz = u16::from_be_bytes([core[8], core[9]]);
        let bonuslen = u16::from_be_bytes([core[10], core[11]]);
        let maxblkid = u64::from_be_bytes([
            core[16], core[17], core[18], core[19], core[20], core[21], core[22], core[23],
        ]);
        core[8..10].copy_from_slice(&blksz.to_le_bytes());
        core[10..12].copy_from_slice(&bonuslen.to_le_bytes());
        core[16..24].copy_from_slice(&maxblkid.to_le_bytes());
    }
    core[7] &= DNODE_FLAG_SPILL_BLKPTR;
    core[24..32].fill(0);
    buf.extend_from_slice(&core);

    if core[0] == 0 {
        return Ok(());
    }
    let nblkptr = usize::from(core[3]);
    if nblkptr > 3 {
        return Err(invalid("objset dnode has more than 3 block pointers"));
    }
    for p in 0..nblkptr {
        let off = 64 + p * 128;
        let bp = BlockPointer::parse(&dnode_raw[off..off + 128], order)?;
        buf.extend_from_slice(&blkptr_auth_buf(&bp, version));
    }
    if (core[7] & DNODE_FLAG_SPILL_BLKPTR) != 0 {
        let spill = BlockPointer::parse(&dnode_raw[DNODE_BYTES - 128..DNODE_BYTES], order)?;
        buf.extend_from_slice(&blkptr_auth_buf(&spill, version));
    }
    Ok(())
}

/// Compute `(os_portable_mac, os_local_mac)` for an `objset_phys_t` block (`zio_crypt_do_objset_hmacs`).
///
/// Matches OpenZFS 2.3.0 `zio_crypt.c:1150-1240`:
/// - `os_type` is encoded **BIG-ENDIAN** (`BE64`) per upstream `BE_64(osp->os_type)`.
/// - `os_portable_mac` covers `BE64(os_type) || LE64(0) || meta_dnode_hmac_updates`.
/// - `os_local_mac` is all zeros unless `(os_flags & 1) != 0` and at least one present
///   accounting dnode (`userused`/`groupused`/`projectused`) is allocated; otherwise covers
///   `LE64(os_flags) || userused || groupused || projectused` (as present in `raw.len()`).
pub fn compute_objset_macs(
    raw: &[u8],
    order: Endian,
    hmac_key: &[u8; ZFS_HMAC_KEY_LEN],
    version: u64,
) -> Result<([u8; ZIO_OBJSET_MAC_LEN], [u8; ZIO_OBJSET_MAC_LEN]), ParseError> {
    if !matches!(raw.len(), 2048 | 4096) {
        return Err(invalid(
            "encrypted objset_phys_t must be 2048 or 4096 bytes",
        ));
    }
    let os_type = order.u64(raw, 704)?;
    let os_flags = order.u64(raw, 712)?;

    let mut portable_in = Vec::with_capacity(256);
    portable_in.extend_from_slice(&os_type.to_be_bytes());
    portable_in.extend_from_slice(&0_u64.to_le_bytes()); // os_flags & OBJSET_FLAG_PORTABLE_MASK (0)
    append_objset_dnode_hmac_input(&raw[0..DNODE_BYTES], order, version, &mut portable_in)?;
    let portable_full = hmac_sha512(hmac_key, &portable_in);
    let mut portable_mac = [0_u8; ZIO_OBJSET_MAC_LEN];
    portable_mac.copy_from_slice(&portable_full[..ZIO_OBJSET_MAC_LEN]);

    let has_userused =
        raw.len() >= OBJSET_USERUSED_OFFSET + DNODE_BYTES && raw[OBJSET_USERUSED_OFFSET] != 0;
    let has_groupused =
        raw.len() >= OBJSET_GROUPUSED_OFFSET + DNODE_BYTES && raw[OBJSET_GROUPUSED_OFFSET] != 0;
    let has_projectused =
        raw.len() >= OBJSET_PROJECTUSED_OFFSET + DNODE_BYTES && raw[OBJSET_PROJECTUSED_OFFSET] != 0;

    let mut local_mac = [0_u8; ZIO_OBJSET_MAC_LEN];
    if (os_flags & 1) != 0 && (has_userused || has_groupused || has_projectused) {
        let mut local_in = Vec::with_capacity(512);
        local_in.extend_from_slice(&os_flags.to_le_bytes());
        if raw.len() >= OBJSET_USERUSED_OFFSET + DNODE_BYTES {
            append_objset_dnode_hmac_input(
                &raw[OBJSET_USERUSED_OFFSET..OBJSET_USERUSED_OFFSET + DNODE_BYTES],
                order,
                version,
                &mut local_in,
            )?;
        }
        if raw.len() >= OBJSET_GROUPUSED_OFFSET + DNODE_BYTES {
            append_objset_dnode_hmac_input(
                &raw[OBJSET_GROUPUSED_OFFSET..OBJSET_GROUPUSED_OFFSET + DNODE_BYTES],
                order,
                version,
                &mut local_in,
            )?;
        }
        if raw.len() >= OBJSET_PROJECTUSED_OFFSET + DNODE_BYTES {
            append_objset_dnode_hmac_input(
                &raw[OBJSET_PROJECTUSED_OFFSET..OBJSET_PROJECTUSED_OFFSET + DNODE_BYTES],
                order,
                version,
                &mut local_in,
            )?;
        }
        let local_full = hmac_sha512(hmac_key, &local_in);
        local_mac.copy_from_slice(&local_full[..ZIO_OBJSET_MAC_LEN]);
    }
    Ok((portable_mac, local_mac))
}

/// Verify both `os_portable_mac` and `os_local_mac` stored at bytes `720..784` of `objset_phys_t`.
pub fn verify_objset_macs(
    raw: &[u8],
    order: Endian,
    hmac_key: &[u8; ZFS_HMAC_KEY_LEN],
    version: u64,
) -> Result<(), ParseError> {
    let (expected_portable, expected_local) = compute_objset_macs(raw, order, hmac_key, version)?;
    let stored_portable = &raw[720..752];
    let stored_local = &raw[752..784];
    if !ct_eq(stored_portable, &expected_portable) {
        return Err(invalid("objset portable MAC mismatch"));
    }
    if !ct_eq(stored_local, &expected_local) {
        return Err(invalid("objset local MAC mismatch"));
    }
    Ok(())
}

// ── Native ZFS Compression Encoder (for writable encrypted/plain blocks) ────

/// LZJB wire groups contain one low-bit-first match bitmap and up to eight
/// literal or two-byte match tokens. A match stores a 10-bit backward distance
/// and a six-bit length biased by three; overlapping copies are permitted.
/// The bounded dictionary is an encoder choice, not part of the wire format.
fn compress_lzjb_payload(input: &[u8]) -> Vec<u8> {
    const HASH_BITS: u32 = 12;
    let mut latest = vec![usize::MAX; 1 << HASH_BITS];
    let mut output = Vec::with_capacity(input.len() + input.len().div_ceil(8));
    let mut position = 0;
    while position < input.len() {
        let map_index = output.len();
        output.push(0);
        for bit in 0..8 {
            if position == input.len() {
                break;
            }
            let mut matched = 0;
            let mut distance = 0;
            if input.len() - position >= 3 {
                let prefix = u32::from_le_bytes([
                    input[position],
                    input[position + 1],
                    input[position + 2],
                    0,
                ]);
                let hash = (prefix.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize;
                let candidate = latest[hash];
                latest[hash] = position;
                if candidate < position
                    && position - candidate <= 1023
                    && input[candidate..candidate + 3] == input[position..position + 3]
                {
                    distance = position - candidate;
                    matched = 3;
                    let limit = (input.len() - position).min(66);
                    while matched < limit && input[candidate + matched] == input[position + matched]
                    {
                        matched += 1;
                    }
                }
            }
            if matched == 0 {
                output.push(input[position]);
                position += 1;
            } else {
                output[map_index] |= 1 << bit;
                output.push((((matched - 3) << 2) | (distance >> 8)) as u8);
                output.push((distance & 255) as u8);
                position += matched;
            }
        }
    }
    output
}

fn compress_zle(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0_usize;
    while i < input.len() {
        if input[i] == 0 {
            let start = i;
            while i < input.len() && input[i] == 0 && i - start < 192 {
                i += 1;
            }
            let len = i - start;
            out.push(u8::try_from(len + 63).unwrap_or(255));
        } else {
            let start = i;
            while i < input.len() && i - start < 64 {
                if input[i] == 0 && i + 1 < input.len() && input[i + 1] == 0 {
                    break;
                }
                i += 1;
            }
            let len = i - start;
            out.push(u8::try_from(len - 1).unwrap_or(63));
            out.extend_from_slice(&input[start..i]);
        }
    }
    out
}

fn push_lz4_ext_len(out: &mut Vec<u8>, mut rem: usize) {
    while rem >= 255 {
        out.push(255);
        rem -= 255;
    }
    out.push(u8::try_from(rem).unwrap_or(0));
}

fn compress_lz4_payload(input: &[u8]) -> Vec<u8> {
    const HASH_BITS: usize = 12;
    const HASH_SIZE: usize = 1 << HASH_BITS;
    let mut table = vec![0_usize; HASH_SIZE];
    let mut out = Vec::with_capacity(input.len() + 16);
    let len = input.len();
    let mut anchor = 0_usize;
    let mut ip = 0_usize;
    let mflimit = len.saturating_sub(12);
    let match_limit = len.saturating_sub(5);

    while ip < mflimit {
        let val = u32::from_le_bytes([input[ip], input[ip + 1], input[ip + 2], input[ip + 3]]);
        let h = ((val.wrapping_mul(2_654_435_761)) >> (32 - HASH_BITS)) as usize;
        let candidate = table[h];
        table[h] = ip;
        if candidate < ip
            && ip - candidate <= 65_535
            && input[candidate..candidate + 4] == input[ip..ip + 4]
        {
            let mut match_len = 4_usize;
            while ip + match_len < match_limit
                && input[candidate + match_len] == input[ip + match_len]
            {
                match_len += 1;
            }
            let lit_len = ip - anchor;
            let ml_code = match_len - 4;
            let token = (u8::try_from(lit_len.min(15)).unwrap_or(15) << 4)
                | u8::try_from(ml_code.min(15)).unwrap_or(15);
            out.push(token);
            if lit_len >= 15 {
                push_lz4_ext_len(&mut out, lit_len - 15);
            }
            out.extend_from_slice(&input[anchor..ip]);
            let offset = u16::try_from(ip - candidate).unwrap_or(0);
            out.extend_from_slice(&offset.to_le_bytes());
            if ml_code >= 15 {
                push_lz4_ext_len(&mut out, ml_code - 15);
            }
            ip += match_len;
            anchor = ip;
        } else {
            ip += 1;
        }
    }
    let last_lit = len - anchor;
    let token = u8::try_from(last_lit.min(15)).unwrap_or(15) << 4;
    out.push(token);
    if last_lit >= 15 {
        push_lz4_ext_len(&mut out, last_lit - 15);
    }
    out.extend_from_slice(&input[anchor..len]);
    out
}

/// Compress a logical block using OpenZFS wire framing (`OFF=2`, `LZJB=3`,
/// `EMPTY=4`, `ZLE=14`, `LZ4=15`, `gzip-1..9 = 5..=13`, `zstd = 16`), zero-padded
/// to `align_bytes` (e.g. `1 << ashift`). Resolve `INHERIT` and `ON` using the
/// dataset and active pool features before calling this codec-level function.
///
/// Automatically falls back to uncompressed (`compression = 2`) when compression does not
/// save the native minimum of one eighth of the logical size or does not reduce
/// the aligned physical size below `input.len()`.
pub fn compress_block(
    input: &[u8],
    requested_compression: u8,
    zstd_level: Option<u8>,
    align_bytes: usize,
) -> Result<(Vec<u8>, u8), ParseError> {
    if input.is_empty()
        || input.len() > MAX_BLOCK_BYTES
        || !input.len().is_multiple_of(512)
        || align_bytes < 512
        || !align_bytes.is_power_of_two()
    {
        return Err(invalid("invalid ZFS compression block size or alignment"));
    }
    let effective = match requested_compression {
        2 | 4 => return Ok((input.to_vec(), 2)),
        other => other,
    };
    let raw_compressed: Vec<u8> = match effective {
        3 => compress_lzjb_payload(input),
        14 => compress_zle(input),
        15 => {
            let body = compress_lz4_payload(input);
            let body_len = u32::try_from(body.len()).map_err(|_| invalid("LZ4 length overflow"))?;
            let mut framed = Vec::with_capacity(4 + body.len());
            framed.extend_from_slice(&body_len.to_be_bytes());
            framed.extend_from_slice(&body);
            framed
        }
        5..=13 => {
            let level = u32::from(effective - 4);
            let mut enc = Compress::new(Compression::new(level), true);
            let mut dst = vec![0_u8; input.len() + 64];
            let status = enc
                .compress(input, &mut dst, FlushCompress::Finish)
                .map_err(|_| invalid("ZFS gzip compression failed"))?;
            if status != Status::StreamEnd {
                return Ok((input.to_vec(), 2));
            }
            dst.truncate(usize::try_from(enc.total_out()).unwrap_or(input.len()));
            dst
        }
        16 => {
            let level = zstd_level.unwrap_or(3);
            if !matches!(level, 1..=19) {
                return Err(invalid("unsupported ZFS zstd compression level"));
            }
            let frame = zstd::bulk::compress(input, i32::from(level))
                .map_err(|_| invalid("ZFS zstd compression failed"))?;
            if frame.len() < 4 || frame[..4] != [0x28, 0xB5, 0x2F, 0xFD] {
                return Err(invalid("unexpected zstd frame magic"));
            }
            let magicless = &frame[4..];
            let packed =
                u32::try_from(magicless.len()).map_err(|_| invalid("ZFS zstd length overflow"))?;
            let mut framed = Vec::with_capacity(8 + magicless.len());
            framed.extend_from_slice(&packed.to_be_bytes());
            // Native OpenZFS zstd header[4..8]: big-endian level in byte 7, zero padding in 4..7.
            framed.extend_from_slice(&[0, 0, 0, level]);
            framed.extend_from_slice(magicless);
            framed
        }
        _ => return Err(invalid("unsupported ZFS write compression algorithm")),
    };

    let savings_limit = input.len() - (input.len() >> 3);
    // Native ZLE uses the unrounded limit; the other codecs receive a limit
    // rounded down to the pool allocation unit. A sub-sector result could be
    // embedded natively, but this encoder's caller emits regular pointers.
    let savings_limit = if effective == 14 {
        savings_limit
    } else {
        (savings_limit - savings_limit % align_bytes).max(112)
    };
    if raw_compressed.len() > savings_limit {
        return Ok((input.to_vec(), 2));
    }
    let aligned_len = raw_compressed.len().next_multiple_of(align_bytes).max(512);
    if aligned_len >= input.len() {
        return Ok((input.to_vec(), 2));
    }
    let mut padded = raw_compressed;
    padded.resize(aligned_len, 0);
    // Self-check roundtrip against the exact native decoder before returning.
    let roundtrip = decompress(&padded, effective, input.len())?;
    if roundtrip != input {
        return Err(invalid("ZFS compression roundtrip mismatch"));
    }
    Ok((padded, effective))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(clean.len().is_multiple_of(2));
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn aes_fips_197_appendix_c_vectors() {
        let pt: [u8; 16] = hex_to_bytes("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        // C.1 AES-128
        let k128 = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let ct128 = AesKeySchedule::new(&k128).unwrap().encrypt_block(&pt);
        assert_eq!(
            ct128.as_slice(),
            hex_to_bytes("69c4e0d86a7b0430d8cdb78070b4c55a").as_slice()
        );
        // C.2 AES-192
        let k192 = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        let ct192 = AesKeySchedule::new(&k192).unwrap().encrypt_block(&pt);
        assert_eq!(
            ct192.as_slice(),
            hex_to_bytes("dda97ca4864cdfe06eaf70a0ec0d7191").as_slice()
        );
        // C.3 AES-256
        let k256 = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let ct256 = AesKeySchedule::new(&k256).unwrap().encrypt_block(&pt);
        assert_eq!(
            ct256.as_slice(),
            hex_to_bytes("8ea2b7ca516745bfeafc49904b496089").as_slice()
        );
    }

    #[test]
    fn aes_gcm_nist_sp_800_38d_vectors() {
        // Test Case 1: AES-128-GCM, empty PT, empty AAD
        let k1 = [0_u8; 16];
        let iv1 = [0_u8; 12];
        let (ct1, tag1) = aes_gcm_encrypt(&k1, &iv1, &[], &[]).unwrap();
        assert_eq!(ct1, b"");
        assert_eq!(
            tag1.as_slice(),
            hex_to_bytes("58e2fccefa7e3061367f1d57a4e7455a").as_slice()
        );
        assert_eq!(aes_gcm_decrypt(&k1, &iv1, &[], &ct1, &tag1).unwrap(), b"");

        // Test Case 4: AES-128-GCM with non-empty AAD + non-block-aligned PT
        let k4 = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv4: [u8; 12] = hex_to_bytes("cafebabefacedbaddecaf888").try_into().unwrap();
        let aad4 = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let pt4 = hex_to_bytes(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b39",
        );
        let (ct4, tag4) = aes_gcm_encrypt(&k4, &iv4, &aad4, &pt4).unwrap();
        assert_eq!(
            ct4,
            hex_to_bytes(
                "42831ec2217774244b7221b784d0d49c\
                 e3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa05\
                 1ba30b396a0aac973d58e091"
            )
        );
        assert_eq!(
            tag4.as_slice(),
            hex_to_bytes("5bc94fbc3221a5db94fae95ae7121a47").as_slice()
        );
        assert_eq!(aes_gcm_decrypt(&k4, &iv4, &aad4, &ct4, &tag4).unwrap(), pt4);

        // Tamper 1 bit of ciphertext, AAD, IV, or tag -> must fail closed.
        let mut bad_ct = ct4.clone();
        bad_ct[0] ^= 1;
        assert!(aes_gcm_decrypt(&k4, &iv4, &aad4, &bad_ct, &tag4).is_err());
        let mut bad_tag = tag4;
        bad_tag[15] ^= 1;
        assert!(aes_gcm_decrypt(&k4, &iv4, &aad4, &ct4, &bad_tag).is_err());
        let mut bad_aad = aad4.clone();
        bad_aad[0] ^= 1;
        assert!(aes_gcm_decrypt(&k4, &iv4, &bad_aad, &ct4, &tag4).is_err());

        // Test Case 16: AES-256-GCM with AAD + PT
        let k16 = hex_to_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let (ct16, tag16) = aes_gcm_encrypt(&k16, &iv4, &aad4, &pt4).unwrap();
        assert_eq!(
            ct16,
            hex_to_bytes(
                "522dc1f099567d07f47f37a32a84427d\
                 643a8cdcbfe5c0c97598a2bd2555d1aa\
                 8cb08e48590dbb3da7b08b1056828838\
                 c5f61e6393ba7a0abcc9f662"
            )
        );
        assert_eq!(
            tag16.as_slice(),
            hex_to_bytes("76fc6ece0f4e1768cddf8853bb2d551b").as_slice()
        );
        assert_eq!(
            aes_gcm_decrypt(&k16, &iv4, &aad4, &ct16, &tag16).unwrap(),
            pt4
        );
    }

    #[test]
    fn aes_ccm_roundtrip_and_tamper_rejection() {
        for key_len in [16_usize, 24, 32] {
            let key: Vec<u8> = (0..key_len).map(|i| (i * 7 + 3) as u8).collect();
            let iv = [0x11_u8; 12];
            for aad in [&[][..], b"short-aad", &[0xAB_u8; 100]] {
                for pt in [&[][..], b"hello zfs ccm", &[0x5C_u8; 4096]] {
                    let (ct, tag) = aes_ccm_encrypt(&key, &iv, aad, pt).unwrap();
                    assert_eq!(aes_ccm_decrypt(&key, &iv, aad, &ct, &tag).unwrap(), pt);
                    let mut bad_tag = tag;
                    bad_tag[0] ^= 0x80;
                    assert!(aes_ccm_decrypt(&key, &iv, aad, &ct, &bad_tag).is_err());
                    if !ct.is_empty() {
                        let mut bad_ct = ct.clone();
                        bad_ct[0] ^= 1;
                        assert!(aes_ccm_decrypt(&key, &iv, aad, &bad_ct, &tag).is_err());
                    }
                }
            }
        }
    }

    #[test]
    fn pbkdf2_hmac_sha1_rfc_6070_vectors() {
        let mut dk = [0_u8; 20];
        pbkdf2_hmac_sha1(b"password", b"salt", 1, &mut dk).unwrap();
        assert_eq!(
            dk.as_slice(),
            hex_to_bytes("0c60c80f961f0e71f3a9b524af6012062fe037a6").as_slice()
        );
        pbkdf2_hmac_sha1(b"password", b"salt", 2, &mut dk).unwrap();
        assert_eq!(
            dk.as_slice(),
            hex_to_bytes("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957").as_slice()
        );
        pbkdf2_hmac_sha1(b"password", b"salt", 4096, &mut dk).unwrap();
        assert_eq!(
            dk.as_slice(),
            hex_to_bytes("4b007901b765489abead49d926f721d065a429c1").as_slice()
        );
    }

    #[test]
    fn hmac_sha512_rfc_4231_and_hkdf_vectors() {
        // RFC 4231 Test Case 1
        let k1 = [0x0b_u8; 20];
        let mac1 = hmac_sha512(&k1, b"Hi There");
        assert_eq!(
            mac1.as_slice(),
            hex_to_bytes(
                "87aa7cdea5ef619d4ff0b4241a1d6cb0\
                 2379f4e2ce4ec2787ad0b30545e17cde\
                 daa833b7d6b8a702038b274eaea3f4e4\
                 be9d914eeb61f1702e696c203a126854"
            )
            .as_slice()
        );
        // RFC 4231 Test Case 2
        let mac2 = hmac_sha512(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac2.as_slice(),
            hex_to_bytes(
                "164b7a7bfcf819e2e395fbe73b56e0a3\
                 87bd64222e831fd610270cd7ea250554\
                 9758bf75c05a994a6d034f65f8f0e6fd\
                 caeab1a34d4a6b4b636e070a38bce737"
            )
            .as_slice()
        );
        let okm = hkdf_sha512(&[0x42_u8; 32], &[], &[1, 2, 3, 4, 5, 6, 7, 8], 32).unwrap();
        assert_eq!(okm.len(), 32);
        let okm_diff = hkdf_sha512(&[0x42_u8; 32], &[], &[1, 2, 3, 4, 5, 6, 7, 9], 32).unwrap();
        assert_ne!(okm, okm_diff);
    }

    #[test]
    fn dsl_crypto_key_wrap_and_unwrap_all_suites() {
        let wrapping = [0x5A_u8; ZFS_WRAPPING_KEY_LEN];
        let wrong = [0x5B_u8; ZFS_WRAPPING_KEY_LEN];
        let master = [0xA1_u8; ZFS_MAX_MASTER_KEY_LEN];
        let hmac = [0xB2_u8; ZFS_HMAC_KEY_LEN];
        let iv = [0x33_u8; ZIO_DATA_IV_LEN];

        for suite in [
            ZioEncrypt::Aes128Ccm,
            ZioEncrypt::Aes192Ccm,
            ZioEncrypt::Aes256Ccm,
            ZioEncrypt::Aes128Gcm,
            ZioEncrypt::Aes192Gcm,
            ZioEncrypt::Aes256Gcm,
        ] {
            for version in [DSL_CRYPTO_KEY_VERSION_V0, DSL_CRYPTO_KEY_VERSION_V1] {
                let rec = DslCryptoKeyRecord::wrap(
                    suite,
                    0x1234_5678_9ABC_DEF0,
                    version,
                    42,
                    1,
                    ZfsKeyFormat::Raw,
                    0,
                    0,
                    iv,
                    &wrapping,
                    &master,
                    &hmac,
                )
                .unwrap();
                let unwrapped = rec.unwrap(&wrapping).unwrap();
                assert_eq!(unwrapped.suite, suite);
                assert_eq!(
                    unwrapped.active_master_key(),
                    &master[..suite.key_len().unwrap()]
                );
                assert_eq!(unwrapped.hmac_key, hmac);
                assert!(rec.unwrap(&wrong).is_err());

                let mut tampered = rec.clone();
                tampered.guid ^= 1;
                assert!(tampered.unwrap(&wrapping).is_err());
            }
        }
    }

    #[test]
    fn compression_roundtrip_all_codecs() {
        let mut block = vec![0_u8; 4096];
        for (i, byte) in block.iter_mut().enumerate().take(512) {
            *byte = (i % 13) as u8;
        }
        for (alg, lvl) in [
            (2, None),
            (3, None),
            (14, None),
            (15, None),
            (6, None),
            (16, Some(3)),
        ] {
            let (phys, actual_alg) = compress_block(&block, alg, lvl, 512).unwrap();
            assert!(phys.len().is_multiple_of(512));
            let decoded = decompress(&phys, actual_alg, block.len()).unwrap();
            assert_eq!(decoded, block);
            if alg != 2 {
                assert_eq!(actual_alg, alg);
                assert!(phys.len() < block.len());
            }
        }
    }

    #[test]
    fn lzjb_encoder_native_tokens_overlap_and_window_boundaries() {
        assert_eq!(compress_lzjb_payload(b"abcdefgh"), b"\x00abcdefgh");
        assert_eq!(
            compress_lzjb_payload(b"abcabcabcabc"),
            [8, b'a', b'b', b'c', 24, 3]
        );
        assert_eq!(compress_lzjb_payload(&[b'x'; 67]), [2, b'x', 252, 1]);
        for period in [1_u32, 2, 3, 7, 65, 66, 67, 255, 1023, 1024, 1025] {
            let block: Vec<u8> = (0_u32..8192)
                .map(|i| u8::try_from((i % period) % 251).expect("remainder fits a byte"))
                .collect();
            let encoded = compress_lzjb_payload(&block);
            assert_eq!(decompress(&encoded, 3, block.len()).unwrap(), block);
        }
    }

    #[test]
    fn compression_fallback_preserves_physical_alignment_and_requires_resolved_policy() {
        let mut state = 0x1234_5678_u32;
        let mut random = vec![0; 4096];
        for byte in &mut random {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = (state & 255) as u8;
        }
        for algorithm in [3, 5, 14, 15, 16] {
            let (physical, selected) = compress_block(&random, algorithm, Some(3), 512).unwrap();
            assert_eq!(selected, 2);
            assert_eq!(physical, random);

            let zeros = vec![0; 4096];
            let (physical, selected) = compress_block(&zeros, algorithm, Some(3), 4096).unwrap();
            assert_eq!(selected, 2);
            assert_eq!(physical, zeros);
        }
        for unresolved in [0, 1, 17, 255] {
            assert!(compress_block(&random, unresolved, None, 512).is_err());
        }
        assert_eq!(compress_block(&random, 4, None, 512).unwrap(), (random, 2));

        // Nine percent savings would occupy fewer sectors but does not meet
        // the native one-eighth threshold. Keep the original bytes in that case.
        let mut marginal = vec![0; 32_768];
        for byte in marginal.iter_mut().take(29_696) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = (state & 255) as u8;
        }
        for algorithm in [5, 15, 16] {
            assert_eq!(
                compress_block(&marginal, algorithm, Some(3), 512).unwrap(),
                (marginal.clone(), 2)
            );
        }
    }

    #[test]
    fn protected_block_pointer_dnode_indirect_and_objset_mac_roundtrips() {
        use crate::zfs::{Dva, ProtectedBlockSpec};
        use crate::zfs_dmu::{Dnode, DnodeSpec, ObjectSet, ZilHeader};

        let key = UnwrappedDslKey {
            suite: ZioEncrypt::Aes256Gcm,
            guid: 0xfeed_beef_cafe_1234,
            version: DSL_CRYPTO_KEY_VERSION_V1,
            master_key: [0x3c_u8; ZFS_MAX_MASTER_KEY_LEN],
            master_key_len: 32,
            hmac_key: [0x9a_u8; ZFS_HMAC_KEY_LEN],
        };
        let dva0 = Dva {
            vdev: 0,
            offset: 0x2000,
            allocated_bytes: 4096,
            gang: false,
        };
        let dva1 = Dva {
            vdev: 0,
            offset: 0x4000,
            allocated_bytes: 4096,
            gang: false,
        };
        let dva2 = Dva {
            vdev: 0,
            offset: 0x6000,
            allocated_bytes: 4096,
            gang: false,
        };
        let salt = [1_u8, 2, 3, 4, 5, 6, 7, 8];
        let iv = [10_u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21];

        for order in [Endian::Little, Endian::Big] {
            // 1. Encrypted L0 regular block (compressed LZ4 + encrypted)
            let mut plain = vec![0_u8; 4096];
            plain[..128].fill(0x5A);
            let (comp, comp_alg) = compress_block(&plain, 15, None, 512).unwrap();
            assert_eq!(comp_alg, 15);
            let (ct, mac) = encrypt_regular_block(&key, &salt, &iv, &comp).unwrap();
            let comp_dva = Dva {
                vdev: 0,
                offset: 0x2000,
                allocated_bytes: comp.len() as u64,
                gang: false,
            };
            let bp = BlockPointer::new_protected(&ProtectedBlockSpec {
                dvas: &[comp_dva],
                logical_bytes: 4096,
                physical: &ct,
                compression: comp_alg,
                checksum_type: 7,
                object_type: 19,
                level: 0,
                payload_order: order,
                birth: 11,
                fill: 1,
                salt: Some(salt),
                iv: Some(iv),
                mac,
            })
            .unwrap();
            assert!(bp.protected());
            assert!(bp.is_encrypted());
            assert!(!bp.is_authenticated());
            // Upper 32 bits of words[11] carry IV2; fill() must mask them off.
            assert_eq!(bp.fill(), 1);
            assert_eq!(bp_crypt_salt(&bp), salt);
            assert_eq!(bp_crypt_iv(&bp), iv);
            assert_eq!(bp_crypt_mac(&bp), mac);
            // decode() MUST fail closed on protected pointers.
            assert!(bp.decode(&ct).is_err());
            bp.verify_physical(&ct).unwrap();
            assert_eq!(decrypt_regular_block(&key, &bp, &ct).unwrap(), plain);

            // Encrypted L0 rejects 3 DVAs (DVA2 slot is reserved for salt/IV1).
            assert!(
                BlockPointer::new_protected(&ProtectedBlockSpec {
                    dvas: &[dva0, dva1, dva2],
                    logical_bytes: 4096,
                    physical: &vec![0_u8; 4096],
                    compression: 2,
                    checksum_type: 7,
                    object_type: 19,
                    level: 0,
                    payload_order: order,
                    birth: 11,
                    fill: 1,
                    salt: Some(salt),
                    iv: Some(iv),
                    mac,
                })
                .is_err()
            );

            // 2. Protected L1 indirect block (up to 3 DVAs, keyless SHA-512 MAC)
            let mut indirect = vec![0_u8; 4096];
            indirect[..128].copy_from_slice(&bp.encode(order));
            let ind_mac = compute_indirect_block_mac(&indirect, order, key.version).unwrap();
            let ind_bp = BlockPointer::new_protected(&ProtectedBlockSpec {
                dvas: &[dva0, dva1, dva2],
                logical_bytes: 4096,
                physical: &indirect,
                compression: 2,
                checksum_type: 8,
                object_type: 19,
                level: 1,
                payload_order: order,
                birth: 11,
                fill: 1,
                salt: None,
                iv: None,
                mac: ind_mac,
            })
            .unwrap();
            assert!(ind_bp.is_authenticated());
            assert_eq!(ind_bp.protected_dvas().unwrap().len(), 3);
            ind_bp.verify_physical(&indirect).unwrap();

            // 3. Encrypted DMU_OT_DNODE block leaves core/BPs plaintext & encrypts SA bonus
            let sa_bonus = vec![0x77_u8; 168];
            let file_dnode = Dnode::from_spec(DnodeSpec {
                object_type: 19,
                bonus_type: 44, // DMU_OT_SA (encrypted!)
                checksum_type: 7,
                compress_type: 15,
                flags: 1,
                order,
                levels: 2,
                indirect_shift: 12,
                data_bytes: 4096,
                max_block: 0,
                used_bytes: 4096,
                slots: 1,
                pointers: vec![ind_bp.clone()],
                bonus: sa_bonus.clone(),
                spill: None,
            })
            .unwrap();
            let mut dnode_block = vec![0_u8; DNODE_BLOCK_BYTES];
            dnode_block[DNODE_BYTES..2 * DNODE_BYTES]
                .copy_from_slice(&file_dnode.encode().unwrap());
            let (enc_dnode_block, dnode_mac) =
                encrypt_dnode_block(&key, &salt, &iv, &dnode_block, order).unwrap();
            // Core + BP stay plaintext, encrypted bonus differs from plaintext!
            assert_eq!(
                &enc_dnode_block[DNODE_BYTES..DNODE_BYTES + 64 + 128],
                &dnode_block[DNODE_BYTES..DNODE_BYTES + 64 + 128]
            );
            assert_ne!(
                &enc_dnode_block[DNODE_BYTES + 192..DNODE_BYTES + 192 + sa_bonus.len()],
                sa_bonus.as_slice()
            );
            let dnode_dva = Dva {
                vdev: 0,
                offset: 0x8000,
                allocated_bytes: DNODE_BLOCK_BYTES as u64,
                gang: false,
            };
            let dnode_bp = BlockPointer::new_protected(&ProtectedBlockSpec {
                dvas: &[dnode_dva],
                logical_bytes: DNODE_BLOCK_BYTES,
                physical: &enc_dnode_block,
                compression: 2,
                checksum_type: 7,
                object_type: DMU_OT_DNODE,
                level: 0,
                payload_order: order,
                birth: 11,
                fill: 1,
                salt: Some(salt),
                iv: Some(iv),
                mac: dnode_mac,
            })
            .unwrap();
            assert_eq!(
                decrypt_regular_block(&key, &dnode_bp, &enc_dnode_block).unwrap(),
                dnode_block
            );

            // 4. Protected DMU_OT_OBJSET MAC stamping + verification + tamper rejection
            let meta_dnode = Dnode::from_spec(DnodeSpec {
                object_type: DMU_OT_DNODE,
                bonus_type: 0,
                checksum_type: 7,
                compress_type: 2,
                flags: 1,
                order,
                levels: 1,
                indirect_shift: 12,
                data_bytes: DNODE_BLOCK_BYTES,
                max_block: 0,
                used_bytes: DNODE_BLOCK_BYTES as u64,
                slots: 1,
                pointers: vec![dnode_bp],
                bonus: Vec::new(),
                spill: None,
            })
            .unwrap();
            let mut os = ObjectSet::new(2, 0, meta_dnode, ZilHeader::empty(), 4096).unwrap();
            os.stamp_encrypted_macs(order, &key.hmac_key, key.version)
                .unwrap();
            let os_raw = os.encode(order).unwrap();
            verify_objset_macs(&os_raw, order, &key.hmac_key, key.version).unwrap();
            let mut tampered_os = os_raw.clone();
            tampered_os[720] ^= 1;
            assert!(verify_objset_macs(&tampered_os, order, &key.hmac_key, key.version).is_err());
        }
    }
}
