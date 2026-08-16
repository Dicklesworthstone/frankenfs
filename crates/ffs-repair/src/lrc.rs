//! Local Reconstruction Codes (LRC) for distributed/multi-disk repair.
//!
//! Implements the Azure LRC scheme (Huang et al., USENIX ATC 2012) where
//! data blocks are partitioned into local repair groups, each with a local
//! parity block. Additional global parity blocks handle multi-failure
//! scenarios.
//!
//! # Advantages over RaptorQ for distributed storage
//!
//! - **Single-failure repair**: read only the local group (3–5 blocks)
//!   instead of the full erasure group (14+ blocks). Reduces repair I/O
//!   by 5–10x.
//! - **Locality**: repair traffic stays within the local group, reducing
//!   cross-rack/cross-node bandwidth.
//! - **Fallback**: multi-failure falls back to global reconstruction
//!   using all data + global parity blocks.
//!
//! # Layout
//!
//! Given `k` data blocks split into `g` local groups of `r` blocks each
//! (`k = g * r`), we generate:
//! - `g` local parity blocks (one per group, XOR of group members)
//! - `p` global parity blocks (Reed-Solomon over all `k` data blocks)
//!
//! Total blocks: `k + g + p` (data + local parity + global parity).
//!
//! # GF(256) arithmetic
//!
//! Global parity uses Galois Field GF(2^8) with the standard AES
//! irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (0x11B) and
//! primitive element `0x03`.
//!
//! # `unsafe_code = "forbid"` Compliance
//!
//! All operations are safe Rust.

use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ── GF(256) arithmetic ─────────────────────────────────────────────────────

/// GF(256) multiplication using log/exp tables.
/// Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B).
mod gf256 {
    /// Precomputed log table (base 0x03, the generator of GF(256)*).
    const LOG: [u8; 256] = {
        let mut table = [0_u8; 256];
        let mut val = 1_u32;
        let mut i = 0_u8;
        loop {
            table[val as usize] = i;
            // Multiply by generator 0x03 in GF(256).
            val = (val << 1) ^ val; // val * 3 = val * 2 + val
            if val >= 256 {
                val ^= 0x11B; // reduce by irreducible polynomial
            }
            i = i.wrapping_add(1);
            if i == 255 {
                break;
            }
        }
        table[0] = 0; // log(0) is undefined, but we handle it specially
        table
    };

    /// Precomputed exp table.
    #[expect(clippy::cast_possible_truncation)] // val is always < 256 after reduction
    const EXP: [u8; 512] = {
        let mut table = [0_u8; 512];
        let mut val = 1_u32;
        let mut i = 0;
        while i < 512 {
            table[i] = val as u8;
            val = (val << 1) ^ val;
            if val >= 256 {
                val ^= 0x11B;
            }
            i += 1;
        }
        table
    };

    #[expect(clippy::cast_possible_truncation)] // loop indices stay in 0..256
    static MUL: [[u8; 256]; 256] = {
        let mut table = [[0_u8; 256]; 256];
        let mut a = 0;
        while a < 256 {
            let mut b = 0;
            while b < 256 {
                table[a][b] = mul_log_exp(a as u8, b as u8);
                b += 1;
            }
            a += 1;
        }
        table
    };

    const fn mul_log_exp(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let log_a = LOG[a as usize] as usize;
        let log_b = LOG[b as usize] as usize;
        EXP[log_a + log_b]
    }

    /// Multiply two elements in GF(256).
    #[must_use]
    pub fn mul(a: u8, b: u8) -> u8 {
        MUL[a as usize][b as usize]
    }

    #[must_use]
    pub fn mul_row(coeff: u8) -> &'static [u8; 256] {
        &MUL[coeff as usize]
    }

    /// Compute generator^exponent in GF(256).
    #[must_use]
    pub fn generator_pow(exponent: usize) -> u8 {
        EXP[exponent % 255]
    }

    /// Compute the multiplicative inverse of `a` in GF(256).
    /// Panics if `a == 0`.
    #[must_use]
    pub fn inv(a: u8) -> u8 {
        assert_ne!(a, 0, "GF(256) inverse of zero is undefined");
        let log_a = LOG[a as usize] as usize;
        EXP[255 - log_a]
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn mul_identity() {
            for a in 0..=255_u8 {
                assert_eq!(mul(a, 1), a);
                assert_eq!(mul(1, a), a);
            }
        }

        #[test]
        fn mul_zero() {
            for a in 0..=255_u8 {
                assert_eq!(mul(a, 0), 0);
                assert_eq!(mul(0, a), 0);
            }
        }

        #[test]
        fn mul_inverse() {
            for a in 1..=255_u8 {
                let a_inv = inv(a);
                assert_eq!(mul(a, a_inv), 1, "a={a}, inv={a_inv}");
            }
        }

        #[test]
        fn mul_commutative() {
            for a in 0..=255_u8 {
                for b in 0..=255_u8 {
                    assert_eq!(mul(a, b), mul(b, a), "a={a}, b={b}");
                }
            }
        }

        #[test]
        fn generator_has_full_nonzero_field_order() {
            let mut seen = [false; 256];
            for exponent in 0..255 {
                let value = generator_pow(exponent);
                assert_ne!(value, 0, "generator power {exponent} produced zero");
                assert!(
                    !seen[value as usize],
                    "generator power {exponent} repeated value {value}"
                );
                seen[value as usize] = true;
            }
            assert_eq!(generator_pow(255), 1);
        }
    }
}

// ── LRC configuration ──────────────────────────────────────────────────────

/// LRC layout configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LrcConfig {
    /// Number of data blocks (`k`).
    pub data_blocks: u32,
    /// Number of blocks per local repair group (`r`).
    pub local_group_size: u32,
    /// Number of global parity blocks (`p`).
    pub global_parity_count: u32,
}

impl LrcConfig {
    /// Create a new LRC configuration.
    ///
    /// # Panics
    ///
    /// Panics if `data_blocks` is zero, `local_group_size` is zero,
    /// `data_blocks` is not divisible by `local_group_size`, or the
    /// GF(256) global parity limits would be exceeded.
    #[must_use]
    pub fn new(data_blocks: u32, local_group_size: u32, global_parity_count: u32) -> Self {
        assert!(data_blocks > 0, "data_blocks must be > 0");
        assert!(local_group_size > 0, "local_group_size must be > 0");
        assert!(
            data_blocks.is_multiple_of(local_group_size),
            "data_blocks ({data_blocks}) must be divisible by local_group_size ({local_group_size})"
        );
        assert!(
            global_parity_count <= 255,
            "global_parity_count must be <= 255 for GF(256)"
        );
        assert!(
            global_parity_count == 0 || data_blocks <= 255,
            "data_blocks must be <= 255 when global parity is enabled"
        );
        let local_parity_count = data_blocks / local_group_size;
        let total_blocks =
            u64::from(data_blocks) + u64::from(local_parity_count) + u64::from(global_parity_count);
        assert!(
            u32::try_from(total_blocks).is_ok(),
            "total LRC block count must fit in u32"
        );
        Self {
            data_blocks,
            local_group_size,
            global_parity_count,
        }
    }

    /// Number of local repair groups.
    #[must_use]
    pub fn num_groups(&self) -> u32 {
        if self.local_group_size == 0 {
            return 0;
        }
        self.data_blocks / self.local_group_size
    }

    /// Number of local parity blocks (one per group).
    #[must_use]
    pub fn local_parity_count(&self) -> u32 {
        self.num_groups()
    }

    /// Total number of blocks (data + local parity + global parity).
    #[must_use]
    pub fn total_blocks(&self) -> u32 {
        self.data_blocks
            .saturating_add(self.local_parity_count())
            .saturating_add(self.global_parity_count)
    }

    /// Total storage overhead as a fraction.
    #[must_use]
    pub fn overhead_fraction(&self) -> f64 {
        if self.data_blocks == 0 {
            return 0.0;
        }
        let parity = self
            .local_parity_count()
            .saturating_add(self.global_parity_count);
        f64::from(parity) / f64::from(self.data_blocks)
    }
}

// ── LRC codec ──────────────────────────────────────────────────────────────

/// Encode local parity blocks.
///
/// For each local group, the local parity is the XOR of all data blocks
/// in that group. Returns `g` parity blocks.
///
/// # Panics
///
/// Panics if `data.len() != config.data_blocks` or block sizes differ.
#[must_use]
pub fn encode_local(config: &LrcConfig, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert!(config.data_blocks > 0, "data_blocks must be > 0");
    assert!(config.local_group_size > 0, "local_group_size must be > 0");
    assert!(
        config.data_blocks.is_multiple_of(config.local_group_size),
        "data_blocks ({}) must be divisible by local_group_size ({})",
        config.data_blocks,
        config.local_group_size
    );
    assert_eq!(
        data.len(),
        config.data_blocks as usize,
        "expected {} data blocks, got {}",
        config.data_blocks,
        data.len()
    );

    let block_size = data[0].len();
    assert!(block_size > 0, "block size must be > 0");
    let groups = config.num_groups() as usize;
    let group_size = config.local_group_size as usize;

    // Each local group's parity is an independent XOR of its own disjoint span
    // of data blocks, so compute the groups in parallel across cores — the same
    // rayon treatment encode_global already uses for the global parity loop
    // (bd-blr6r sibling). Ordered collect preserves the per-group output order.
    let local_parities: Vec<Vec<u8>> = (0..groups)
        .into_par_iter()
        .map(|g| {
            let mut parity = vec![0_u8; block_size];
            for i in 0..group_size {
                let block = &data[g * group_size + i];
                assert_eq!(block.len(), block_size, "block size mismatch");
                xor_into(&mut parity, block);
            }
            parity
        })
        .collect();

    local_parities
}

/// Encode global parity blocks using Reed-Solomon in GF(256).
///
/// Global parity `P_j[byte] = sum_{i=0}^{k-1} alpha^{(i+1)*(j+1)} * data[i][byte]`
/// where `alpha = 0x03` is a primitive generator element.
///
/// Returns `p` global parity blocks.
///
/// # Panics
///
/// Panics if `config.global_parity_count > 255`, if global parity is
/// enabled for more than 255 data blocks, or if block sizes differ.
#[must_use]
pub fn encode_global(config: &LrcConfig, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert!(config.data_blocks > 0, "data_blocks must be > 0");
    assert_eq!(data.len(), config.data_blocks as usize);
    assert!(
        config.global_parity_count <= 255,
        "global parity count must fit in GF(256)"
    );
    assert!(
        config.global_parity_count == 0 || config.data_blocks <= 255,
        "global parity requires at most 255 data blocks"
    );

    let block_size = data[0].len();
    let p = config.global_parity_count as usize;

    if p > 0 {
        assert!(block_size > 0, "block size must be > 0");
        for block in data {
            assert_eq!(block.len(), block_size, "block size mismatch");
        }
    }

    (0..p)
        .into_par_iter()
        .map(|j| {
            let mut parity = vec![0_u8; block_size];
            let step = global_parity_row_step(j);
            let mut coeff = step;
            // as_chunks::<2>() yields the same pairs in the same order and the
            // same trailing remainder chunks_exact(2)/.remainder() did, so the
            // GF(256) coefficient chain below advances identically.
            let (block_pairs, remainder) = data.as_chunks::<2>();
            for pair in block_pairs {
                let lhs_coeff = coeff;
                coeff = gf256::mul(coeff, step);
                let rhs_coeff = coeff;
                gf256_mul_xor_pair_into(&mut parity, &pair[0], lhs_coeff, &pair[1], rhs_coeff);
                coeff = gf256::mul(coeff, step);
            }
            if let Some(block) = remainder.first() {
                gf256_mul_xor_into(&mut parity, block, coeff);
            }
            parity
        })
        .collect()
}

/// Full LRC encode: returns `(local_parities, global_parities)`.
#[must_use]
pub fn encode(config: &LrcConfig, data: &[Vec<u8>]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let local = encode_local(config, data);
    let global = encode_global(config, data);
    (local, global)
}

// ── Repair ─────────────────────────────────────────────────────────────────

/// Which blocks are available for repair.
#[derive(Debug, Clone)]
pub struct BlockAvailability {
    /// For each data block index, `Some(data)` if available, `None` if lost.
    pub data: Vec<Option<Vec<u8>>>,
    /// For each local parity block, `Some(data)` if available, `None` if lost.
    pub local_parity: Vec<Option<Vec<u8>>>,
    /// For each global parity block, `Some(data)` if available, `None` if lost.
    pub global_parity: Vec<Option<Vec<u8>>>,
}

/// Result of a repair attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairResult {
    /// Whether repair succeeded.
    pub success: bool,
    /// Number of blocks repaired.
    pub blocks_repaired: u32,
    /// Indices of blocks that were repaired.
    pub repaired_indices: Vec<u32>,
    /// Reconstructed block data, keyed by original index.
    pub recovered_data: BTreeMap<u32, Vec<u8>>,
    /// Whether local repair was sufficient.
    pub used_local_only: bool,
    /// Whether global repair was needed.
    pub used_global: bool,
}

/// Attempt local repair for a single missing data block.
///
/// If exactly one block in a local group is missing and the local parity
/// is available, XOR-recover the missing block.
///
/// Returns the repaired block data, or `None` if local repair is not possible.
#[must_use]
pub fn repair_local_single(
    config: &LrcConfig,
    group_idx: u32,
    missing_idx_in_group: u32,
    available_blocks: &[Option<&[u8]>],
    local_parity: &[u8],
) -> Option<Vec<u8>> {
    if config.data_blocks == 0
        || config.local_group_size == 0
        || !config.data_blocks.is_multiple_of(config.local_group_size)
    {
        return None;
    }

    let group_size = config.local_group_size as usize;
    if available_blocks.len() != group_size {
        return None;
    }

    let missing_idx = usize::try_from(missing_idx_in_group).ok()?;
    if missing_idx >= group_size || group_idx >= config.num_groups() {
        return None;
    }

    // Count missing blocks in this group.
    let missing_count = available_blocks.iter().filter(|b| b.is_none()).count();
    if missing_count != 1 {
        return None; // Local repair only works for single failures.
    }

    // Verify the missing index matches.
    if available_blocks[missing_idx].is_some() {
        return None; // The specified block isn't actually missing.
    }

    let block_size = local_parity.len();
    if block_size == 0 {
        return None;
    }

    if available_blocks
        .iter()
        .flatten()
        .any(|block| block.len() != block_size)
    {
        return None;
    }

    let mut recovered = local_parity.to_vec();

    // XOR all available blocks into the parity to isolate the missing block.
    for (i, block) in available_blocks.iter().enumerate() {
        if let Some(b) = block
            && i != missing_idx
        {
            xor_into(&mut recovered, b);
        }
    }

    Some(recovered)
}

/// Attempt repair using global parity (multi-failure recovery).
///
/// Uses Gaussian elimination in GF(256) to solve for missing blocks
/// when local repair is insufficient.
///
/// Supports up to `config.global_parity_count` simultaneous failures
/// across any combination of data blocks.
#[must_use]
#[expect(clippy::too_many_lines)]
pub fn repair_global(
    config: &LrcConfig,
    availability: &BlockAvailability,
    block_size: usize,
) -> RepairResult {
    let p = config.global_parity_count as usize;
    if block_size == 0
        || !config_supports_global_repair(config)
        || availability.data.len() != config.data_blocks as usize
        || availability
            .data
            .iter()
            .flatten()
            .any(|block| block.len() != block_size)
    {
        return failed_global_repair();
    }

    // Find missing data block indices.
    let missing: Vec<usize> = availability
        .data
        .iter()
        .enumerate()
        .filter_map(|(i, b)| if b.is_none() { Some(i) } else { None })
        .collect();

    if missing.is_empty() {
        return RepairResult {
            success: true,
            blocks_repaired: 0,
            repaired_indices: Vec::new(),
            recovered_data: BTreeMap::new(),
            used_local_only: false,
            used_global: false,
        };
    }

    if availability.global_parity.len() != p
        || availability
            .global_parity
            .iter()
            .flatten()
            .any(|block| block.len() != block_size)
    {
        return failed_global_repair();
    }

    if missing.len() > p {
        return failed_global_repair();
    }

    // Check we have enough global parity blocks.
    let available_global: Vec<(usize, &Vec<u8>)> = availability
        .global_parity
        .iter()
        .enumerate()
        .filter_map(|(i, b)| b.as_ref().map(|data| (i, data)))
        .collect();

    if available_global.len() < missing.len() {
        return failed_global_repair();
    }

    // Build the system of equations in GF(256).
    // For each global parity j that we have:
    //   P_j = sum_{i in known} coeff(i,j) * D_i + sum_{i in missing} coeff(i,j) * D_i
    //
    // Rearranging for unknown D_i:
    //   sum_{i in missing} coeff(i,j) * D_i = P_j - sum_{i in known} coeff(i,j) * D_i
    //
    // This gives us `missing.len()` equations in `missing.len()` unknowns.

    let m = missing.len();

    // Build coefficient matrix (m x m) and RHS vectors (one per byte position).
    let mut coeff_matrix = vec![vec![0_u8; m]; m];
    let mut rhs = vec![vec![0_u8; block_size]; m];

    for (eq_idx, &(parity_j, parity_data)) in available_global.iter().take(m).enumerate() {
        // Build coefficients for missing blocks.
        for (col, &missing_i) in missing.iter().enumerate() {
            coeff_matrix[eq_idx][col] = global_parity_coeff(missing_i, parity_j);
        }

        // RHS = P_j XOR sum_{known} coeff * D_known
        rhs[eq_idx].copy_from_slice(&parity_data[..block_size]);
        for (i, block_opt) in availability.data.iter().enumerate() {
            if let Some(block) = block_opt {
                let coeff = global_parity_coeff(i, parity_j);
                gf256_mul_xor_into(&mut rhs[eq_idx], block, coeff);
            }
        }
    }

    // Gaussian elimination in GF(256).
    // Process column by column.
    for col in 0..m {
        // Find pivot.
        let pivot_row = (col..m).find(|&row| coeff_matrix[row][col] != 0);
        let Some(pivot_row) = pivot_row else {
            // Singular matrix — cannot recover.
            return failed_global_repair();
        };

        // Swap rows.
        if pivot_row != col {
            coeff_matrix.swap(col, pivot_row);
            rhs.swap(col, pivot_row);
        }

        // Scale pivot row.
        let pivot_inv = gf256::inv(coeff_matrix[col][col]);
        for coeff in &mut coeff_matrix[col][..m] {
            *coeff = gf256::mul(*coeff, pivot_inv);
        }
        let pivot_mul = gf256::mul_row(pivot_inv);
        for byte in &mut rhs[col] {
            *byte = pivot_mul[*byte as usize];
        }

        // Eliminate other rows.
        for row in 0..m {
            if row == col {
                continue;
            }
            let factor = coeff_matrix[row][col];
            if factor == 0 {
                continue;
            }
            // Must index by c since we read coeff_matrix[col][c] while
            // writing coeff_matrix[row][c] — two different rows.
            #[expect(clippy::needless_range_loop)]
            for c in 0..m {
                coeff_matrix[row][c] ^= gf256::mul(coeff_matrix[col][c], factor);
            }
            // Same: reading rhs[col] while writing rhs[row].
            let factor_mul = gf256::mul_row(factor);
            for byte_idx in 0..block_size {
                rhs[row][byte_idx] ^= factor_mul[rhs[col][byte_idx] as usize];
            }
        }
    }

    // After elimination, rhs[i] contains the recovered block for missing[i].
    let mut recovered_data = BTreeMap::new();
    let mut repaired_indices = Vec::with_capacity(m);
    for (i, &idx) in missing.iter().enumerate() {
        let idx_u32 = u32::try_from(idx).unwrap_or(u32::MAX);
        repaired_indices.push(idx_u32);
        recovered_data.insert(idx_u32, std::mem::take(&mut rhs[i]));
    }

    RepairResult {
        success: true,
        #[expect(clippy::cast_possible_truncation)]
        blocks_repaired: m as u32,
        repaired_indices,
        recovered_data,
        used_local_only: false,
        used_global: true,
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn config_supports_global_repair(config: &LrcConfig) -> bool {
    config.data_blocks > 0
        && config.local_group_size > 0
        && config.data_blocks.is_multiple_of(config.local_group_size)
        && config.global_parity_count <= 255
        && (config.global_parity_count == 0 || config.data_blocks <= 255)
}

fn failed_global_repair() -> RepairResult {
    RepairResult {
        success: false,
        blocks_repaired: 0,
        repaired_indices: Vec::new(),
        recovered_data: BTreeMap::new(),
        used_local_only: false,
        used_global: true,
    }
}

fn global_parity_coeff(data_idx: usize, parity_idx: usize) -> u8 {
    let exponent = ((data_idx + 1) * (parity_idx + 1)) % 255;
    gf256::generator_pow(exponent)
}

fn global_parity_row_step(parity_idx: usize) -> u8 {
    gf256::generator_pow(parity_idx + 1)
}

/// XOR `src` into `dst` (byte-by-byte).
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
}

/// Compute `dst[i] ^= gf256_mul(src[i], coeff)` for each byte.
fn gf256_mul_xor_into(dst: &mut [u8], src: &[u8], coeff: u8) {
    if coeff == 0 {
        return;
    }
    if coeff == 1 {
        xor_into(dst, src);
        return;
    }
    let coeff_mul = gf256::mul_row(coeff);
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= coeff_mul[*s as usize];
    }
}

/// Compute two adjacent GF(256) projections into one destination pass.
fn gf256_mul_xor_pair_into(dst: &mut [u8], lhs: &[u8], lhs_coeff: u8, rhs: &[u8], rhs_coeff: u8) {
    debug_assert_eq!(dst.len(), lhs.len());
    debug_assert_eq!(lhs.len(), rhs.len());
    match (lhs_coeff, rhs_coeff) {
        (0, 0) => {}
        (0, coeff) => gf256_mul_xor_into(dst, rhs, coeff),
        (coeff, 0) => gf256_mul_xor_into(dst, lhs, coeff),
        (1, 1) => {
            for ((d, l), r) in dst.iter_mut().zip(lhs.iter()).zip(rhs.iter()) {
                *d ^= *l ^ *r;
            }
        }
        (1, coeff) => {
            let rhs_mul = gf256::mul_row(coeff);
            for ((d, l), r) in dst.iter_mut().zip(lhs.iter()).zip(rhs.iter()) {
                *d ^= *l ^ rhs_mul[*r as usize];
            }
        }
        (coeff, 1) => {
            let lhs_mul = gf256::mul_row(coeff);
            for ((d, l), r) in dst.iter_mut().zip(lhs.iter()).zip(rhs.iter()) {
                *d ^= lhs_mul[*l as usize] ^ *r;
            }
        }
        (lhs_coeff, rhs_coeff) => {
            let lhs_mul = gf256::mul_row(lhs_coeff);
            let rhs_mul = gf256::mul_row(rhs_coeff);
            for ((d, l), r) in dst.iter_mut().zip(lhs.iter()).zip(rhs.iter()) {
                *d ^= lhs_mul[*l as usize] ^ rhs_mul[*r as usize];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data(k: usize, block_size: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|i| {
                (0..block_size)
                    .map(|j| {
                        u8::try_from((i * 37 + j * 53) & 0xFF).expect("pattern byte fits in u8")
                    })
                    .collect()
            })
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    #[test]
    fn config_basics() {
        let cfg = LrcConfig::new(12, 4, 2);
        assert_eq!(cfg.num_groups(), 3);
        assert_eq!(cfg.local_parity_count(), 3);
        assert_eq!(cfg.total_blocks(), 17); // 12 + 3 + 2
        let overhead = cfg.overhead_fraction();
        assert!((overhead - 5.0 / 12.0).abs() < 0.001);
    }

    #[test]
    fn public_field_config_accessors_do_not_panic_on_invalid_values() {
        let zero_group = LrcConfig {
            data_blocks: 12,
            local_group_size: 0,
            global_parity_count: 2,
        };
        assert_eq!(zero_group.num_groups(), 0);
        assert_eq!(zero_group.local_parity_count(), 0);
        assert_eq!(zero_group.total_blocks(), 14);
        assert_eq!(zero_group.overhead_fraction(), 2.0 / 12.0);

        let zero_data = LrcConfig {
            data_blocks: 0,
            local_group_size: 4,
            global_parity_count: 2,
        };
        assert_eq!(zero_data.num_groups(), 0);
        assert_eq!(zero_data.local_parity_count(), 0);
        assert_eq!(zero_data.total_blocks(), 2);
        assert_eq!(zero_data.overhead_fraction(), 0.0);

        let saturated = LrcConfig {
            data_blocks: u32::MAX,
            local_group_size: 1,
            global_parity_count: 1,
        };
        assert_eq!(saturated.num_groups(), u32::MAX);
        assert_eq!(saturated.local_parity_count(), u32::MAX);
        assert_eq!(saturated.total_blocks(), u32::MAX);
        assert_eq!(saturated.overhead_fraction(), 1.0);
    }

    #[test]
    fn local_parity_xor_correct() {
        let cfg = LrcConfig::new(8, 4, 2);
        let data = make_data(8, 64);
        let local = encode_local(&cfg, &data);

        assert_eq!(local.len(), 2); // 2 groups

        // Verify: XOR of group 0 blocks == local parity 0.
        let mut expected = vec![0_u8; 64];
        for block in &data[0..4] {
            xor_into(&mut expected, block);
        }
        assert_eq!(local[0], expected);
    }

    #[test]
    fn local_repair_single_failure() {
        let cfg = LrcConfig::new(8, 4, 2);
        let data = make_data(8, 64);
        let local = encode_local(&cfg, &data);

        // Simulate losing block 2 (in group 0, position 2).
        let available: Vec<Option<&[u8]>> = vec![
            Some(&data[0]),
            Some(&data[1]),
            None, // block 2 is lost
            Some(&data[3]),
        ];

        let recovered = repair_local_single(&cfg, 0, 2, &available, &local[0]);
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap(), data[2]);
    }

    #[test]
    fn local_repair_fails_for_two_missing() {
        let cfg = LrcConfig::new(8, 4, 2);
        let data = make_data(8, 64);
        let local = encode_local(&cfg, &data);

        // Two blocks missing in the same group.
        let available: Vec<Option<&[u8]>> = vec![
            Some(&data[0]),
            None, // block 1 lost
            None, // block 2 lost
            Some(&data[3]),
        ];

        let recovered = repair_local_single(&cfg, 0, 1, &available, &local[0]);
        assert!(recovered.is_none());
    }

    #[test]
    fn local_repair_rejects_malformed_available_count_without_panic() {
        let cfg = LrcConfig::new(8, 4, 2);
        let data = make_data(8, 64);
        let local = encode_local(&cfg, &data);

        let short_available: Vec<Option<&[u8]>> = vec![Some(&data[0]), None, Some(&data[2])];
        let long_available: Vec<Option<&[u8]>> = vec![
            Some(&data[0]),
            Some(&data[1]),
            None,
            Some(&data[3]),
            Some(&data[4]),
        ];

        assert!(repair_local_single(&cfg, 0, 1, &short_available, &local[0]).is_none());
        assert!(repair_local_single(&cfg, 0, 2, &long_available, &local[0]).is_none());
    }

    #[test]
    fn local_repair_rejects_block_size_mismatch_without_panic() {
        let cfg = LrcConfig::new(8, 4, 2);
        let data = make_data(8, 64);
        let local = encode_local(&cfg, &data);
        let short_block = data[1][..63].to_vec();

        let available: Vec<Option<&[u8]>> = vec![
            Some(&data[0]),
            Some(short_block.as_slice()),
            None,
            Some(&data[3]),
        ];

        assert!(repair_local_single(&cfg, 0, 2, &available, &local[0]).is_none());
        assert!(repair_local_single(&cfg, 0, 2, &available, &local[0][..63]).is_none());
    }

    #[test]
    fn local_repair_rejects_zero_block_size_without_empty_recovery() {
        let cfg = LrcConfig::new(4, 2, 1);
        let empty = [];
        let available: Vec<Option<&[u8]>> = vec![None, Some(empty.as_slice())];

        assert!(repair_local_single(&cfg, 0, 0, &available, &[]).is_none());
    }

    #[test]
    fn global_encode_decode_single_failure() {
        let cfg = LrcConfig::new(4, 2, 2);
        let data = make_data(4, 32);
        let global = encode_global(&cfg, &data);

        assert_eq!(global.len(), 2);

        // Lose block 1.
        let availability = BlockAvailability {
            data: vec![
                Some(data[0].clone()),
                None, // lost
                Some(data[2].clone()),
                Some(data[3].clone()),
            ],
            local_parity: vec![],
            global_parity: global.iter().map(|p| Some(p.clone())).collect(),
        };

        let result = repair_global(&cfg, &availability, 32);
        assert!(result.success);
        assert_eq!(result.blocks_repaired, 1);
        assert_eq!(result.repaired_indices, vec![1]);
        assert_eq!(result.recovered_data.get(&1), Some(&data[1]));
        assert!(result.used_global);
    }

    #[test]
    fn config_supports_global_repair_enforces_gf256_and_divisibility() {
        // A valid config supports global repair.
        assert!(config_supports_global_repair(&LrcConfig::new(12, 4, 2)));

        // Build invalid configs via the public fields (LrcConfig::new would panic).
        let cfg = |d, g, p| LrcConfig {
            data_blocks: d,
            local_group_size: g,
            global_parity_count: p,
        };
        // Zero data blocks / zero group size are invalid.
        assert!(!config_supports_global_repair(&cfg(0, 4, 2)));
        assert!(!config_supports_global_repair(&cfg(12, 0, 2)));
        // data_blocks must divide evenly into local groups.
        assert!(!config_supports_global_repair(&cfg(10, 4, 2)));
        // A global parity count beyond GF(256) is invalid.
        assert!(!config_supports_global_repair(&cfg(12, 4, 256)));
        // With global parity, data_blocks must fit GF(256) (<= 255).
        assert!(!config_supports_global_repair(&cfg(256, 4, 2)));
        // Without global parity the GF(256) data limit does not apply.
        assert!(config_supports_global_repair(&cfg(256, 4, 0)));
    }

    #[test]
    fn global_repair_two_failures() {
        let cfg = LrcConfig::new(4, 2, 2);
        let data = make_data(4, 32);
        let global = encode_global(&cfg, &data);

        // Lose blocks 0 and 3.
        let availability = BlockAvailability {
            data: vec![
                None, // lost
                Some(data[1].clone()),
                Some(data[2].clone()),
                None, // lost
            ],
            local_parity: vec![],
            global_parity: global.iter().map(|p| Some(p.clone())).collect(),
        };

        let result = repair_global(&cfg, &availability, 32);
        assert!(result.success);
        assert_eq!(result.blocks_repaired, 2);
    }

    #[test]
    fn global_repair_handles_columns_separated_by_51() {
        let cfg = LrcConfig::new(104, 4, 2);
        let data = make_data(104, 32);
        let global = encode_global(&cfg, &data);

        let mut available_data: Vec<Option<Vec<u8>>> =
            data.iter().map(|block| Some(block.clone())).collect();
        available_data[0] = None;
        available_data[51] = None;

        let availability = BlockAvailability {
            data: available_data,
            local_parity: vec![],
            global_parity: global.iter().map(|p| Some(p.clone())).collect(),
        };

        let result = repair_global(&cfg, &availability, 32);
        assert!(
            result.success,
            "global repair should not become singular for 51-apart columns"
        );
        assert_eq!(result.blocks_repaired, 2);
        assert_eq!(result.recovered_data.get(&0), Some(&data[0]));
        assert_eq!(result.recovered_data.get(&51), Some(&data[51]));
    }

    #[test]
    fn global_repair_exceeds_capacity() {
        let cfg = LrcConfig::new(4, 2, 1);
        let data = make_data(4, 32);
        let global = encode_global(&cfg, &data);

        // 2 failures but only 1 global parity → cannot repair.
        let availability = BlockAvailability {
            data: vec![None, None, Some(data[2].clone()), Some(data[3].clone())],
            local_parity: vec![],
            global_parity: global.iter().map(|p| Some(p.clone())).collect(),
        };

        let result = repair_global(&cfg, &availability, 32);
        assert!(!result.success);
    }

    #[test]
    fn global_repair_rejects_zero_block_size_without_empty_recovery() {
        let cfg = LrcConfig::new(4, 2, 1);
        let availability = BlockAvailability {
            data: vec![None, Some(Vec::new()), Some(Vec::new()), Some(Vec::new())],
            local_parity: vec![],
            global_parity: vec![Some(Vec::new())],
        };

        let result = repair_global(&cfg, &availability, 0);

        assert!(!result.success);
        assert_eq!(result.blocks_repaired, 0);
        assert!(result.recovered_data.is_empty());
    }

    #[test]
    fn full_encode_local_plus_global() {
        let cfg = LrcConfig::new(12, 4, 2);
        let data = make_data(12, 128);
        let (local, global) = encode(&cfg, &data);

        assert_eq!(local.len(), 3);
        assert_eq!(global.len(), 2);
    }

    #[test]
    fn local_repair_all_groups() {
        let cfg = LrcConfig::new(12, 4, 2);
        let data = make_data(12, 64);
        let local = encode_local(&cfg, &data);

        // Test local repair in each group.
        for (group, local_parity) in local.iter().enumerate() {
            let base = group * 4;
            for missing in 0..4 {
                let available: Vec<Option<&[u8]>> = (0..4)
                    .map(|i| {
                        if i == missing {
                            None
                        } else {
                            Some(data[base + i].as_slice())
                        }
                    })
                    .collect();

                let group_u32 = u32::try_from(group).expect("group index fits in u32");
                let missing_u32 = u32::try_from(missing).expect("missing index fits in u32");
                let recovered =
                    repair_local_single(&cfg, group_u32, missing_u32, &available, local_parity);
                assert_eq!(
                    recovered.as_ref(),
                    Some(&data[base + missing]),
                    "failed to repair group {group} block {missing}"
                );
            }
        }
    }

    #[test]
    fn repair_io_comparison() {
        // LRC with local groups of 4 should read 3 blocks + 1 parity = 4 blocks
        // for single-failure repair, vs 12+ for full erasure coding.
        let cfg = LrcConfig::new(12, 4, 2);

        // Local repair reads: group_size - 1 + 1 (parity) = group_size blocks.
        let local_io = cfg.local_group_size;
        // Global repair reads: all remaining data blocks + parity blocks.
        let global_io = cfg.data_blocks - 1 + cfg.global_parity_count;

        assert_eq!(local_io, 4);
        assert_eq!(global_io, 13); // 11 data + 2 global parity
        assert!(
            local_io < global_io / 2,
            "local repair IO ({local_io}) should be much less than global ({global_io})"
        );
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = LrcConfig::new(12, 4, 2);
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: LrcConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, cfg);
    }

    // ── Edge-case hardening tests ──────────────────────────────────────

    #[test]
    fn lrc_config_num_groups_and_total() {
        let cfg = LrcConfig::new(20, 5, 3);
        assert_eq!(cfg.num_groups(), 4);
        assert_eq!(cfg.local_parity_count(), 4);
        assert_eq!(cfg.total_blocks(), 20 + 4 + 3); // 27
    }

    #[test]
    fn lrc_config_overhead_fraction_correct() {
        let cfg = LrcConfig::new(12, 4, 2);
        // 3 local + 2 global = 5 parity / 12 data ≈ 0.4167
        let overhead = cfg.overhead_fraction();
        assert!((overhead - 5.0 / 12.0).abs() < 1e-10);
    }

    #[test]
    fn lrc_config_minimum_viable() {
        // Smallest valid config: 2 data blocks, group size 2, 1 global parity
        let cfg = LrcConfig::new(2, 2, 1);
        assert_eq!(cfg.num_groups(), 1);
        assert_eq!(cfg.total_blocks(), 4); // 2 data + 1 local + 1 global
    }

    #[test]
    #[should_panic(expected = "local_group_size must be > 0")]
    fn lrc_config_rejects_zero_group_size() {
        let _ = LrcConfig::new(4, 0, 1);
    }

    #[test]
    #[should_panic(expected = "data_blocks must be > 0")]
    fn lrc_config_rejects_zero_data_blocks() {
        let _ = LrcConfig::new(0, 4, 1);
    }

    #[test]
    #[should_panic(expected = "must be divisible by")]
    fn lrc_config_rejects_indivisible() {
        let _ = LrcConfig::new(7, 3, 1);
    }

    #[test]
    #[should_panic(expected = "data_blocks must be <= 255")]
    fn lrc_config_rejects_too_many_global_data_columns() {
        let _ = LrcConfig::new(256, 4, 1);
    }

    #[test]
    fn lrc_config_clone_and_copy() {
        let cfg = LrcConfig::new(8, 4, 2);
        let cfg2 = cfg; // Copy
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn gf256_mul_associative_spot_check() {
        // (a * b) * c == a * (b * c) for a few triples
        for (a, b, c) in [(3_u8, 7, 11), (42, 99, 200), (255, 128, 1)] {
            let left = gf256::mul(gf256::mul(a, b), c);
            let right = gf256::mul(a, gf256::mul(b, c));
            assert_eq!(left, right, "associativity failed for ({a}, {b}, {c})");
        }
    }

    #[test]
    #[should_panic(expected = "inverse of zero")]
    fn gf256_inv_zero_panics() {
        let _ = gf256::inv(0);
    }

    #[test]
    fn gf256_mul_self_inverse() {
        // a * inv(a) == 1 for a few specific values
        for a in [1_u8, 2, 127, 128, 254, 255] {
            assert_eq!(
                gf256::mul(a, gf256::inv(a)),
                1,
                "self-inverse failed for {a}"
            );
        }
    }

    #[test]
    fn encode_local_produces_correct_count() {
        let cfg = LrcConfig::new(8, 4, 1);
        let data = make_data(8, 16);
        let local = encode_local(&cfg, &data);
        assert_eq!(local.len(), 2); // 8/4 = 2 groups
    }

    #[test]
    fn encode_global_produces_correct_count() {
        let cfg = LrcConfig::new(8, 4, 2);
        let data = make_data(8, 16);
        let global = encode_global(&cfg, &data);
        assert_eq!(global.len(), 2);
    }

    #[test]
    fn encode_global_zero_parity_preserves_no_extra_block_size_validation() {
        let cfg = LrcConfig::new(4, 2, 0);
        let mut data = make_data(4, 16);
        data[2].truncate(8);
        let global = encode_global(&cfg, &data);
        assert!(global.is_empty());
    }

    #[test]
    #[should_panic(expected = "block size must be > 0")]
    fn encode_local_rejects_zero_block_size() {
        let cfg = LrcConfig::new(4, 2, 1);
        let data = vec![Vec::new(); 4];

        let _ = encode_local(&cfg, &data);
    }

    #[test]
    #[should_panic(expected = "block size must be > 0")]
    fn encode_global_rejects_zero_block_size_when_parity_emitted() {
        let cfg = LrcConfig::new(4, 2, 1);
        let data = vec![Vec::new(); 4];

        let _ = encode_global(&cfg, &data);
    }

    #[test]
    fn global_parity_coefficient_recurrence_matches_formula() {
        for parity_idx in 0..255 {
            let step = global_parity_row_step(parity_idx);
            let mut coeff = step;
            for data_idx in 0..255 {
                assert_eq!(
                    coeff,
                    global_parity_coeff(data_idx, parity_idx),
                    "data_idx={data_idx}, parity_idx={parity_idx}"
                );
                coeff = gf256::mul(coeff, step);
            }
        }
    }

    #[test]
    fn gf256_mul_xor_pair_matches_separate_passes() {
        const COEFFS: [u8; 6] = [0, 1, 2, 17, 128, 255];
        const LENS: [usize; 7] = [0, 1, 7, 8, 31, 96, 4096];

        for len in LENS {
            let mut dst = vec![0_u8; len];
            let lhs: Vec<u8> = (0..len)
                .map(|idx| u8::try_from((idx * 29 + 11) & 0xff).expect("pattern fits in u8"))
                .collect();
            let rhs: Vec<u8> = (0..len)
                .map(|idx| u8::try_from((idx * 43 + 7) & 0xff).expect("pattern fits in u8"))
                .collect();
            for (idx, byte) in dst.iter_mut().enumerate() {
                *byte = u8::try_from((idx * 19 + 5) & 0xff).expect("pattern fits in u8");
            }

            for lhs_coeff in COEFFS {
                for rhs_coeff in COEFFS {
                    let mut separate = dst.clone();
                    gf256_mul_xor_into(&mut separate, &lhs, lhs_coeff);
                    gf256_mul_xor_into(&mut separate, &rhs, rhs_coeff);

                    let mut fused = dst.clone();
                    gf256_mul_xor_pair_into(&mut fused, &lhs, lhs_coeff, &rhs, rhs_coeff);

                    assert_eq!(
                        fused, separate,
                        "len={len} lhs_coeff={lhs_coeff} rhs_coeff={rhs_coeff}"
                    );
                }
            }
        }
    }

    #[test]
    fn lrc_global_parity_golden_report() {
        let cfg = LrcConfig::new(16, 4, 4);
        let data = make_data(16, 96);
        let global = encode_global(&cfg, &data);

        assert_eq!(global.len(), cfg.global_parity_count as usize);
        assert!(global.iter().all(|block| block.len() == 96));

        println!("LRC_GLOBAL_PARITY_GOLDEN_BEGIN");
        println!(
            "config data_blocks={} local_group_size={} global_parity_count={} block_size=96",
            cfg.data_blocks, cfg.local_group_size, cfg.global_parity_count
        );
        for (idx, parity) in global.iter().enumerate() {
            println!("parity[{idx}]={}", hex_encode(parity));
        }
        println!("LRC_GLOBAL_PARITY_GOLDEN_END");
    }

    #[test]
    #[should_panic(expected = "block size mismatch")]
    fn encode_global_rejects_mismatched_block_sizes() {
        let cfg = LrcConfig::new(4, 2, 1);
        let mut data = make_data(4, 16);
        data[2].truncate(8);
        let _ = encode_global(&cfg, &data);
    }

    #[test]
    fn local_repair_invalid_group_or_missing_index_returns_none() {
        let cfg = LrcConfig::new(4, 2, 1);
        let data = make_data(4, 16);
        let local = encode_local(&cfg, &data);
        let available: Vec<Option<&[u8]>> = vec![Some(&data[0]), None];

        assert_eq!(repair_local_single(&cfg, 0, 2, &available, &local[0]), None);
        assert_eq!(repair_local_single(&cfg, 2, 1, &available, &local[0]), None);
    }

    #[test]
    fn global_repair_rejects_mismatched_parity_size_without_panic() {
        let cfg = LrcConfig::new(4, 2, 1);
        let data = make_data(4, 16);
        let availability = BlockAvailability {
            data: vec![
                None,
                Some(data[1].clone()),
                Some(data[2].clone()),
                Some(data[3].clone()),
            ],
            local_parity: vec![],
            global_parity: vec![Some(vec![0_u8; 8])],
        };

        let result = repair_global(&cfg, &availability, 16);
        assert!(!result.success);
        assert!(result.used_global);
    }

    #[test]
    fn local_parity_is_xor_of_group() {
        let cfg = LrcConfig::new(4, 2, 1);
        let data = vec![
            vec![0xAA_u8; 8],
            vec![0x55_u8; 8],
            vec![0xFF; 8],
            vec![0x00; 8],
        ];
        let local = encode_local(&cfg, &data);
        // Group 0: 0xAA ^ 0x55 = 0xFF
        assert_eq!(local[0], vec![0xFF; 8]);
        // Group 1: 0xFF ^ 0x00 = 0xFF
        assert_eq!(local[1], vec![0xFF; 8]);
    }

    // ── Property-based tests (proptest) ────────────────────────────────

    use proptest::prelude::*;

    fn valid_lrc_config_strategy() -> impl Strategy<Value = (u32, u32, u32)> {
        // group_size in {2, 4}, num_groups in {2..6}, global_parity in {1, 2}
        (
            prop::sample::select(vec![2_u32, 4]),
            2_u32..6,
            prop::sample::select(vec![1_u32, 2]),
        )
            .prop_map(|(group_size, num_groups, global_parity)| {
                let data_blocks = group_size * num_groups;
                (data_blocks, group_size, global_parity)
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// XOR of local group data always equals local parity.
        #[test]
        fn proptest_local_parity_xor_identity(
            (data_blocks, group_size, global_parity) in valid_lrc_config_strategy(),
            fill_byte in any::<u8>(),
        ) {
            let cfg = LrcConfig::new(data_blocks, group_size, global_parity);
            let block_size = 32_usize;
            let data: Vec<Vec<u8>> = (0..data_blocks as usize)
                .map(|i| {
                    vec![fill_byte.wrapping_add(u8::try_from(i % 256).unwrap()); block_size]
                })
                .collect();

            let local = encode_local(&cfg, &data);
            prop_assert_eq!(local.len(), cfg.num_groups() as usize);

            for (g, local_parity) in local
                .iter()
                .enumerate()
                .take(cfg.num_groups() as usize)
            {
                let base = g * group_size as usize;
                let mut expected = vec![0_u8; block_size];
                for i in 0..group_size as usize {
                    xor_into(&mut expected, &data[base + i]);
                }
                prop_assert_eq!(local_parity, &expected, "group {} parity mismatch", g);
            }
        }

        /// Local repair recovers any single lost block within any group.
        #[test]
        fn proptest_local_repair_single_block(
            (data_blocks, group_size, global_parity) in valid_lrc_config_strategy(),
            fill_byte in any::<u8>(),
            group_selector in 0_u32..6,
            missing_selector in 0_u32..4,
        ) {
            let cfg = LrcConfig::new(data_blocks, group_size, global_parity);
            let num_groups = cfg.num_groups();
            let group_idx = group_selector % num_groups;
            let missing_in_group = missing_selector % group_size;

            let block_size = 32_usize;
            let data: Vec<Vec<u8>> = (0..data_blocks as usize)
                .map(|i| {
                    (0..block_size)
                        .map(|j| fill_byte.wrapping_add(u8::try_from((i + j) % 256).unwrap()))
                        .collect()
                })
                .collect();

            let local = encode_local(&cfg, &data);
            let base = group_idx as usize * group_size as usize;

            let available: Vec<Option<&[u8]>> = (0..group_size as usize)
                .map(|i| {
                    if i == missing_in_group as usize {
                        None
                    } else {
                        Some(data[base + i].as_slice())
                    }
                })
                .collect();

            let recovered = repair_local_single(
                &cfg,
                group_idx,
                missing_in_group,
                &available,
                &local[group_idx as usize],
            );

            prop_assert!(recovered.is_some(), "local repair should succeed for single failure");
            prop_assert_eq!(
                &recovered.unwrap(),
                &data[base + missing_in_group as usize],
                "recovered block mismatch"
            );
        }

        /// Config total_blocks = data + local_parity + global_parity.
        #[test]
        fn proptest_config_total_blocks(
            (data_blocks, group_size, global_parity) in valid_lrc_config_strategy(),
        ) {
            let cfg = LrcConfig::new(data_blocks, group_size, global_parity);
            let num_groups = cfg.num_groups();
            prop_assert_eq!(
                cfg.total_blocks(),
                data_blocks + num_groups + global_parity
            );
            prop_assert_eq!(num_groups * group_size, data_blocks);
        }

        /// Global repair succeeds for up to global_parity_count failures.
        #[test]
        fn proptest_global_repair_within_budget(
            (data_blocks, group_size, global_parity) in valid_lrc_config_strategy(),
            fill_byte in any::<u8>(),
            failure_selector in 0_u32..20,
        ) {
            let cfg = LrcConfig::new(data_blocks, group_size, global_parity);
            let num_failures = (failure_selector % global_parity).saturating_add(1)
                .min(data_blocks);

            let block_size = 32_usize;
            let data: Vec<Vec<u8>> = (0..data_blocks as usize)
                .map(|i| {
                    (0..block_size)
                        .map(|j| fill_byte.wrapping_add(u8::try_from((i * 7 + j * 3) % 256).unwrap()))
                        .collect()
                })
                .collect();

            let global = encode_global(&cfg, &data);

            // Lose the first num_failures blocks.
            let mut data_availability: Vec<Option<Vec<u8>>> = data
                .iter()
                .map(|b| Some(b.clone()))
                .collect();
            for block in data_availability.iter_mut().take(num_failures as usize) {
                *block = None;
            }

            let availability = BlockAvailability {
                data: data_availability,
                local_parity: vec![],
                global_parity: global.iter().map(|p| Some(p.clone())).collect(),
            };

            let result = repair_global(&cfg, &availability, block_size);
            prop_assert!(
                result.success,
                "global repair should succeed with {} failures and {} global parities",
                num_failures,
                global_parity,
            );
            prop_assert_eq!(result.blocks_repaired, num_failures);
        }

        /// Overhead fraction is always positive and <= 1.0 for sensible configs.
        #[test]
        fn proptest_overhead_fraction_bounded(
            (data_blocks, group_size, global_parity) in valid_lrc_config_strategy(),
        ) {
            let cfg = LrcConfig::new(data_blocks, group_size, global_parity);
            let overhead = cfg.overhead_fraction();
            prop_assert!(overhead > 0.0);
            prop_assert!(overhead <= 1.0);
        }

        /// LrcConfig serialization roundtrip.
        #[test]
        fn proptest_config_serde_roundtrip(
            (data_blocks, group_size, global_parity) in valid_lrc_config_strategy(),
        ) {
            let cfg = LrcConfig::new(data_blocks, group_size, global_parity);
            let json = serde_json::to_string(&cfg).expect("serialize");
            let parsed: LrcConfig = serde_json::from_str(&json).expect("deserialize");
            prop_assert_eq!(parsed, cfg);
        }
    }

    #[test]
    fn no_failures_returns_trivial_success() {
        let cfg = LrcConfig::new(4, 2, 2);
        let data = make_data(4, 32);
        let global = encode_global(&cfg, &data);

        let availability = BlockAvailability {
            data: data.iter().map(|b| Some(b.clone())).collect(),
            local_parity: vec![],
            global_parity: global.iter().map(|p| Some(p.clone())).collect(),
        };

        let result = repair_global(&cfg, &availability, 32);
        assert!(result.success);
        assert_eq!(result.blocks_repaired, 0);
        assert!(!result.used_global);
    }

    #[test]
    fn no_failures_do_not_require_available_global_parity() {
        let cfg = LrcConfig::new(4, 2, 2);
        let data = make_data(4, 32);
        let availability = BlockAvailability {
            data: data.iter().map(|b| Some(b.clone())).collect(),
            local_parity: vec![],
            global_parity: vec![],
        };

        let result = repair_global(&cfg, &availability, 32);
        assert!(result.success);
        assert_eq!(result.blocks_repaired, 0);
        assert!(!result.used_global);
    }
}
