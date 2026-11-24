//! OpenZFS 2.4.0 dRAID static seed table and `xoroshiro128++` Fisher-Yates
//! permutation table generator.
//!
//! Contract: OpenZFS `zfs-2.4.0` `module/zfs/vdev_draid.c` (`draid_maps[]`,
//! `vdev_draid_generate_perms`, `verify_perms`) and `module/zfs/vdev_draid_rand.c`.
//! Every generated table is verified against OpenZFS's own `fletcher4_varsize_le`
//! checksum (`dm_checksum`) and row-by-row bijection invariant.

use super::super::invalid;
use super::super::send_stream::fletcher4_varsize_le;
use ffs_types::ParseError;

/// Fixed high 64-bit PRNG state word (`VDEV_DRAID_SEED`).
pub const VDEV_DRAID_SEED: u64 = 0x0000_000d_7a1d_5eed;

/// Minimum dRAID child count supported by OpenZFS.
pub const VDEV_DRAID_MIN_CHILDREN: usize = 2;

/// Maximum dRAID child count supported by OpenZFS.
pub const VDEV_DRAID_MAX_CHILDREN: usize = 255;

/// Static OpenZFS dRAID permutation map definition (`draid_map_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DraidMapSeed {
    pub children: u8,
    pub nperms: u16,
    pub seed: u64,
    pub checksum: u64,
}

/// Generated and checksum-verified dRAID permutation matrix (`nperms × children`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraidPermTable {
    pub children: usize,
    pub nperms: usize,
    pub perms: Vec<u8>,
}

impl DraidPermTable {
    /// Look up `(base_row, iter)` for permutation index `pindex`
    /// (`vdev_draid_get_perm`).
    #[must_use]
    pub fn row_and_iter(&self, pindex: u64) -> (&[u8], usize) {
        let ncols = self.children as u64;
        let cycle = (self.nperms as u64) * ncols;
        let poff = pindex % cycle;
        let row = (poff / ncols) as usize;
        let iter = (poff % ncols) as usize;
        let start = row * self.children;
        (&self.perms[start..start + self.children], iter)
    }

    /// Permute logical column `index` using `(base_row, iter)`
    /// (`vdev_draid_permute_id`).
    #[must_use]
    pub fn permute_id(&self, base_row: &[u8], iter: usize, index: usize) -> usize {
        (usize::from(base_row[index]) + iter) % self.children
    }
}

/// Exact OpenZFS `vdev_draid_rand` (`xoroshiro128++` 1.0).
#[inline]
const fn vdev_draid_rand(state: &mut [u64; 2]) -> u64 {
    let s0 = state[0];
    let mut s1 = state[1];
    let result = s0.wrapping_add(s1).rotate_left(17).wrapping_add(s0);

    s1 ^= s0;
    state[0] = s0.rotate_left(49) ^ s1 ^ (s1 << 21);
    state[1] = s1.rotate_left(28);
    result
}

/// Look up the static OpenZFS 2.4.0 seed descriptor for `children` (`2..=255`).
#[must_use]
pub fn lookup_draid_seed(children: usize) -> Option<DraidMapSeed> {
    if !(VDEV_DRAID_MIN_CHILDREN..=VDEV_DRAID_MAX_CHILDREN).contains(&children) {
        return None;
    }
    let seed = DRAID_MAPS[children - VDEV_DRAID_MIN_CHILDREN];
    debug_assert_eq!(usize::from(seed.children), children);
    Some(seed)
}

/// Generate and checksum-verify the OpenZFS 2.4.0 dRAID permutation table for
/// `children` (`2..=255`).
pub fn generate_draid_perms(children: usize) -> Result<DraidPermTable, ParseError> {
    let entry = lookup_draid_seed(children)
        .ok_or_else(|| invalid("dRAID child count must be between 2 and 255"))?;
    let nperms = usize::from(entry.nperms);
    let total = children
        .checked_mul(nperms)
        .ok_or_else(|| invalid("dRAID permutation table size overflow"))?;
    let mut perms = vec![0_u8; total];
    let mut prev_row: Vec<u8> = (0..children)
        .map(|i| u8::try_from(i).expect("children <= 255"))
        .collect();
    let mut prng = [VDEV_DRAID_SEED, entry.seed];

    for row in 0..nperms {
        let start = row * children;
        let current = &mut perms[start..start + children];
        current.copy_from_slice(&prev_row);
        for j in (1..children).rev() {
            let k = (vdev_draid_rand(&mut prng) % (j as u64 + 1)) as usize;
            current.swap(j, k);
        }
        prev_row.copy_from_slice(current);
    }

    verify_draid_perms(&perms, children, nperms, entry.checksum)?;
    Ok(DraidPermTable {
        children,
        nperms,
        perms,
    })
}

fn verify_draid_perms(
    perms: &[u8],
    children: usize,
    nperms: usize,
    expected_checksum: u64,
) -> Result<(), ParseError> {
    let mut counts = vec![0_u16; children];
    for row in 0..nperms {
        let base = row * children;
        for col in 0..children {
            let val = usize::from(perms[base + col]);
            if val >= children || usize::from(counts[val]) != row {
                return Err(invalid(
                    "generated dRAID permutation row is not a bijection",
                ));
            }
            counts[val] = counts[val]
                .checked_add(1)
                .ok_or_else(|| invalid("dRAID permutation count overflow"))?;
        }
    }
    let cksum = fletcher4_varsize_le(perms);
    if cksum[0] != expected_checksum {
        return Err(invalid("generated dRAID permutation checksum mismatch"));
    }
    Ok(())
}

/// Complete OpenZFS `zfs-2.4.0` `draid_maps[254]` table (`children = 2..=255`).
pub const DRAID_MAPS: [DraidMapSeed; 254] = [
    DraidMapSeed {
        children: 2,
        nperms: 256,
        seed: 0x89ef_3dab_bcc7_de37,
        checksum: 0x0000_0000_433d_433d,
    },
    DraidMapSeed {
        children: 3,
        nperms: 256,
        seed: 0x89a5_7f3d_e981_21b4,
        checksum: 0x0000_0000_bcd8_b7b5,
    },
    DraidMapSeed {
        children: 4,
        nperms: 256,
        seed: 0xc9ea_9ec8_2340_c885,
        checksum: 0x0000_0001_819d_7c69,
    },
    DraidMapSeed {
        children: 5,
        nperms: 256,
        seed: 0xf467_33b7_f4d4_7dfd,
        checksum: 0x0000_0002_a164_8d74,
    },
    DraidMapSeed {
        children: 6,
        nperms: 256,
        seed: 0x88c3_c62d_8585_b362,
        checksum: 0x0000_0003_d3b0_c2c4,
    },
    DraidMapSeed {
        children: 7,
        nperms: 256,
        seed: 0x3a65_d809_b4d1_b9d5,
        checksum: 0x0000_0005_5c41_83ee,
    },
    DraidMapSeed {
        children: 8,
        nperms: 256,
        seed: 0xe989_30e3_c5d2_e90a,
        checksum: 0x0000_0006_edfb_0329,
    },
    DraidMapSeed {
        children: 9,
        nperms: 256,
        seed: 0x5a54_3003_6b98_2ccb,
        checksum: 0x0000_0008_ceaf_6934,
    },
    DraidMapSeed {
        children: 10,
        nperms: 256,
        seed: 0x92bf_389e_9ead_ac74,
        checksum: 0x0000_000b_2666_8c09,
    },
    DraidMapSeed {
        children: 11,
        nperms: 256,
        seed: 0x74cc_ebf1_dcf3_ae80,
        checksum: 0x0000_000d_d691_358c,
    },
    DraidMapSeed {
        children: 12,
        nperms: 256,
        seed: 0x8847_e41a_1a9f_5671,
        checksum: 0x0000_0010_a0c6_3c8e,
    },
    DraidMapSeed {
        children: 13,
        nperms: 256,
        seed: 0x7481_b56d_ebf0_e637,
        checksum: 0x0000_0014_2412_1fe4,
    },
    DraidMapSeed {
        children: 14,
        nperms: 256,
        seed: 0x559b_8c44_065f_8967,
        checksum: 0x0000_0016_ab2f_f079,
    },
    DraidMapSeed {
        children: 15,
        nperms: 256,
        seed: 0x34c4_9545_a2ee_7f01,
        checksum: 0x0000_001a_6028_efd6,
    },
    DraidMapSeed {
        children: 16,
        nperms: 256,
        seed: 0xb85f_4fa8_1a76_98f7,
        checksum: 0x0000_001e_95ff_5e66,
    },
    DraidMapSeed {
        children: 17,
        nperms: 256,
        seed: 0x6353_e47b_7e47_aba0,
        checksum: 0x0000_0021_a81f_a0fe,
    },
    DraidMapSeed {
        children: 18,
        nperms: 256,
        seed: 0xaa54_9746_b1cb_b81c,
        checksum: 0x0000_0026_f024_94c9,
    },
    DraidMapSeed {
        children: 19,
        nperms: 256,
        seed: 0x892e_343f_2f31_d690,
        checksum: 0x0000_0029_eb39_2835,
    },
    DraidMapSeed {
        children: 20,
        nperms: 256,
        seed: 0x7691_4824_db98_cc3f,
        checksum: 0x0000_0030_04f3_1a7c,
    },
    DraidMapSeed {
        children: 21,
        nperms: 256,
        seed: 0x4b3c_babf_9cfb_1d0f,
        checksum: 0x0000_0036_363a_2408,
    },
    DraidMapSeed {
        children: 22,
        nperms: 256,
        seed: 0xf45c_77ab_b4f0_35d4,
        checksum: 0x0000_0038_dd0f_3e84,
    },
    DraidMapSeed {
        children: 23,
        nperms: 256,
        seed: 0x5e18_bd7f_3fd4_baf4,
        checksum: 0x0000_003f_0660_391f,
    },
    DraidMapSeed {
        children: 24,
        nperms: 256,
        seed: 0xa7b3_a4d2_85d6_503b,
        checksum: 0x0000_0044_3dfc_9ff6,
    },
    DraidMapSeed {
        children: 25,
        nperms: 256,
        seed: 0x56ac_7dd9_6752_1f5a,
        checksum: 0x0000_004b_03a8_7eb7,
    },
    DraidMapSeed {
        children: 26,
        nperms: 256,
        seed: 0x3a42_dfda_4eb8_80f7,
        checksum: 0x0000_0052_2c71_9bba,
    },
    DraidMapSeed {
        children: 27,
        nperms: 256,
        seed: 0xd200_d2fc_6b54_bf60,
        checksum: 0x0000_0057_60b4_fdf5,
    },
    DraidMapSeed {
        children: 28,
        nperms: 256,
        seed: 0xc526_05bb_d486_c546,
        checksum: 0x0000_005e_00d8_f74c,
    },
    DraidMapSeed {
        children: 29,
        nperms: 256,
        seed: 0xc761_779e_63cd_762f,
        checksum: 0x0000_0067_be3c_d85c,
    },
    DraidMapSeed {
        children: 30,
        nperms: 256,
        seed: 0xca57_7b1e_07f8_5ca5,
        checksum: 0x0000_006f_5517_f3e4,
    },
    DraidMapSeed {
        children: 31,
        nperms: 256,
        seed: 0xfd50_a593_c518_b3d4,
        checksum: 0x0000_0073_70e7_778f,
    },
    DraidMapSeed {
        children: 32,
        nperms: 512,
        seed: 0xc6c8_7ba5_b042_650b,
        checksum: 0x0000_00f7_eb08_a156,
    },
    DraidMapSeed {
        children: 33,
        nperms: 512,
        seed: 0xc388_0d0c_9d45_8304,
        checksum: 0x0000_0107_34b5_d160,
    },
    DraidMapSeed {
        children: 34,
        nperms: 512,
        seed: 0xe920_927e_4d8b_2c97,
        checksum: 0x0000_0118_c1ed_bce0,
    },
    DraidMapSeed {
        children: 35,
        nperms: 512,
        seed: 0x8da7_fcda_87bd_e316,
        checksum: 0x0000_012a_3e9f_9110,
    },
    DraidMapSeed {
        children: 36,
        nperms: 512,
        seed: 0xcf09_9374_9151_4a29,
        checksum: 0x0000_013b_d6a2_4bef,
    },
    DraidMapSeed {
        children: 37,
        nperms: 512,
        seed: 0x9b5a_bbf3_45cb_d7cc,
        checksum: 0x0000_014b_9d90_fac3,
    },
    DraidMapSeed {
        children: 38,
        nperms: 512,
        seed: 0x5063_12a4_4668_d6a9,
        checksum: 0x0000_015e_1b5f_6148,
    },
    DraidMapSeed {
        children: 39,
        nperms: 512,
        seed: 0x7165_9ede_62b4_755f,
        checksum: 0x0000_0173_ef02_9bcd,
    },
    DraidMapSeed {
        children: 40,
        nperms: 512,
        seed: 0xa7fd_e73f_b74c_f2d7,
        checksum: 0x0000_0186_6fb7_2748,
    },
    DraidMapSeed {
        children: 41,
        nperms: 512,
        seed: 0x19e8_b461_a1de_a1d3,
        checksum: 0x0000_01a0_46f7_6b23,
    },
    DraidMapSeed {
        children: 42,
        nperms: 512,
        seed: 0x031c_9b86_8cc3_e976,
        checksum: 0x0000_01af_a64c_49d3,
    },
    DraidMapSeed {
        children: 43,
        nperms: 512,
        seed: 0xbaa5_125f_aa78_1854,
        checksum: 0x0000_01c7_6789_e278,
    },
    DraidMapSeed {
        children: 44,
        nperms: 512,
        seed: 0x4ed5_5052_550d_721b,
        checksum: 0x0000_01d8_00cc_d8eb,
    },
    DraidMapSeed {
        children: 45,
        nperms: 512,
        seed: 0x0fd6_3ddb_dff9_0677,
        checksum: 0x0000_01f0_8ad5_9ed2,
    },
    DraidMapSeed {
        children: 46,
        nperms: 512,
        seed: 0x36d6_6546_de7f_dd6f,
        checksum: 0x0000_0201_6f09_574b,
    },
    DraidMapSeed {
        children: 47,
        nperms: 512,
        seed: 0x99f9_97e7_eafb_69d7,
        checksum: 0x0000_021e_42e4_7cb6,
    },
    DraidMapSeed {
        children: 48,
        nperms: 512,
        seed: 0xbecd_9c25_7131_2c5d,
        checksum: 0x0000_0232_0fe2_872b,
    },
    DraidMapSeed {
        children: 49,
        nperms: 512,
        seed: 0xd973_7132_9e48_8a32,
        checksum: 0x0000_024c_d73f_2ca7,
    },
    DraidMapSeed {
        children: 50,
        nperms: 512,
        seed: 0x30e9_b136_6707_49ee,
        checksum: 0x0000_0268_1c83_b0e0,
    },
    DraidMapSeed {
        children: 51,
        nperms: 512,
        seed: 0x11ad_6bc8_f47a_aeb4,
        checksum: 0x0000_027e_9261_b5d5,
    },
    DraidMapSeed {
        children: 52,
        nperms: 512,
        seed: 0x68e4_4530_0af4_32c1,
        checksum: 0x0000_029a_a0eb_7dbf,
    },
    DraidMapSeed {
        children: 53,
        nperms: 512,
        seed: 0x910f_b561_657e_a98c,
        checksum: 0x0000_02b3_dca0_4853,
    },
    DraidMapSeed {
        children: 54,
        nperms: 512,
        seed: 0xd619_693d_8ce5_e7a5,
        checksum: 0x0000_02cc_280e_9c97,
    },
    DraidMapSeed {
        children: 55,
        nperms: 512,
        seed: 0x24e2_81f5_64db_b60a,
        checksum: 0x0000_02e9_fa84_2713,
    },
    DraidMapSeed {
        children: 56,
        nperms: 512,
        seed: 0x947a_7d3b_daab_44c5,
        checksum: 0x0000_0304_6680_f72e,
    },
    DraidMapSeed {
        children: 57,
        nperms: 512,
        seed: 0x2d44_fec9_c093_e0de,
        checksum: 0x0000_0324_198b_a810,
    },
    DraidMapSeed {
        children: 58,
        nperms: 512,
        seed: 0x8774_3c27_2d29_bb4c,
        checksum: 0x0000_033e_c48c_9ac9,
    },
    DraidMapSeed {
        children: 59,
        nperms: 512,
        seed: 0x96aa_3b6f_67f5_d923,
        checksum: 0x0000_034f_aead_902c,
    },
    DraidMapSeed {
        children: 60,
        nperms: 512,
        seed: 0x94a4_f1fa_f520_b0d3,
        checksum: 0x0000_037d_713a_b005,
    },
    DraidMapSeed {
        children: 61,
        nperms: 512,
        seed: 0xb13e_d3a2_72f7_11a2,
        checksum: 0x0000_0397_368f_3cbd,
    },
    DraidMapSeed {
        children: 62,
        nperms: 512,
        seed: 0x3b1b_1180_5fa4_a64a,
        checksum: 0x0000_03b8_a5e2_840c,
    },
    DraidMapSeed {
        children: 63,
        nperms: 512,
        seed: 0x4c74_caad_9172_ba71,
        checksum: 0x0000_03d4_be28_0290,
    },
    DraidMapSeed {
        children: 64,
        nperms: 512,
        seed: 0x035f_f643_923d_d29e,
        checksum: 0x0000_03fa_d6c3_55e1,
    },
    DraidMapSeed {
        children: 65,
        nperms: 512,
        seed: 0x768e_9171_b11a_bd3c,
        checksum: 0x0000_040e_b07f_ed20,
    },
    DraidMapSeed {
        children: 66,
        nperms: 512,
        seed: 0x7588_0e6f_78a1_3ddd,
        checksum: 0x0000_0443_3d6a_cf14,
    },
    DraidMapSeed {
        children: 67,
        nperms: 512,
        seed: 0x910b_9714_f698_a877,
        checksum: 0x0000_0451_ea65_d5db,
    },
    DraidMapSeed {
        children: 68,
        nperms: 512,
        seed: 0x87f5_db6f_9fdc_f5c7,
        checksum: 0x0000_0473_2169_e3f7,
    },
    DraidMapSeed {
        children: 69,
        nperms: 512,
        seed: 0x836d_4968_fbaa_3706,
        checksum: 0x0000_0495_4068_a380,
    },
    DraidMapSeed {
        children: 70,
        nperms: 512,
        seed: 0xc567_d73a_0364_21ab,
        checksum: 0x0000_04bd_7cb7_bd3d,
    },
    DraidMapSeed {
        children: 71,
        nperms: 512,
        seed: 0x619d_f40f_240b_8fed,
        checksum: 0x0000_04e3_76c2_e972,
    },
    DraidMapSeed {
        children: 72,
        nperms: 512,
        seed: 0x4276_3a68_0d5b_ed8e,
        checksum: 0x0000_0508_4275_c680,
    },
    DraidMapSeed {
        children: 73,
        nperms: 512,
        seed: 0x5866_f064_b323_0431,
        checksum: 0x0000_0529_06f2_c9ab,
    },
    DraidMapSeed {
        children: 74,
        nperms: 512,
        seed: 0x9fa0_8548_b162_1a44,
        checksum: 0x0000_0547_0801_9247,
    },
    DraidMapSeed {
        children: 75,
        nperms: 512,
        seed: 0xb605_3078_ce0f_c303,
        checksum: 0x0000_0572_cc5c_72b0,
    },
    DraidMapSeed {
        children: 76,
        nperms: 512,
        seed: 0x4a7a_ad7b_f389_0923,
        checksum: 0x0000_058e_987b_c8e9,
    },
    DraidMapSeed {
        children: 77,
        nperms: 512,
        seed: 0xe165_613f_d75b_5a53,
        checksum: 0x0000_05c2_0473_a211,
    },
    DraidMapSeed {
        children: 78,
        nperms: 512,
        seed: 0x3ff1_54ac_8781_63a6,
        checksum: 0x0000_05d6_5919_4bf3,
    },
    DraidMapSeed {
        children: 79,
        nperms: 512,
        seed: 0x24b9_3ade_0aa8_a532,
        checksum: 0x0000_060a_201c_4f8e,
    },
    DraidMapSeed {
        children: 80,
        nperms: 512,
        seed: 0xc18e_2d14_cd9b_b554,
        checksum: 0x0000_062c_55cf_e48c,
    },
    DraidMapSeed {
        children: 81,
        nperms: 512,
        seed: 0x98cc_7830_2feb_58b6,
        checksum: 0x0000_0666_56a0_7194,
    },
    DraidMapSeed {
        children: 82,
        nperms: 512,
        seed: 0xc6c5_fd5a_2abc_0543,
        checksum: 0x0000_067c_ff94_fbf8,
    },
    DraidMapSeed {
        children: 83,
        nperms: 512,
        seed: 0xa796_2f51_4acb_ba21,
        checksum: 0x0000_06ab_7b5a_fa2e,
    },
    DraidMapSeed {
        children: 84,
        nperms: 512,
        seed: 0xba02_5450_69dd_c6dc,
        checksum: 0x0000_06d1_9861_364f,
    },
    DraidMapSeed {
        children: 85,
        nperms: 512,
        seed: 0x447c_7319_2c35_073e,
        checksum: 0x0000_06fc_e315_ce35,
    },
    DraidMapSeed {
        children: 86,
        nperms: 512,
        seed: 0x48be_ef9e_2d42_b0c2,
        checksum: 0x0000_0720_a8e3_8b6b,
    },
    DraidMapSeed {
        children: 87,
        nperms: 512,
        seed: 0x4874_cf98_541a_35e0,
        checksum: 0x0000_0758_382a_2273,
    },
    DraidMapSeed {
        children: 88,
        nperms: 512,
        seed: 0xad4c_f833_3a31_127a,
        checksum: 0x0000_0781_e165_1b1b,
    },
    DraidMapSeed {
        children: 89,
        nperms: 512,
        seed: 0x47ae_4859_d578_88c1,
        checksum: 0x0000_07b2_7edb_e5bc,
    },
    DraidMapSeed {
        children: 90,
        nperms: 512,
        seed: 0x06f7_723c_fe5d_1891,
        checksum: 0x0000_07dc_2a96_d8eb,
    },
    DraidMapSeed {
        children: 91,
        nperms: 512,
        seed: 0xd4e4_4218_d660_576d,
        checksum: 0x0000_080a_c46f_02d5,
    },
    DraidMapSeed {
        children: 92,
        nperms: 512,
        seed: 0x7066_702b_0d5b_e1f2,
        checksum: 0x0000_0832_c96d_154e,
    },
    DraidMapSeed {
        children: 93,
        nperms: 512,
        seed: 0x0112_09b4_f9e1_1fb9,
        checksum: 0x0000_085e_efda_104c,
    },
    DraidMapSeed {
        children: 94,
        nperms: 512,
        seed: 0x47ff_ba30_a0b3_5708,
        checksum: 0x0000_0899_badc_32dc,
    },
    DraidMapSeed {
        children: 95,
        nperms: 512,
        seed: 0x1a95_a6ac_4538_aaa8,
        checksum: 0x0000_08b6_b69a_42b2,
    },
    DraidMapSeed {
        children: 96,
        nperms: 512,
        seed: 0xbda2_b239_bb20_08eb,
        checksum: 0x0000_08f2_2d2d_e38a,
    },
    DraidMapSeed {
        children: 97,
        nperms: 512,
        seed: 0x7ffa_0bea_9035_5c6c,
        checksum: 0x0000_092e_5b23_b816,
    },
    DraidMapSeed {
        children: 98,
        nperms: 512,
        seed: 0x1d56_ba34_be42_6795,
        checksum: 0x0000_094f_482e_5d1b,
    },
    DraidMapSeed {
        children: 99,
        nperms: 512,
        seed: 0x0aa8_9d45_c502_e93d,
        checksum: 0x0000_0977_d94a_98ce,
    },
    DraidMapSeed {
        children: 100,
        nperms: 512,
        seed: 0x5436_9449_f685_7774,
        checksum: 0x0000_09c0_6c9b_34cc,
    },
    DraidMapSeed {
        children: 101,
        nperms: 512,
        seed: 0xf7d4_dd84_45b4_6765,
        checksum: 0x0000_09e5_dc54_2259,
    },
    DraidMapSeed {
        children: 102,
        nperms: 512,
        seed: 0xfa88_6631_2f16_9469,
        checksum: 0x0000_0a16_b54e_ae93,
    },
    DraidMapSeed {
        children: 103,
        nperms: 512,
        seed: 0xd8a5_aea0_8aef_3ff9,
        checksum: 0x0000_0a38_1d2c_bfe7,
    },
    DraidMapSeed {
        children: 104,
        nperms: 512,
        seed: 0x66bc_d2c3_d5f9_ef0e,
        checksum: 0x0000_0a81_9181_7be7,
    },
    DraidMapSeed {
        children: 105,
        nperms: 512,
        seed: 0x3fb1_3a47_a012_ec81,
        checksum: 0x0000_0ab5_62b9_a254,
    },
    DraidMapSeed {
        children: 106,
        nperms: 512,
        seed: 0x4310_0f01_c9e5_e3ca,
        checksum: 0x0000_0aee_e84c_185f,
    },
    DraidMapSeed {
        children: 107,
        nperms: 512,
        seed: 0xca09_c50c_cee2_d054,
        checksum: 0x0000_0b1c_359c_047d,
    },
    DraidMapSeed {
        children: 108,
        nperms: 512,
        seed: 0xd717_6732_ac50_3f9b,
        checksum: 0x0000_0b57_8bc5_2a73,
    },
    DraidMapSeed {
        children: 109,
        nperms: 512,
        seed: 0xed20_6e51_f8d9_422d,
        checksum: 0x0000_0b80_83e0_d960,
    },
    DraidMapSeed {
        children: 110,
        nperms: 512,
        seed: 0x17ea_d5dc_6ba0_dcd6,
        checksum: 0x0000_0bcf_b1a3_2ca8,
    },
    DraidMapSeed {
        children: 111,
        nperms: 512,
        seed: 0x5f1d_c21e_38a9_69eb,
        checksum: 0x0000_0c01_71be_cdd6,
    },
    DraidMapSeed {
        children: 112,
        nperms: 512,
        seed: 0xddaa_973d_e33e_c528,
        checksum: 0x0000_0c3e_daba_4b95,
    },
    DraidMapSeed {
        children: 113,
        nperms: 512,
        seed: 0x2a5e_ccd7_735a_3630,
        checksum: 0x0000_0c63_0664_e7df,
    },
    DraidMapSeed {
        children: 114,
        nperms: 512,
        seed: 0xafcc_cee5_c0b7_1446,
        checksum: 0x0000_0cb6_5392_f6e4,
    },
    DraidMapSeed {
        children: 115,
        nperms: 512,
        seed: 0x8fa3_0c5e_7b14_7e27,
        checksum: 0x0000_0cd4_db39_1e55,
    },
    DraidMapSeed {
        children: 116,
        nperms: 512,
        seed: 0x5afe_0711_fdfa_fd82,
        checksum: 0x0000_0d08_cb4e_c35d,
    },
    DraidMapSeed {
        children: 117,
        nperms: 512,
        seed: 0x533a_6090_238a_fd4c,
        checksum: 0x0000_0d33_6f11_5d1b,
    },
    DraidMapSeed {
        children: 118,
        nperms: 512,
        seed: 0x90cf_11b5_95e3_9a84,
        checksum: 0x0000_0d8e_041c_2048,
    },
    DraidMapSeed {
        children: 119,
        nperms: 512,
        seed: 0x0d61_a3b8_0944_4009,
        checksum: 0x0000_0dcb_798a_fe35,
    },
    DraidMapSeed {
        children: 120,
        nperms: 512,
        seed: 0x7f34_da0f_54b0_d114,
        checksum: 0x0000_0df3_9226_64e1,
    },
    DraidMapSeed {
        children: 121,
        nperms: 512,
        seed: 0xa522_58d5_b72f_6551,
        checksum: 0x0000_0e4d_37a9_872d,
    },
    DraidMapSeed {
        children: 122,
        nperms: 512,
        seed: 0xc1de_54d7_6728_78db,
        checksum: 0x0000_0e65_83a9_4cf6,
    },
    DraidMapSeed {
        children: 123,
        nperms: 512,
        seed: 0x1d03_3543_16a4_14ab,
        checksum: 0x0000_0ebf_fc50_308d,
    },
    DraidMapSeed {
        children: 124,
        nperms: 512,
        seed: 0xcebd_cc37_7665_412c,
        checksum: 0x0000_0ede_e199_7cea,
    },
    DraidMapSeed {
        children: 125,
        nperms: 512,
        seed: 0x4ddd_4c04_b1a1_2344,
        checksum: 0x0000_0f21_d64b_373f,
    },
    DraidMapSeed {
        children: 126,
        nperms: 512,
        seed: 0x64fc_8f94_e397_3658,
        checksum: 0x0000_0f8f_87a8_896b,
    },
    DraidMapSeed {
        children: 127,
        nperms: 512,
        seed: 0x6876_5f78_034a_334e,
        checksum: 0x0000_0fb8_fe62_197e,
    },
    DraidMapSeed {
        children: 128,
        nperms: 512,
        seed: 0xaf36_b871_a303_e816,
        checksum: 0x0000_0fec_6f3a_fb1e,
    },
    DraidMapSeed {
        children: 129,
        nperms: 512,
        seed: 0x2a4c_bf73_866c_3a28,
        checksum: 0x0000_1027_febf_e4e5,
    },
    DraidMapSeed {
        children: 130,
        nperms: 512,
        seed: 0x9cb1_28aa_cdcd_3b2f,
        checksum: 0x0000_106a_a8ac_569d,
    },
    DraidMapSeed {
        children: 131,
        nperms: 512,
        seed: 0x5511_d41c_5586_9124,
        checksum: 0x0000_10bb_d755_ddf1,
    },
    DraidMapSeed {
        children: 132,
        nperms: 512,
        seed: 0x42f9_2461_937f_284a,
        checksum: 0x0000_10fb_8bce_b3b5,
    },
    DraidMapSeed {
        children: 133,
        nperms: 512,
        seed: 0xe2d8_9a1c_f6f1_f287,
        checksum: 0x0000_114c_f533_1e34,
    },
    DraidMapSeed {
        children: 134,
        nperms: 512,
        seed: 0xdc63_1a03_8956_200e,
        checksum: 0x0000_1164_28d2_adc5,
    },
    DraidMapSeed {
        children: 135,
        nperms: 512,
        seed: 0xb2e5_ac22_2cd2_36be,
        checksum: 0x0000_11ca_88e4_d4d2,
    },
    DraidMapSeed {
        children: 136,
        nperms: 512,
        seed: 0xbc7d_8236_655d_88e7,
        checksum: 0x0000_11e3_9cb9_4e66,
    },
    DraidMapSeed {
        children: 137,
        nperms: 512,
        seed: 0x073e_02d8_8d2d_8e75,
        checksum: 0x0000_1231_36c7_933c,
    },
    DraidMapSeed {
        children: 138,
        nperms: 512,
        seed: 0x3ddb_9c38_7316_6be0,
        checksum: 0x0000_1280_e4ec_6d52,
    },
    DraidMapSeed {
        children: 139,
        nperms: 512,
        seed: 0x7d3b_1a84_5420_e1b5,
        checksum: 0x0000_12c2_e7cd_6a44,
    },
    DraidMapSeed {
        children: 140,
        nperms: 512,
        seed: 0x6010_2308_aa7b_2a6c,
        checksum: 0x0000_12fc_490e_6c7d,
    },
    DraidMapSeed {
        children: 141,
        nperms: 512,
        seed: 0xdb22_bb2f_9eb8_94aa,
        checksum: 0x0000_1343_f5a8_5a1a,
    },
    DraidMapSeed {
        children: 142,
        nperms: 512,
        seed: 0xd853_f879_a13b_1606,
        checksum: 0x0000_13bb_7d5f_9048,
    },
    DraidMapSeed {
        children: 143,
        nperms: 512,
        seed: 0x0016_20a0_3f80_4b1d,
        checksum: 0x0000_13e7_4cc7_94fd,
    },
    DraidMapSeed {
        children: 144,
        nperms: 512,
        seed: 0xfdb5_2dda_76fb_f667,
        checksum: 0x0000_1442_d2f2_2480,
    },
    DraidMapSeed {
        children: 145,
        nperms: 512,
        seed: 0xa916_0110_f66e_24ff,
        checksum: 0x0000_144b_899f_9dbb,
    },
    DraidMapSeed {
        children: 146,
        nperms: 512,
        seed: 0x7730_6a30_379a_e03b,
        checksum: 0x0000_14cb_98eb_1f81,
    },
    DraidMapSeed {
        children: 147,
        nperms: 512,
        seed: 0x14f5_985d_2752_319d,
        checksum: 0x0000_14fe_ab82_1fc9,
    },
    DraidMapSeed {
        children: 148,
        nperms: 512,
        seed: 0xa4b8_ff11_de78_63f8,
        checksum: 0x0000_154a_0e60_b9c9,
    },
    DraidMapSeed {
        children: 149,
        nperms: 512,
        seed: 0x44b3_4542_6455_c1b3,
        checksum: 0x0000_1599_9c3c_569c,
    },
    DraidMapSeed {
        children: 150,
        nperms: 512,
        seed: 0x2726_7782_6049_b46c,
        checksum: 0x0000_15c9_697f_4b92,
    },
    DraidMapSeed {
        children: 151,
        nperms: 512,
        seed: 0x2f92_16e2_cd74_fe40,
        checksum: 0x0000_162b_1f7b_bd39,
    },
    DraidMapSeed {
        children: 152,
        nperms: 512,
        seed: 0x706a_e3e7_63ad_8771,
        checksum: 0x0000_1661_371c_55e1,
    },
    DraidMapSeed {
        children: 153,
        nperms: 512,
        seed: 0xf7fd_3453_07c2_480e,
        checksum: 0x0000_16e2_51f2_8b6a,
    },
    DraidMapSeed {
        children: 154,
        nperms: 512,
        seed: 0x6e94_e3d2_6b31_39eb,
        checksum: 0x0000_16f2_429b_b8c6,
    },
    DraidMapSeed {
        children: 155,
        nperms: 512,
        seed: 0x5458_bbfb_b781_fcba,
        checksum: 0x0000_173e_fdec_a1b9,
    },
    DraidMapSeed {
        children: 156,
        nperms: 512,
        seed: 0xa80e_2afe_ccd9_3b33,
        checksum: 0x0000_17bf_dcb7_8adc,
    },
    DraidMapSeed {
        children: 157,
        nperms: 512,
        seed: 0x1e4c_cbb2_2796_cf9d,
        checksum: 0x0000_1826_fdcc_39c9,
    },
    DraidMapSeed {
        children: 158,
        nperms: 512,
        seed: 0x8fba_4b67_6aaa_3663,
        checksum: 0x0000_1841_a137_9480,
    },
    DraidMapSeed {
        children: 159,
        nperms: 512,
        seed: 0xf82b_8438_14b3_15fa,
        checksum: 0x0000_1888_6e19_b8a3,
    },
    DraidMapSeed {
        children: 160,
        nperms: 512,
        seed: 0x7f21_e920_ecf7_53a3,
        checksum: 0x0000_1918_12ca_0ea7,
    },
    DraidMapSeed {
        children: 161,
        nperms: 512,
        seed: 0x48bb_8ea2_c4ca_a620,
        checksum: 0x0000_192f_310f_accf,
    },
    DraidMapSeed {
        children: 162,
        nperms: 512,
        seed: 0x5cdb_652b_4952_c91b,
        checksum: 0x0000_199e_1d74_37c7,
    },
    DraidMapSeed {
        children: 163,
        nperms: 512,
        seed: 0x6ac1_ba6f_78c0_6cd4,
        checksum: 0x0000_19cd_11f8_2c70,
    },
    DraidMapSeed {
        children: 164,
        nperms: 512,
        seed: 0x9faf_5f9c_a266_9a56,
        checksum: 0x0000_1a18_d543_1f6a,
    },
    DraidMapSeed {
        children: 165,
        nperms: 512,
        seed: 0xaa57_e938_3eb0_1194,
        checksum: 0x0000_1a9e_7d25_3d85,
    },
    DraidMapSeed {
        children: 166,
        nperms: 512,
        seed: 0x8969_67bf_495c_34d2,
        checksum: 0x0000_1afb_8319_b9fc,
    },
    DraidMapSeed {
        children: 167,
        nperms: 512,
        seed: 0xdfad_5f05_de22_5f1b,
        checksum: 0x0000_1b3a_59c3_093b,
    },
    DraidMapSeed {
        children: 168,
        nperms: 512,
        seed: 0xfd29_9a99_f9f2_abdd,
        checksum: 0x0000_1bb6_f1a1_0799,
    },
    DraidMapSeed {
        children: 169,
        nperms: 512,
        seed: 0xdda2_39e7_98fe_9fd4,
        checksum: 0x0000_1bfa_e0c9_692d,
    },
    DraidMapSeed {
        children: 170,
        nperms: 512,
        seed: 0x5fca_6704_14a3_2c3e,
        checksum: 0x0000_1c22_129d_bcff,
    },
    DraidMapSeed {
        children: 171,
        nperms: 512,
        seed: 0x1bb8_9343_14b0_87de,
        checksum: 0x0000_1c95_5db3_6cd0,
    },
    DraidMapSeed {
        children: 172,
        nperms: 512,
        seed: 0xd963_94b4_b082_200d,
        checksum: 0x0000_1cfc_8619_b7e6,
    },
    DraidMapSeed {
        children: 173,
        nperms: 512,
        seed: 0xb612_a773_5b1c_8cbc,
        checksum: 0x0000_1d30_3acd_d585,
    },
    DraidMapSeed {
        children: 174,
        nperms: 512,
        seed: 0x28e7_430f_e587_5fe1,
        checksum: 0x0000_1d7e_d5b3_697d,
    },
    DraidMapSeed {
        children: 175,
        nperms: 512,
        seed: 0x5038_e89e_fdd9_81b9,
        checksum: 0x0000_1dc4_0ec3_5c59,
    },
    DraidMapSeed {
        children: 176,
        nperms: 512,
        seed: 0x075f_d78f_1d14_db7c,
        checksum: 0x0000_1e31_c83b_4a2b,
    },
    DraidMapSeed {
        children: 177,
        nperms: 512,
        seed: 0xc50f_afdb_5021_be15,
        checksum: 0x0000_1e7c_dac8_2fbc,
    },
    DraidMapSeed {
        children: 178,
        nperms: 512,
        seed: 0xe6dc_7572_ce7b_91c7,
        checksum: 0x0000_1edd_8bb4_54fc,
    },
    DraidMapSeed {
        children: 179,
        nperms: 512,
        seed: 0x21f7_843e_7bed_a537,
        checksum: 0x0000_1f3a_8e01_9d6c,
    },
    DraidMapSeed {
        children: 180,
        nperms: 512,
        seed: 0xc833_85e2_0b43_ec82,
        checksum: 0x0000_1f70_735e_c137,
    },
    DraidMapSeed {
        children: 181,
        nperms: 512,
        seed: 0xca81_8217_dddb_21fd,
        checksum: 0x0000_201c_a44c_5a3c,
    },
    DraidMapSeed {
        children: 182,
        nperms: 512,
        seed: 0xe603_5def_ea48_f933,
        checksum: 0x0000_2038_e334_6658,
    },
    DraidMapSeed {
        children: 183,
        nperms: 512,
        seed: 0x4726_2a4f_953d_ac5a,
        checksum: 0x0000_20c2_e554_314e,
    },
    DraidMapSeed {
        children: 184,
        nperms: 512,
        seed: 0xe24c_7246_2608_73ea,
        checksum: 0x0000_2119_7e61_8d64,
    },
    DraidMapSeed {
        children: 185,
        nperms: 512,
        seed: 0xeef6_b57c_9b58_e9e1,
        checksum: 0x0000_217e_a48e_cddc,
    },
    DraidMapSeed {
        children: 186,
        nperms: 512,
        seed: 0x2bec_d334_6e38_6142,
        checksum: 0x0000_21c4_96d4_a5f9,
    },
    DraidMapSeed {
        children: 187,
        nperms: 512,
        seed: 0x63c6_207b_df3b_40a3,
        checksum: 0x0000_220e_0f2e_ec0c,
    },
    DraidMapSeed {
        children: 188,
        nperms: 512,
        seed: 0x3056_ce89_8976_7d4b,
        checksum: 0x0000_228e_b76c_d137,
    },
    DraidMapSeed {
        children: 189,
        nperms: 512,
        seed: 0x91af_61c3_07ce_e780,
        checksum: 0x0000_22e1_7e2e_a501,
    },
    DraidMapSeed {
        children: 190,
        nperms: 512,
        seed: 0xda35_9da2_25f6_d54f,
        checksum: 0x0000_2358_a2de_bc19,
    },
    DraidMapSeed {
        children: 191,
        nperms: 512,
        seed: 0x0a5f_7a2a_5560_7ba0,
        checksum: 0x0000_238a_79da_c18c,
    },
    DraidMapSeed {
        children: 192,
        nperms: 512,
        seed: 0x27bb_75bf_5224_638a,
        checksum: 0x0000_2403_a58e_2351,
    },
    DraidMapSeed {
        children: 193,
        nperms: 512,
        seed: 0x1ebf_db94_630f_5d0f,
        checksum: 0x0000_2492_a10c_b339,
    },
    DraidMapSeed {
        children: 194,
        nperms: 512,
        seed: 0x6eae_5e51_d9c5_f6fb,
        checksum: 0x0000_24ce_4bf9_8715,
    },
    DraidMapSeed {
        children: 195,
        nperms: 512,
        seed: 0x08d9_03b4_daed_c2e0,
        checksum: 0x0000_250d_1e15_886c,
    },
    DraidMapSeed {
        children: 196,
        nperms: 512,
        seed: 0xc722_a2f7_fa7c_d686,
        checksum: 0x0000_258a_99ed_0c9e,
    },
    DraidMapSeed {
        children: 197,
        nperms: 512,
        seed: 0x8f71_faf0_e54e_361d,
        checksum: 0x0000_25de_e119_76f5,
    },
    DraidMapSeed {
        children: 198,
        nperms: 512,
        seed: 0x87f6_4695_c91a_54e7,
        checksum: 0x0000_264e_00a4_3da0,
    },
    DraidMapSeed {
        children: 199,
        nperms: 512,
        seed: 0xc719_cbac_2c33_6b92,
        checksum: 0x0000_26d3_2727_7ac1,
    },
    DraidMapSeed {
        children: 200,
        nperms: 512,
        seed: 0xe7e6_47af_af77_1ade,
        checksum: 0x0000_2752_3a5c_44bf,
    },
    DraidMapSeed {
        children: 201,
        nperms: 512,
        seed: 0x12d4_b5c3_8ce8_c946,
        checksum: 0x0000_2738_9843_2545,
    },
    DraidMapSeed {
        children: 202,
        nperms: 512,
        seed: 0xf2e0_cd40_67bd_c94a,
        checksum: 0x0000_27e4_7bb2_c935,
    },
    DraidMapSeed {
        children: 203,
        nperms: 512,
        seed: 0x21b7_9f14_d6d9_47d3,
        checksum: 0x0000_281e_6497_7f0d,
    },
    DraidMapSeed {
        children: 204,
        nperms: 512,
        seed: 0x5150_93f9_52f1_8cd6,
        checksum: 0x0000_2896_91a4_73fd,
    },
    DraidMapSeed {
        children: 205,
        nperms: 512,
        seed: 0xd47b_160a_1b10_22c8,
        checksum: 0x0000_2903_e8b5_2411,
    },
    DraidMapSeed {
        children: 206,
        nperms: 512,
        seed: 0xc02f_c966_8471_5a16,
        checksum: 0x0000_2975_1560_8601,
    },
    DraidMapSeed {
        children: 207,
        nperms: 512,
        seed: 0xef51_e68e_fba7_2ed0,
        checksum: 0x0000_29ef_7360_4804,
    },
    DraidMapSeed {
        children: 208,
        nperms: 512,
        seed: 0x9e3b_e6e5_448b_4f33,
        checksum: 0x0000_2a28_46ed_074b,
    },
    DraidMapSeed {
        children: 209,
        nperms: 512,
        seed: 0x81d4_46c6_d5fe_c063,
        checksum: 0x0000_2a92_ca69_3455,
    },
    DraidMapSeed {
        children: 210,
        nperms: 512,
        seed: 0xff21_5de8_224e_57d5,
        checksum: 0x0000_2b22_71fe_3729,
    },
    DraidMapSeed {
        children: 211,
        nperms: 512,
        seed: 0xe252_4d9b_a8f6_9796,
        checksum: 0x0000_2b64_b99c_3ba2,
    },
    DraidMapSeed {
        children: 212,
        nperms: 512,
        seed: 0xf6b2_8e26_097b_7e4b,
        checksum: 0x0000_2bd7_68b6_e068,
    },
    DraidMapSeed {
        children: 213,
        nperms: 512,
        seed: 0x893a_487f_30ce_1644,
        checksum: 0x0000_2c67_f722_b4b2,
    },
    DraidMapSeed {
        children: 214,
        nperms: 512,
        seed: 0x3865_66c3_fc98_71df,
        checksum: 0x0000_2cc1_cf8b_4037,
    },
    DraidMapSeed {
        children: 215,
        nperms: 512,
        seed: 0x1e0e_d78e_df1f_558a,
        checksum: 0x0000_2d39_48d3_6c7f,
    },
    DraidMapSeed {
        children: 216,
        nperms: 512,
        seed: 0xe3bc_20c3_1e61_f113,
        checksum: 0x0000_2d6d_6b12_e025,
    },
    DraidMapSeed {
        children: 217,
        nperms: 512,
        seed: 0xd6c3_ad2e_2302_1882,
        checksum: 0x0000_2def_f757_2241,
    },
    DraidMapSeed {
        children: 218,
        nperms: 512,
        seed: 0xb4a9_f95c_f0f6_9c5a,
        checksum: 0x0000_2e67_d537_aa36,
    },
    DraidMapSeed {
        children: 219,
        nperms: 512,
        seed: 0x6e98_ed6f_6c38_e82f,
        checksum: 0x0000_2e97_2062_6789,
    },
    DraidMapSeed {
        children: 220,
        nperms: 512,
        seed: 0x2e01_edba_33fd_dac7,
        checksum: 0x0000_2f40_7c6b_0198,
    },
    DraidMapSeed {
        children: 221,
        nperms: 512,
        seed: 0x559d_02e1_f5f5_7ccc,
        checksum: 0x0000_2fb6_a5ab_4f24,
    },
    DraidMapSeed {
        children: 222,
        nperms: 512,
        seed: 0xac18_f5a9_16ad_cd8e,
        checksum: 0x0000_304a_e1c5_c57e,
    },
    DraidMapSeed {
        children: 223,
        nperms: 512,
        seed: 0x1578_9fba_ddb8_6f4b,
        checksum: 0x0000_306f_6e01_9c78,
    },
    DraidMapSeed {
        children: 224,
        nperms: 512,
        seed: 0xf4a9_c36d_5bc4_c408,
        checksum: 0x0000_30da_4043_4213,
    },
    DraidMapSeed {
        children: 225,
        nperms: 512,
        seed: 0xf640_f90f_d272_7f44,
        checksum: 0x0000_3189_ed37_b90c,
    },
    DraidMapSeed {
        children: 226,
        nperms: 512,
        seed: 0xb531_3d39_0d61_884a,
        checksum: 0x0000_31e1_5261_6b37,
    },
    DraidMapSeed {
        children: 227,
        nperms: 512,
        seed: 0x4bae_6b3c_e916_0939,
        checksum: 0x0000_321f_40ae_ac42,
    },
    DraidMapSeed {
        children: 228,
        nperms: 512,
        seed: 0x838c_3448_0f1a_66a1,
        checksum: 0x0000_32f3_89c0_f78e,
    },
    DraidMapSeed {
        children: 229,
        nperms: 512,
        seed: 0xb1c4_a52c_8e3d_6060,
        checksum: 0x0000_3300_62a4_0284,
    },
    DraidMapSeed {
        children: 230,
        nperms: 512,
        seed: 0xe0f1_110c_6d0e_d822,
        checksum: 0x0000_338b_e435_644f,
    },
    DraidMapSeed {
        children: 231,
        nperms: 512,
        seed: 0x9f1a_8ccd_cea6_8d4b,
        checksum: 0x0000_3404_5a4e_97e1,
    },
    DraidMapSeed {
        children: 232,
        nperms: 512,
        seed: 0x3261_ed62_223f_3099,
        checksum: 0x0000_3470_2cfc_401c,
    },
    DraidMapSeed {
        children: 233,
        nperms: 512,
        seed: 0xf219_1e23_1102_2d65,
        checksum: 0x0000_3509_dd19_c9fc,
    },
    DraidMapSeed {
        children: 234,
        nperms: 512,
        seed: 0xf102_a395_c203_3abc,
        checksum: 0x0000_3565_4dc9_6fae,
    },
    DraidMapSeed {
        children: 235,
        nperms: 512,
        seed: 0x11fe_378f_0279_06b6,
        checksum: 0x0000_35b5_193b_0264,
    },
    DraidMapSeed {
        children: 236,
        nperms: 512,
        seed: 0xf777_f2c0_26b3_37aa,
        checksum: 0x0000_3670_4f5d_9297,
    },
    DraidMapSeed {
        children: 237,
        nperms: 512,
        seed: 0x1b04_e9c2_ee14_3f32,
        checksum: 0x0000_36df_bb7a_f218,
    },
    DraidMapSeed {
        children: 238,
        nperms: 512,
        seed: 0x2fce_c952_66f9_352c,
        checksum: 0x0000_3785_c8df_24a9,
    },
    DraidMapSeed {
        children: 239,
        nperms: 512,
        seed: 0xfe2b_0e47_e427_dd85,
        checksum: 0x0000_37cb_df5d_a729,
    },
    DraidMapSeed {
        children: 240,
        nperms: 512,
        seed: 0x72b4_9bf2_225f_6c6d,
        checksum: 0x0000_3822_27c1_5855,
    },
    DraidMapSeed {
        children: 241,
        nperms: 512,
        seed: 0x5048_6b43_df7d_f9c7,
        checksum: 0x0000_389b_88be_6453,
    },
    DraidMapSeed {
        children: 242,
        nperms: 512,
        seed: 0x5192_a3e5_3181_c8ab,
        checksum: 0x0000_38dd_f3d6_7263,
    },
    DraidMapSeed {
        children: 243,
        nperms: 512,
        seed: 0xe9f5_d836_5296_fd5e,
        checksum: 0x0000_399f_1c6c_9e9c,
    },
    DraidMapSeed {
        children: 244,
        nperms: 512,
        seed: 0xc740_263f_0301_efa8,
        checksum: 0x0000_3a14_7146_512d,
    },
    DraidMapSeed {
        children: 245,
        nperms: 512,
        seed: 0x23cd_0f2b_5671_e67d,
        checksum: 0x0000_3ab1_0bcc_0d9d,
    },
    DraidMapSeed {
        children: 246,
        nperms: 512,
        seed: 0x002c_cc7e_5cd4_1390,
        checksum: 0x0000_3ad6_cd14_a6c0,
    },
    DraidMapSeed {
        children: 247,
        nperms: 512,
        seed: 0x9aaf_b3c0_2544_b31b,
        checksum: 0x0000_3b8c_b877_9fb0,
    },
    DraidMapSeed {
        children: 248,
        nperms: 512,
        seed: 0x72ba_07a7_8b12_1999,
        checksum: 0x0000_3c24_142a_5a3f,
    },
    DraidMapSeed {
        children: 249,
        nperms: 512,
        seed: 0x3d78_4aa5_8edf_c7b4,
        checksum: 0x0000_3cd0_8481_7d99,
    },
    DraidMapSeed {
        children: 250,
        nperms: 512,
        seed: 0xaab7_5042_4d80_04af,
        checksum: 0x0000_3d50_6a8e_098e,
    },
    DraidMapSeed {
        children: 251,
        nperms: 512,
        seed: 0x8440_3fcf_8e6b_5ca2,
        checksum: 0x0000_3d4c_54c2_aec4,
    },
    DraidMapSeed {
        children: 252,
        nperms: 512,
        seed: 0x71eb_7455_ec98_e207,
        checksum: 0x0000_3e65_5715_cf2c,
    },
    DraidMapSeed {
        children: 253,
        nperms: 512,
        seed: 0xd752_b4f1_9301_595b,
        checksum: 0x0000_3ecd_7b2c_a5ac,
    },
    DraidMapSeed {
        children: 254,
        nperms: 512,
        seed: 0xc467_4129_7504_99de,
        checksum: 0x0000_3e99_e86d_3e95,
    },
    DraidMapSeed {
        children: 255,
        nperms: 512,
        seed: 0x9772_baff_5cd1_2ef5,
        checksum: 0x0000_3f89_5c01_9841,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_254_openzfs_2_4_draid_maps_match_native_fletcher4_checksums() {
        assert_eq!(lookup_draid_seed(0), None);
        assert_eq!(lookup_draid_seed(1), None);
        assert_eq!(lookup_draid_seed(256), None);
        assert!(generate_draid_perms(1).is_err());
        assert!(generate_draid_perms(256).is_err());

        for children in VDEV_DRAID_MIN_CHILDREN..=VDEV_DRAID_MAX_CHILDREN {
            let table = generate_draid_perms(children)
                .unwrap_or_else(|err| panic!("children={children} failed: {err}"));
            assert_eq!(table.children, children);
            assert_eq!(table.perms.len(), table.children * table.nperms);
            let (base, iter) = table.row_and_iter((table.nperms * children + 7) as u64);
            assert_eq!(iter, 7 % children);
            assert_eq!(base.len(), children);
            let mut seen = vec![false; children];
            for idx in 0..children {
                let mapped = table.permute_id(base, iter, idx);
                assert!(!seen[mapped], "duplicate mapped child {mapped}");
                seen[mapped] = true;
            }
        }
    }
}
