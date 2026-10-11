//! Native SHA-512/256 known answers and block admission.
//! Vectors: NIST SHA512_256.pdf, also used by OpenZFS sha2_test.c.
//! https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
//! Native word layout: OpenZFS module/zfs/sha2_zfs.c.

use super::{BlockPointer, Endian, MAX_BLOCK_BYTES, checksum};

fn known_answer(message: &[u8], big: [u64; 4], little: [u64; 4]) {
    assert_eq!(checksum(message, 11, Endian::Big).unwrap(), big);
    assert_eq!(checksum(message, 11, Endian::Little).unwrap(), little);
}

#[test]
fn sha512_256_nist_short_message_has_native_checksum_words() {
    known_answer(
        b"abc",
        [
            0x5304_8e26_8194_1ef9,
            0x9b2e_29b7_6b4c_7dab,
            0xe4c2_d0c6_34fc_6d46,
            0xe0e2_f131_07e7_af23,
        ],
        [
            0xf91e_9481_268e_0453,
            0xab7d_4c6b_b729_2e9b,
            0x466d_fc34_c6d0_c2e4,
            0x23af_e707_31f1_e2e0,
        ],
    );
}

#[test]
fn sha512_256_nist_two_block_message_uses_the_distinct_sha512_256_iv() {
    let message = concat!(
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn",
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    );
    assert_eq!(message.len(), 112);
    known_answer(
        message.as_bytes(),
        [
            0x3928_e184_fb86_90f8,
            0x40da_3988_121d_31be,
            0x65cb_9d3e_f83e_e614,
            0x6fea_c861_e19b_563a,
        ],
        [
            0xf890_86fb_84e1_2839,
            0xbe31_1d12_8839_da40,
            0x14e6_3ef8_3e9d_cb65,
            0x3a56_9be1_61c8_ea6f,
        ],
    );
}

#[test]
fn sha512_256_admission_preserves_sha256_historical_word_order() {
    // SHA256's numeric words are always big-endian, including on LE pools.
    let expected = [
        0xba78_16bf_8f01_cfea,
        0x4141_40de_5dae_2223,
        0xb003_61a3_9617_7a9c,
        0xb410_ff61_f200_15ad,
    ];
    for order in [Endian::Little, Endian::Big] {
        assert_eq!(checksum(b"abc", 8, order).unwrap(), expected);
    }
}

fn pointer(physical: &[u8], containing: Endian, payload: Endian) -> BlockPointer {
    assert_eq!(physical.len(), 512);
    let mut words = [0_u64; 16];
    words[0] = 1; // One allocated sector.
    words[1] = 8;
    words[6] = (2 << 32)
        | (11 << 40)
        | (19 << 48)
        | (u64::from(payload == Endian::Little) << 63);
    words[10] = 42;
    words[12..].copy_from_slice(&checksum(physical, 11, payload).unwrap());
    let raw: Vec<u8> = words
        .into_iter()
        .flat_map(|word| containing.encode(word))
        .collect();
    BlockPointer::parse(&raw, containing).unwrap()
}

#[test]
fn sha512_256_physical_blocks_use_payload_order_inside_either_container() {
    let physical: Vec<u8> = (0..=u8::MAX).cycle().take(512).collect();
    for containing in [Endian::Little, Endian::Big] {
        for payload in [Endian::Little, Endian::Big] {
            let bp = pointer(&physical, containing, payload);
            assert_eq!(bp.checksum_type(), 11);
            assert_eq!(bp.payload_order(), payload);
            assert_eq!((bp.logical_bytes(), bp.physical_bytes()), (512, 512));
            assert_eq!(bp.regular_dvas().unwrap().len(), 1);
            assert_eq!(bp.decode(&physical).unwrap(), physical);
            assert!(bp.decode(&physical[..511]).is_err());

            let mut damaged = physical.clone();
            damaged[511] ^= 1;
            assert!(bp.decode(&damaged).is_err());

            let mut bad_checksum = bp.clone();
            bad_checksum.words[12] ^= 1;
            assert!(bad_checksum.decode(&physical).is_err());

            let mut wrong_order = bp.clone();
            wrong_order.words[6] ^= 1_u64 << 63;
            assert!(wrong_order.decode(&physical).is_err());

            let mut swapped_words = bp.clone();
            for word in &mut swapped_words.words[12..] {
                *word = word.swap_bytes();
            }
            assert!(swapped_words.decode(&physical).is_err());
        }
    }
}

#[test]
fn sha512_256_does_not_admit_disabled_or_other_checksum_algorithms() {
    let physical = [0_u8; 512];
    let good = pointer(&physical, Endian::Little, Endian::Little);
    assert!(good.decode(&physical).is_ok());
    for algorithm in [0_u8, 1, 2, 3, 4, 5, 9, 10, 12, 13, 14, u8::MAX] {
        assert!(checksum(&physical, algorithm, Endian::Little).is_err());
        let mut bp = good.clone();
        bp.words[6] = (bp.words[6] & !(0xff_u64 << 40)) | (u64::from(algorithm) << 40);
        assert!(bp.regular_dvas().is_err());
        assert!(bp.decode(&physical).is_err());
    }
}

#[test]
fn sha512_256_enforces_the_physical_checksum_input_budget() {
    let oversized = vec![0; MAX_BLOCK_BYTES + 1];
    assert!(checksum(&oversized, 11, Endian::Little).is_err());
}
