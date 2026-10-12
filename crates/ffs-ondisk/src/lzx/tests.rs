use super::*;

#[derive(Default)]
struct Words {
    bytes: Vec<u8>,
    word: u16,
    used: u8,
}

impl Words {
    fn put(&mut self, value: u32, count: u8) {
        for shift in (0..count).rev() {
            self.word |= (((value >> shift) & 1) as u16) << (15 - self.used);
            self.used += 1;
            if self.used == 16 {
                self.flush();
            }
        }
    }

    fn flush(&mut self) {
        self.bytes.extend(self.word.to_le_bytes());
        self.word = 0;
        self.used = 0;
    }

    fn finish(mut self) -> Vec<u8> {
        if self.used != 0 {
            self.flush();
        }
        self.bytes
    }

    fn header(&mut self, kind: u32, size: usize) {
        self.put(kind, 3);
        self.put(u32::from(size == MAX_OUTPUT_BYTES), 1);
        if size != MAX_OUTPUT_BYTES {
            self.put(u32::try_from(size).unwrap(), 16);
        }
    }

    fn raw_block(&mut self, bytes: &[u8], recent: [u32; 3]) {
        self.header(3, bytes.len());
        // Raw framing always discards a word, even when already aligned.
        self.flush();
        for offset in recent {
            self.bytes.extend(offset.to_le_bytes());
        }
        self.bytes.extend(bytes);
        if !bytes.len().is_multiple_of(2) {
            self.bytes.push(0);
        }
    }

    fn precode(&mut self) {
        for symbol in 0..20 {
            self.put(if symbol < 12 { 4 } else { 5 }, 4);
        }
    }

    fn pre_symbol(&mut self, symbol: u32) {
        if symbol < 12 {
            self.put(symbol, 4);
        } else {
            self.put(symbol + 12, 5);
        }
    }

    fn lengths(&mut self, previous: &[u8], next: &[u8]) {
        assert_eq!(previous.len(), next.len());
        self.precode();
        for (&old, &new) in previous.iter().zip(next) {
            self.pre_symbol((u32::from(old) + 17 - u32::from(new)) % 17);
        }
    }

    fn tables(
        &mut self,
        previous_main: &[u8; MAIN_SYMBOLS],
        next_main: &[u8; MAIN_SYMBOLS],
        previous_length: &[u8; LENGTH_SYMBOLS],
        next_length: &[u8; LENGTH_SYMBOLS],
    ) {
        self.lengths(&previous_main[..256], &next_main[..256]);
        self.lengths(&previous_main[256..], &next_main[256..]);
        self.lengths(previous_length, next_length);
    }
}

// Constructed WIM framing: RLE pretree lengths, literal A, 127 distance-one
// matches of 257 bytes, then a match of 128 bytes. This is not a CAB stream.
const REPEATED_A: &[u8] = &[
    0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x02, 0xf5, 0x0f, 0xff, 0x3f, 0xe2, 0xff,
    0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x44, 0xff, 0x1b, 0xff, 0xff, 0x08, 0xfa,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x3f, 0x88, 0xb5, 0xff, 0xff, 0xff, 0xff, 0x32,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xfe,
];

#[test]
fn full_native_chunk_uses_overlapping_extended_matches_and_no_cross_call_history() {
    let input = REPEATED_A.to_vec();
    assert_eq!(
        decompress_chunk(&input, MAX_OUTPUT_BYTES).unwrap(),
        vec![b'A'; MAX_OUTPUT_BYTES]
    );
    assert_eq!(input, REPEATED_A);
    for end in 0..input.len() {
        assert!(
            decompress_chunk(&input[..end], MAX_OUTPUT_BYTES).is_err(),
            "{end}"
        );
    }
    assert!(decompress_chunk(&input, MAX_OUTPUT_BYTES - 1).is_err());

    let mut main = [0; MAIN_SYMBOLS];
    main[65] = 1;
    main[256] = 1;
    let mut words = Words::default();
    words.header(1, 2);
    words.tables(
        &[0; MAIN_SYMBOLS],
        &main,
        &[0; LENGTH_SYMBOLS],
        &[0; LENGTH_SYMBOLS],
    );
    words.put(1, 1); // R0 before this chunk has produced a literal.
    assert!(decompress_chunk(&words.finish(), 2).is_err());

    let mut late_overrun = input;
    *late_overrun.last_mut().unwrap() |= 1; // Final length 128 becomes 257.
    assert!(decompress_chunk(&late_overrun, MAX_OUTPUT_BYTES).is_err());
}

#[test]
fn block_history_preserves_huffman_deltas_dictionary_and_native_r2_swaps() {
    let mut main = [0; MAIN_SYMBOLS];
    main[65] = 1;
    main[66] = 1;
    let mut words = Words::default();
    words.header(1, 4);
    words.tables(
        &[0; MAIN_SYMBOLS],
        &main,
        &[0; LENGTH_SYMBOLS],
        &[0; LENGTH_SYMBOLS],
    );
    words.put(0b0110, 4);
    words.header(1, 4);
    words.tables(&main, &main, &[0; LENGTH_SYMBOLS], &[0; LENGTH_SYMBOLS]);
    words.put(0b1010, 4);
    assert_eq!(decompress_chunk(&words.finish(), 8).unwrap(), b"ABBABABA");

    let mut words = Words::default();
    words.raw_block(b"ABCDEFGHIJ", [2, 3, 5]);
    let mut main = [0; MAIN_SYMBOLS];
    main[264] = 1; // R1, length 2.
    main[272] = 1; // R2, length 2.
    words.header(1, 6);
    words.tables(
        &[0; MAIN_SYMBOLS],
        &main,
        &[0; LENGTH_SYMBOLS],
        &[0; LENGTH_SYMBOLS],
    );
    words.put(0b101, 3);
    assert_eq!(
        decompress_chunk(&words.finish(), 16).unwrap(),
        b"ABCDEFGHIJFGJFJF"
    );

    let mut words = Words::default();
    words.raw_block(b"abc", [3, 1, 1]);
    let mut main = [0; MAIN_SYMBOLS];
    main[65] = 1;
    main[263] = 1;
    let mut length = [0; LENGTH_SYMBOLS];
    length[0] = 1;
    length[248] = 1;
    words.header(1, 257);
    words.tables(&[0; MAIN_SYMBOLS], &main, &[0; LENGTH_SYMBOLS], &length);
    words.put(0b11, 2);
    words.header(1, 257);
    words.tables(&main, &main, &length, &length);
    words.put(0b11, 2);
    assert_eq!(
        decompress_chunk(&words.finish(), 517).unwrap(),
        b"abc".repeat(173)[..517]
    );
}

#[test]
fn aligned_offsets_keep_high_bits_and_verbatim_offsets_use_the_complete_suffix() {
    let prefix: Vec<_> = (1..=50).collect();
    for aligned in [false, true] {
        let mut words = Words::default();
        words.raw_block(&prefix, [1, 1, 1]);
        let mut main = [0; MAIN_SYMBOLS];
        main[256 + 8 * 8] = 1;
        main[256 + 10 * 8] = 1;
        words.header(if aligned { 2 } else { 1 }, 4);
        if aligned {
            for _ in 0..8 {
                words.put(3, 3);
            }
        }
        words.tables(
            &[0; MAIN_SYMBOLS],
            &main,
            &[0; LENGTH_SYMBOLS],
            &[0; LENGTH_SYMBOLS],
        );
        words.put(0, 1);
        words.put(4, 3); // Slot 8: base 16 plus suffix 4 minus 2 = 18.
        words.put(1, 1);
        if aligned {
            words.put(1, 1);
            words.put(4, 3);
        } else {
            words.put(12, 4);
        }
        let mut expected = prefix.clone();
        expected.extend([33, 34, 11, 12]);
        assert_eq!(
            decompress_chunk(&words.finish(), expected.len()).unwrap(),
            expected
        );
    }
}

#[test]
fn e8_translation_uses_chunk_positions_and_preserves_native_tail_and_signed_limits() {
    let mut translated = vec![0x90; 64];
    for (at, absolute) in [
        (2, 100_i32),
        (10, -3),
        (18, -19),
        (26, E8_FILE_SIZE),
        (34, 0),
        (54, 100),
    ] {
        translated[at] = 0xE8;
        translated[at + 1..at + 5].copy_from_slice(&absolute.to_le_bytes());
    }
    let mut expected = translated.clone();
    for (at, relative) in [(2, 98_i32), (10, E8_FILE_SIZE - 3), (34, -34)] {
        expected[at + 1..at + 5].copy_from_slice(&relative.to_le_bytes());
    }
    let mut words = Words::default();
    words.raw_block(&translated[..16], [1, 1, 1]);
    words.raw_block(&translated[16..], [1, 1, 1]);
    assert_eq!(decompress_chunk(&words.finish(), 64).unwrap(), expected);

    // Literal native compact raw header and offsets, without the optional
    // final odd-byte padding. Expected bytes are independent of Words.
    let raw = [
        0, 0x60, 0, 0x30, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, b'a', b'b', b'c',
    ];
    assert_eq!(decompress_chunk(&raw, 3).unwrap(), b"abc");
}

#[test]
fn raw_alignment_consumes_a_word_when_already_aligned_and_rejects_invalid_offsets() {
    let bytes = [0xCD, 0xAB, 0x34, 0x12, 0xEF, 0xBE];
    let mut bits = InputBits::new(&bytes);
    assert_eq!(bits.take(16).unwrap(), 0xABCD);
    bits.align_raw().unwrap();
    assert_eq!(bits.raw(2).unwrap(), [0xEF, 0xBE]);

    let mut bits = InputBits::new(&bytes);
    assert_eq!(bits.take(4).unwrap(), 0xA);
    bits.align_raw().unwrap();
    assert_eq!(bits.raw(2).unwrap(), [0x34, 0x12]);

    for offset in [0, MAX_OUTPUT_BYTES as u32 + 1, u32::MAX] {
        let mut words = Words::default();
        words.raw_block(b"abc", [1, offset, 1]);
        assert!(decompress_chunk(&words.finish(), 3).is_err());
    }
}

#[test]
fn malformed_trees_runs_blocks_and_chunk_bounds_never_publish_partial_output() {
    assert!(Huffman::new(&[1]).is_err());
    assert!(Huffman::new(&[1, 1, 1]).is_err());
    assert!(Huffman::new(&[17]).is_err());
    let empty = Huffman::new(&[0; 8]).unwrap();
    assert!(empty.read(&mut InputBits::new(&[0, 0])).is_err());

    for symbol in [17, 18, 19] {
        let mut words = Words::default();
        words.precode();
        for _ in 0..254 {
            words.pre_symbol(0);
        }
        words.pre_symbol(symbol);
        match symbol {
            17 => words.put(0, 4),
            18 => words.put(0, 5),
            _ => {
                words.put(0, 1);
                words.pre_symbol(0);
            }
        }
        assert!(update_lengths(&mut InputBits::new(&words.finish()), &mut [0; 256]).is_err());
    }
    let mut words = Words::default();
    words.precode();
    words.pre_symbol(19);
    words.put(0, 1);
    words.pre_symbol(18);
    assert!(update_lengths(&mut InputBits::new(&words.finish()), &mut [0; 256]).is_err());

    for (kind, size, expected) in [(0, 1, 1), (4, 1, 1), (1, 0, 1), (3, 2, 1)] {
        let mut words = Words::default();
        words.header(kind, size);
        assert!(decompress_chunk(&words.finish(), expected).is_err());
    }
    assert!(decompress_chunk(REPEATED_A, 0).is_err());
    assert!(decompress_chunk(REPEATED_A, MAX_OUTPUT_BYTES + 1).is_err());
    assert!(decompress_chunk(&vec![0; MAX_INPUT_BYTES + 1], 1).is_err());
}

#[test]
fn independent_libfwnt_verbatim_and_aligned_vectors_match_complete_native_outputs() {
    use sha2::{Digest, Sha256};

    let digest_hex = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };

    // Exact upstream inputs and expected output digests, with source and
    // license retained beside the fixtures. No candidate encoder is involved.
    let cases: [(&[u8], usize, &str, &str); 2] = [
        (
            include_bytes!("fixtures/libfwnt_verbatim.lzx"),
            28_672,
            "163a7d802b9770628f90efca0207f282bc1f051f5e240876c5060f01d8d4773e",
            "efbc2a1e000ffb483defe83987085916fa1559950a7a193449bd841ecb98e1fa",
        ),
        (
            include_bytes!("fixtures/libfwnt_aligned.lzx"),
            10_752,
            "dc8b2a538df218041f83fbd742845090f470d11a7a0f9652ac3e2eae4fb3db13",
            "c31e17f565f5c1ac31815807ca7a66095a3bdb03749cad428471e510ff2bcb4f",
        ),
    ];
    for (input, expected_size, input_digest, output_digest) in cases {
        assert_eq!(digest_hex(input), input_digest);
        let output = decompress_chunk(input, expected_size).unwrap();
        assert_eq!(output.len(), expected_size);
        assert_eq!(digest_hex(&output), output_digest);
        assert!(decompress_chunk(input, expected_size - 1).is_err());
        for end in [0, 1, input.len() / 2, input.len() - 1] {
            assert!(
                decompress_chunk(&input[..end], expected_size).is_err(),
                "{end}"
            );
        }
    }
}
