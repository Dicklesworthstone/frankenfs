#![no_main]

use ffs_dir::{
    add_entry, compute_dx_hash, htree_find_leaf, htree_find_leaf_idx, htree_insert, htree_remove,
    init_dir_block, remove_entry, HtreeEntry,
};
use ffs_error::FfsError;
use ffs_ondisk::Ext4FileType;
use libfuzzer_sys::fuzz_target;

const BLOCK_SIZES: [usize; 5] = [64, 128, 256, 512, 1024];
const MAX_ENTRIES: usize = 12;
const MAX_MUTATIONS: usize = 32;
const MAX_NAME_LEN: usize = 24;

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            usize::from(self.next_u8()) % len
        }
    }
}

fn next_name(cursor: &mut ByteCursor<'_>) -> Vec<u8> {
    let len = usize::from(cursor.next_u8() % MAX_NAME_LEN as u8) + 1;
    (0..len).map(|_| b'a' + (cursor.next_u8() % 26)).collect()
}

fn next_file_type(cursor: &mut ByteCursor<'_>) -> Ext4FileType {
    match cursor.next_u8() % 3 {
        0 => Ext4FileType::RegFile,
        1 => Ext4FileType::Dir,
        _ => Ext4FileType::Symlink,
    }
}

fn normalize_remove_result(result: Result<bool, FfsError>) -> String {
    match result {
        Ok(found) => format!("ok:{found}"),
        Err(err) => format!("err:{err}"),
    }
}

fn assert_sorted(entries: &[HtreeEntry]) {
    for pair in entries.windows(2) {
        assert!(
            pair[0].hash <= pair[1].hash,
            "htree entries must remain sorted by hash"
        );
    }
}

fn assert_leaf_lookup_consistent(entries: &[HtreeEntry], target_hash: u32) {
    let idx = htree_find_leaf_idx(entries, target_hash);
    let leaf = htree_find_leaf(entries, target_hash);
    let expected = entries.get(idx).map(|entry| entry.block);
    assert_eq!(leaf, expected, "leaf index and block lookup must agree");
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);
    let block_len = BLOCK_SIZES[cursor.next_index(BLOCK_SIZES.len())];
    let reserved_tail = if block_len >= 64 && cursor.next_u8() & 1 == 0 {
        12
    } else {
        0
    };
    let mut block = vec![0_u8; block_len];
    if init_dir_block(&mut block, 2, 2, reserved_tail).is_err() {
        return;
    }

    let hash_version = cursor.next_u8();
    let seed = [
        cursor.next_u32(),
        cursor.next_u32(),
        cursor.next_u32(),
        cursor.next_u32(),
    ];

    let mut names = Vec::new();
    let mut htree_entries = Vec::new();

    for idx in 0..MAX_ENTRIES {
        let name = next_name(&mut cursor);
        let ino = idx as u32 + 10;
        let file_type = next_file_type(&mut cursor);
        match add_entry(&mut block, ino, &name, file_type, reserved_tail) {
            Ok(_) => {
                let hash = compute_dx_hash(hash_version, &name, &seed);
                let block_id = ino;
                let insert_idx = htree_insert(&mut htree_entries, hash, block_id);
                assert_eq!(
                    htree_entries.get(insert_idx),
                    Some(&HtreeEntry {
                        hash,
                        block: block_id
                    }),
                    "inserted htree entry must be recoverable at the returned index"
                );
                assert_eq!(
                    compute_dx_hash(hash_version, &name, &seed),
                    hash,
                    "dx hash must be deterministic for identical inputs"
                );
                names.push((name, hash, block_id));
            }
            Err(FfsError::NoSpace) => break,
            Err(_err) => return,
        }
    }

    assert_sorted(&htree_entries);
    if !htree_entries.is_empty() {
        let probe_idx = cursor.next_index(htree_entries.len());
        let probe_hash = htree_entries[probe_idx].hash;
        assert_leaf_lookup_consistent(&htree_entries, probe_hash);
        assert_leaf_lookup_consistent(&htree_entries, probe_hash.saturating_add(1));
    }

    if !names.is_empty() {
        let remove_idx = cursor.next_index(names.len());
        let (target_name, target_hash, target_block) = &names[remove_idx];

        let mut first = block.clone();
        let mut second = block.clone();
        let first_result =
            normalize_remove_result(remove_entry(&mut first, target_name, reserved_tail));
        let second_result =
            normalize_remove_result(remove_entry(&mut second, target_name, reserved_tail));
        assert_eq!(
            first_result, second_result,
            "remove_entry must be deterministic on identical valid blocks"
        );
        assert_eq!(
            first, second,
            "remove_entry must produce identical block bytes on identical valid inputs"
        );

        if first_result == "ok:true" {
            // add_entry permits duplicate names — a directory can legitimately
            // contain multiple entries sharing a basename (different inodes).
            // The "removing the same name twice fails" property only holds
            // when the name is unique in our model; otherwise the second
            // remove finds the next duplicate.
            let occurrences = names
                .iter()
                .filter(|(name, _, _)| name == target_name)
                .count();
            let retry =
                normalize_remove_result(remove_entry(&mut first, target_name, reserved_tail));
            let expected_retry = if occurrences > 1 {
                "ok:true"
            } else {
                "ok:false"
            };
            assert_eq!(
                retry,
                expected_retry,
                "after removing a live entry of a {} name, second remove must report {}",
                if occurrences > 1 {
                    "duplicated"
                } else {
                    "unique"
                },
                expected_retry,
            );
        }

        // Same caveat for htree_remove: duplicate (hash, block) pairs can
        // exist when names collide on hash — but we use ino as block_id and
        // each entry has a distinct ino, so (hash, block) pairs are always
        // unique here. Assert the unique-mapping invariant directly.
        assert!(
            htree_remove(&mut htree_entries, *target_hash, *target_block),
            "removing an existing htree mapping must succeed"
        );
        assert!(
            !htree_remove(&mut htree_entries, *target_hash, *target_block),
            "removing the same htree mapping twice must report false"
        );
        assert_sorted(&htree_entries);
    }

    let mutation_count = cursor.next_index(MAX_MUTATIONS + 1);
    let mut mutated = block.clone();
    for _ in 0..mutation_count {
        let offset = cursor.next_index(mutated.len());
        mutated[offset] ^= cursor.next_u8();
    }

    let target_name = if let Some((name, _, _)) = names.get(cursor.next_index(names.len())) {
        name.clone()
    } else {
        next_name(&mut cursor)
    };

    let mut mutated_a = mutated.clone();
    let mut mutated_b = mutated.clone();
    let bounded_tail = reserved_tail.min(mutated.len());
    let mutated_result_a =
        normalize_remove_result(remove_entry(&mut mutated_a, &target_name, bounded_tail));
    let mutated_result_b =
        normalize_remove_result(remove_entry(&mut mutated_b, &target_name, bounded_tail));
    assert_eq!(
        mutated_result_a, mutated_result_b,
        "remove_entry must stay deterministic on identical mutated blocks"
    );
    assert_eq!(
        mutated_a, mutated_b,
        "remove_entry must not diverge byte-for-byte across identical mutated inputs"
    );

    let random_name = next_name(&mut cursor);
    let hash = compute_dx_hash(hash_version, &random_name, &seed);
    assert_eq!(
        compute_dx_hash(hash_version, &random_name, &seed),
        hash,
        "dx hash must stay deterministic for fuzz-generated names"
    );
});
