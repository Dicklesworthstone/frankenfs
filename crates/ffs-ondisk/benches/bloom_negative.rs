#![forbid(unsafe_code)]
//! `dir_name_index` answers negative lookups (stat of a non-existent file —
//! common: build systems, `test -f`, rsync) via `FxHashSet<Vec<u8>>::contains`.
//! For a LARGE dir that set doesn't fit in L1/L2, so each probe cache-misses. A
//! succinct BLOOM FILTER (~10 bits/name, e.g. 12 KB for 10k names, L1-resident)
//! answers "definitely absent" with a few bit tests and NO false negatives — so
//! a negative lookup skips the set. Measure negative-contains: bloom vs HashSet
//! across dir sizes (where does the cache-resident win appear?).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench bloom_negative
use criterion::{Criterion, criterion_group, criterion_main};
use rustc_hash::{FxHashSet, FxHasher};
use std::hash::{Hash, Hasher};
use std::hint::black_box;

/// Minimal bloom filter: m bits (Vec<u64>), k probes via double-hashing off one
/// 64-bit FxHash. No false negatives; tunable false-positive rate.
struct Bloom {
    bits: Vec<u64>,
    m: usize, // number of bits (power of two)
    k: u32,
}

impl Bloom {
    fn new(n: usize, bits_per: usize, k: u32) -> Self {
        let want = (n * bits_per).max(64);
        let m = want.next_power_of_two();
        Bloom {
            bits: vec![0u64; m / 64],
            m,
            k,
        }
    }
    #[inline]
    fn hash(name: &[u8]) -> u64 {
        let mut h = FxHasher::default();
        name.hash(&mut h);
        h.finish()
    }
    fn insert(&mut self, name: &[u8]) {
        let h = Self::hash(name);
        let mask = self.m - 1;
        let (h1, h2) = (h as usize, (h >> 32) as usize | 1);
        for i in 0..self.k as usize {
            let bit = h1.wrapping_add(i.wrapping_mul(h2)) & mask;
            self.bits[bit >> 6] |= 1u64 << (bit & 63);
        }
    }
    #[inline]
    fn contains(&self, name: &[u8]) -> bool {
        let h = Self::hash(name);
        let mask = self.m - 1;
        let (h1, h2) = (h as usize, (h >> 32) as usize | 1);
        for i in 0..self.k as usize {
            let bit = h1.wrapping_add(i.wrapping_mul(h2)) & mask;
            if self.bits[bit >> 6] & (1u64 << (bit & 63)) == 0 {
                return false; // definitely absent (short-circuit on first 0)
            }
        }
        true // maybe present
    }
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("bloom_negative");
    for &n in &[1_000usize, 10_000, 100_000] {
        // Present set: "present_<i>"; absent queries: "absent_<i>".
        let present: Vec<Vec<u8>> = (0..n)
            .map(|i| format!("present_{i:08}").into_bytes())
            .collect();
        let absent: Vec<Vec<u8>> = (0..1024)
            .map(|i| format!("absent_{i:08}").into_bytes())
            .collect();

        let mut set: FxHashSet<Vec<u8>> = FxHashSet::default();
        let mut bloom = Bloom::new(n, 10, 7);
        for p in &present {
            set.insert(p.clone());
            bloom.insert(p);
        }
        // Every absent query is truly absent in the set.
        let fp = absent.iter().filter(|a| bloom.contains(a)).count();
        assert_eq!(absent.iter().filter(|a| set.contains(*a)).count(), 0);

        let label = format!("n{}", n);
        g.bench_function(format!("hashset/{label}"), |b| {
            b.iter(|| {
                let mut miss = 0usize;
                for a in black_box(&absent) {
                    miss += (!black_box(&set).contains(a.as_slice())) as usize;
                }
                black_box(miss)
            })
        });
        g.bench_function(format!("bloom/{label}"), |b| {
            b.iter(|| {
                let mut miss = 0usize;
                for a in black_box(&absent) {
                    miss += (!black_box(&bloom).contains(a.as_slice())) as usize;
                }
                black_box(miss)
            })
        });
        let _ = fp;
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
