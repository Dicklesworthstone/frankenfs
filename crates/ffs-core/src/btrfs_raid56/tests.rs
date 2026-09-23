use super::*;
use ffs_ondisk::{BtrfsKey, BtrfsStripe};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const STRIPE: usize = 64;
const BASE: u64 = 0x10_0000;

// Independent bit-serial oracle, not the production logarithm tables/solver.
fn oracle_mul(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0;
    while b != 0 {
        if b & 1 != 0 {
            out ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    out
}

struct Fixture {
    chunk: BtrfsChunkEntry,
    columns: Vec<Vec<u8>>,
    row: usize,
    data_count: usize,
}

impl Fixture {
    fn new(parity: usize, data_count: usize, row: usize) -> Self {
        let mut columns: Vec<Vec<u8>> = (0..data_count)
            .map(|column| {
                (0..STRIPE)
                    .map(|byte| ((column * 71 + byte * 31 + row * 17) % 251) as u8)
                    .collect()
            })
            .collect();
        let mut p = vec![0; STRIPE];
        let mut q = vec![0; STRIPE];
        let mut coefficient = 1;
        for data in &columns {
            for (offset, &byte) in data.iter().enumerate() {
                p[offset] ^= byte;
                q[offset] ^= oracle_mul(coefficient, byte);
            }
            coefficient = oracle_mul(coefficient, 2);
        }
        columns.push(p);
        if parity == 2 {
            columns.push(q);
        }
        let profile = if parity == 1 {
            ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5
        } else {
            ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6
        };
        Self {
            chunk: BtrfsChunkEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: 228,
                    offset: BASE,
                },
                length: ((row + 1) * data_count * STRIPE) as u64,
                owner: 2,
                stripe_len: STRIPE as u64,
                chunk_type: profile | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
                io_align: 1,
                io_width: 1,
                sector_size: 1,
                num_stripes: u16::try_from(data_count + parity).expect("stripe count"),
                sub_stripes: 0,
                stripes: (0..data_count + parity)
                    .map(|device| BtrfsStripe {
                        devid: device as u64 + 1,
                        offset: device as u64 * 17,
                        dev_uuid: [device as u8; 16],
                    })
                    .collect(),
            },
            columns,
            row,
            data_count,
        }
    }

    fn logical(&self, target: usize, within: usize) -> u64 {
        BASE + ((self.row * self.data_count + target) * STRIPE + within) as u64
    }

    fn devices(
        &self,
        missing: &[usize],
        corrupt: &[usize],
    ) -> (BtrfsReadDevices, Arc<AtomicUsize>) {
        let mut readers = ffs_btrfs::BtrfsDeviceSet::new();
        let calls = Arc::new(AtomicUsize::new(0));
        for (column, original) in self.columns.iter().enumerate() {
            if missing.contains(&column) {
                continue;
            }
            let device = (self.row + column) % self.columns.len();
            let offset = device * 17 + self.row * STRIPE;
            let mut bytes = vec![0; offset];
            bytes.extend_from_slice(original);
            if corrupt.contains(&column) {
                for byte in &mut bytes[offset..] {
                    *byte ^= 0x87;
                }
            }
            let calls = Arc::clone(&calls);
            readers
                .add_device(
                    device as u64 + 1,
                    Box::new(move |_, position, len| {
                        calls.fetch_add(1, Ordering::Relaxed);
                        let start = usize::try_from(position).expect("physical offset");
                        Ok(bytes[start..start + len].to_vec())
                    }),
                )
                .expect("device");
        }
        (
            BtrfsReadDevices {
                readers,
                identities: std::collections::BTreeMap::default(),
            },
            calls,
        )
    }

    fn recover(&self, target: usize, missing: &[usize], corrupt: &[usize]) -> Option<Vec<u8>> {
        let (devices, _) = self.devices(missing, corrupt);
        devices
            .reconstruct_raid56(
                &Cx::for_testing(),
                std::slice::from_ref(&self.chunk),
                self.logical(target, 7),
                31,
                |bytes| bytes == &self.columns[target][7..38],
            )
            .expect("reconstruction attempt")
    }
}

#[test]
fn every_single_data_erasure_across_raid5_and_raid6_rotations() {
    for parity in [1, 2] {
        for data_count in [2, 3, 6] {
            for row in 0..data_count + parity {
                let fixture = Fixture::new(parity, data_count, row);
                for target in 0..data_count {
                    assert_eq!(
                        fixture.recover(target, &[target], &[]),
                        Some(fixture.columns[target][7..38].to_vec()),
                        "parity={parity} data={data_count} row={row} target={target}"
                    );
                }
            }
        }
    }
}

#[test]
fn every_raid6_two_device_erasure_including_missing_p() {
    for data_count in [2, 3, 6] {
        for row in 0..data_count + 2 {
            let fixture = Fixture::new(2, data_count, row);
            for target in 0..data_count {
                for other in 0..data_count + 2 {
                    if other == target {
                        continue;
                    }
                    assert_eq!(
                        fixture.recover(target, &[target, other], &[]),
                        Some(fixture.columns[target][7..38].to_vec()),
                        "data={data_count} row={row} target={target} other={other}"
                    );
                }
            }
        }
    }
}

#[test]
fn readable_bad_p_is_replaced_by_q_after_validation_failure() {
    for row in 0..5 {
        let fixture = Fixture::new(2, 3, row);
        for target in 0..3 {
            assert_eq!(
                fixture.recover(target, &[target], &[3]),
                Some(fixture.columns[target][7..38].to_vec())
            );
        }
    }
}

#[test]
fn second_silent_data_error_is_located_without_rereading_partners() {
    for row in 0..8 {
        let fixture = Fixture::new(2, 6, row);
        for target in 0..6 {
            for suspect in 0..6 {
                if suspect == target {
                    continue;
                }
                let (devices, calls) = fixture.devices(&[target], &[suspect]);
                let result = devices
                    .reconstruct_raid56(
                        &Cx::for_testing(),
                        std::slice::from_ref(&fixture.chunk),
                        fixture.logical(target, 7),
                        31,
                        |bytes| bytes == &fixture.columns[target][7..38],
                    )
                    .expect("recover");
                assert_eq!(result, Some(fixture.columns[target][7..38].to_vec()));
                assert_eq!(calls.load(Ordering::Relaxed), 7);
            }
        }
    }
}

#[test]
fn exhausted_redundancy_and_invalid_candidates_never_return_bytes() {
    let fixture = Fixture::new(2, 4, 3);
    assert_eq!(fixture.recover(0, &[0, 1, 2], &[]), None);
    assert_eq!(fixture.recover(0, &[0, 4, 5], &[]), None);
    assert_eq!(fixture.recover(0, &[0, 1], &[4]), None);
    let (devices, _) = fixture.devices(&[0], &[]);
    let result = devices
        .reconstruct_raid56(
            &Cx::for_testing(),
            std::slice::from_ref(&fixture.chunk),
            fixture.logical(0, 7),
            31,
            |_| false,
        )
        .expect("invalid target checksum");
    assert_eq!(result, None);
}

#[test]
fn malformed_or_oversized_rows_fail_before_device_reads() {
    let fixture = Fixture::new(2, 3, 0);
    let (devices, calls) = fixture.devices(&[], &[]);
    let mut duplicate = fixture.chunk.clone();
    duplicate.stripes[1].devid = duplicate.stripes[0].devid;
    let mut zero = fixture.chunk.clone();
    zero.stripes[1].devid = 0;
    let too_wide = Fixture::new(2, 256, 0).chunk;
    for (chunk, logical, len) in [
        (duplicate, BASE, 31),
        (zero, BASE, 31),
        (too_wide, BASE, 31),
        (fixture.chunk.clone(), BASE + 63, 2),
        (fixture.chunk.clone(), BASE, 0),
        (fixture.chunk, u64::MAX, 1),
    ] {
        assert!(
            devices
                .reconstruct_raid56(&Cx::for_testing(), &[chunk], logical, len, |_| true)
                .is_err()
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn cancellation_during_partner_or_parity_read_stops_immediately() {
    for cancel_column in [1, 3, 4] {
        let fixture = Fixture::new(2, 3, 0);
        let mut readers = ffs_btrfs::BtrfsDeviceSet::new();
        let calls = Arc::new(AtomicUsize::new(0));
        for column in 1..5 {
            let calls = Arc::clone(&calls);
            readers
                .add_device(
                    column as u64 + 1,
                    Box::new(move |cx, _, len| {
                        assert!(cx.checkpoint().is_ok(), "I/O after cancellation");
                        calls.fetch_add(1, Ordering::Relaxed);
                        if column == cancel_column {
                            cx.set_cancel_requested(true);
                        }
                        Ok(vec![0; len])
                    }),
                )
                .expect("device");
        }
        let devices = BtrfsReadDevices {
            readers,
            identities: std::collections::BTreeMap::default(),
        };
        assert!(matches!(
            devices.reconstruct_raid56(&Cx::for_testing(), &[fixture.chunk], BASE, 31, |_| true),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(calls.load(Ordering::Relaxed), cancel_column);
    }
}

#[test]
fn validation_callback_cancellation_overrides_a_valid_candidate() {
    let fixture = Fixture::new(2, 3, 0);
    let (devices, _) = fixture.devices(&[0], &[]);
    let cx = Cx::for_testing();
    assert!(matches!(
        devices.reconstruct_raid56(&cx, &[fixture.chunk], BASE, 31, |_| {
            cx.set_cancel_requested(true);
            true
        }),
        Err(FfsError::Cancelled)
    ));
}

#[test]
fn permission_and_control_plane_failures_are_not_media_erasures() {
    for kind in [
        ErrorKind::PermissionDenied,
        ErrorKind::WouldBlock,
        ErrorKind::Other,
    ] {
        let fixture = Fixture::new(2, 3, 0);
        let mut readers = ffs_btrfs::BtrfsDeviceSet::new();
        readers
            .add_device(
                2,
                Box::new(move |_, _, _| Err(std::io::Error::from(kind).into())),
            )
            .expect("device");
        let devices = BtrfsReadDevices {
            readers,
            identities: std::collections::BTreeMap::default(),
        };
        let error = devices
            .reconstruct_raid56(&Cx::for_testing(), &[fixture.chunk], BASE, 31, |_| true)
            .expect_err("non-media failure");
        assert!(matches!(error, FfsError::Io(ref error) if error.kind() == kind));
    }
    assert!(is_erasure(
        &std::io::Error::from(ErrorKind::UnexpectedEof).into()
    ));
    assert!(!is_erasure(&BtrfsDeviceError::Cancelled));
}
