use asupersync::Cx;
use ffs_btrfs::BtrfsDeviceSet;
use ffs_ondisk::{BtrfsChunkEntry, BtrfsKey, BtrfsStripe};
use ffs_types::ParseError;
use std::sync::Arc;

const BTRFS_TEST_NODESIZE: u32 = 4096;

#[test]
fn btrfs_multi_device_raid5_read_conforms() {
    let logical = 0x50_000_u64;
    let stripe_len = 0x10_000_u64;
    // RAID5 with 3 devices: 2 data stripes, 1 parity stripe.
    // Length is 2 * stripe_len = 0x20_000.
    let chunks = vec![BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: logical,
        },
        length: stripe_len * 2,
        owner: 2,
        stripe_len,
        chunk_type: ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 3,
        sub_stripes: 0,
        stripes: vec![
            BtrfsStripe {
                devid: 1,
                offset: 0x100_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 2,
                offset: 0x200_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 3,
                offset: 0x300_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    let data1 = Arc::new(vec![0x11_u8; 4]);
    let data2 = Arc::new(vec![0x22_u8; 4]);

    // In RAID5, data is striped.
    // Stripe 0: dev1:0x100_000, dev2:0x200_000, dev3:0x300_000 (P)
    // Row 1 starts at the next full RAID5 row: dev1:0x110_000 (P),
    // dev2:0x210_000, dev3:0x310_000.

    let d1 = Arc::clone(&data1);
    devices
        .add_device(
            1,
            Box::new(move |_cx, physical, len| {
                assert_eq!(len, 4);
                if physical == 0x100_000 {
                    Ok((*d1).clone())
                } else {
                    Err(ParseError::InvalidField {
                        field: "device",
                        reason: "unexpected physical offset",
                    }
                    .into())
                }
            }),
        )
        .unwrap();

    let d2 = Arc::clone(&data2);
    devices
        .add_device(
            2,
            Box::new(move |_cx, physical, len| {
                assert_eq!(len, 4);
                if physical == 0x200_000 {
                    Ok((*d2).clone())
                } else {
                    Err(ParseError::InvalidField {
                        field: "device",
                        reason: "unexpected physical offset",
                    }
                    .into())
                }
            }),
        )
        .unwrap();

    devices
        .add_device(
            3,
            Box::new(move |_cx, _physical, _len| {
                Err(ParseError::InvalidField {
                    field: "device",
                    reason: "RAID5 data-stripe fixture unexpectedly read parity stripe",
                }
                .into())
            }),
        )
        .unwrap();

    let cx = Cx::for_testing();

    // Read from logical 0x50_000 (stripe 0, data 1)
    let res1 = devices
        .read_logical(&cx, &chunks, logical, 4)
        .expect("read RAID5 data1");
    assert_eq!(res1, vec![0x11_u8; 4]);

    // Read row 0, data stripe 1. Row 0 has parity on dev3, so this maps to dev2:0x200_000.
    let res2 = devices
        .read_logical(&cx, &chunks, logical + stripe_len, 4)
        .expect("read RAID5 data2");
    assert_eq!(res2, vec![0x22_u8; 4]);
}
