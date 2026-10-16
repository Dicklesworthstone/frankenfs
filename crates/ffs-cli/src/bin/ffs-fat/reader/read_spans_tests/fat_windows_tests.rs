//! Sequential metadata reads remain demand-correct on damaged media.
use super::*;

#[test]
fn short_and_random_chains_keep_demand_sector_io() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for clusters in [vec![32, 33, 34], vec![32, 1500, 64, 3000]] {
            let fixture = Fixture::new(kind, 512, 1, &clusters, clusters.len() as u32 * 512);
            let chain = fixture.volume.file_chain(&Cx::for_testing(), &fixture.entry).unwrap();
            assert_eq!(chain.clusters, clusters);
            let trace = fixture.device.trace.lock().unwrap();
            assert!(trace.reads.iter().all(|(_, size)| *size == 512));
            assert_eq!(trace.reads.len(), if clusters[1] == 33 { 2 } else { 8 });
        }
    }
}

#[test]
fn free_space_scans_batch_each_copy_and_stop_at_its_covered_table_boundary() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512_u16, 4096] {
            let fixture = Fixture::new(kind, sector, 1, &[32, 33, 34], 1029);
            let geometry = &fixture.volume.geometry;
            let expected = u64::from(geometry.cluster_count()) - 3 - u64::from(kind == FatKind::Fat32);
            assert_eq!(fixture.volume.free_clusters(&Cx::for_testing()).unwrap(), expected);
            let sector_bytes = u64::from(sector);
            let coverage = ((u64::from(geometry.cluster_count()) + 2)
                * u64::from(kind.entry_bytes())).div_ceil(sector_bytes) * sector_bytes;
            let mut expected_reads = Vec::new();
            for fat in &fixture.device.fats {
                expected_reads.push((fat.start, usize::from(sector)));
                let mut at = sector_bytes;
                while at < coverage {
                    let count = (coverage - at).min(FatTable::MAX_WINDOW_BYTES);
                    expected_reads.push((fat.start + at, count as usize));
                    at += count;
                }
            }
            let trace = fixture.device.trace.lock().unwrap();
            let mut actual = trace.reads.clone();
            actual.sort_unstable();
            expected_reads.sort_unstable();
            assert_eq!(actual, expected_reads);
            assert!(actual.iter().all(|(at, size)| *size <= FatTable::MAX_WINDOW_BYTES as usize
                && fixture.device.fats.iter().any(|fat| fat.contains(at) && *at + *size as u64 <= fat.end)));
            assert!(actual.len() < (coverage / sector_bytes * 2) as usize);
        }
    }
}

#[test]
fn failed_speculation_rechecks_only_demand_and_disables_readahead_for_that_copy() {
    for failure in [Failure::Media, Failure::Corruption] {
        let fixture = Fixture::new(FatKind::Fat16, 512, 1, &[32], 1);
        let cx = Cx::for_testing();
        let mut table = FatTable::new(&fixture.volume);
        assert_eq!(table.raw_entry(&cx, 0, 32).unwrap(), 0xffff);
        let start = fixture.device.fats[0].start;
        {
            let mut trace = fixture.device.trace.lock().unwrap();
            trace.fail = Some(start + 1024..start + 1025);
            trace.failure = failure;
        }
        assert_eq!(table.raw_entry(&cx, 0, 256).unwrap(), 0);
        assert_eq!(table.prefetch_failed, [true, false]);
        assert_eq!(table.sectors[0].as_ref().unwrap().0, start + 512 - fixture.volume.base);
        assert_eq!(table.sectors[0].as_ref().unwrap().1.len(), 512);
        assert_eq!(fixture.device.trace.lock().unwrap().reads.len(), 3);
        // The actually damaged demanded sector still fails. No byte from the
        // failed, 0xee-filled speculative buffer was installed as valid data.
        assert!(table.raw_entry(&cx, 0, 512).is_err());
        assert_eq!(fixture.device.trace.lock().unwrap().reads.len(), 4);
        assert_eq!(table.raw_entry(&cx, 0, 256).unwrap(), 0);
        assert_eq!(fixture.device.trace.lock().unwrap().reads.len(), 4);
        assert_eq!(table.raw_entry(&cx, 0, 1024).unwrap(), 0);
        assert_eq!(fixture.device.trace.lock().unwrap().reads.last().unwrap().1, 512);
        // A failure in copy zero does not disable a healthy copy's batching.
        table.raw_entry(&cx, 1, 32).unwrap();
        table.raw_entry(&cx, 1, 256).unwrap();
        assert!(table.sectors[1].as_ref().unwrap().1.len() > 512);
        assert_eq!(table.prefetch_failed, [true, false]);
    }
}

#[test]
fn damaged_demand_is_not_hidden_by_discarding_a_failed_window() {
    let fixture = Fixture::new(FatKind::Fat16, 512, 1, &[32], 1);
    let cx = Cx::for_testing();
    let mut table = FatTable::new(&fixture.volume);
    table.raw_entry(&cx, 0, 32).unwrap();
    let start = fixture.device.fats[0].start;
    fixture.device.trace.lock().unwrap().fail = Some(start + 512..start + 513);
    assert!(matches!(table.raw_entry(&cx, 0, 256), Err(FfsError::Io(_))));
    let trace = fixture.device.trace.lock().unwrap();
    assert_eq!(trace.reads.len(), 3);
    assert!(trace.reads[1].1 > 512);
    assert_eq!(trace.reads[2], (start + 512, 512));
    drop(trace);
    assert_eq!(table.sectors[0].as_ref().unwrap().0, start - fixture.volume.base);
    assert_eq!(table.raw_entry(&cx, 0, 32).unwrap(), 0xffff);
}

#[test]
fn terminal_read_errors_never_trigger_a_demand_retry() {
    for failure in [Failure::Cancelled, Failure::Denied] {
        let fixture = Fixture::new(FatKind::Fat16, 512, 1, &[32], 1);
        let cx = Cx::for_testing();
        let mut table = FatTable::new(&fixture.volume);
        table.raw_entry(&cx, 0, 32).unwrap();
        let start = fixture.device.fats[0].start;
        {
            let mut trace = fixture.device.trace.lock().unwrap();
            trace.fail = Some(start + 1024..start + 1025);
            trace.failure = failure;
        }
        let error = table.raw_entry(&cx, 0, 256).unwrap_err();
        match failure {
            Failure::Cancelled => assert!(matches!(error, FfsError::Cancelled)),
            Failure::Denied => assert!(matches!(error,
                FfsError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied)),
            _ => unreachable!("only terminal faults in this test"),
        }
        assert_eq!(fixture.device.trace.lock().unwrap().reads.len(), 2);
        assert_eq!(table.prefetch_failed, [false, false]);
        assert_eq!(table.sectors[0].as_ref().unwrap().1.len(), 512);
    }
}

#[test]
fn cancellation_after_window_io_does_not_publish_or_retry_its_buffer() {
    let fixture = Fixture::new(FatKind::Fat16, 512, 1, &[32], 1);
    let cx = Cx::for_testing();
    let mut table = FatTable::new(&fixture.volume);
    table.raw_entry(&cx, 0, 32).unwrap();
    fixture.device.trace.lock().unwrap().cancel_after = Some(2);
    assert!(matches!(table.raw_entry(&cx, 0, 256), Err(FfsError::Cancelled)));
    assert_eq!(fixture.device.trace.lock().unwrap().reads.len(), 2);
    assert_eq!(table.sectors[0].as_ref().unwrap().1.len(), 512);
    fixture.device.reset();
    assert_eq!(table.raw_entry(&Cx::for_testing(), 0, 256).unwrap(), 0);
    assert!(table.sectors[0].as_ref().unwrap().1.len() > 512);
}

#[test]
fn windows_preserve_mirror_disagreement_and_fat32_high_bit_rules() {
    let fixture = Fixture::new(FatKind::Fat16, 512, 1, &[32], 1);
    fixture.device.put(fixture.device.fats[1].start + 800 * 2, &0xffff_u16.to_le_bytes());
    let error = fixture.volume.free_clusters(&Cx::for_testing()).unwrap_err();
    assert!(error.to_string().contains("copies disagree at cluster 800"));

    let fixture = Fixture::new(FatKind::Fat32, 512, 1, &[32], 1);
    fixture.device.put(fixture.device.fats[0].start + 800 * 4, &0xafff_ffff_u32.to_le_bytes());
    fixture.device.put(fixture.device.fats[1].start + 800 * 4, &0xbfff_ffff_u32.to_le_bytes());
    let mut table = FatTable::new(&fixture.volume);
    let cx = Cx::for_testing();
    assert_eq!(table.entry(&cx, 32).unwrap(), FatEntry::End);
    assert_eq!(table.entry(&cx, 128).unwrap(), FatEntry::Free);
    assert_eq!(table.entry(&cx, 800).unwrap(), FatEntry::End);
    assert!(table.sectors.iter().all(|cache| cache.as_ref().unwrap().1.len() > 512));
}

#[test]
fn active_copy_scans_never_read_an_inactive_fat_and_new_operations_get_fresh_windows() {
    let fixture = Fixture::new(FatKind::Fat32, 512, 1, &[32, 33], 513);
    let base = fixture.volume.base;
    fixture.device.put(base + 40, &0x81_u16.to_le_bytes());
    fixture.device.put(base + 6 * 512 + 40, &0x81_u16.to_le_bytes());
    let volume = FatVolume::from_device(&Cx::for_testing(), Box::new(fixture.device.clone()),
        base, fixture.volume.geometry.volume_bytes()).unwrap();
    fixture.device.reset();
    fixture.device.trace.lock().unwrap().fail = Some(fixture.device.fats[0].clone());
    assert_eq!(volume.free_clusters(&Cx::for_testing()).unwrap(), 69997);
    assert!(fixture.device.trace.lock().unwrap().reads.iter().all(|(at, _)| fixture.device.fats[1].contains(at)));
    let cx = Cx::for_testing();
    let mut table = FatTable::new(&volume);
    table.raw_entry(&cx, 1, 32).unwrap();
    table.raw_entry(&cx, 1, 128).unwrap();
    assert_eq!(table.raw_entry(&cx, 1, 800).unwrap(), 0);
    drop(table);
    fixture.device.put(fixture.device.fats[1].start + 800 * 4, &0x0fff_ffff_u32.to_le_bytes());
    assert_eq!(FatTable::new(&volume).entry(&cx, 800).unwrap(), FatEntry::End);
}
