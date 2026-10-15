use super::*;

fn sparse_image() -> Vec<u8> {
    let mut bytes = image();
    // Logical clusters: hole, LCN 600, LCN 601, hole, LCN 590.
    // LCN 590 is entirely beyond ValidDataLength and must never be read.
    let mut data = mapped(
        &[0x01, 1, 0x21, 2, 88, 2, 0x01, 1, 0x11, 1, 0xF6, 0],
        5,
        2560,
        false,
    );
    data[12..14].copy_from_slice(&0x8000_u16.to_le_bytes());
    data[40..48].copy_from_slice(&2560_u64.to_le_bytes());
    data[56..64].copy_from_slice(&1300_u64.to_le_bytes());
    // Sparse nonresident attributes carry the physical allocation count in
    // the extended header, so move the mapping pairs from 64 to 72 bytes.
    drop(data.splice(64..64, 1536_u64.to_le_bytes()));
    let length = data.len() as u32;
    data[4..8].copy_from_slice(&length.to_le_bytes());
    data[32..34].copy_from_slice(&72_u16.to_le_bytes());
    put(
        &mut bytes,
        25,
        &record(
            25,
            false,
            1,
            &[
                standard_with_flags(0x200),
                data,
                resident(0x30, 2, "", &filename(27, "payload.bin", 1)),
            ],
        ),
    );
    bytes
}

fn payload(fs: &NtfsFs, cx: &Cx, scope: &mut RequestScope) -> InodeNumber {
    let directory = fs.lookup(cx, scope, ROOT, OsStr::new("Subdir")).unwrap();
    fs.lookup(cx, scope, directory.ino, OsStr::new("payload.bin"))
        .unwrap()
        .ino
}

#[test]
fn native_sparse_seek_uses_validated_mapping_without_payload_io() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let fs = open(sparse_image(), reads.clone(), None).unwrap();
    let mut scope = RequestScope::empty();
    let ino = payload(&fs, &cx, &mut scope);
    assert_eq!(
        fs.lseek(&cx, &mut scope, ino, 0, SeekWhence::Data).unwrap(),
        512
    );
    let after_admission = reads.lock().unwrap().len();
    for (offset, whence, expected) in [
        (1, SeekWhence::Hole, 1),
        (600, SeekWhence::Data, 600),
        (512, SeekWhence::Hole, 1300),
        (1300, SeekWhence::Hole, 1300),
        (2300, SeekWhence::Hole, 2300),
    ] {
        assert_eq!(
            fs.lseek(&cx, &mut scope, ino, offset, whence).unwrap(),
            expected
        );
    }
    assert!(matches!(
        fs.lseek(&cx, &mut scope, ino, 1300, SeekWhence::Data),
        Err(FfsError::Io(error)) if error.raw_os_error() == Some(libc::ENXIO)
    ));
    assert_eq!(reads.lock().unwrap().len(), after_admission);
    assert!(reads.lock().unwrap().iter().all(|&(offset, _)| {
        !(BASE as u64 + 590 * 512..BASE as u64 + 602 * 512).contains(&offset)
    }));
    assert_eq!(
        fs.read(&cx, &mut scope, ino, 1300, 1260).unwrap(),
        vec![0; 1260]
    );
    assert_eq!(reads.lock().unwrap().len(), after_admission);
}

#[test]
fn native_compression_padding_is_not_reported_as_a_file_hole() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let fs = open(image(), reads.clone(), None).unwrap();
    let mut scope = RequestScope::empty();
    let ino = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("packed.bin"))
        .unwrap()
        .ino;
    assert_eq!(
        fs.lseek(&cx, &mut scope, ino, 0, SeekWhence::Hole).unwrap(),
        8192
    );
    let after_admission = reads.lock().unwrap().len();
    assert_eq!(
        fs.lseek(&cx, &mut scope, ino, 4096, SeekWhence::Data).unwrap(),
        4096
    );
    assert_eq!(reads.lock().unwrap().len(), after_admission);
    assert_eq!(fs.read(&cx, &mut scope, ino, 4096, 8).unwrap(), b"DDDDDDDD");
}

#[test]
fn native_fiemap_reports_sparse_and_unwritten_ranges_without_payload_io() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let fs = open(sparse_image(), reads.clone(), None).unwrap();
    let mut scope = RequestScope::empty();
    let ino = payload(&fs, &cx, &mut scope);
    let extents = fs.fiemap(&cx, &mut scope, ino, 0, u64::MAX).unwrap();
    let values: Vec<_> = extents
        .iter()
        .map(|extent| {
            (
                extent.logical,
                extent.physical,
                extent.length,
                extent.flags,
            )
        })
        .collect();
    // Physical offsets exclude the enclosing image's 1024-byte prefix.
    assert_eq!(
        values,
        vec![
            (512, 307_200, 788, 0x100),
            (1300, 307_988, 236, 0x900),
            (2048, 302_080, 512, 0x801),
        ]
    );
    let after_admission = reads.lock().unwrap().len();
    assert_eq!(
        fs.fiemap(&cx, &mut scope, ino, 512, 1).unwrap(),
        vec![extents[0]]
    );
    assert!(fs.fiemap(&cx, &mut scope, ino, 0, 512).unwrap().is_empty());
    assert_eq!(reads.lock().unwrap().len(), after_admission);
    assert!(reads.lock().unwrap().iter().all(|&(offset, _)| {
        !(BASE as u64 + 590 * 512..BASE as u64 + 602 * 512).contains(&offset)
    }));
}

#[test]
fn native_fiemap_preserves_inline_identity_and_refuses_encoded_physical_guesses() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let fs = open(image(), reads.clone(), None).unwrap();
    let mut scope = RequestScope::empty();
    let inline = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("hello.txt"))
        .unwrap();
    let extents = fs.fiemap(&cx, &mut scope, inline.ino, 0, u64::MAX).unwrap();
    assert_eq!(extents.len(), 1);
    let extent = extents[0];
    assert_eq!(
        (extent.logical, extent.physical, extent.length, extent.flags),
        (0, 0, 5, 0x303)
    );
    assert!(matches!(
        fs.fiemap(&cx, &mut scope, ROOT, 0, u64::MAX),
        Err(FfsError::Io(error)) if error.raw_os_error() == Some(libc::EINVAL)
    ));
    let packed = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("packed.bin"))
        .unwrap();
    fs.lseek(&cx, &mut scope, packed.ino, 0, SeekWhence::Data)
        .unwrap();
    let after_admission = reads.lock().unwrap().len();
    assert!(matches!(
        fs.fiemap(&cx, &mut scope, packed.ino, 0, u64::MAX),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(reads.lock().unwrap().len(), after_admission);
}
