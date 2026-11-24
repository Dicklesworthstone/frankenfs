//! Authenticated native ZFS encryption (`com.datto:encryption`), key/transform lifecycle,
//! inheritance, keyless scrubbing/destroy, immediate key revocation, tamper detection,
//! nonce uniqueness, and persistence-prefix fault-cut rollback integration tests.

use super::*;
use ffs_core::{FsOps, RequestScope};
use ffs_ondisk::zfs::crypto::{
    DSL_CRYPTO_MAC, DSL_DIR_CRYPTO_KEY_OBJ, ZfsKeyFormat, ZioEncrypt, bp_crypt_iv, bp_crypt_salt,
    decrypt_dnode_block, decrypt_regular_block, encode_crypt_mac_words, encrypt_regular_block,
    verify_objset_macs,
};
use ffs_zfs::reader::dmu::properties::PropertyValue;
use ffs_zfs::{
    ZfsEncryptionCreateOptions, ZfsFs, ZfsKeyMaterial, ZfsKeyStatus, ZfsMountWriteOptions,
    ZfsPropertySetValue, ZfsXattrSetMode, ZfsZvolCreateOptions,
};
use std::collections::BTreeSet;

const OBJSET_PORTABLE_MAC_OFFSET: usize = 720;
const OBJSET_LOCAL_MAC_OFFSET: usize = 752;

fn encryption_pool_spec(mirror_width: usize) -> PoolFixtureSpec {
    PoolFixtureSpec {
        mirror_width,
        ashift: 12,
        image_bytes: 32 * 1024 * 1024,
        deadlist_mode: DeadlistMode::NativeDeadlist,
        additional_read_features: vec![
            (b"com.datto:encryption", 0),
            (b"com.datto:bookmark_v2", 0),
            (b"org.freebsd:zstd_compress", 0),
        ],
        additional_write_features: vec![(b"com.delphix:bookmarks", 0)],
        ..PoolFixtureSpec::default()
    }
}

fn open_pool_objects(
    cx: &Cx,
    devs: &[FaultableMemberDevice],
    pool_guid: u64,
    slot: usize,
) -> ffs_zfs::Objects {
    let leaves: Vec<Leaf> = devs
        .iter()
        .cloned()
        .map(|d| {
            let len = d.len_bytes();
            Leaf::from_device(cx, Box::new(d), 0, len).unwrap()
        })
        .collect();
    let pool = Pool::from_leaves(leaves).unwrap();
    pool.objects(cx, 0, slot, pool_guid).unwrap()
}

fn hex_key_from_byte(seed: u8) -> String {
    let mut out = String::with_capacity(64);
    for i in 0..32_u8 {
        use std::fmt::Write as _;
        let _ = write!(out, "{:02x}", seed.wrapping_add(i.wrapping_mul(7)));
    }
    out
}

fn find_dva_physical_offset(dva: Dva) -> usize {
    usize::try_from(DATA_OFFSET + dva.offset).unwrap()
}

/// Read an encrypted file's `(os_bp, l1_bp, l0_bps)` directly from raw disk media bytes using
/// public `ffs_ondisk::zfs::crypto` primitives, verifying on-disk wire layout end-to-end.
fn inspect_raw_encrypted_file_bps(
    cx: &Cx,
    mos: &mut ffs_zfs::Objects,
    media: &[u8],
    ds: &[Vec<u8>],
    file_obj: u64,
) -> (BlockPointer, BlockPointer, Vec<BlockPointer>) {
    let ds_row = mos
        .datasets(cx)
        .unwrap()
        .into_iter()
        .find(|d| d.components == ds)
        .unwrap();
    let head_dn = mos.object(cx, ds_row.head_object).unwrap();
    let os_bp = BlockPointer::parse(&head_dn.bonus()[128..256], head_dn.order()).unwrap();
    assert!(os_bp.protected());
    let crypto = mos.dataset_crypto_info(cx, ds).unwrap().unwrap();
    let key = mos.keyring().get(crypto.encryption_root_ddobj).unwrap();

    let os_dva = os_bp.data_dvas().unwrap()[0];
    let os_off = find_dva_physical_offset(os_dva);
    let os_phys = &media[os_off..os_off + os_bp.physical_bytes()];
    let os_raw =
        ffs_ondisk::zfs::decompress(os_phys, os_bp.compression(), os_bp.logical_bytes()).unwrap();
    verify_objset_macs(&os_raw, os_bp.payload_order(), &key.hmac_key, key.version).unwrap();
    let os = ObjectSet::parse(&os_raw, os_bp.payload_order()).unwrap();

    let dnode_blk_bp = &os.meta.pointers()[0];
    assert!(dnode_blk_bp.is_encrypted());
    let dn_dva = dnode_blk_bp.data_dvas().unwrap()[0];
    let dn_off = find_dva_physical_offset(dn_dva);
    let dn_phys = &media[dn_off..dn_off + dnode_blk_bp.physical_bytes()];
    let dn_plain = decrypt_dnode_block(&key, dnode_blk_bp, dn_phys).unwrap();
    let file_slot = usize::try_from(file_obj).unwrap();
    let file_dn = ffs_ondisk::zfs_dmu::dnode_at(&dn_plain, file_slot, dnode_blk_bp.payload_order())
        .unwrap()
        .unwrap();
    assert!(file_dn.levels() >= 2, "expected L1 indirect block");

    let l1_bp = file_dn.pointers()[0].clone();
    assert!(l1_bp.protected() && !l1_bp.is_encrypted());
    let l1_dva = l1_bp.data_dvas().unwrap()[0];
    let l1_off = find_dva_physical_offset(l1_dva);
    let l1_phys = &media[l1_off..l1_off + l1_bp.physical_bytes()];
    let l1_raw =
        ffs_ondisk::zfs::decompress(l1_phys, l1_bp.compression(), l1_bp.logical_bytes()).unwrap();
    let mut l0_bps = Vec::new();
    for blk_idx in 0..5 {
        let bp = BlockPointer::parse(
            &l1_raw[blk_idx * 128..(blk_idx + 1) * 128],
            l1_bp.payload_order(),
        )
        .unwrap();
        l0_bps.push(bp);
    }
    (os_bp, l1_bp, l0_bps)
}

#[test]
#[allow(clippy::too_many_lines)]
fn encrypted_root_all_six_suites_keyformats_compression_and_inheritance() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_730_000_000,
        nanos: 0,
    };

    let matrix: [(ZioEncrypt, ZfsKeyMaterial, &str, u64); 6] = [
        (
            ZioEncrypt::Aes128Ccm,
            ZfsKeyMaterial::Raw([0x11; 32]),
            "off",
            2,
        ),
        (
            ZioEncrypt::Aes192Ccm,
            ZfsKeyMaterial::Hex(hex_key_from_byte(0x22)),
            "zle",
            14,
        ),
        (
            ZioEncrypt::Aes256Ccm,
            ZfsKeyMaterial::Passphrase(b"correct-horse-ccm-256".to_vec()),
            "lz4",
            15,
        ),
        (
            ZioEncrypt::Aes128Gcm,
            ZfsKeyMaterial::Raw([0x44; 32]),
            "gzip",
            10,
        ),
        (
            ZioEncrypt::Aes192Gcm,
            ZfsKeyMaterial::Hex(hex_key_from_byte(0x55)),
            "zstd-3",
            (3 << 7) | 16,
        ),
        (
            ZioEncrypt::Aes256Gcm,
            ZfsKeyMaterial::Passphrase(b"strong-passphrase-gcm-256".to_vec()),
            "lz4",
            15,
        ),
    ];

    let built = build_clean_zfs_pool(&encryption_pool_spec(1));
    let devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let parent_ds = vec![b"data".to_vec()];

    for (idx, (suite, material, comp_label, comp_val)) in matrix.into_iter().enumerate() {
        let name = format!("enc_{idx}");
        let ds_path = vec![b"data".to_vec(), name.as_bytes().to_vec()];
        let enc_opts = ZfsEncryptionCreateOptions {
            suite,
            key_material: Some(material.clone()),
            keylocation: Some(format!("file:///keys/{name}.key").into_bytes()),
            pbkdf2_iters: (material.format() == ZfsKeyFormat::Passphrase).then_some(100_000),
            extra_entropy: format!("suite-matrix-{idx}").into_bytes(),
        };
        let (_, tok) = engine
            .create_encrypted_dataset(
                &cx,
                &parent_ds,
                name.as_bytes(),
                &[
                    (
                        "compression".to_owned(),
                        ZfsPropertySetValue::Number(comp_val),
                    ),
                    ("recordsize".to_owned(), ZfsPropertySetValue::Number(16_384)),
                ],
                &enc_opts,
                ts,
            )
            .into_result()
            .unwrap_or_else(|err| panic!("create_encrypted_dataset {name} ({comp_label}): {err}"));

        // Verify keyless metadata properties + locked status on a fresh MOS reader.
        let mut fresh_mos = open_pool_objects(&cx, &devices, built.pool_guid, tok.published_slot());
        assert_eq!(
            fresh_mos.key_status(&cx, &ds_path).unwrap(),
            ZfsKeyStatus::Unavailable
        );
        let locked_props = fresh_mos
            .properties(
                &cx,
                &ds_path,
                None,
                &[
                    "encryption".to_owned(),
                    "keyformat".to_owned(),
                    "keylocation".to_owned(),
                    "pbkdf2iters".to_owned(),
                    "encryptionroot".to_owned(),
                    "keystatus".to_owned(),
                ],
            )
            .unwrap();
        let prop_map: BTreeMap<&str, Option<&PropertyValue>> = locked_props
            .values
            .iter()
            .map(|p| (p.name.as_str(), p.value.as_ref()))
            .collect();
        assert_eq!(
            prop_map["encryption"],
            Some(&PropertyValue::Number(suite.raw()))
        );
        assert_eq!(
            prop_map["keyformat"],
            Some(&PropertyValue::Number(material.format().raw()))
        );
        assert_eq!(
            prop_map["keylocation"],
            Some(&PropertyValue::Text(
                format!("file:///keys/{name}.key").into_bytes()
            ))
        );
        assert_eq!(
            prop_map["keystatus"],
            Some(&PropertyValue::Text(b"unavailable".to_vec()))
        );
        assert_eq!(
            prop_map["encryptionroot"],
            Some(&PropertyValue::Text(
                format!("ffstestpool/data/{name}").into_bytes()
            ))
        );
        if material.format() == ZfsKeyFormat::Passphrase {
            assert_eq!(
                prop_map["pbkdf2iters"],
                Some(&PropertyValue::Number(100_000))
            );
        }
        // Locked dataset refuses ZPL read with PermissionDenied.
        assert!(matches!(
            fresh_mos.zpl(&cx, &ds_path),
            Err(FfsError::PermissionDenied)
        ));

        // Write multi-block compressible file (forcing indirect blocks + compression) + inline & spilled SA xattrs.
        let (file_obj, _) = engine
            .create_file(
                &cx,
                &ds_path,
                2,
                b"secret.bin",
                0o640,
                1000,
                1000,
                ts,
                ZfsDataChecksum::Sha256,
            )
            .into_result()
            .unwrap();
        let mut payload = Vec::with_capacity(64 * 1024 + 37);
        for blk in 0..4_u8 {
            payload.extend(std::iter::repeat_n(0_u8, 8192));
            payload.extend(std::iter::repeat_n(blk.wrapping_add(0x41), 8192));
        }
        payload.extend_from_slice(b"TAIL-AUTHENTICATED-PAYLOAD-0123456789");
        let (_, _) = engine
            .write_file_data(
                &cx,
                &ds_path,
                file_obj,
                0,
                &payload,
                ts,
                ZfsDataChecksum::Sha256,
            )
            .into_result()
            .unwrap();
        let (_, _) = engine
            .set_xattr(
                &cx,
                &ds_path,
                file_obj,
                "user.inline",
                b"ok-inline",
                ZfsXattrSetMode::Create,
                ts,
            )
            .into_result()
            .unwrap();
        let large_xattr: Vec<u8> = (0..3000_usize).map(|i| (i % 251) as u8).collect();
        let (_, _) = engine
            .set_xattr(
                &cx,
                &ds_path,
                file_obj,
                "user.spilled",
                &large_xattr,
                ZfsXattrSetMode::Create,
                ts,
            )
            .into_result()
            .unwrap();

        // Snapshot + inherited child dataset on first & last suites (covering both CCM & GCM).
        let mut child_ds = None;
        let final_slot = if idx == 0 || idx == 5 {
            let (_, _) = engine
                .create_snapshot(&cx, &ds_path, b"s1", ts)
                .into_result()
                .unwrap();
            let (_, _) = engine
                .write_file_data(
                    &cx,
                    &ds_path,
                    file_obj,
                    0,
                    b"OVERWRITTEN-HEAD-PREFIX",
                    ts,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            let cpath = vec![
                b"data".to_vec(),
                name.as_bytes().to_vec(),
                b"child".to_vec(),
            ];
            let (_, _) = engine
                .create_dataset(&cx, &ds_path, b"child", &[], ts)
                .into_result()
                .unwrap();
            let (cfile, _) = engine
                .create_file(
                    &cx,
                    &cpath,
                    2,
                    b"inherited.txt",
                    0o644,
                    0,
                    0,
                    ts,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            let (_, ctok) = engine
                .write_file_data(
                    &cx,
                    &cpath,
                    cfile,
                    0,
                    b"inherited-encryption-root-works",
                    ts,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            child_ds = Some(cpath);
            ctok.published_slot()
        } else {
            engine.committed_slot()
        };

        // Re-open fresh MOS: keyless scrub succeeds, keyed scrub + readback + xattrs match byte-for-byte!
        let mut verify_mos = open_pool_objects(&cx, &devices, built.pool_guid, final_slot);
        let keyless_scrub = verify_mos
            .scrub_dataset(&cx, &ds_path, None, ScrubLimits::default())
            .unwrap();
        assert!(
            keyless_scrub.is_clean(),
            "keyless scrub failed on {name}: {keyless_scrub:?}"
        );
        verify_mos.load_key(&cx, &ds_path, &material).unwrap();
        assert_eq!(
            verify_mos.key_status(&cx, &ds_path).unwrap(),
            ZfsKeyStatus::Available
        );
        let keyed_scrub = verify_mos
            .scrub_dataset(&cx, &ds_path, None, ScrubLimits::default())
            .unwrap();
        assert!(
            keyed_scrub.is_clean(),
            "keyed scrub failed on {name}: {keyed_scrub:?}"
        );

        let mut zpl = verify_mos.zpl(&cx, &ds_path).unwrap();
        let obj = zpl.resolve(&cx, b"/secret.bin").unwrap();
        let mut expected_head = payload.clone();
        if child_ds.is_some() {
            expected_head[..23].copy_from_slice(b"OVERWRITTEN-HEAD-PREFIX");
        }
        assert_eq!(
            zpl.read(&cx, obj, 0, expected_head.len()).unwrap(),
            expected_head
        );
        assert_eq!(
            zpl.getxattr(&cx, obj, "user.inline").unwrap().as_deref(),
            Some(b"ok-inline".as_slice())
        );
        assert_eq!(
            zpl.getxattr(&cx, obj, "user.spilled").unwrap().as_deref(),
            Some(large_xattr.as_slice())
        );

        if let Some(cpath) = child_ds {
            let mut snap_zpl = verify_mos.zpl_snapshot(&cx, &ds_path, b"s1").unwrap();
            let sobj = snap_zpl.resolve(&cx, b"/secret.bin").unwrap();
            assert_eq!(snap_zpl.read(&cx, sobj, 0, payload.len()).unwrap(), payload);

            // Inherited child unlocked automatically by loading root key!
            let cinfo = verify_mos
                .dataset_crypto_info(&cx, &cpath)
                .unwrap()
                .unwrap();
            assert_eq!(cinfo.encryption_root_components, ds_path);
            let mut czpl = verify_mos.zpl(&cx, &cpath).unwrap();
            let cobj = czpl.resolve(&cx, b"/inherited.txt").unwrap();
            assert_eq!(
                czpl.read(&cx, cobj, 0, 31).unwrap(),
                b"inherited-encryption-root-works"
            );
        }
    }

    let _ = assert_pool_scrub_and_allocation_clean(
        &cx,
        &devices,
        built.pool_guid,
        Some(engine.committed_slot()),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn encrypted_key_lifecycle_change_key_unload_revocation_zvol_and_locked_destroy() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_731_000_000,
        nanos: 0,
    };

    let built = build_clean_zfs_pool(&encryption_pool_spec(2));
    let devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();

    let parent_ds = vec![b"data".to_vec()];
    let root_ds = vec![b"data".to_vec(), b"vault".to_vec()];
    let child_ds = vec![b"data".to_vec(), b"vault".to_vec(), b"child".to_vec()];
    let zvol_ds = vec![b"data".to_vec(), b"vault".to_vec(), b"disk0".to_vec()];

    let key_a = ZfsKeyMaterial::Raw([0xA5; 32]);
    let key_b = ZfsKeyMaterial::Hex(hex_key_from_byte(0xB6));
    let key_c = ZfsKeyMaterial::Passphrase(b"rotated-passphrase-2026".to_vec());

    let (_, _) = engine
        .create_encrypted_dataset(
            &cx,
            &parent_ds,
            b"vault",
            &[("compression".to_owned(), ZfsPropertySetValue::Number(15))],
            &ZfsEncryptionCreateOptions {
                suite: ZioEncrypt::Aes256Gcm,
                key_material: Some(key_a.clone()),
                keylocation: Some(b"prompt".to_vec()),
                pbkdf2_iters: None,
                extra_entropy: b"vault-init".to_vec(),
            },
            ts,
        )
        .into_result()
        .unwrap();

    let (file_obj, _) = engine
        .create_file(
            &cx,
            &root_ds,
            2,
            b"alpha.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let original_bytes = b"pre-rotation-confidential-data".repeat(256);
    let (_, _) = engine
        .write_file_data(
            &cx,
            &root_ds,
            file_obj,
            0,
            &original_bytes,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let (_, _) = engine
        .create_snapshot(&cx, &root_ds, b"s1", ts)
        .into_result()
        .unwrap();
    let (_, _) = engine
        .create_dataset(&cx, &root_ds, b"child", &[], ts)
        .into_result()
        .unwrap();
    let (c_file, _) = engine
        .create_file(
            &cx,
            &child_ds,
            2,
            b"c.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let (_, _) = engine
        .write_file_data(
            &cx,
            &child_ds,
            c_file,
            0,
            b"child-payload",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();

    // Create encrypted ZVOL inheriting from `data/vault`, write unaligned 512B + multi-block + discard + snapshot + shrink!
    let (_, _) = engine
        .zvol_create(
            &cx,
            &root_ds,
            b"disk0",
            &ZfsZvolCreateOptions {
                volsize: 256 * 1024,
                volblocksize: 16 * 1024,
                sparse: true,
                initial_props: Vec::new(),
                timestamp: ts,
            },
        )
        .into_result()
        .unwrap();
    let zvol_sector = vec![0xCD_u8; 512];
    let (_, _) = engine
        .zvol_write_at(&cx, &zvol_ds, 512, &zvol_sector, ZfsDataChecksum::Sha256)
        .into_result()
        .unwrap();
    let zvol_blk = vec![0xEF_u8; 32 * 1024];
    let (_, _) = engine
        .zvol_write_at(&cx, &zvol_ds, 16 * 1024, &zvol_blk, ZfsDataChecksum::Sha256)
        .into_result()
        .unwrap();
    let (_, _) = engine
        .create_snapshot(&cx, &zvol_ds, b"vs1", ts)
        .into_result()
        .unwrap();
    let (_, _) = engine
        .zvol_discard(&cx, &zvol_ds, 16 * 1024, 16 * 1024, ZfsDataChecksum::Sha256)
        .into_result()
        .unwrap();
    let (_, tok_pre_rot) = engine
        .zvol_resize(&cx, &zvol_ds, 128 * 1024)
        .into_result()
        .unwrap();

    // Verify immediate `unload_key` revocation on live `Zpl` reader!
    {
        let mut mos =
            open_pool_objects(&cx, &devices, built.pool_guid, tok_pre_rot.published_slot());
        mos.load_key(&cx, &root_ds, &key_a).unwrap();
        let mut zpl = mos.zpl(&cx, &root_ds).unwrap();
        let obj = zpl.resolve(&cx, b"/alpha.txt").unwrap();
        assert_eq!(zpl.read(&cx, obj, 0, 30).unwrap(), &original_bytes[..30]);
        assert!(zpl.unload_key(&cx).unwrap());
        assert!(matches!(
            zpl.read(&cx, obj, 0, 30),
            Err(FfsError::PermissionDenied)
        ));
    }

    // Verify `rename_dataset` refuses moving non-root encrypted child outside its encryption root!
    let bad_rename =
        engine.rename_dataset(&cx, &child_ds, &[b"data".to_vec(), b"escaped".to_vec()]);
    assert!(matches!(bad_rename, ZfsTxOutcome::NotCommitted(_)));

    // Verify `destroy_dataset` refuses destroying encryption root while dependents exist.
    let bad_root_destroy = engine.destroy_dataset(&cx, &root_ds);
    assert!(matches!(bad_root_destroy, ZfsTxOutcome::NotCommitted(_)));

    // Rotate wrapping key A -> B (hex) -> C (passphrase + new keylocation) without rewriting data!
    let (_, _) = engine
        .change_key(
            &cx,
            &root_ds,
            &key_b,
            Some(b"file:///keys/b.hex"),
            None,
            b"rot-1",
        )
        .into_result()
        .unwrap();
    let (_, tok_rot) = engine
        .change_key(
            &cx,
            &root_ds,
            &key_c,
            Some(b"file:///keys/c.pass"),
            Some(100_000),
            b"rot-2",
        )
        .into_result()
        .unwrap();

    // Re-open fresh MOS: old keys A & B MUST fail closed; wrong passphrase fails closed; key C unlocks ALL!
    let mut post_mos = open_pool_objects(&cx, &devices, built.pool_guid, tok_rot.published_slot());
    assert!(matches!(
        post_mos.load_key(&cx, &root_ds, &key_a),
        Err(FfsError::PermissionDenied)
    ));
    assert!(matches!(
        post_mos.load_key(&cx, &root_ds, &key_b),
        Err(FfsError::PermissionDenied)
    ));
    assert!(matches!(
        post_mos.load_key(
            &cx,
            &root_ds,
            &ZfsKeyMaterial::Passphrase(b"wrong-passphrase".to_vec())
        ),
        Err(FfsError::PermissionDenied)
    ));
    post_mos.load_key(&cx, &root_ds, &key_c).unwrap();
    let mut zpl = post_mos.zpl(&cx, &root_ds).unwrap();
    let obj = zpl.resolve(&cx, b"/alpha.txt").unwrap();
    assert_eq!(
        zpl.read(&cx, obj, 0, original_bytes.len()).unwrap(),
        original_bytes
    );
    let mut snap = post_mos.zpl_snapshot(&cx, &root_ds, b"s1").unwrap();
    assert_eq!(
        snap.read(
            &cx,
            snap.resolve(&cx, b"/alpha.txt").unwrap(),
            0,
            original_bytes.len()
        )
        .unwrap(),
        original_bytes
    );
    let mut zvol = post_mos.zvol(&cx, &zvol_ds, None).unwrap();
    assert_eq!(zvol.read(&cx, 512, 512).unwrap(), zvol_sector);
    assert_eq!(
        zvol.read(&cx, 16 * 1024, 16 * 1024).unwrap(),
        vec![0_u8; 16 * 1024]
    );
    assert_eq!(
        zvol.read(&cx, 32 * 1024, 16 * 1024).unwrap(),
        vec![0xEF_u8; 16 * 1024]
    );
    let mut vsnap = post_mos.zvol(&cx, &zvol_ds, Some(b"vs1")).unwrap();
    assert_eq!(vsnap.read(&cx, 16 * 1024, 32 * 1024).unwrap(), zvol_blk);
    assert!(
        post_mos
            .scrub_dataset(&cx, &zvol_ds, None, ScrubLimits::default())
            .unwrap()
            .is_clean()
    );

    // Verify immediate key revocation on mounted writable `ZfsFs` (`FsOps`)!
    let fs_engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(built.pool_guid, tok_rot.published_slot()),
    )
    .unwrap();
    fs_engine.load_key(&cx, &root_ds, &key_c).unwrap();
    let fs = ZfsFs::with_writer_options(
        &cx,
        fs_engine,
        root_ds.clone(),
        ZfsMountWriteOptions::default(),
    )
    .unwrap();
    let root_ino = ffs_types::InodeNumber(1);
    let attr = fs
        .lookup(
            &cx,
            &mut RequestScope::empty(),
            root_ino,
            std::ffi::OsStr::new("alpha.txt"),
        )
        .unwrap();
    assert_eq!(
        fs.read(&cx, &mut RequestScope::empty(), attr.ino, 0, 30)
            .unwrap(),
        &original_bytes[..30]
    );
    let root_ddobj = post_mos
        .dataset_crypto_info(&cx, &root_ds)
        .unwrap()
        .unwrap()
        .encryption_root_ddobj;
    assert!(
        fs.keyring()
            .unwrap()
            .unwrap()
            .unload_key(root_ddobj)
            .unwrap()
    );
    assert!(matches!(
        fs.read(&cx, &mut RequestScope::empty(), attr.ino, 0, 30),
        Err(FfsError::PermissionDenied)
    ));
    drop(fs);

    // Now test LOCKED destroy (zero keys loaded in fresh engine!): destroys ZVOL, child, snapshots, and root!
    let mut locked_engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(built.pool_guid, tok_rot.published_slot()),
    )
    .unwrap();
    assert_eq!(
        locked_engine.key_status(&cx, &root_ds).unwrap(),
        ZfsKeyStatus::Unavailable
    );
    let (_, _) = locked_engine
        .destroy_snapshot(&cx, &zvol_ds, b"vs1", false)
        .into_result()
        .unwrap();
    let (_, _) = locked_engine
        .zvol_destroy(&cx, &zvol_ds)
        .into_result()
        .unwrap();
    let (_, _) = locked_engine
        .destroy_dataset(&cx, &child_ds)
        .into_result()
        .unwrap();
    let (_, _) = locked_engine
        .destroy_snapshot(&cx, &root_ds, b"s1", false)
        .into_result()
        .unwrap();
    let (_, final_tok) = locked_engine
        .destroy_dataset(&cx, &root_ds)
        .into_result()
        .unwrap();

    // Verify zero leaks, clean space maps, and `com.datto:encryption` feature refcount returned to 0!
    let _ = assert_pool_scrub_and_allocation_clean(
        &cx,
        &devices,
        built.pool_guid,
        Some(final_tok.published_slot()),
    );
    let mut clean_mos =
        open_pool_objects(&cx, &devices, built.pool_guid, final_tok.published_slot());
    let root_dir_entries = clean_mos.zap_values(&cx, 1).unwrap();
    let feat_read_obj = root_dir_entries
        .iter()
        .find(|e| e.name == b"features_for_read")
        .unwrap()
        .scalar()
        .unwrap();
    let read_feats = clean_mos.zap_values(&cx, feat_read_obj).unwrap();
    let enc_count = read_feats
        .iter()
        .find(|e| e.name == b"com.datto:encryption")
        .unwrap()
        .scalar()
        .unwrap();
    assert_eq!(
        enc_count, 0,
        "com.datto:encryption refcount leaked after destroy"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn encrypted_tamper_rejection_nonce_uniqueness_and_fault_cut_rollback() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_732_000_000,
        nanos: 0,
    };

    let built = build_clean_zfs_pool(&encryption_pool_spec(1));
    let devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let parent_ds = vec![b"data".to_vec()];
    let enc_ds = vec![b"data".to_vec(), b"sec".to_vec()];
    let key1 = ZfsKeyMaterial::Raw([0x33; 32]);
    let key2 = ZfsKeyMaterial::Raw([0x77; 32]);

    // 1. Fault-cut BEFORE Uberblock during `create_encrypted_dataset`: must return NotCommitted
    //    AND insert ZERO ghost keys into `engine.keyring()`!
    let next_call = devices[0].write_calls();
    devices[0].set_fault(DeviceFault::FailWriteOnCall {
        call_index: next_call,
    });
    let failed_create = engine.create_encrypted_dataset(
        &cx,
        &parent_ds,
        b"ghost",
        &[],
        &ZfsEncryptionCreateOptions {
            suite: ZioEncrypt::Aes256Gcm,
            key_material: Some(key1.clone()),
            keylocation: Some(b"prompt".to_vec()),
            pbkdf2_iters: None,
            extra_entropy: b"fault-cut-create".to_vec(),
        },
        ts,
    );
    assert!(matches!(failed_create, ZfsTxOutcome::NotCommitted(_)));
    devices[0].set_fault(DeviceFault::None);
    devices[0].state.lock().unwrap().crash_drop_unsynced();
    let pre_mos = open_pool_objects(&cx, &devices, built.pool_guid, engine.committed_slot());
    assert!(pre_mos.keyring().loaded_roots().is_empty());
    assert!(engine.keyring().loaded_roots().is_empty());

    // 2. Commit encrypted dataset cleanly and verify multi-TXG nonce uniqueness!
    let (_, _) = engine
        .create_encrypted_dataset(
            &cx,
            &parent_ds,
            b"sec",
            &[("recordsize".to_owned(), ZfsPropertySetValue::Number(4096))],
            &ZfsEncryptionCreateOptions {
                suite: ZioEncrypt::Aes256Gcm,
                key_material: Some(key1.clone()),
                keylocation: Some(b"prompt".to_vec()),
                pbkdf2_iters: None,
                extra_entropy: b"sec-root".to_vec(),
            },
            ts,
        )
        .into_result()
        .unwrap();

    let (file_obj, _) = engine
        .create_file(
            &cx,
            &enc_ds,
            2,
            b"nonce.bin",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Sha256,
        )
        .into_result()
        .unwrap();
    let mut seen_nonces: BTreeSet<([u8; 8], [u8; 12])> = BTreeSet::new();
    let mut last_slot = engine.committed_slot();
    for round in 0..4_u8 {
        let data = vec![round.wrapping_add(1); 20 * 1024]; // 5 x 4 KiB blocks -> L1 indirect block
        let (_, tok) = engine
            .write_file_data(
                &cx,
                &enc_ds,
                file_obj,
                0,
                &data,
                ts,
                ZfsDataChecksum::Sha256,
            )
            .into_result()
            .unwrap();
        last_slot = tok.published_slot();

        let media = devices[0].durable_snapshot();
        let mut mos = open_pool_objects(&cx, &devices, built.pool_guid, last_slot);
        mos.load_key(&cx, &enc_ds, &key1).unwrap();
        let (_, _, l0_bps) =
            inspect_raw_encrypted_file_bps(&cx, &mut mos, &media, &enc_ds, file_obj);
        for (blk_idx, l0_bp) in l0_bps.iter().enumerate() {
            assert!(l0_bp.is_encrypted());
            let pair = (bp_crypt_salt(l0_bp), bp_crypt_iv(l0_bp));
            assert!(
                seen_nonces.insert(pair),
                "duplicate (salt, iv) nonce detected at round {round} block {blk_idx}!"
            );
        }
    }
    assert_eq!(seen_nonces.len(), 20);

    // 3. Fault-cut BEFORE Uberblock during `change_key`: prior key MUST stay valid, new key MUST be rejected!
    let next_call = devices[0].write_calls();
    devices[0].set_fault(DeviceFault::FailWriteOnCall {
        call_index: next_call,
    });
    let failed_rot = engine.change_key(&cx, &enc_ds, &key2, None, None, b"fault-cut-rot");
    assert!(matches!(failed_rot, ZfsTxOutcome::NotCommitted(_)));
    devices[0].set_fault(DeviceFault::None);
    devices[0].state.lock().unwrap().crash_drop_unsynced();
    let mut after_fail_mos = open_pool_objects(&cx, &devices, built.pool_guid, last_slot);
    assert!(matches!(
        after_fail_mos.load_key(&cx, &enc_ds, &key2),
        Err(FfsError::PermissionDenied)
    ));
    after_fail_mos.load_key(&cx, &enc_ds, &key1).unwrap();

    // 4. Planted 1-bit tamper tests on cloned images:
    let clean_img = devices[0].durable_snapshot();
    let mut inspect_mos = open_pool_objects(&cx, &devices, built.pool_guid, last_slot);
    inspect_mos.load_key(&cx, &enc_ds, &key1).unwrap();
    let crypto = inspect_mos
        .dataset_crypto_info(&cx, &enc_ds)
        .unwrap()
        .unwrap();
    let (os_bp, l1_bp, l0_bps) =
        inspect_raw_encrypted_file_bps(&cx, &mut inspect_mos, &clean_img, &enc_ds, file_obj);
    let l0_bp = &l0_bps[0];

    // 4a. Flip 1 bit in encrypted L0 ciphertext payload -> keyed read fails AND scrub detects!
    {
        let mut tampered = clean_img.clone();
        let off = find_dva_physical_offset(l0_bp.data_dvas().unwrap()[0]);
        tampered[off + 17] ^= 0x01;
        let tdev = vec![FaultableMemberDevice::new(tampered)];
        let mut tmos = open_pool_objects(&cx, &tdev, built.pool_guid, last_slot);
        tmos.load_key(&cx, &enc_ds, &key1).unwrap();
        let mut tzpl = tmos.zpl(&cx, &enc_ds).unwrap();
        assert!(tzpl.read(&cx, file_obj, 0, 4096).is_err());
        let scrub = tmos
            .scrub_dataset(&cx, &enc_ds, None, ScrubLimits::default())
            .unwrap();
        assert!(
            !scrub.is_clean(),
            "scrub failed to detect L0 ciphertext bitflip"
        );
    }

    // 4b. Flip 1 bit in indirect block (L1) -> BOTH keyless scrub AND keyed read fail closed!
    {
        let mut tampered = clean_img.clone();
        let off = find_dva_physical_offset(l1_bp.data_dvas().unwrap()[0]);
        tampered[off + 120] ^= 0x80;
        let tdev = vec![FaultableMemberDevice::new(tampered)];
        let mut tmos = open_pool_objects(&cx, &tdev, built.pool_guid, last_slot);
        let keyless_scrub = tmos
            .scrub_dataset(&cx, &enc_ds, None, ScrubLimits::default())
            .unwrap();
        assert!(
            !keyless_scrub.is_clean(),
            "keyless scrub failed to detect L1 indirect tamper"
        );
        tmos.load_key(&cx, &enc_ds, &key1).unwrap();
        let mut tzpl = tmos.zpl(&cx, &enc_ds).unwrap();
        assert!(tzpl.read(&cx, file_obj, 0, 4096).is_err());
    }

    // 4c. Flip 1 bit in `objset_phys_t` `os_portable_mac` / `os_local_mac` -> keyed open MUST reject!
    {
        let mut tampered = clean_img.clone();
        let os_dva = os_bp.data_dvas().unwrap()[0];
        let os_off = find_dva_physical_offset(os_dva);
        tampered[os_off + OBJSET_PORTABLE_MAC_OFFSET] ^= 0x04;
        tampered[os_off + OBJSET_LOCAL_MAC_OFFSET] ^= 0x08;
        let tdev = vec![FaultableMemberDevice::new(tampered)];
        let mut tmos = open_pool_objects(&cx, &tdev, built.pool_guid, last_slot);
        tmos.load_key(&cx, &enc_ds, &key1).unwrap();
        assert!(
            tmos.zpl(&cx, &enc_ds).is_err(),
            "tampered objset_phys_t MAC must fail closed"
        );
    }

    // 4d. Flip 1 bit in `dsl_crypto_key` ZAP physical block -> `load_key` MUST fail closed!
    {
        let mut tampered = clean_img.clone();
        let ck_dn = inspect_mos.object(&cx, crypto.crypto_key_obj).unwrap();
        let ck_dva = ck_dn.pointers()[0].data_dvas().unwrap()[0];
        let ck_off = find_dva_physical_offset(ck_dva);
        tampered[ck_off + 64] ^= 0x20;
        let tdev = vec![FaultableMemberDevice::new(tampered)];
        let mut tmos = open_pool_objects(&cx, &tdev, built.pool_guid, last_slot);
        assert!(
            tmos.load_key(&cx, &enc_ds, &key1).is_err(),
            "tampered dsl_crypto_key ({:?}/{:?}) must fail closed",
            std::str::from_utf8(DSL_DIR_CRYPTO_KEY_OBJ),
            std::str::from_utf8(DSL_CRYPTO_MAC),
        );
    }

    // 4e. Replayed block / swapped `(salt, iv)` / birth-TXG replay MUST fail closed without plaintext fabrication!
    {
        let key = inspect_mos
            .keyring()
            .get(crypto.encryption_root_ddobj)
            .unwrap();
        let l0_0_off = find_dva_physical_offset(l0_bps[0].data_dvas().unwrap()[0]);
        let l0_0_phys = &clean_img[l0_0_off..l0_0_off + l0_bps[0].physical_bytes()];
        // Replaying valid block 1's `(salt, iv, mac)` metadata against block 0's ciphertext fails AEAD MAC.
        assert!(
            decrypt_regular_block(&key, &l0_bps[1], l0_0_phys).is_err(),
            "replayed BlockPointer from sibling block must fail AEAD authentication"
        );
        // Mutating salt/IV inside an otherwise valid BlockPointer fails AEAD authentication.
        let order = l0_bps[0].payload_order();
        let mut mutated_raw = [0_u8; 128];
        for word_idx in 0..16 {
            mutated_raw[word_idx * 8..(word_idx + 1) * 8]
                .copy_from_slice(&order.encode(l0_bps[0].raw_word(word_idx)));
        }
        mutated_raw[4 * 8] ^= 0x01; // flip 1 bit in salt
        let mutated_salt_bp = BlockPointer::parse(&mutated_raw, order).unwrap();
        assert!(
            decrypt_regular_block(&key, &mutated_salt_bp, l0_0_phys).is_err(),
            "mutated salt in BlockPointer must fail AEAD authentication"
        );
        // Swapping valid L0 block 1's BP into L0 block 0's slot on disk inside L1 indirect block
        // fails closed on BOTH keyless scrub AND keyed read!
        let mut replayed_img = clean_img.clone();
        let l1_off = find_dva_physical_offset(l1_bp.data_dvas().unwrap()[0]);
        let bp1_bytes = replayed_img[l1_off + 128..l1_off + 256].to_vec();
        replayed_img[l1_off..l1_off + 128].copy_from_slice(&bp1_bytes);
        let tdev = vec![FaultableMemberDevice::new(replayed_img)];
        let mut tmos = open_pool_objects(&cx, &tdev, built.pool_guid, last_slot);
        let keyless_scrub = tmos
            .scrub_dataset(&cx, &enc_ds, None, ScrubLimits::default())
            .unwrap();
        assert!(
            !keyless_scrub.is_clean(),
            "keyless scrub must reject replayed/swapped L0 slot inside L1 indirect block"
        );
        tmos.load_key(&cx, &enc_ds, &key1).unwrap();
        let mut tzpl = tmos.zpl(&cx, &enc_ds).unwrap();
        assert!(tzpl.read(&cx, file_obj, 0, 4096).is_err());
    }

    // 4f. Truncated ciphertext & forged compressed LZ4 decompression-bomb payload fail closed cleanly!
    {
        let key = inspect_mos
            .keyring()
            .get(crypto.encryption_root_ddobj)
            .unwrap();
        let l0_0_off = find_dva_physical_offset(l0_bps[0].data_dvas().unwrap()[0]);
        let l0_0_phys = &clean_img[l0_0_off..l0_0_off + l0_bps[0].physical_bytes()];
        // Truncated ciphertext slice fails AEAD verification before any decode.
        assert!(
            decrypt_regular_block(&key, &l0_bps[0], &l0_0_phys[..l0_0_phys.len() - 7]).is_err(),
            "truncated encrypted block must fail closed"
        );
        // Even with an authentic AEAD MAC, a malformed/truncated LZ4 decompression payload
        // declaring an invalid compressed length or bomb-like expansion must fail closed without OOM/fabrication.
        let order = l0_bps[0].payload_order();
        let salt = bp_crypt_salt(&l0_bps[0]);
        let iv = bp_crypt_iv(&l0_bps[0]);
        let mut bomb_plain = vec![0_u8; 4096];
        // ZFS LZ4 header = big-endian compressed payload length; 0xFFFF_FFFF exceeds physical buffer (truncated/bomb).
        bomb_plain[0..4].copy_from_slice(&0xFFFF_FFFF_u32.to_be_bytes());
        let (bomb_ct, bomb_mac) = encrypt_regular_block(&key, &salt, &iv, &bomb_plain).unwrap();
        let mut bomb_bp_raw = [0_u8; 128];
        for word_idx in 0..16 {
            bomb_bp_raw[word_idx * 8..(word_idx + 1) * 8]
                .copy_from_slice(&order.encode(l0_bps[0].raw_word(word_idx)));
        }
        // Set compression field (word 6, bits 32..39) to LZ4 (15) and update MAC words[14..16].
        let w6_lz4 = (l0_bps[0].raw_word(6) & !(0x7F_u64 << 32)) | (15_u64 << 32);
        bomb_bp_raw[6 * 8..7 * 8].copy_from_slice(&order.encode(w6_lz4));
        let mac_words = encode_crypt_mac_words(&bomb_mac, order);
        bomb_bp_raw[14 * 8..15 * 8].copy_from_slice(&order.encode(mac_words[0]));
        bomb_bp_raw[15 * 8..16 * 8].copy_from_slice(&order.encode(mac_words[1]));
        let bomb_bp = BlockPointer::parse(&bomb_bp_raw, order).unwrap();
        assert!(
            decrypt_regular_block(&key, &bomb_bp, &bomb_ct).is_err(),
            "malformed/bomb LZ4 payload inside encrypted block must fail closed"
        );
    }

    // 4g. Pre-cancelled `Cx` on create_encrypted_dataset, change_key, and encrypted write MUST
    //     fail closed with `NotCommitted(Cancelled)` and mutate neither disk nor `engine.keyring()`!
    {
        let cancelled = Cx::for_testing();
        cancelled.cancel_with(asupersync::types::CancelKind::User, Some("test cancel"));
        let before_txg = engine.committed_txg();
        let before_slot = engine.committed_slot();
        let before_media = devices[0].durable_snapshot();
        let before_roots = engine.keyring().loaded_roots();

        assert!(matches!(
            engine.create_encrypted_dataset(
                &cancelled,
                &parent_ds,
                b"cancelled_ds",
                &[],
                &ZfsEncryptionCreateOptions {
                    suite: ZioEncrypt::Aes256Gcm,
                    key_material: Some(key2.clone()),
                    keylocation: Some(b"prompt".to_vec()),
                    pbkdf2_iters: None,
                    extra_entropy: b"cancel-create".to_vec(),
                },
                ts,
            ),
            ZfsTxOutcome::NotCommitted(FfsError::Cancelled)
        ));
        assert!(matches!(
            engine.change_key(&cancelled, &enc_ds, &key2, None, None, b"cancel-rot"),
            ZfsTxOutcome::NotCommitted(FfsError::Cancelled)
        ));
        assert!(matches!(
            engine.write_file_data(
                &cancelled,
                &enc_ds,
                file_obj,
                0,
                b"should-not-write",
                ts,
                ZfsDataChecksum::Sha256,
            ),
            ZfsTxOutcome::NotCommitted(FfsError::Cancelled)
        ));

        assert_eq!(engine.committed_txg(), before_txg);
        assert_eq!(engine.committed_slot(), before_slot);
        assert_eq!(devices[0].durable_snapshot(), before_media);
        assert_eq!(engine.keyring().loaded_roots(), before_roots);
    }

    // 4h. `ENOSPC` / `refquota` exhaustion on encrypted dataset MUST fail closed without
    //     corrupting existing ciphertext or evicting valid loaded keys!
    {
        let tight_ds = vec![b"data".to_vec(), b"sec".to_vec(), b"tight".to_vec()];
        let (_, _) = engine
            .create_dataset(
                &cx,
                &enc_ds,
                b"tight",
                &[
                    ("recordsize".to_owned(), ZfsPropertySetValue::Number(4096)),
                    (
                        "refquota".to_owned(),
                        ZfsPropertySetValue::Number(128 * 1024),
                    ),
                ],
                ts,
            )
            .into_result()
            .unwrap();
        let (tight_file, _) = engine
            .create_file(
                &cx,
                &tight_ds,
                2,
                b"keep.bin",
                0o644,
                0,
                0,
                ts,
                ZfsDataChecksum::Sha256,
            )
            .into_result()
            .unwrap();
        let seed_payload = vec![0x5A_u8; 4096];
        let (_, good_tok) = engine
            .write_file_data(
                &cx,
                &tight_ds,
                tight_file,
                0,
                &seed_payload,
                ts,
                ZfsDataChecksum::Sha256,
            )
            .into_result()
            .unwrap();
        let too_big = vec![0xA5_u8; 256 * 1024];
        let oos = engine.write_file_data(
            &cx,
            &tight_ds,
            tight_file,
            0,
            &too_big,
            ts,
            ZfsDataChecksum::Sha256,
        );
        assert!(
            matches!(oos, ZfsTxOutcome::NotCommitted(FfsError::NoSpace)),
            "expected NotCommitted(NoSpace) on encrypted refquota exhaustion, got {oos:?}"
        );
        // Existing encrypted payload and key remain 100% intact after refusal!
        let mut post_mos =
            open_pool_objects(&cx, &devices, built.pool_guid, good_tok.published_slot());
        post_mos.load_key(&cx, &enc_ds, &key1).unwrap();
        let mut post_zpl = post_mos.zpl(&cx, &tight_ds).unwrap();
        assert_eq!(
            post_zpl.read(&cx, tight_file, 0, 4096).unwrap(),
            seed_payload
        );
    }
}
