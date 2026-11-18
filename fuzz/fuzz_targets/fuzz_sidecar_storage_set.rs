#![no_main]

use ffs_repair::decision::{
    evaluate_automatic_repair_gate, AutomaticRepairVerdict, MandatoryRepairPreconditions,
    RepairLossCalibration,
};
use ffs_repair::evidence::{
    parse_evidence_ledger, EvidenceRecord, ProtectedCommitAckDetail, ProtectedRepairGateDetail,
};
use ffs_repair::por::PorKey;
use ffs_repair::sidecar::{
    por_key_id, MemberProtectionBinding, MemberRole, MemberSliceGeometry, NativeCommitBinding,
    ProtectedViewIdentity, ProvenanceAuth, StorageSetManifest, StorageSetTopology, TrustPolicy,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        b
    }

    fn bool(&mut self) -> bool {
        self.u8() & 1 != 0
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(std::array::from_fn(|_| self.u8()))
    }

    fn f64(&mut self) -> f64 {
        f64::from_bits(self.u64())
    }

    fn bytes16(&mut self) -> [u8; 16] {
        std::array::from_fn(|_| self.u8())
    }

    fn bytes32(&mut self) -> [u8; 32] {
        std::array::from_fn(|_| self.u8())
    }
}

fn synth_binding(c: &mut Cursor<'_>) -> NativeCommitBinding {
    match c.u8() % 6 {
        0 => NativeCommitBinding::UninterpretedRaw,
        1 => NativeCommitBinding::Ext4 {
            uuid: c.bytes16(),
            blocks_count: c.u64(),
            journal_uuid: c.bytes16(),
            journal_inum: c.u32(),
            state: c.u16(),
        },
        2 => NativeCommitBinding::Btrfs {
            fsid: c.bytes16(),
            generation: c.u64(),
            root_bytenr: c.u64(),
            chunk_root_bytenr: c.u64(),
            log_root: c.u64(),
            num_devices: u64::from(c.u8() % 4 + 1),
        },
        3 => NativeCommitBinding::Fat {
            kind: if c.bool() {
                "fat32".to_owned()
            } else {
                "fat16".to_owned()
            },
            volume_id: c.u32(),
            total_sectors: c.u64(),
            clean: c.bool(),
        },
        4 => NativeCommitBinding::Ntfs {
            volume_serial: c.u64(),
            volume_bytes: u64::from(c.u32().max(4096)),
            cluster_bytes: 4096,
            record_bytes: 1024,
            index_bytes: 4096,
            mft_cluster: 4,
            mirror_cluster: 8,
            boot_blake3: c.bytes32(),
            transaction_id: c.u32(),
            commit_lsn: c.u64(),
            checkpoint_lsn: c.bool().then(|| c.u64()),
            generation: c.u64(),
            operation_digest: c.bytes32(),
        },
        _ => NativeCommitBinding::Zfs {
            pool_guid: c.u64().max(1),
            top_guid: c.u64().max(1),
            member_guids: vec![c.u64().max(1), c.u64().max(1)],
            guid_sum: c.u64(),
            version: 5000,
            ashift: 9,
            asize: u64::from(c.u32().max(4096)),
            label_txg: c.u64(),
            committed_txg: c.u64(),
            published_slot: u32::from(c.u8() % 128),
            root_bp_blake3: c.bytes32(),
            generation: c.u64(),
            operation_digest: c.bytes32(),
        },
    }
}

fuzz_target!(|data: &[u8]| {
    let bounded = &data[..data.len().min(MAX_INPUT_BYTES)];
    let mut cur = Cursor::new(bounded);
    let key: PorKey = cur.bytes32();
    let mut wrong_key = key;
    wrong_key[0] ^= 0xFF;

    // 1. Arbitrary untrusted manifest decode must never panic and must enforce TrustPolicy.
    let _ = StorageSetManifest::decode(bounded, TrustPolicy::AllowUnauthenticated);
    if let Ok(auth_manifest) =
        StorageSetManifest::decode(bounded, TrustPolicy::RequireTrustedRoot { key })
    {
        assert!(
            auth_manifest.is_authenticated(),
            "RequireTrustedRoot must never admit unauthenticated provenance"
        );
        assert!(
            StorageSetManifest::decode(bounded, TrustPolicy::RequireTrustedRoot { key: wrong_key })
                .is_err(),
            "wrong PorKey must reject an authenticated manifest"
        );
    }

    // 2. Structured StorageSetManifest encode/decode + tamper detection.
    let member_count = usize::from(cur.u8() % 3) + 1;
    let mut members = Vec::with_capacity(member_count);
    for idx in 0..member_count {
        let role = match cur.u8() % 3 {
            0 => MemberRole::Data,
            1 => MemberRole::Log,
            _ => MemberRole::Special,
        };
        let backing = u64::from(cur.u16().max(4096));
        members.push(MemberProtectionBinding {
            member_index: u32::try_from(idx).unwrap(),
            role,
            native_member_id: cur.bytes16(),
            geometry: MemberSliceGeometry {
                backing_bytes: backing,
                offset: 0,
                length: backing,
                block_size: 4096,
                group_blocks: 8,
                repair_symbols: 2,
                groups: 1,
            },
            archive_filename: format!("member-{idx}.ffsrq"),
            header_blake3: cur.bytes32(),
            snapshot_digest: cur.bytes32(),
            tables_root: cur.bytes32(),
        });
    }
    let topology = match cur.u8() % 4 {
        0 => StorageSetTopology::SingleData,
        1 => StorageSetTopology::Ext4WithExternalLog,
        2 => StorageSetTopology::ZfsSingleLeaf,
        _ => StorageSetTopology::ZfsMirror { width: 2 },
    };
    let signed = cur.bool();
    let manifest = StorageSetManifest {
        set_id: cur.bytes16(),
        generation: cur.u64().max(1),
        filesystem: "zfs".to_owned(),
        topology,
        view: ProtectedViewIdentity {
            partition_selector: cur.bool().then(|| "gpt:1".to_owned()),
            zfs_dataset: vec!["data".to_owned()],
            btrfs_subvolume_id: None,
        },
        native_binding: synth_binding(&mut cur),
        members,
        provenance: if signed {
            ProvenanceAuth::AuthenticatedTrustedRoot {
                key_id: por_key_id(&key),
                mac_hex: String::new(),
            }
        } else {
            ProvenanceAuth::UnauthenticatedChecksum
        },
    };
    if let Ok(encoded) = manifest.encode(signed.then_some(&key)) {
        if signed {
            let decoded =
                StorageSetManifest::decode(&encoded, TrustPolicy::RequireTrustedRoot { key })
                    .expect("valid signed manifest must decode with matching key");
            assert_eq!(decoded.generation, manifest.generation);
            assert_eq!(decoded.native_binding, manifest.native_binding);
            assert!(StorageSetManifest::decode(
                &encoded,
                TrustPolicy::RequireTrustedRoot { key: wrong_key },
            )
            .is_err());
            let mut tampered = encoded;
            let flip_at = usize::from(cur.u16()) % tampered.len();
            tampered[flip_at] ^= 0x01;
            assert!(
                StorageSetManifest::decode(&tampered, TrustPolicy::RequireTrustedRoot { key },)
                    .is_err(),
                "any 1-bit tamper in prefix, JSON body, or MAC must fail authenticated decode"
            );
        } else {
            assert!(
                StorageSetManifest::decode(&encoded, TrustPolicy::RequireTrustedRoot { key },)
                    .is_err(),
                "unsigned manifest must fail RequireTrustedRoot"
            );
        }
    }

    // 3. Two-stage expected-loss repair gate invariants: mandatory failures can NEVER be overridden.
    let preconditions = MandatoryRepairPreconditions {
        exclusive_ownership: cur.bool(),
        storage_set_identity_match: cur.bool(),
        native_generation_fresh: cur.bool(),
        group_peer_digests_unchanged: cur.bool(),
        symbol_and_decoded_digests_valid: cur.bool(),
        trusted_root_authenticated: cur.bool(),
        target_prewrite_unchanged: cur.bool(),
    };
    let calibration = cur.bool().then(|| RepairLossCalibration {
        c_repair: cur.f64(),
        l_wrong: cur.f64(),
        l_refusal: cur.f64(),
        q_correct: cur.f64(),
        provenance: "fuzz-cal".to_owned(),
    });
    match evaluate_automatic_repair_gate(&preconditions, calibration.as_ref()) {
        AutomaticRepairVerdict::Authorize {
            expected_repair_loss,
            refusal_loss,
            ..
        } => {
            assert!(
                preconditions.first_failure().is_none(),
                "Authorize verdict requires every mandatory precondition to hold"
            );
            let cal = calibration
                .as_ref()
                .expect("Authorize requires calibration");
            assert!(cal.validate().is_ok());
            assert!(expected_repair_loss < refusal_loss);
        }
        AutomaticRepairVerdict::Refuse { .. } => {}
    }

    // 4. EvidenceRecord JSONL round-trip with ProtectedRepairGateDetail & ProtectedCommitAckDetail.
    let gate_rec = EvidenceRecord::protected_repair_gate(
        0,
        ProtectedRepairGateDetail {
            set_id_hex: "deadbeef".to_owned(),
            member_index: 0,
            generation: 2,
            authenticated_provenance: signed,
            damaged_blocks: 1,
            authorized: true,
            expected_repair_loss: Some(1.5),
            refusal_loss: Some(100.0),
            calibration_provenance: Some("fuzz".to_owned()),
            refusal_reason: None,
        },
    );
    let ack_rec = EvidenceRecord::protected_commit_ack(ProtectedCommitAckDetail {
        set_id_hex: "deadbeef".to_owned(),
        generation: 2,
        native_durable: true,
        protected_durable: cur.bool(),
        unprotected_interval_ns: u64::from(cur.u32()),
        native_token_summary: Some(manifest.native_binding.summary()),
        post_commit_error: None,
    });
    if let (Ok(mut l1), Ok(l2)) = (gate_rec.to_json(), ack_rec.to_json()) {
        l1.push('\n');
        l1.push_str(&l2);
        l1.push('\n');
        let parsed = parse_evidence_ledger(l1.as_bytes());
        assert_eq!(parsed.len(), 2);
    }
});
