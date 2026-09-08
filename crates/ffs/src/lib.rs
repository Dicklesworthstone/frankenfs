#![forbid(unsafe_code)]
//! FrankenFS public API facade.
//!
//! Re-exports core functionality from `ffs-core` through a stable external
//! interface. This is the crate that downstream consumers (CLI, TUI, harness)
//! depend on.

pub use ffs_core::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_options_default_matches_expected_policy() {
        let options = OpenOptions::default();
        assert!(!options.skip_validation);
        assert!(matches!(
            options.ext4_journal_replay_mode,
            Ext4JournalReplayMode::Apply
        ));
        assert_eq!(options.ext4_data_err_policy, Ext4DataErrPolicy::Ignore);
    }

    #[test]
    fn repair_policy_default_is_static_without_autopilot() {
        let policy = RepairPolicy::default();
        assert!(!policy.eager_refresh);
        assert!(policy.autopilot.is_none());
        assert!(policy.autopilot_decision().is_none());
        assert!((policy.effective_overhead() - 1.05).abs() < f64::EPSILON);
    }

    #[test]
    fn detect_filesystem_reports_unsupported_for_empty_image() {
        assert!(matches!(
            detect_filesystem(&[]),
            Err(DetectionError::UnsupportedImage)
        ));
    }

    #[test]
    fn detect_filesystem_reports_unsupported_for_short_image() {
        // A 1024-byte buffer is too short to contain any valid superblock.
        let buf = vec![0u8; 1024];
        assert!(matches!(
            detect_filesystem(&buf),
            Err(DetectionError::UnsupportedImage)
        ));
    }

    #[test]
    fn detection_error_display_formats() {
        let e = DetectionError::UnsupportedImage;
        assert_eq!(
            format!("{e}"),
            "image does not decode as supported ext4/btrfs superblock"
        );
    }

    #[test]
    fn degradation_level_from_raw_all_values() {
        assert_eq!(DegradationLevel::from_raw(0), DegradationLevel::Normal);
        assert_eq!(DegradationLevel::from_raw(1), DegradationLevel::Warning);
        assert_eq!(DegradationLevel::from_raw(2), DegradationLevel::Degraded);
        assert_eq!(DegradationLevel::from_raw(3), DegradationLevel::Critical);
        assert_eq!(DegradationLevel::from_raw(4), DegradationLevel::Emergency);
        // Out-of-range saturates to Emergency.
        assert_eq!(DegradationLevel::from_raw(255), DegradationLevel::Emergency);
    }

    #[test]
    fn degradation_level_labels_match() {
        assert_eq!(DegradationLevel::Normal.label(), "normal");
        assert_eq!(DegradationLevel::Warning.label(), "warning");
        assert_eq!(DegradationLevel::Degraded.label(), "degraded");
        assert_eq!(DegradationLevel::Critical.label(), "critical");
        assert_eq!(DegradationLevel::Emergency.label(), "emergency");
    }

    #[test]
    fn degradation_level_display_matches_label() {
        for raw in 0..=4 {
            let level = DegradationLevel::from_raw(raw);
            assert_eq!(format!("{level}"), level.label());
        }
    }

    #[test]
    fn degradation_level_u8_round_trip() {
        for raw in 0..=4 {
            let level = DegradationLevel::from_raw(raw);
            let val: u8 = level.into();
            assert_eq!(val, raw);
        }
    }

    #[test]
    fn degradation_level_policy_thresholds() {
        // Normal: nothing paused/reduced/throttled/readonly
        assert!(!DegradationLevel::Normal.should_pause_background());
        assert!(!DegradationLevel::Normal.should_reduce_cache());
        assert!(!DegradationLevel::Normal.should_throttle_writes());
        assert!(!DegradationLevel::Normal.should_read_only());

        // Warning: background paused only
        assert!(DegradationLevel::Warning.should_pause_background());
        assert!(!DegradationLevel::Warning.should_reduce_cache());

        // Degraded: background paused + caches reduced
        assert!(DegradationLevel::Degraded.should_reduce_cache());
        assert!(!DegradationLevel::Degraded.should_throttle_writes());

        // Critical: + writes throttled
        assert!(DegradationLevel::Critical.should_throttle_writes());
        assert!(!DegradationLevel::Critical.should_read_only());

        // Emergency: read-only
        assert!(DegradationLevel::Emergency.should_read_only());
    }

    #[test]
    fn request_op_write_classification() {
        // Read operations
        assert!(!RequestOp::Getattr.is_write());
        assert!(!RequestOp::Statfs.is_write());
        assert!(!RequestOp::Getxattr.is_write());
        assert!(!RequestOp::Lookup.is_write());
        assert!(!RequestOp::Listxattr.is_write());
        assert!(!RequestOp::Open.is_write());
        assert!(!RequestOp::Opendir.is_write());
        assert!(!RequestOp::Read.is_write());
        assert!(!RequestOp::Readdir.is_write());
        assert!(!RequestOp::Readlink.is_write());
        assert!(!RequestOp::IoctlRead.is_write());
        assert!(!RequestOp::IoctlRead.is_metadata_write());

        // Write operations
        assert!(RequestOp::Create.is_write());
        assert!(RequestOp::Mkdir.is_write());
        assert!(RequestOp::Unlink.is_write());
        assert!(RequestOp::Rmdir.is_write());
        assert!(RequestOp::Rename.is_write());
        assert!(RequestOp::Link.is_write());
        assert!(RequestOp::Symlink.is_write());
        assert!(RequestOp::Fallocate.is_write());
        assert!(RequestOp::Setattr.is_write());
        assert!(RequestOp::Setxattr.is_write());
        assert!(RequestOp::Removexattr.is_write());
        assert!(RequestOp::Write.is_write());
        assert!(RequestOp::IoctlWrite.is_write());
        assert!(RequestOp::IoctlWrite.is_metadata_write());

        // Non-metadata data writes remain distinct from metadata-only writes.
        assert!(!RequestOp::Write.is_metadata_write());
        assert!(!RequestOp::Fallocate.is_metadata_write());
    }

    #[test]
    fn request_scope_empty_has_no_snapshot_or_tx() {
        let scope = RequestScope::empty();
        assert_eq!(scope.snapshot, None);
        assert_eq!(scope.tx, None);
        assert_eq!(scope, RequestScope::empty());
    }

    #[test]
    fn set_attr_request_default_is_all_none() {
        let req = SetAttrRequest::default();
        assert!(req.mode.is_none());
        assert!(req.uid.is_none());
        assert!(req.gid.is_none());
    }

    #[test]
    fn ext4_journal_replay_modes_are_distinct() {
        assert_ne!(Ext4JournalReplayMode::Apply, Ext4JournalReplayMode::Skip);
        assert_ne!(
            Ext4JournalReplayMode::Apply,
            Ext4JournalReplayMode::SimulateOverlay
        );
        assert_ne!(
            Ext4JournalReplayMode::Skip,
            Ext4JournalReplayMode::SimulateOverlay
        );
    }

    #[test]
    fn durability_posterior_default_is_uninformative() {
        let p = DurabilityPosterior::default();
        assert!((p.alpha - 1.0).abs() < f64::EPSILON);
        assert!((p.beta - 1.0).abs() < f64::EPSILON);
        assert!((p.expected_corruption_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn durability_posterior_observe_clean_blocks() {
        let mut p = DurabilityPosterior::default();
        p.observe_blocks(100, 0);
        // After 100 clean blocks: alpha=1, beta=101
        assert!((p.alpha - 1.0).abs() < f64::EPSILON);
        assert!((p.beta - 101.0).abs() < f64::EPSILON);
        // Expected corruption rate very low
        assert!(p.expected_corruption_rate() < 0.02);
        assert!(p.variance() > 0.0);
    }

    #[test]
    fn durability_posterior_observe_corruption_event() {
        let mut p = DurabilityPosterior::default();
        p.observe_event(true);
        // alpha=2, beta=1
        assert!((p.alpha - 2.0).abs() < f64::EPSILON);
        assert!((p.beta - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn durability_loss_model_default_values() {
        let m = DurabilityLossModel::default();
        assert!((m.corruption_cost - 10_000.0).abs() < f64::EPSILON);
        assert!((m.redundancy_cost - 25.0).abs() < f64::EPSILON);
        assert!((m.z_score - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn durability_autopilot_choose_overhead_default() {
        let ap = DurabilityAutopilot::new();
        let candidates: Vec<f64> = (1..=10).map(|i| f64::from(i).mul_add(0.01, 1.0)).collect();
        let decision = ap.choose_overhead(&candidates);
        // With uninformative prior, should choose some valid overhead in [1.03, 1.10]
        assert!(decision.repair_overhead >= 1.03);
        assert!(decision.repair_overhead <= 1.10);
    }

    #[test]
    fn repair_policy_with_autopilot_overrides_static() {
        let mut policy = RepairPolicy::default();
        assert!(policy.autopilot_decision().is_none());

        let mut ap = DurabilityAutopilot::new();
        // Observe lots of clean blocks so autopilot picks low overhead
        ap.observe_scrub(10_000, 0);
        policy.autopilot = Some(ap);

        assert!(policy.autopilot_decision().is_some());
        let overhead = policy.effective_overhead();
        assert!(overhead >= 1.03);
        assert!(overhead <= 1.10);
    }

    #[test]
    fn check_verdict_and_integrity_report_constructable() {
        let verdict = CheckVerdict {
            component: "superblock".to_string(),
            passed: true,
            detail: String::new(),
        };
        assert!(verdict.passed);

        let report = IntegrityReport {
            verdicts: vec![verdict],
            passed: 100,
            failed: 0,
            posterior_alpha: 1.0,
            posterior_beta: 101.0,
            expected_corruption_rate: 0.0098,
            upper_bound_corruption_rate: 0.005,
            healthy: true,
        };
        assert!(report.healthy);
        // prob_healthy returns a valid probability in [0, 1]
        let p = report.prob_healthy(0.05);
        assert!((0.0..=1.0).contains(&p));
    }

    #[test]
    fn integrity_report_log_bayes_factor_healthy() {
        let report = IntegrityReport {
            verdicts: Vec::new(),
            passed: 100,
            failed: 0,
            posterior_alpha: 1.0,
            posterior_beta: 101.0,
            expected_corruption_rate: 0.0098,
            upper_bound_corruption_rate: 0.005,
            healthy: true,
        };
        // Positive bayes factor = evidence favors health
        let lbf = report.log_bayes_factor();
        assert!(lbf > 0.0, "expected positive log bayes factor, got {lbf}");
    }

    #[test]
    fn fs_stat_is_constructable() {
        let stat = FsStat {
            blocks: 100_000,
            blocks_free: 50_000,
            blocks_available: 48_000,
            files: 10_000,
            files_free: 5_000,
            block_size: 4096,
            name_max: 255,
            fragment_size: 4096,
        };
        assert_eq!(stat.blocks, 100_000);
        assert_eq!(stat.name_max, 255);
    }

    #[test]
    fn file_type_variants_exist() {
        let types = [
            FileType::RegularFile,
            FileType::Directory,
            FileType::Symlink,
            FileType::BlockDevice,
            FileType::CharDevice,
            FileType::Fifo,
            FileType::Socket,
        ];
        assert_eq!(types.len(), 7);
    }

    #[test]
    fn frankenfs_engine_default_is_constructable() {
        let engine = FrankenFsEngine::new();
        let debug = format!("{engine:?}");
        assert!(debug.contains("FrankenFsEngine"));
    }

    #[test]
    fn ext4_geometry_is_constructable() {
        const EXT4_GEOMETRY_DEBUG_GOLDEN: &str = "Ext4Geometry { block_size: 4096, inodes_count: 8192, inodes_per_group: 1024, first_ino: 11, inode_size: 256, groups_count: 8, group_desc_size: 64, csum_seed: 3735928559, uuid: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], is_64bit: true, has_metadata_csum: true, group_desc_checksum_kind: MetadataCsum }";

        let geo = Ext4Geometry {
            block_size: 4096,
            inodes_count: 8192,
            inodes_per_group: 1024,
            first_ino: 11,
            inode_size: 256,
            groups_count: 8,
            group_desc_size: 64,
            csum_seed: 0xDEAD_BEEF,
            uuid: [0; 16],
            is_64bit: true,
            has_metadata_csum: true,
            group_desc_checksum_kind: ffs_ondisk::ext4::Ext4GroupDescChecksumKind::MetadataCsum,
        };
        let debug = format!("{geo:?}");
        assert_eq!(debug, EXT4_GEOMETRY_DEBUG_GOLDEN);
    }

    #[test]
    fn redundancy_decision_to_raptorq_config() {
        let decision = RedundancyDecision {
            repair_overhead: 1.05,
            expected_loss: 0.01,
            posterior_mean_corruption_rate: 0.001,
            posterior_hi_corruption_rate: 0.005,
            unrecoverable_risk_bound: 0.0001,
            redundancy_loss: 0.5,
            corruption_loss: 100.0,
        };
        let cfg = decision.to_raptorq_config(4096);
        assert!((cfg.encoding.repair_overhead - 1.05).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_budget_samples_and_returns_headroom() {
        let pressure = std::sync::Arc::new(asupersync::SystemPressure::default());
        let budget = ComputeBudget::new(std::sync::Arc::clone(&pressure));
        let h = budget.sample();
        assert!((0.0..=1.0).contains(&h));
        assert!((0.0..=1.0).contains(&budget.current_headroom()));
    }

    #[test]
    fn backpressure_gate_reads_proceed_at_all_levels() {
        let pressure = std::sync::Arc::new(asupersync::SystemPressure::default());
        let fsm = std::sync::Arc::new(DegradationFsm::new(pressure, 3));
        let gate = BackpressureGate::new(fsm);

        // Default level should be Normal
        assert_eq!(gate.level(), DegradationLevel::Normal);
        // Reads always proceed at Normal
        assert!(matches!(
            gate.check(RequestOp::Read),
            BackpressureDecision::Proceed
        ));
    }

    #[test]
    fn ext4_free_space_summary_is_constructable() {
        let summary = Ext4FreeSpaceSummary {
            free_blocks_total: 5000,
            free_inodes_total: 2000,
            gd_free_blocks_total: 5000,
            gd_free_inodes_total: 2000,
            blocks_mismatch: false,
            inodes_mismatch: false,
        };
        assert!(!summary.blocks_mismatch);
        assert_eq!(summary.free_blocks_total, summary.gd_free_blocks_total);
    }

    #[test]
    fn ext4_orphan_list_is_constructable() {
        let orphans = Ext4OrphanList {
            head: 0,
            inodes: Vec::new(),
        };
        assert_eq!(orphans.head, 0);
        assert_eq!(orphans.inodes.len(), 0);
    }

    #[test]
    fn representative_public_diagnostics_exact_golden_contract() {
        let verdict = CheckVerdict {
            component: "superblock".to_string(),
            passed: true,
            detail: String::new(),
        };
        let report = IntegrityReport {
            verdicts: vec![verdict.clone()],
            passed: 100,
            failed: 0,
            posterior_alpha: 1.0,
            posterior_beta: 101.0,
            expected_corruption_rate: 0.0098,
            upper_bound_corruption_rate: 0.005,
            healthy: true,
        };
        let stat = FsStat {
            blocks: 100_000,
            blocks_free: 50_000,
            blocks_available: 48_000,
            files: 10_000,
            files_free: 5_000,
            block_size: 4096,
            name_max: 255,
            fragment_size: 4096,
        };
        let geo = Ext4Geometry {
            block_size: 4096,
            inodes_count: 8192,
            inodes_per_group: 1024,
            first_ino: 11,
            inode_size: 256,
            groups_count: 8,
            group_desc_size: 64,
            csum_seed: 0xDEAD_BEEF,
            uuid: [0; 16],
            is_64bit: true,
            has_metadata_csum: true,
            group_desc_checksum_kind: ffs_ondisk::ext4::Ext4GroupDescChecksumKind::MetadataCsum,
        };
        let summary = Ext4FreeSpaceSummary {
            free_blocks_total: 5000,
            free_inodes_total: 2000,
            gd_free_blocks_total: 5000,
            gd_free_inodes_total: 2000,
            blocks_mismatch: false,
            inodes_mismatch: false,
        };
        let orphans = Ext4OrphanList {
            head: 42,
            inodes: Vec::new(),
        };

        let actual = format!(
            "{}\n{}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}",
            DetectionError::UnsupportedImage,
            DegradationLevel::Critical,
            verdict,
            report,
            stat,
            geo,
            summary,
            orphans,
        );

        let expected = "\
image does not decode as supported ext4/btrfs superblock
critical
CheckVerdict { component: \"superblock\", passed: true, detail: \"\" }
IntegrityReport { verdicts: [CheckVerdict { component: \"superblock\", passed: true, detail: \"\" }], passed: 100, failed: 0, posterior_alpha: 1.0, posterior_beta: 101.0, expected_corruption_rate: 0.0098, upper_bound_corruption_rate: 0.005, healthy: true }
FsStat { blocks: 100000, blocks_free: 50000, blocks_available: 48000, files: 10000, files_free: 5000, block_size: 4096, name_max: 255, fragment_size: 4096 }
Ext4Geometry { block_size: 4096, inodes_count: 8192, inodes_per_group: 1024, first_ino: 11, inode_size: 256, groups_count: 8, group_desc_size: 64, csum_seed: 3735928559, uuid: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], is_64bit: true, has_metadata_csum: true, group_desc_checksum_kind: MetadataCsum }
Ext4FreeSpaceSummary { free_blocks_total: 5000, free_inodes_total: 2000, gd_free_blocks_total: 5000, gd_free_inodes_total: 2000, blocks_mismatch: false, inodes_mismatch: false }
Ext4OrphanList { head: 42, inodes: [] }";

        assert_eq!(actual, expected);
    }

    #[test]
    fn xattr_set_mode_variants_exist() {
        // Verify all three variants are accessible through the facade
        assert_ne!(
            std::mem::discriminant(&XattrSetMode::Set),
            std::mem::discriminant(&XattrSetMode::Create)
        );
        assert_ne!(
            std::mem::discriminant(&XattrSetMode::Create),
            std::mem::discriminant(&XattrSetMode::Replace)
        );
    }

    #[test]
    fn pressure_monitor_samples_without_panic() {
        let pressure = std::sync::Arc::new(asupersync::SystemPressure::default());
        let monitor = PressureMonitor::new(pressure, 3);
        let transition = monitor.sample();
        // May or may not transition, but should not panic
        assert!(
            transition.is_none() || transition.is_some(),
            "sample returned valid option"
        );
    }

    #[test]
    fn fiemap_extent_type_is_accessible_through_facade() {
        let extent = FiemapExtent {
            logical: 0,
            physical: 4096,
            length: 8192,
            flags: FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_UNWRITTEN,
        };
        assert_eq!(extent.logical, 0);
        assert_eq!(extent.physical, 4096);
        assert_eq!(extent.length, 8192);
        assert_ne!(extent.flags & FIEMAP_EXTENT_LAST, 0);
        assert_ne!(extent.flags & FIEMAP_EXTENT_UNWRITTEN, 0);
    }
}
