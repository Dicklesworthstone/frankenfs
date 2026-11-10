//! Bounded allocation diagnostics from the shared native NTFS library.

use super::{Cx, ImageArgs, Result, bail, json};
use clap::Args;
use ffs_ntfs::reader::allocation::{
    AllocationLimits, AllocationReport, MftMirrorReport, NamespaceLimits, NamespaceReport,
    RecordOwnershipLimits, RecordOwnershipReport,
};
use serde_json::{Value, json as value};

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("structural_check")
    .args(["verify_record_ownership", "verify_namespace", "verify_mft_mirror"])
    .multiple(true)))]
pub struct AllocationArgs {
    #[command(flatten)]
    image: ImageArgs,
    /// Maximum logical MFT record slots, checked before bitmap materialization.
    #[arg(long, default_value_t = 1_048_576, value_parser = clap::value_parser!(u64).range(1..=16_777_216))]
    max_records: u64,
    /// Maximum volume clusters, not a promise to check an arbitrary prefix.
    #[arg(long, default_value_t = 33_554_432, value_parser = clap::value_parser!(u64).range(1..=268_435_456))]
    max_clusters: u64,
    /// Maximum decoded mapping runs, including sparse holes.
    #[arg(long, default_value_t = 1_048_576, value_parser = clap::value_parser!(u64).range(1..=1_048_576))]
    max_runs: u64,
    /// Also validate allocated FILE extensions against their base ATTRIBUTE_LIST catalogs.
    #[arg(long)]
    verify_record_ownership: bool,
    /// Also reconcile FILE_NAME links with native directory indexes and root reachability.
    #[arg(long)]
    verify_namespace: bool,
    /// Also compare the complete declared MFT mirror with the corresponding primary records.
    #[arg(long)]
    verify_mft_mirror: bool,
    /// Maximum FILE_NAME and directory-index identities for namespace checking.
    #[arg(long, requires = "verify_namespace", value_parser = clap::value_parser!(u64).range(1..=16_777_216))]
    max_namespace_entries: Option<u64>,
    /// Metadata work cap for each selected structural check; defaults to one GiB each.
    #[arg(long, requires = "structural_check", value_parser = clap::value_parser!(u64).range(1..=1_099_511_627_776))]
    max_metadata_bytes: Option<u64>,
}

impl AllocationArgs {
    fn preflight(&self) -> Result<AllocationLimits> {
        if self.image.sidecar.is_some() || self.image.recover_logfile {
            bail!(
                "allocation checking requires original image bytes without a sidecar or recovery overlay"
            );
        }
        if self.max_metadata_bytes.is_some()
            && !self.verify_record_ownership
            && !self.verify_namespace
            && !self.verify_mft_mirror
        {
            bail!("--max-metadata-bytes requires a selected structural check");
        }
        if self.max_namespace_entries.is_some() && !self.verify_namespace {
            bail!("--max-namespace-entries requires --verify-namespace");
        }
        let limits = AllocationLimits {
            records: self.max_records,
            clusters: self.max_clusters,
            runs: usize::try_from(self.max_runs)?,
        };
        limits.validate()?;
        Ok(limits)
    }

    fn ownership_limits(&self) -> Result<Option<RecordOwnershipLimits>> {
        if !self.verify_record_ownership {
            return Ok(None);
        }
        let limits = RecordOwnershipLimits {
            records: self.max_records,
            metadata_bytes: self
                .max_metadata_bytes
                .unwrap_or_else(|| RecordOwnershipLimits::default().metadata_bytes),
        };
        limits.validate()?;
        Ok(Some(limits))
    }

    fn namespace_limits(&self) -> Result<Option<NamespaceLimits>> {
        if !self.verify_namespace {
            return Ok(None);
        }
        let defaults = NamespaceLimits::default();
        let limits = NamespaceLimits {
            records: self.max_records,
            metadata_bytes: self.max_metadata_bytes.unwrap_or(defaults.metadata_bytes),
            entries: self.max_namespace_entries.unwrap_or(defaults.entries),
        };
        limits.validate()?;
        Ok(Some(limits))
    }

    fn mirror_limits(&self) -> Result<Option<RecordOwnershipLimits>> {
        if !self.verify_mft_mirror {
            return Ok(None);
        }
        let limits = RecordOwnershipLimits {
            records: self.max_records,
            metadata_bytes: self
                .max_metadata_bytes
                .unwrap_or_else(|| RecordOwnershipLimits::default().metadata_bytes),
        };
        limits.validate()?;
        Ok(Some(limits))
    }
}

fn report_json(report: &AllocationReport, offset: u64) -> Value {
    let issues: Vec<_> = report
        .issues
        .iter()
        .map(|issue| {
            value!({
                "category": issue.category,
                "record": issue.record,
                "attribute_id": issue.attribute_id,
                "other_record": issue.other_record,
                "other_attribute_id": issue.other_attribute_id,
                "first_cluster": issue.first_cluster,
                "clusters": issue.clusters,
                "detail": issue.detail,
            })
        })
        .collect();
    let counts = value!({
        "initialized_mft_records": report.initialized_records,
        "logical_mft_records": report.logical_records,
        "volume_clusters": report.volume_clusters,
        "record_slots_examined": report.record_slots_examined,
        "allocated_records_examined": report.allocated_records_examined,
        "extension_records_examined": report.extension_records_examined,
        "attributes_examined": report.attributes_examined,
        "runs_examined": report.runs_examined,
        "sparse_clusters": report.sparse_clusters,
        "referenced_clusters": report.referenced_clusters,
        "bitmap_allocated_clusters": report.bitmap_allocated_clusters,
        "bitmap_free_clusters": report.bitmap_free_clusters,
        "cross_linked_clusters": report.cross_linked_clusters,
        "referenced_free_clusters": report.referenced_free_clusters,
    });
    value!({
        "format": "NTFS",
        "operation": "check_allocation",
        "scope": "allocated_mft_record_physical_runs",
        "read_only": true,
        "backing_writes": false,
        "replay_performed": false,
        "repair_performed": false,
        "volume_offset": offset,
        "allocation_consistent": report.is_consistent(),
        "complete": report.complete,
        "limit_reached": report.limit_reached,
        "counts": counts,
        "allocated_without_reference": report.allocated_without_reference,
        "errors": report.errors,
        "unsupported": report.unsupported,
        "issues": issues,
        "omitted_issues": report.omitted_issues,
        "reclaimable_clusters": null,
        "not_checked": [
            "journal state, hibernation and native recovery",
            "unallocated FILE headers and MFT bitmap completeness",
            "directory indexes, links and namespace reachability",
            "ATTRIBUTE_LIST semantics and complete logical stream assembly",
            "file payload, compression and encryption validity",
            "security descriptors, secondary indexes and full MFT mirror coverage"
        ]
    })
}

fn outcome(report: &AllocationReport) -> Result<()> {
    if !report.is_consistent() {
        bail!(
            "NTFS allocation discrepancies or incomplete coverage; see the JSON report; no repair performed"
        );
    }
    Ok(())
}

fn combined_json(
    report: &AllocationReport,
    ownership: Option<&RecordOwnershipReport>,
    namespace: Option<&NamespaceReport>,
    offset: u64,
) -> Value {
    let mut output = report_json(report, offset);
    output["requested_checks_consistent"] = (report.is_consistent()
        && ownership.is_none_or(RecordOwnershipReport::is_consistent)
        && namespace.is_none_or(NamespaceReport::is_consistent))
    .into();
    let ownership_json =
        ownership.map_or_else(
            || Value::Null,
            |report| {
                output["not_checked"][3] =
                    "complete logical stream assembly beyond catalog identity".into();
                let issues: Vec<_> = report.issues.iter().map(|issue| value!({
                "category": issue.category, "record": issue.record, "detail": issue.detail,
            })).collect();
                value!({
                    "scope": "allocated_mft_base_extension_catalogs",
                    "consistent": report.is_consistent(),
                    "complete": report.complete,
                    "limit_reached": report.limit_reached,
                    "logical_records": report.logical_records,
                    "initialized_records": report.initialized_records,
                    "record_slots_examined": report.record_slots_examined,
                    "base_records_examined": report.base_records_examined,
                    "extension_records_examined": report.extension_records_examined,
                    "referenced_extension_records": report.referenced_extension_records,
                    "metadata_bytes_attempted": report.metadata_bytes_attempted,
                    "extensions_without_owner": report.extensions_without_owner,
                    "errors": report.errors,
                    "unsupported": report.unsupported,
                    "issues": issues,
                    "omitted_issues": report.omitted_issues,
                    "reclaimable_records": null,
                })
            },
        );
    output["record_ownership"] = ownership_json;
    let namespace_json = namespace.map_or_else(
        || Value::Null,
        |report| {
            output["not_checked"][2] = "DOS alias pairing and non-I30 secondary indexes".into();
            let issues: Vec<_> = report
                .issues
                .iter()
                .map(|issue| {
                    value!({
                        "category": issue.category,
                        "record": issue.record,
                        "attribute_id": issue.attribute_id,
                        "other_record": issue.other_record,
                        "detail": issue.detail,
                    })
                })
                .collect();
            value!({
                "scope": "allocated_base_file_names_and_i30_indexes",
                "consistent": report.is_consistent(),
                "complete": report.complete,
                "limit_reached": report.limit_reached,
                "logical_records": report.logical_records,
                "initialized_records": report.initialized_records,
                "record_slots_examined": report.record_slots_examined,
                "base_records_examined": report.base_records_examined,
                "directories_examined": report.directories_examined,
                "file_names_examined": report.file_names_examined,
                "index_entries_examined": report.index_entries_examined,
                "metadata_bytes_attempted": report.metadata_bytes_attempted,
                "missing_index_entries": report.missing_index_entries,
                "unreachable_records": report.unreachable_records,
                "errors": report.errors,
                "unsupported": report.unsupported,
                "issues": issues,
                "omitted_issues": report.omitted_issues,
                "reclaimable_records": null,
            })
        },
    );
    output["namespace"] = namespace_json;
    output
}

fn ownership_outcome(report: Option<&RecordOwnershipReport>) -> Result<()> {
    if report.is_some_and(|report| !report.is_consistent()) {
        bail!(
            "NTFS record ownership discrepancies or incomplete coverage; see the JSON report; no repair performed"
        );
    }
    Ok(())
}

fn namespace_outcome(report: Option<&NamespaceReport>) -> Result<()> {
    if report.is_some_and(|report| !report.is_consistent()) {
        bail!(
            "NTFS namespace discrepancies or incomplete coverage; see the JSON report; no repair performed"
        );
    }
    Ok(())
}

fn add_mirror_json(output: &mut Value, mirror: Option<&MftMirrorReport>) {
    output["requested_checks_consistent"] = (output["requested_checks_consistent"]
        .as_bool()
        .unwrap_or(false)
        && mirror.is_none_or(MftMirrorReport::is_consistent))
    .into();
    let Some(report) = mirror else {
        output["mft_mirror"] = Value::Null;
        return;
    };
    output["not_checked"][5] = "security descriptors and secondary indexes".into();
    let issues: Vec<_> = report
        .issues
        .iter()
        .map(|issue| {
            value!({
                "category": issue.category,
                "record": issue.record,
                "detail": issue.detail,
            })
        })
        .collect();
    output["mft_mirror"] = value!({
        "scope": "mftmirr_declared_record_prefix",
        "consistent": report.is_consistent(),
        "complete": report.complete,
        "limit_reached": report.limit_reached,
        "declared_records": report.declared_records,
        "record_pairs_examined": report.record_pairs_examined,
        "matching_records": report.matching_records,
        "different_records": report.different_records,
        "required_prefix_records": 4,
        "required_prefix_matches": report.required_prefix_matches,
        "extended_record_differences": report.extended_record_differences,
        "extended_tail_policy": "differences beyond record 3 do not alone establish corruption on Windows big-cluster volumes",
        "metadata_bytes_attempted": report.metadata_bytes_attempted,
        "errors": report.errors,
        "unsupported": report.unsupported,
        "issues": issues,
        "omitted_issues": report.omitted_issues,
        "repair_source": null,
    });
}

fn mirror_outcome(report: Option<&MftMirrorReport>) -> Result<()> {
    if report.is_some_and(|report| !report.is_consistent()) {
        bail!(
            "NTFS MFT mirror differences or incomplete coverage; see the JSON report; neither copy selected for repair"
        );
    }
    Ok(())
}

pub fn run(cx: &Cx, args: &AllocationArgs) -> Result<()> {
    cx.checkpoint()
        .map_err(|_| ffs_error::FfsError::Cancelled)?;
    let limits = args.preflight()?;
    let ownership_limits = args.ownership_limits()?;
    let namespace_limits = args.namespace_limits()?;
    let mirror_limits = args.mirror_limits()?;
    let volume = args.image.open(cx)?;
    let report = volume.check_allocations(cx, limits)?;
    let ownership = ownership_limits
        .map(|limits| volume.check_record_ownership(cx, limits))
        .transpose()?;
    let namespace = namespace_limits
        .map(|limits| volume.check_namespace(cx, limits))
        .transpose()?;
    let mirror = mirror_limits
        .map(|limits| volume.check_mft_mirror(cx, limits))
        .transpose()?;
    cx.checkpoint()
        .map_err(|_| ffs_error::FfsError::Cancelled)?;
    let mut output = combined_json(
        &report,
        ownership.as_ref(),
        namespace.as_ref(),
        args.image.offset,
    );
    add_mirror_json(&mut output, mirror.as_ref());
    json(&output)?;
    outcome(&report)?;
    ownership_outcome(ownership.as_ref())?;
    namespace_outcome(namespace.as_ref())?;
    mirror_outcome(mirror.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;
    use ffs_ntfs::reader::allocation::AllocationIssue;

    #[test]
    fn mirror_cli_selects_independent_bounded_work_and_can_combine_checks() {
        for others in [false, true] {
            let mut args = vec![
                "ffs-ntfs",
                "check-allocation",
                "unopened.img",
                "--offline-image",
                "--verify-mft-mirror",
                "--max-records",
                "4096",
                "--max-metadata-bytes",
                "8388608",
            ];
            if others {
                args.extend(["--verify-namespace", "--verify-record-ownership"]);
            }
            let cli = Cli::try_parse_from(args).unwrap();
            let Command::CheckAllocation { options } = cli.command else {
                panic!("allocation");
            };
            options.preflight().unwrap();
            let limits = options.mirror_limits().unwrap().unwrap();
            assert_eq!((limits.records, limits.metadata_bytes), (4096, 8_388_608));
            assert_eq!(options.ownership_limits().unwrap().is_some(), others);
            assert_eq!(options.namespace_limits().unwrap().is_some(), others);
        }
        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                "check-allocation",
                "unopened.img",
                "--offline-image",
                "--verify-mft-mirror",
                "--max-metadata-bytes",
                "0",
            ])
            .is_err()
        );
    }

    #[test]
    fn mirror_cli_refuses_sidecars_and_recovery_before_opening() {
        for extra in [vec!["--recover-logfile"], vec!["--sidecar", "unopened.rq"]] {
            let cli = Cli::try_parse_from(
                [
                    "ffs-ntfs",
                    "check-allocation",
                    "unopened.img",
                    "--offline-image",
                    "--verify-mft-mirror",
                ]
                .into_iter()
                .chain(extra),
            )
            .unwrap();
            let Command::CheckAllocation { options } = cli.command else {
                panic!("allocation");
            };
            assert!(
                run(&Cx::for_testing(), &options)
                    .unwrap_err()
                    .to_string()
                    .contains("without a sidecar or recovery overlay")
            );
        }
    }

    #[test]
    fn mirror_report_never_conflates_a_required_prefix_with_full_equivalence_or_repair() {
        let allocation = AllocationReport {
            complete: true,
            allocated_without_reference: Some(0),
            ..AllocationReport::default()
        };
        let mut output = combined_json(&allocation, None, None, 1024);
        add_mirror_json(&mut output, None);
        assert!(output["mft_mirror"].is_null());
        assert!(mirror_outcome(None).is_ok());
        let mut report = MftMirrorReport::default();
        add_mirror_json(&mut output, Some(&report));
        assert_eq!(output["requested_checks_consistent"], false);
        assert!(output["mft_mirror"]["required_prefix_matches"].is_null());
        assert!(mirror_outcome(Some(&report)).is_err());
        report.complete = true;
        report.declared_records = 8;
        report.record_pairs_examined = 8;
        report.matching_records = 8;
        report.required_prefix_matches = Some(true);
        let mut output = combined_json(&allocation, None, None, 1024);
        add_mirror_json(&mut output, Some(&report));
        assert_eq!(output["requested_checks_consistent"], true);
        assert!(mirror_outcome(Some(&report)).is_ok());
        report.matching_records = 7;
        report.different_records = 1;
        report.extended_record_differences = 1;
        add_mirror_json(&mut output, Some(&report));
        assert_eq!(output["requested_checks_consistent"], false);
        assert_eq!(output["mft_mirror"]["required_prefix_matches"], true);
        assert_eq!(output["mft_mirror"]["extended_record_differences"], 1);
        assert_eq!(output["mft_mirror"]["errors"], 0);
        assert!(output["mft_mirror"]["repair_source"].is_null());
        assert!(mirror_outcome(Some(&report)).is_err());
    }

    #[test]
    fn namespace_cli_selects_bounded_work_independently_or_with_record_ownership() {
        let base = [
            "ffs-ntfs",
            "check-allocation",
            "unopened.img",
            "--offline-image",
        ];
        for also_ownership in [false, true] {
            let mut arguments = base.to_vec();
            arguments.extend([
                "--verify-namespace",
                "--max-records",
                "4096",
                "--max-metadata-bytes",
                "8388608",
                "--max-namespace-entries",
                "16384",
            ]);
            if also_ownership {
                arguments.push("--verify-record-ownership");
            }
            let cli = Cli::try_parse_from(arguments).unwrap();
            let Command::CheckAllocation { options } = cli.command else {
                panic!("allocation");
            };
            options.preflight().unwrap();
            let limits = options.namespace_limits().unwrap().unwrap();
            assert_eq!(limits.records, 4096);
            assert_eq!(limits.metadata_bytes, 8_388_608);
            assert_eq!(limits.entries, 16_384);
            let ownership = options.ownership_limits().unwrap();
            assert_eq!(ownership.is_some(), also_ownership);
            if let Some(ownership) = ownership {
                assert_eq!(ownership.metadata_bytes, 8_388_608);
            }
        }
        let cli = Cli::try_parse_from(base).unwrap();
        let Command::CheckAllocation { options } = cli.command else {
            panic!("allocation");
        };
        assert!(options.namespace_limits().unwrap().is_none());
        for extra in [
            vec!["--max-namespace-entries", "1024"],
            vec![
                "--verify-record-ownership",
                "--max-namespace-entries",
                "1024",
            ],
            vec!["--verify-namespace", "--max-namespace-entries", "0"],
            vec!["--verify-namespace", "--max-namespace-entries", "16777217"],
            vec!["--verify-namespace", "--max-metadata-bytes", "0"],
        ] {
            assert!(Cli::try_parse_from(base.into_iter().chain(extra)).is_err());
        }
    }

    #[test]
    fn namespace_cli_refuses_recovery_and_sidecars_before_opening_sources() {
        for extra in [vec!["--recover-logfile"], vec!["--sidecar", "unopened.rq"]] {
            let cli = Cli::try_parse_from(
                [
                    "ffs-ntfs",
                    "check-allocation",
                    "unopened.img",
                    "--offline-image",
                    "--verify-namespace",
                ]
                .into_iter()
                .chain(extra),
            )
            .unwrap();
            let Command::CheckAllocation { options } = cli.command else {
                panic!("allocation");
            };
            assert!(
                run(&Cx::for_testing(), &options)
                    .unwrap_err()
                    .to_string()
                    .contains("without a sidecar or recovery overlay")
            );
        }
    }

    #[test]
    fn namespace_report_preserves_unknown_results_and_never_grants_reclamation() {
        let allocation = AllocationReport {
            complete: true,
            allocated_without_reference: Some(0),
            ..AllocationReport::default()
        };
        assert!(combined_json(&allocation, None, None, 1024)["namespace"].is_null());
        assert!(namespace_outcome(None).is_ok());
        let mut namespace = NamespaceReport::default();
        let report = combined_json(&allocation, None, Some(&namespace), 1024);
        assert_eq!(report["allocation_consistent"], true);
        assert_eq!(report["requested_checks_consistent"], false);
        assert!(report["namespace"]["missing_index_entries"].is_null());
        assert!(report["namespace"]["unreachable_records"].is_null());
        assert!(report["namespace"]["reclaimable_records"].is_null());
        assert!(namespace_outcome(Some(&namespace)).is_err());
        namespace.complete = true;
        namespace.missing_index_entries = Some(0);
        namespace.unreachable_records = Some(0);
        assert!(namespace_outcome(Some(&namespace)).is_ok());
        assert_eq!(
            combined_json(&allocation, None, Some(&namespace), 1024)["requested_checks_consistent"],
            true
        );
        namespace.errors = 1;
        namespace.missing_index_entries = Some(1);
        assert!(namespace_outcome(Some(&namespace)).is_err());
        assert_eq!(
            combined_json(&allocation, None, Some(&namespace), 1024)["requested_checks_consistent"],
            false
        );
        namespace.errors = 0;
        namespace.missing_index_entries = Some(0);
        namespace.complete = false;
        namespace.limit_reached = Some("metadata work budget");
        assert!(namespace_outcome(Some(&namespace)).is_err());
        assert_eq!(
            combined_json(&allocation, None, Some(&namespace), 1024)["namespace"]["limit_reached"],
            "metadata work budget"
        );
    }

    #[test]
    fn record_ownership_cli_is_explicit_and_preserves_independent_limits() {
        let base = [
            "ffs-ntfs",
            "check-allocation",
            "unopened.img",
            "--offline-image",
        ];
        let cli = Cli::try_parse_from(base).unwrap();
        let Command::CheckAllocation { options } = cli.command else {
            panic!("allocation");
        };
        assert!(options.ownership_limits().unwrap().is_none());
        let cli = Cli::try_parse_from(base.into_iter().chain([
            "--verify-record-ownership",
            "--max-records",
            "4096",
            "--max-metadata-bytes",
            "8388608",
        ]))
        .unwrap();
        let Command::CheckAllocation { options } = cli.command else {
            panic!("allocation");
        };
        let limits = options.ownership_limits().unwrap().unwrap();
        assert_eq!((limits.records, limits.metadata_bytes), (4096, 8_388_608));
        assert!(
            Cli::try_parse_from(base.into_iter().chain(["--max-metadata-bytes", "1024"])).is_err()
        );
        for value in ["0", "1099511627777"] {
            assert!(
                Cli::try_parse_from(base.into_iter().chain([
                    "--verify-record-ownership",
                    "--max-metadata-bytes",
                    value,
                ]))
                .is_err()
            );
        }
    }

    #[test]
    fn record_ownership_cli_refuses_transformed_sources_before_io() {
        for extra in [vec!["--recover-logfile"], vec!["--sidecar", "unopened.rq"]] {
            let cli = Cli::try_parse_from(
                [
                    "ffs-ntfs",
                    "check-allocation",
                    "unopened.img",
                    "--offline-image",
                    "--verify-record-ownership",
                ]
                .into_iter()
                .chain(extra),
            )
            .unwrap();
            let Command::CheckAllocation { options } = cli.command else {
                panic!("allocation");
            };
            assert!(
                run(&Cx::for_testing(), &options)
                    .unwrap_err()
                    .to_string()
                    .contains("without a sidecar or recovery overlay")
            );
        }
    }

    #[test]
    fn record_ownership_json_cannot_turn_unknown_ownership_into_success_or_reuse() {
        let allocation = AllocationReport {
            complete: true,
            allocated_without_reference: Some(0),
            ..AllocationReport::default()
        };
        assert!(combined_json(&allocation, None, None, 1024)["record_ownership"].is_null());
        assert!(ownership_outcome(None).is_ok());
        let mut ownership = RecordOwnershipReport::default();
        let report = combined_json(&allocation, Some(&ownership), None, 1024);
        assert_eq!(report["allocation_consistent"], true);
        assert_eq!(report["requested_checks_consistent"], false);
        assert!(report["record_ownership"]["extensions_without_owner"].is_null());
        assert!(report["record_ownership"]["reclaimable_records"].is_null());
        assert!(ownership_outcome(Some(&ownership)).is_err());
        ownership.complete = true;
        ownership.extensions_without_owner = Some(0);
        assert!(ownership_outcome(Some(&ownership)).is_ok());
        assert_eq!(
            combined_json(&allocation, Some(&ownership), None, 1024)["requested_checks_consistent"],
            true
        );
        ownership.errors = 1;
        ownership.extensions_without_owner = Some(1);
        assert!(ownership_outcome(Some(&ownership)).is_err());
        assert_eq!(
            combined_json(&allocation, Some(&ownership), None, 1024)["requested_checks_consistent"],
            false
        );
    }

    #[test]
    fn allocation_cli_keeps_volume_bounds_and_exact_work_limits() {
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "check-allocation",
            "unopened.img",
            "--offline-image",
            "--offset",
            "1048576",
            "--length",
            "67108864",
            "--max-records",
            "2048",
            "--max-clusters",
            "65536",
            "--max-runs",
            "1000",
        ])
        .unwrap();
        let Command::CheckAllocation { options } = cli.command else {
            panic!("allocation");
        };
        assert!(options.image.offline_image);
        assert_eq!(
            (options.image.offset, options.image.length),
            (1_048_576, Some(67_108_864))
        );
        let limits = options.preflight().unwrap();
        assert_eq!(
            (limits.records, limits.clusters, limits.runs),
            (2048, 65536, 1000)
        );
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "check-allocation",
            "unopened.img",
            "--offline-image",
        ])
        .unwrap();
        let Command::CheckAllocation { options } = cli.command else {
            panic!("allocation");
        };
        let limits = options.preflight().unwrap();
        let expected = AllocationLimits::default();
        assert_eq!(
            (limits.records, limits.clusters, limits.runs),
            (expected.records, expected.clusters, expected.runs)
        );
    }

    #[test]
    fn allocation_cli_refuses_unbounded_work_and_mutation_options() {
        let base = [
            "ffs-ntfs",
            "check-allocation",
            "unopened.img",
            "--offline-image",
        ];
        for (option, value) in [
            ("--max-records", "0"),
            ("--max-records", "16777217"),
            ("--max-clusters", "0"),
            ("--max-clusters", "268435457"),
            ("--max-runs", "0"),
            ("--max-runs", "1048577"),
        ] {
            assert!(
                Cli::try_parse_from(base.into_iter().chain(<[_; 2]>::from((option, value))))
                    .is_err()
            );
        }
        for option in ["--repair", "--rw", "--force", "--clear-dirty"] {
            assert!(Cli::try_parse_from(base.into_iter().chain([option])).is_err());
        }
        assert!(Cli::try_parse_from(["ffs-ntfs", "check-allocation", "unopened.img"]).is_err());
    }

    #[test]
    fn allocation_cli_rejects_transformed_sources_before_any_open() {
        for extra in [vec!["--recover-logfile"], vec!["--sidecar", "unopened.rq"]] {
            let cli = Cli::try_parse_from(
                [
                    "ffs-ntfs",
                    "check-allocation",
                    "unopened.img",
                    "--offline-image",
                ]
                .into_iter()
                .chain(extra),
            )
            .unwrap();
            let Command::CheckAllocation { options } = cli.command else {
                panic!("allocation");
            };
            assert!(
                run(&Cx::for_testing(), &options)
                    .unwrap_err()
                    .to_string()
                    .contains("without a sidecar or recovery overlay")
            );
        }
    }

    #[test]
    fn allocation_json_and_exit_status_distinguish_incomplete_from_zero_unexplained_clusters() {
        let mut report = AllocationReport::default();
        let json = report_json(&report, 1024);
        assert_eq!(json["allocation_consistent"], false);
        assert!(json["allocated_without_reference"].is_null());
        assert!(json["reclaimable_clusters"].is_null());
        assert!(outcome(&report).is_err());
        report.complete = true;
        report.allocated_without_reference = Some(0);
        assert!(outcome(&report).is_ok());
        assert_eq!(report_json(&report, 1024)["allocation_consistent"], true);
        report.errors = 1;
        report.cross_linked_clusters = 3;
        report.issues.push(AllocationIssue {
            category: "cross_link",
            record: Some(24),
            attribute_id: Some(1),
            other_record: Some(25),
            other_attribute_id: Some(2),
            first_cluster: Some(100),
            clusters: 3,
            detail: "overlap".into(),
        });
        let json = report_json(&report, 1024);
        assert!(outcome(&report).is_err());
        assert_eq!(json["issues"][0]["record"], 24);
        assert_eq!(json["issues"][0]["other_record"], 25);
        assert_eq!(json["issues"][0]["first_cluster"], 100);
        assert_eq!(json["issues"][0]["clusters"], 3);
        assert_eq!(json["counts"]["cross_linked_clusters"], 3);
        assert_eq!(json["backing_writes"], false);
        assert_eq!(json["volume_offset"], 1024);
        assert!(json.get("clean").is_none());
        assert!(json["not_checked"].as_array().unwrap().len() >= 6);
    }
}
