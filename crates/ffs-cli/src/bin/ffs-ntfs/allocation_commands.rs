//! Bounded allocation diagnostics from the shared native NTFS library.

use super::{Cx, ImageArgs, Result, bail, json};
use clap::Args;
use ffs_ntfs::reader::allocation::{AllocationLimits, AllocationReport};
use serde_json::{Value, json as value};

#[derive(Debug, Args)]
pub(super) struct AllocationArgs {
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
}

impl AllocationArgs {
    fn preflight(&self) -> Result<AllocationLimits> {
        if self.image.sidecar.is_some() || self.image.recover_logfile {
            bail!("allocation checking requires original image bytes without a sidecar or recovery overlay");
        }
        let limits = AllocationLimits {
            records: self.max_records,
            clusters: self.max_clusters,
            runs: usize::try_from(self.max_runs)?,
        };
        limits.validate()?;
        Ok(limits)
    }
}

fn report_json(report: &AllocationReport, offset: u64) -> Value {
    let issues: Vec<_> = report.issues.iter().map(|issue| value!({
        "category": issue.category,
        "record": issue.record,
        "attribute_id": issue.attribute_id,
        "other_record": issue.other_record,
        "other_attribute_id": issue.other_attribute_id,
        "first_cluster": issue.first_cluster,
        "clusters": issue.clusters,
        "detail": issue.detail,
    })).collect();
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
        bail!("NTFS allocation discrepancies or incomplete coverage; see the JSON report; no repair performed");
    }
    Ok(())
}

pub(super) fn run(cx: &Cx, args: &AllocationArgs) -> Result<()> {
    cx.checkpoint().map_err(|_| ffs_error::FfsError::Cancelled)?;
    let limits = args.preflight()?;
    let volume = args.image.open(cx)?;
    let report = volume.check_allocations(cx, limits)?;
    cx.checkpoint().map_err(|_| ffs_error::FfsError::Cancelled)?;
    json(&report_json(&report, args.image.offset))?;
    outcome(&report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;
    use ffs_ntfs::reader::allocation::AllocationIssue;

    #[test]
    fn allocation_cli_keeps_volume_bounds_and_exact_work_limits() {
        let cli = Cli::try_parse_from([
            "ffs-ntfs", "check-allocation", "unopened.img", "--offline-image",
            "--offset", "1048576", "--length", "67108864",
            "--max-records", "2048", "--max-clusters", "65536", "--max-runs", "1000",
        ]).unwrap();
        let Command::CheckAllocation { options } = cli.command else { panic!("allocation"); };
        assert!(options.image.offline_image);
        assert_eq!((options.image.offset, options.image.length), (1_048_576, Some(67_108_864)));
        let limits = options.preflight().unwrap();
        assert_eq!((limits.records, limits.clusters, limits.runs), (2048, 65536, 1000));
        let cli = Cli::try_parse_from([
            "ffs-ntfs", "check-allocation", "unopened.img", "--offline-image",
        ]).unwrap();
        let Command::CheckAllocation { options } = cli.command else { panic!("allocation"); };
        let limits = options.preflight().unwrap();
        let expected = AllocationLimits::default();
        assert_eq!((limits.records, limits.clusters, limits.runs),
            (expected.records, expected.clusters, expected.runs));
    }

    #[test]
    fn allocation_cli_refuses_unbounded_work_and_mutation_options() {
        let base = ["ffs-ntfs", "check-allocation", "unopened.img", "--offline-image"];
        for (option, value) in [
            ("--max-records", "0"), ("--max-records", "16777217"),
            ("--max-clusters", "0"), ("--max-clusters", "268435457"),
            ("--max-runs", "0"), ("--max-runs", "1048577"),
        ] {
            assert!(Cli::try_parse_from(base.into_iter().chain([option, value])).is_err());
        }
        for option in ["--repair", "--rw", "--force", "--clear-dirty"] {
            assert!(Cli::try_parse_from(base.into_iter().chain([option])).is_err());
        }
        assert!(Cli::try_parse_from(["ffs-ntfs", "check-allocation", "unopened.img"]).is_err());
    }

    #[test]
    fn allocation_cli_rejects_transformed_sources_before_any_open() {
        for extra in [vec!["--recover-logfile"], vec!["--sidecar", "unopened.rq"]] {
            let cli = Cli::try_parse_from([
                "ffs-ntfs", "check-allocation", "unopened.img", "--offline-image",
            ].into_iter().chain(extra)).unwrap();
            let Command::CheckAllocation { options } = cli.command else { panic!("allocation"); };
            assert!(run(&Cx::for_testing(), &options).unwrap_err().to_string()
                .contains("without a sidecar or recovery overlay"));
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
            category: "cross_link", record: Some(24), attribute_id: Some(1),
            other_record: Some(25), other_attribute_id: Some(2),
            first_cluster: Some(100), clusters: 3, detail: "overlap".into(),
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
