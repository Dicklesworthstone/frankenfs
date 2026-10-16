//! Committed native allocation inspection, never a free-space write authority.

use super::{CandidateArgs, Cx, Result, bail, json};
use super::reader::dmu::allocation::{AllocationLimits, PoolAllocation};
use clap::Subcommand;
use serde_json::{Value, json as value};

#[derive(Debug, Subcommand)]
pub enum AllocationCommand {
    /// Reconstruct all admitted metaslab maps and check their allocation counters.
    Allocation {
        #[command(flatten)]
        candidate: CandidateArgs,
        /// Maximum complete metaslabs across all top-level data vdevs.
        #[arg(long, default_value_t = 65_536, value_parser = clap::value_parser!(u64).range(1..=65_536))]
        max_metaslabs: u64,
        /// Maximum native allocation, free and debug records examined.
        #[arg(long, default_value_t = 16_777_216, value_parser = clap::value_parser!(u64).range(1..=4_294_967_296))]
        max_records: u64,
        /// Conservative decoded metadata work, including cached tree traversals.
        #[arg(long, default_value_t = 536_870_912, value_parser = clap::value_parser!(u64).range(1..=1_099_511_627_776))]
        max_metadata_bytes: u64,
        /// Maximum coalesced allocation intervals retained for one metaslab.
        #[arg(long, default_value_t = 65_536, value_parser = clap::value_parser!(u64).range(1..=1_048_576))]
        max_ranges: u64,
    },
}

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| ffs_error::FfsError::Cancelled)?;
    Ok(())
}

fn report_json(cx: &Cx, report: &PoolAllocation) -> Result<Value> {
    let mut vdevs = Vec::with_capacity(report.vdevs.len());
    for top in &report.vdevs {
        let mut metaslabs = Vec::with_capacity(top.metaslabs.len());
        for slab in &top.metaslabs {
            checkpoint(cx)?;
            metaslabs.push(value!({
                "id": slab.id.to_string(), "object": slab.object.to_string(),
                "start": slab.start.to_string(), "size": slab.size.to_string(),
                "allocated_bytes": slab.allocated_bytes.to_string(),
                "free_bytes": slab.free_bytes.to_string(),
                "allocated_ranges": slab.allocated_ranges,
                "free_ranges": slab.free_ranges.to_string(),
                "largest_free_range": slab.largest_free_range.to_string(),
                "stream_bytes": slab.stream_bytes.to_string()
            }));
        }
        vdevs.push(value!({
            "id": top.id, "guid": top.guid.to_string(), "ashift": top.ashift,
            "metaslab_shift": top.metaslab_shift,
            "metaslab_array": top.metaslab_array.to_string(),
            "asize": top.asize.to_string(), "mapped_bytes": top.mapped_bytes.to_string(),
            "allocated_bytes": top.allocated_bytes.to_string(), "free_bytes": top.free_bytes.to_string(),
            "unmapped_tail_bytes": top.unmapped_tail_bytes.to_string(), "metaslabs": metaslabs
        }));
    }
    checkpoint(cx)?;
    Ok(value!({
        "format": "ZFS", "operation": "allocation", "read_only": true,
        "scope": "complete_committed_metaslab_space_maps",
        "address_domain": "top_level_vdev_DVA_asize_bytes_including_RAIDZ_parity_and_padding",
        "pool_guid": report.pool_guid.to_string(), "txg": report.txg.to_string(),
        "mapped_bytes": report.mapped_bytes.to_string(),
        "allocated_bytes": report.allocated_bytes.to_string(), "free_bytes": report.free_bytes.to_string(),
        "records_examined": report.records_examined.to_string(),
        "charged_metadata_bytes": report.charged_metadata_bytes.to_string(),
        "all_replicas_checked": false, "allocator_admission": false,
        "not_covered": [
            "namespace reachability, leaked or multiply-owned data blocks",
            "dataset quotas, reservations, pool slop and user-available payload capacity",
            "native allocation, reclamation, repairs, TXGs or writes"
        ],
        "refused_active_states": ["log_spacemap", "zpool_checkpoint"],
        "vdevs": vdevs
    }))
}

impl AllocationCommand {
    pub(super) fn run(self, cx: &Cx) -> Result<()> {
        let Self::Allocation { candidate, max_metaslabs, max_records, max_metadata_bytes, max_ranges } = self;
        if candidate.image.sidecar.is_some() {
            bail!("native allocation inspection does not admit sidecar healing");
        }
        let ranges_per_metaslab = usize::try_from(max_ranges)?;
        let view = candidate.objects(cx)?;
        let report = view.allocation(cx, AllocationLimits {
            metaslabs: max_metaslabs, records: max_records,
            metadata_bytes: max_metadata_bytes, ranges_per_metaslab,
        })?;
        // Complete reconstruction and serialization precede any stdout output.
        // A transport/write error can still leave a partial JSON document.
        let result = report_json(cx, &report)?;
        checkpoint(cx)?;
        json(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn allocation_command_retains_explicit_member_partition_and_work_limits() {
        let cli = Cli::try_parse_from([
            "ffs-zfs", "allocation", "first.img", "--offline-image", "--pool-guid", "123",
            "--label", "2", "--slot", "3", "--member", "second.img", "--offset", "1048576",
            "--length", "67108864", "--max-metaslabs", "512", "--max-records", "4096",
            "--max-metadata-bytes", "16777216", "--max-ranges", "1024",
        ]).unwrap();
        let Command::Allocation(AllocationCommand::Allocation {
            candidate, max_metaslabs, max_records, max_metadata_bytes, max_ranges,
        }) = cli.command else { panic!("allocation command"); };
        assert_eq!((candidate.pool_guid, candidate.label, candidate.slot), (123, 2, 3));
        assert_eq!(candidate.members, [PathBuf::from("second.img")]);
        assert_eq!((candidate.image.offset, candidate.image.length), (1_048_576, Some(67_108_864)));
        assert_eq!((max_metaslabs, max_records, max_metadata_bytes, max_ranges), (512, 4096, 16_777_216, 1024));
    }

    #[test]
    fn allocation_refuses_missing_ownership_zero_budgets_and_mutation_options() {
        assert!(Cli::try_parse_from(["ffs-zfs", "allocation", "leaf.img", "--auto-import"]).is_err());
        assert!(Cli::try_parse_from(["ffs-zfs", "allocation", "leaf.img", "--offline-image"]).is_err());
        let base = ["ffs-zfs", "allocation", "leaf.img", "--offline-image", "--auto-import"];
        for option in ["--max-metaslabs", "--max-records", "--max-metadata-bytes", "--max-ranges"] {
            assert!(Cli::try_parse_from(base.into_iter().chain([option, "0"])).is_err());
        }
        for option in ["--rw", "--repair", "--reclaim", "--force", "--heal"] {
            assert!(Cli::try_parse_from(base.into_iter().chain([option])).is_err());
        }
        assert!(Cli::try_parse_from(base.into_iter().chain(["--max-metaslabs", "65537"])).is_err());
        assert!(Cli::try_parse_from(base.into_iter().chain(["--snapshot", "before"])).is_err());
    }

    #[test]
    fn sidecar_is_rejected_before_attempting_an_image_open() {
        let cli = Cli::try_parse_from([
            "ffs-zfs", "allocation", "absent-allocation.img", "--offline-image",
            "--auto-import", "--sidecar", "absent-allocation.rq",
        ]).unwrap();
        let Command::Allocation(command) = cli.command else { panic!("allocation command"); };
        assert!(command.run(&Cx::for_testing()).unwrap_err().to_string().contains("does not admit sidecar healing"));
    }

    #[test]
    fn json_preserves_large_numeric_values_and_distinguishes_scope_from_write_authority() {
        let report = PoolAllocation { pool_guid: u64::MAX, txg: 1_u64 << 54,
            mapped_bytes: 1_u64 << 60, allocated_bytes: 512, free_bytes: (1_u64 << 60) - 512,
            records_examined: 1, charged_metadata_bytes: 4096, vdevs: Vec::new() };
        let value = report_json(&Cx::for_testing(), &report).unwrap();
        assert_eq!(value["pool_guid"], u64::MAX.to_string());
        assert_eq!(value["txg"], "18014398509481984");
        assert_eq!(value["mapped_bytes"], "1152921504606846976");
        assert_eq!(value["allocator_admission"], false);
        assert_eq!(value["all_replicas_checked"], false);
        assert_eq!(value["refused_active_states"], value!(["log_spacemap", "zpool_checkpoint"]));
    }
}
