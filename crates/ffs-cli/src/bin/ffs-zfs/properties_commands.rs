//! Native DSL property queries; no host paths are derived from property values.
use super::{CandidateArgs, Cx, Result, bail, json};
use crate::reader::dmu::properties::{Properties, Property, PropertySource, PropertyValue};
use clap::Subcommand;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

#[derive(Debug, Subcommand)]
pub enum PropertyCommand {
    /// Resolve stored native/user properties with local, received and inherited sources.
    Properties {
        #[command(flatten)]
        candidate: CandidateArgs,
        /// Pool-relative dataset name. Empty selects the pool root.
        #[arg(long, default_value = "")]
        dataset: OsString,
        /// Exact stored snapshot name. Properties are read at the selected MOS TXG.
        #[arg(long)]
        snapshot: Option<OsString>,
        /// Explicit property names, separated by spaces or commas. No implicit 'all'.
        #[arg(required = true, num_args = 1..=128, value_delimiter = ',')]
        names: Vec<String>,
    },
}

fn components(name: &[u8]) -> Result<Vec<Vec<u8>>> {
    if name.is_empty() {
        return Ok(Vec::new());
    }
    if name.len() > 65_536 || name.contains(&0) {
        bail!("invalid dataset name length or NUL");
    }
    let parts: Vec<_> = name.split(|byte| *byte == b'/').collect();
    if parts.len() > 64
        || parts.iter().any(|part| {
            part.is_empty()
                || *part == b"."
                || *part == b".."
                || part.contains(&b'@')
                || part.contains(&b'#')
        })
    {
        bail!("expected a pool-relative dataset name, not a host path or snapshot");
    }
    Ok(parts.into_iter().map(<[u8]>::to_vec).collect())
}

fn source(value: PropertySource) -> &'static str {
    match value {
        PropertySource::Local => "local",
        PropertySource::Received => "received",
        PropertySource::Inherited => "inherited",
        PropertySource::Default => "default",
        PropertySource::Unset => "unset",
    }
}

fn value_json(value: &PropertyValue) -> serde_json::Value {
    match value {
        PropertyValue::Number(value) => serde_json::json!({
            "type": "uint64", "decimal": value.to_string(),
        }),
        PropertyValue::Text(bytes) => serde_json::json!({
            "type": "string", "text": std::str::from_utf8(bytes).ok(), "bytes": bytes,
        }),
    }
}

fn property_json(property: &Property) -> serde_json::Value {
    serde_json::json!({
        "name": property.name,
        "value": property.value.as_ref().map(value_json),
        "source": source(property.source),
        "stored_source": property.stored_source.map(source),
        "setpoint_components_bytes": property.setpoint,
        "setpoint_snapshot_bytes": property.setpoint_snapshot,
        "received": property.received.as_ref().map(value_json),
    })
}

fn report_json(report: &Properties) -> serde_json::Value {
    serde_json::json!({
        "format": "ZFS", "operation": "properties", "read_only": true,
        "pool_guid": report.pool_guid.to_string(), "pool_txg": report.pool_txg.to_string(),
        "dataset_guid": report.dataset_guid.to_string(),
        "dataset_object": report.dataset_object.to_string(),
        "dataset_components_bytes": report.components,
        "snapshot_name_bytes": report.snapshot,
        "snapshot_creation_txg": report.snapshot_creation_txg.map(|value| value.to_string()),
        "properties": report.values.iter().map(property_json).collect::<Vec<_>>(),
        "scope": "stored DSL properties at selected MOS TXG; not host policy or write admission",
    })
}

impl PropertyCommand {
    pub(super) fn run(self, cx: &Cx) -> Result<()> {
        let Self::Properties {
            candidate,
            dataset,
            snapshot,
            names,
        } = self;
        // This path promises no on-read healing even when a sidecar is supplied.
        if candidate.image.sidecar.is_some() {
            bail!("read-only ZFS property queries do not admit sidecar healing");
        }
        let components = components(dataset.as_bytes())?;
        let mut objects = candidate.objects(cx)?;
        let report = objects.properties(
            cx,
            &components,
            snapshot.as_deref().map(OsStrExt::as_bytes),
            &names,
        )?;
        cx.checkpoint().map_err(|_| super::FfsError::Cancelled)?;
        json(&report_json(&report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    #[test]
    fn command_preserves_explicit_root_members_ranges_and_snapshot_name_bytes() {
        let mut args: Vec<OsString> = [
            "ffs-zfs",
            "properties",
            "first.img",
            "--offline-image",
            "--pool-guid",
            "123",
            "--label",
            "1",
            "--slot",
            "2",
            "--member",
            "second.img",
            "--offset",
            "1048576",
            "--length",
            "67108864",
            "--dataset",
            "data/nested",
            "--snapshot",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        args.push(OsString::from_vec(vec![0xfe]));
        args.push("exec,p:owner".into());
        let cli = Cli::try_parse_from(args).unwrap();
        let Command::Properties(PropertyCommand::Properties {
            candidate,
            dataset,
            snapshot,
            names,
        }) = cli.command
        else {
            panic!("properties command");
        };
        assert_eq!(candidate.members, [PathBuf::from("second.img")]);
        assert_eq!(
            (candidate.label, candidate.slot, candidate.pool_guid),
            (1, 2, 123)
        );
        assert_eq!(
            (candidate.image.offset, candidate.image.length),
            (1048576, Some(67108864))
        );
        assert_eq!(dataset, OsString::from("data/nested"));
        assert_eq!(snapshot.unwrap().as_bytes(), [0xfe]);
        assert_eq!(names, ["exec", "p:owner"]);
        assert_eq!(
            components(&[b'd', b'/', 0xff]).unwrap(),
            [vec![b'd'], vec![0xff]]
        );
    }

    #[test]
    fn property_cli_keeps_candidate_and_no_write_requirements() {
        let base = [
            "ffs-zfs",
            "properties",
            "absent.img",
            "--offline-image",
            "--auto-import",
        ];
        assert!(Cli::try_parse_from(base).is_err());
        assert!(Cli::try_parse_from(["ffs-zfs", "properties", "absent.img", "atime"]).is_err());
        for flag in ["--rw", "--set", "--inherit", "--force", "--heal"] {
            assert!(Cli::try_parse_from(base.into_iter().chain(["atime", flag])).is_err());
        }
        let cli = Cli::try_parse_from(base.into_iter().chain(["--sidecar", "absent.rq", "atime"]))
            .unwrap();
        let Command::Properties(command) = cli.command else {
            panic!("properties command");
        };
        assert!(
            command
                .run(&Cx::for_testing())
                .unwrap_err()
                .to_string()
                .contains("sidecar healing")
        );
        for path in [
            b"/data".as_slice(),
            b"data/",
            b"data//child",
            b"../data",
            b"data@snap",
            b"a\0b",
        ] {
            assert!(components(path).is_err());
        }
    }

    #[test]
    fn json_preserves_uint64_byte_strings_and_distinct_property_time() {
        let report = Properties {
            pool_guid: u64::MAX,
            pool_txg: 100,
            dataset_guid: 999,
            dataset_object: 7,
            components: vec![vec![0xff]],
            snapshot: Some(b"before".to_vec()),
            snapshot_creation_txg: Some(30),
            values: vec![Property {
                name: "p:owner".into(),
                value: Some(PropertyValue::Text(vec![0xfe])),
                source: PropertySource::Inherited,
                setpoint: Some(Vec::new()),
                setpoint_snapshot: None,
                stored_source: Some(PropertySource::Received),
                received: Some(PropertyValue::Text(Vec::new())),
            }],
        };
        let encoded = report_json(&report);
        assert_eq!(encoded["pool_guid"], u64::MAX.to_string());
        assert_eq!(encoded["pool_txg"], "100");
        assert_eq!(encoded["snapshot_creation_txg"], "30");
        assert_eq!(encoded["properties"][0]["source"], "inherited");
        assert_eq!(encoded["properties"][0]["stored_source"], "received");
        assert!(encoded["properties"][0]["value"]["text"].is_null());
        assert_eq!(encoded["properties"][0]["value"]["bytes"][0], 254);
        assert_eq!(encoded["properties"][0]["received"]["text"], "");
        assert_eq!(
            value_json(&PropertyValue::Number(u64::MAX))["decimal"],
            u64::MAX.to_string()
        );
    }
}
