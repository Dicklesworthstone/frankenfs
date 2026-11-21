//! Explicit native EA mutations with bounded payload admission before opening
//! a writable image, including when recovery is requested.

use super::{Args, Context, Cx, EaName, PayloadArgs, Result, TxWriteArgs, emit_tx_outcome, ensure};
use ffs_ntfs::{DEFAULT_NTFS_FILETIME, NtfsEaSetMode};
use ffs_ondisk::ntfs::ea::{FILE_NEED_EA, MAX_EA_BYTES, NtfsEa, encode_extended_attributes};
use std::io::Read;

#[derive(Debug, Args)]
struct Selector {
    /// Exact UTF-8 EA name, including user. when selecting a host xattr.
    #[arg(long, value_parser = EaName::parse_text, conflicts_with = "name_hex", required_unless_present = "name_hex")]
    name: Option<EaName>,
    /// Exact eight-bit EA name as hexadecimal bytes, without OEM conversion.
    #[arg(long, value_parser = EaName::parse_hex, conflicts_with = "name", required_unless_present = "name")]
    name_hex: Option<EaName>,
}

impl Selector {
    fn bytes(&self) -> Result<&[u8]> {
        self.name
            .as_ref()
            .or(self.name_hex.as_ref())
            .map(EaName::as_bytes)
            .context("select --name or --name-hex")
    }
}

fn name_hex(name: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(name.len() * 2);
    for &byte in name {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    encoded
}

#[derive(Debug, Args)]
pub(super) struct SetArgs {
    #[command(flatten)]
    target: TxWriteArgs,
    path: String,
    #[command(flatten)]
    selector: Selector,
    #[command(flatten)]
    payload: PayloadArgs,
    /// Refuse an existing EA instead of replacing it.
    #[arg(long, conflicts_with = "replace")]
    create: bool,
    /// Refuse a missing EA instead of creating it.
    #[arg(long, conflicts_with = "create")]
    replace: bool,
    /// Set or clear FILE_NEED_EA; omission preserves an existing entry's flag.
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    need_ea: Option<bool>,
}

#[derive(Debug, Args)]
pub(super) struct RemoveArgs {
    #[command(flatten)]
    target: TxWriteArgs,
    path: String,
    #[command(flatten)]
    selector: Selector,
}

fn load_payload(payload: &PayloadArgs) -> Result<Vec<u8>> {
    let data = if let Some(text) = &payload.data {
        ensure!(text.len() <= MAX_EA_BYTES, "EA payload exceeds 64 KiB");
        text.as_bytes().to_vec()
    } else if let Some(path) = &payload.data_file {
        let file = std::fs::File::open(path)
            .with_context(|| format!("reading EA payload {}", path.display()))?;
        let mut bytes = Vec::new();
        file.take(MAX_EA_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_EA_BYTES, "EA payload exceeds 64 KiB");
        bytes
    } else {
        ensure!(
            payload.empty,
            "specify --data, --data-file, or --empty for the EA value"
        );
        Vec::new()
    };
    Ok(data)
}

pub(super) fn set(cx: &Cx, options: &SetArgs) -> Result<()> {
    let name = options.selector.bytes()?;
    let mut entry = NtfsEa {
        name: name.to_vec(),
        flags: 0,
        value: load_payload(&options.payload)?,
    };
    // The native header/name overhead counts toward the EA budget too.
    encode_extended_attributes(std::slice::from_ref(&entry))
        .context("EA value and name exceed the native catalog budget")?;
    let mode = if options.create {
        NtfsEaSetMode::Create
    } else if options.replace {
        NtfsEaSetMode::Replace
    } else {
        NtfsEaSetMode::Set
    };
    let mut engine = options.target.open(cx, false)?;
    let reference = engine.resolve_path_reference(cx, &options.path)?;
    let volume = engine.volume_view(cx)?;
    let record = volume.record(cx, reference.record, Some(reference.sequence))?;
    let current = volume.extended_attributes(cx, &record)?;
    entry.flags = options.need_ea.map_or_else(
        || current.find(name).map_or(0, |old| old.flags),
        |need| if need { FILE_NEED_EA } else { 0 },
    );
    let outcome = engine.set_extended_attribute(cx, reference, &entry, mode, DEFAULT_NTFS_FILETIME);
    emit_tx_outcome("tx_set_ea", &engine, outcome, |()| {
        serde_json::json!({
            "record": reference.record, "sequence": reference.sequence,
            "name_hex": name_hex(name), "bytes": entry.value.len(), "need_ea": entry.need_ea(),
        })
    })
}

pub(super) fn remove(cx: &Cx, options: &RemoveArgs) -> Result<()> {
    let name = options.selector.bytes()?;
    let mut engine = options.target.open(cx, false)?;
    let reference = engine.resolve_path_reference(cx, &options.path)?;
    let outcome = engine.remove_extended_attribute(cx, reference, name, DEFAULT_NTFS_FILETIME);
    emit_tx_outcome("tx_remove_ea", &engine, outcome, |()| {
        serde_json::json!({
            "record": reference.record, "sequence": reference.sequence, "name_hex": name_hex(name),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;

    #[test]
    fn ea_mutation_cli_requires_authority_and_exact_selector() {
        for command in ["tx-set-ea", "tx-remove-ea"] {
            let base = [
                "ffs-ntfs",
                command,
                "volume.img",
                "/notes",
                "--name-hex",
                "757365722eff",
            ];
            assert!(Cli::try_parse_from(base).is_err());
            let mut args = base.to_vec();
            args.extend(["--offline-image", "--allow-write"]);
            assert!(Cli::try_parse_from(&args).is_ok());
            args.extend(["--name", "user.ambiguous"]);
            assert!(Cli::try_parse_from(args).is_err());
        }
        let base = [
            "ffs-ntfs",
            "tx-set-ea",
            "volume.img",
            "/notes",
            "--offline-image",
            "--allow-write",
        ];
        assert!(Cli::try_parse_from(base).is_err());
        let mut args = base.to_vec();
        args.extend(["--name", "user.note", "--create", "--replace"]);
        assert!(Cli::try_parse_from(args).is_err());
    }

    #[test]
    fn ea_payload_errors_precede_writable_open_even_with_recovery() {
        let cx = Cx::for_testing();
        let base = [
            "ffs-ntfs",
            "tx-set-ea",
            "/definitely-absent-ntfs-image",
            "/notes",
            "--name",
            "user.note",
            "--offline-image",
            "--allow-write",
            "--recover-dirty",
        ];
        let Command::TxSetEa { options } = Cli::try_parse_from(base).unwrap().command else {
            unreachable!()
        };
        assert!(
            set(&cx, &options)
                .unwrap_err()
                .to_string()
                .contains("specify --data")
        );
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("oversized.bin");
        std::fs::write(&payload, vec![0xAB; MAX_EA_BYTES + 1]).unwrap();
        let mut args = base.to_vec();
        args.extend(["--data-file", payload.to_str().unwrap()]);
        let Command::TxSetEa { options } = Cli::try_parse_from(args).unwrap().command else {
            unreachable!()
        };
        assert!(
            set(&cx, &options)
                .unwrap_err()
                .to_string()
                .contains("exceeds 64 KiB")
        );
        std::fs::write(&payload, vec![0xAB; MAX_EA_BYTES - 1]).unwrap();
        assert!(
            set(&cx, &options)
                .unwrap_err()
                .to_string()
                .contains("native catalog budget")
        );
    }
}
