#![allow(clippy::too_many_lines)]

//! Dry-run catalog validation for deterministic metamorphic workload seeds.
//!
//! The catalog records where existing deterministic seeds live, which
//! metamorphic relation each seed exercises, and whether reproducing that seed
//! is analysis-only, dry-run, or requires an explicit permissioned-run ack.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const METAMORPHIC_WORKLOAD_SEED_CATALOG_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_METAMORPHIC_WORKLOAD_SEED_CATALOG_PATH: &str =
    "tests/metamorphic-workload-seeds/metamorphic_workload_seed_catalog.json";

const MIN_SOURCE_KIND_COUNT: usize = 5;

const PERMISSIONED_REPRODUCTION_COMMAND_TOKENS: &[&str] = &[
    "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD",
    "FFS_SWARM_WORKLOAD_REAL_RUN_ACK",
    "swarm-workload-may-use-permissioned-large-host",
    "XFSTESTS_REAL_RUN_ACK",
    "xfstests-may-mutate-test-and-scratch-devices",
];

const KNOWN_PROOF_CONSUMERS: &[&str] = &[
    "workload_corpus",
    "soak_canary_campaigns",
    "swarm_workload_harness",
    "swarm_tail_latency",
    "crash_replay_lab",
    "chaos_replay_lab",
    "repair_lab",
    "fault_injection_corpus",
    "proof_bundle",
    "release_gate",
    "operational_readiness_report",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetamorphicWorkloadSeedCatalog {
    pub schema_version: u32,
    pub catalog_id: String,
    pub catalog_version: String,
    pub bead_id: String,
    pub relation_types: Vec<String>,
    pub execution_modes: Vec<String>,
    pub proof_consumers: Vec<String>,
    pub seeds: Vec<MetamorphicWorkloadSeed>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetamorphicWorkloadSeed {
    pub seed_id: String,
    pub seed_value: SeedValue,
    pub source_kind: String,
    pub source_artifact: String,
    pub source_seed_field: String,
    pub source_value_pointer: String,
    pub relation_type: String,
    pub invariant: String,
    pub proof_consumers: Vec<String>,
    pub reproduction_command: String,
    pub execution_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_requirement: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub linked_workload_scenarios: Vec<String>,
    pub expected_artifacts: Vec<ExpectedMetamorphicArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SeedValue {
    Number(u64),
    Symbolic(String),
}

impl SeedValue {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Number(value) => *value > 0,
            Self::Symbolic(value) => !value.trim().is_empty(),
        }
    }

    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Number(value) => value.to_string(),
            Self::Symbolic(value) => value.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedMetamorphicArtifact {
    pub path: String,
    pub kind: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetamorphicWorkloadSeedCatalogReport {
    pub schema_version: u32,
    pub catalog_id: String,
    pub catalog_version: String,
    pub bead_id: String,
    pub valid: bool,
    pub seed_count: usize,
    pub source_kind_count: usize,
    pub relation_counts: BTreeMap<String, usize>,
    pub source_kind_counts: BTreeMap<String, usize>,
    pub execution_mode_counts: BTreeMap<String, usize>,
    pub by_proof_consumer: BTreeMap<String, usize>,
    pub dry_run_seed_ids: Vec<String>,
    pub permissioned_seed_ids: Vec<String>,
    pub source_artifacts: Vec<String>,
    pub source_value_verified_count: usize,
    pub coverage_matrix: Vec<MetamorphicWorkloadSeedCoverageRow>,
    pub duplicate_seed_ids: Vec<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetamorphicWorkloadSeedCoverageRow {
    pub seed_id: String,
    pub seed_value: String,
    pub source_kind: String,
    pub source_artifact: String,
    pub source_value_pointer: String,
    pub relation_type: String,
    pub invariant: String,
    pub proof_consumers: Vec<String>,
    pub execution_mode: String,
    pub ack_requirement: Option<String>,
    pub linked_workload_scenarios: Vec<String>,
    pub reproduction_command: String,
    pub expected_artifact_fields: Vec<String>,
}

pub fn load_metamorphic_workload_seed_catalog(
    path: &Path,
) -> Result<MetamorphicWorkloadSeedCatalog> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read metamorphic workload seed catalog {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "invalid metamorphic workload seed catalog JSON {}",
            path.display()
        )
    })
}

#[must_use]
pub fn validate_metamorphic_workload_seed_catalog(
    catalog: &MetamorphicWorkloadSeedCatalog,
) -> MetamorphicWorkloadSeedCatalogReport {
    validate_metamorphic_workload_seed_catalog_with_repo_root(catalog, Path::new("."))
}

#[must_use]
pub fn validate_metamorphic_workload_seed_catalog_with_repo_root(
    catalog: &MetamorphicWorkloadSeedCatalog,
    repo_root: &Path,
) -> MetamorphicWorkloadSeedCatalogReport {
    let mut errors = Vec::new();
    let warnings = Vec::new();
    let mut seen_seed_ids = BTreeMap::<&str, usize>::new();
    let mut duplicate_seed_ids = Vec::new();
    let mut relation_counts = BTreeMap::<String, usize>::new();
    let mut source_kind_counts = BTreeMap::<String, usize>::new();
    let mut execution_mode_counts = BTreeMap::<String, usize>::new();
    let mut by_proof_consumer = BTreeMap::<String, usize>::new();
    let mut dry_run_seed_ids = Vec::new();
    let mut permissioned_seed_ids = Vec::new();
    let mut source_artifacts = BTreeSet::<String>::new();
    let mut source_value_verified_count = 0usize;
    let mut coverage_matrix = Vec::new();

    validate_header(catalog, &mut errors);

    let relation_vocab = catalog
        .relation_types
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let execution_vocab = catalog
        .execution_modes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let proof_consumer_vocab = catalog
        .proof_consumers
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    for seed in &catalog.seeds {
        *seen_seed_ids.entry(seed.seed_id.as_str()).or_default() += 1;
        *relation_counts
            .entry(seed.relation_type.clone())
            .or_default() += 1;
        *source_kind_counts
            .entry(seed.source_kind.clone())
            .or_default() += 1;
        *execution_mode_counts
            .entry(seed.execution_mode.clone())
            .or_default() += 1;
        for consumer in &seed.proof_consumers {
            *by_proof_consumer.entry(consumer.clone()).or_default() += 1;
        }
        if seed.execution_mode.eq("dry_run") {
            dry_run_seed_ids.push(seed.seed_id.clone());
        }
        if seed.execution_mode.eq("permissioned") {
            permissioned_seed_ids.push(seed.seed_id.clone());
        }
        source_artifacts.insert(seed.source_artifact.clone());

        if validate_seed(
            seed,
            repo_root,
            &relation_vocab,
            &execution_vocab,
            &proof_consumer_vocab,
            &mut errors,
        ) {
            source_value_verified_count += 1;
        }
        coverage_matrix.push(build_coverage_row(seed));
    }

    for (seed_id, count) in seen_seed_ids {
        if count > 1 {
            duplicate_seed_ids.push(seed_id.to_owned());
        }
    }
    for duplicate in &duplicate_seed_ids {
        errors.push(format!("duplicate seed_id {duplicate}"));
    }

    if source_kind_counts.len() < MIN_SOURCE_KIND_COUNT {
        errors.push(format!(
            "catalog must cover at least {MIN_SOURCE_KIND_COUNT} source kinds, got {}",
            source_kind_counts.len()
        ));
    }
    if dry_run_seed_ids.is_empty() {
        errors.push("catalog must include at least one dry_run seed".to_owned());
    }
    if permissioned_seed_ids.is_empty() {
        errors.push(
            "catalog must include at least one permissioned seed with ack metadata".to_owned(),
        );
    }

    MetamorphicWorkloadSeedCatalogReport {
        schema_version: catalog.schema_version,
        catalog_id: catalog.catalog_id.clone(),
        catalog_version: catalog.catalog_version.clone(),
        bead_id: catalog.bead_id.clone(),
        valid: errors.is_empty(),
        seed_count: catalog.seeds.len(),
        source_kind_count: source_kind_counts.len(),
        relation_counts,
        source_kind_counts,
        execution_mode_counts,
        by_proof_consumer,
        dry_run_seed_ids,
        permissioned_seed_ids,
        source_artifacts: source_artifacts.into_iter().collect(),
        source_value_verified_count,
        coverage_matrix,
        duplicate_seed_ids,
        errors,
        warnings,
    }
}

pub fn fail_on_metamorphic_workload_seed_catalog_errors(
    report: &MetamorphicWorkloadSeedCatalogReport,
) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "metamorphic workload seed catalog validation failed: {}",
        report.errors.join("; ")
    )
}

#[must_use]
pub fn render_metamorphic_workload_seed_catalog_markdown(
    report: &MetamorphicWorkloadSeedCatalogReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Metamorphic Workload Seed Catalog");
    let _ = writeln!(out);
    let _ = writeln!(out, "- catalog: `{}`", report.catalog_id);
    let _ = writeln!(out, "- version: `{}`", report.catalog_version);
    let _ = writeln!(out, "- bead: `{}`", report.bead_id);
    let _ = writeln!(out, "- valid: `{}`", report.valid);
    let _ = writeln!(out, "- seeds: `{}`", report.seed_count);
    let _ = writeln!(out, "- source kinds: `{}`", report.source_kind_count);
    let _ = writeln!(
        out,
        "- source values verified: `{}`",
        report.source_value_verified_count
    );
    let _ = writeln!(out);
    render_counts(&mut out, "Relation Coverage", &report.relation_counts);
    render_counts(&mut out, "Source Kind Coverage", &report.source_kind_counts);
    render_counts(
        &mut out,
        "Execution Mode Coverage",
        &report.execution_mode_counts,
    );
    render_counts(
        &mut out,
        "Proof Consumer Coverage",
        &report.by_proof_consumer,
    );
    let _ = writeln!(out, "## Coverage Matrix");
    let _ = writeln!(
        out,
        "| Seed | Source | Pointer | Relation | Execution | Consumers | Invariant |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|");
    for row in &report.coverage_matrix {
        let consumers = row.proof_consumers.join(", ");
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |",
            row.seed_id,
            row.source_kind,
            row.source_value_pointer,
            row.relation_type,
            row.execution_mode,
            consumers,
            row.invariant
        );
    }
    out
}

fn validate_header(catalog: &MetamorphicWorkloadSeedCatalog, errors: &mut Vec<String>) {
    if catalog
        .schema_version
        .ne(&METAMORPHIC_WORKLOAD_SEED_CATALOG_SCHEMA_VERSION)
    {
        errors.push(format!(
            "schema_version must be {METAMORPHIC_WORKLOAD_SEED_CATALOG_SCHEMA_VERSION}, got {}",
            catalog.schema_version
        ));
    }
    validate_nonempty("catalog_id", &catalog.catalog_id, errors);
    validate_nonempty("catalog_version", &catalog.catalog_version, errors);
    validate_nonempty("bead_id", &catalog.bead_id, errors);
    validate_nonempty_vec("relation_types", &catalog.relation_types, errors);
    validate_nonempty_vec("execution_modes", &catalog.execution_modes, errors);
    validate_nonempty_vec("proof_consumers", &catalog.proof_consumers, errors);
    if catalog.seeds.is_empty() {
        errors.push("seeds must not be empty".to_owned());
    }
    for consumer in &catalog.proof_consumers {
        if !KNOWN_PROOF_CONSUMERS.contains(&consumer.as_str()) {
            errors.push(format!(
                "proof_consumer vocabulary references unknown existing consumer {consumer}"
            ));
        }
    }
}

fn validate_seed(
    seed: &MetamorphicWorkloadSeed,
    repo_root: &Path,
    relation_vocab: &BTreeSet<&str>,
    execution_vocab: &BTreeSet<&str>,
    proof_consumer_vocab: &BTreeSet<&str>,
    errors: &mut Vec<String>,
) -> bool {
    validate_stable_seed_id(&seed.seed_id, errors);
    if !seed.seed_value.is_valid() {
        errors.push(format!(
            "seed {} seed_value must be a positive integer or non-empty symbolic value",
            seed.seed_id
        ));
    }
    validate_nonempty("source_kind", &seed.source_kind, errors);
    validate_nonempty("source_artifact", &seed.source_artifact, errors);
    validate_nonempty("source_seed_field", &seed.source_seed_field, errors);
    validate_nonempty("source_value_pointer", &seed.source_value_pointer, errors);
    validate_nonempty("relation_type", &seed.relation_type, errors);
    validate_nonempty("invariant", &seed.invariant, errors);
    validate_nonempty("reproduction_command", &seed.reproduction_command, errors);
    validate_members(
        "proof_consumers",
        &seed.proof_consumers,
        proof_consumer_vocab,
        &seed.seed_id,
        errors,
    );
    if !seed
        .proof_consumers
        .iter()
        .any(|consumer| KNOWN_PROOF_CONSUMERS.contains(&consumer.as_str()))
    {
        errors.push(format!(
            "seed {} must reference at least one existing proof consumer",
            seed.seed_id
        ));
    }
    if !relation_vocab.contains(seed.relation_type.as_str()) {
        errors.push(format!(
            "seed {} relation_type references unknown value {}",
            seed.seed_id, seed.relation_type
        ));
    }
    if !execution_vocab.contains(seed.execution_mode.as_str()) {
        errors.push(format!(
            "seed {} execution_mode references unknown value {}",
            seed.seed_id, seed.execution_mode
        ));
    }
    validate_execution_safety(seed, errors);
    let source_value_verified = validate_source_artifact_and_value(seed, repo_root, errors);
    validate_expected_artifacts(seed, errors);
    source_value_verified
}

fn validate_execution_safety(seed: &MetamorphicWorkloadSeed, errors: &mut Vec<String>) {
    if seed.execution_mode.eq("permissioned") {
        validate_permissioned_seed_ack(seed, errors);
        return;
    }

    if seed
        .ack_requirement
        .as_deref()
        .is_some_and(|ack| !ack.trim().is_empty())
    {
        errors.push(format!(
            "non-permissioned seed {} must not declare ack_requirement",
            seed.seed_id
        ));
    }
    for token in PERMISSIONED_REPRODUCTION_COMMAND_TOKENS {
        if seed.reproduction_command.contains(token) {
            errors.push(format!(
                "non-permissioned seed {} reproduction_command must not mention permissioned token {token}",
                seed.seed_id
            ));
        }
    }
}

fn validate_permissioned_seed_ack(seed: &MetamorphicWorkloadSeed, errors: &mut Vec<String>) {
    let Some(ack) = seed
        .ack_requirement
        .as_deref()
        .filter(|ack| !ack.trim().is_empty())
    else {
        errors.push(format!(
            "permissioned seed {} must declare ack_requirement",
            seed.seed_id
        ));
        return;
    };

    if !is_exact_env_assignment_token(ack) {
        errors.push(format!(
            "permissioned seed {} ack_requirement must be an exact KEY=value env assignment token",
            seed.seed_id
        ));
    }
    if !seed.reproduction_command.contains(ack) {
        errors.push(format!(
            "permissioned seed {} reproduction_command must include ack_requirement {ack}",
            seed.seed_id
        ));
    }
}

fn is_exact_env_assignment_token(raw: &str) -> bool {
    let Some((key, value)) = raw.split_once('=') else {
        return false;
    };
    !key.is_empty()
        && !value.is_empty()
        && !raw.chars().any(char::is_whitespace)
        && !value.contains('*')
        && key
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

fn validate_source_artifact_and_value(
    seed: &MetamorphicWorkloadSeed,
    repo_root: &Path,
    errors: &mut Vec<String>,
) -> bool {
    let Ok(resolved) = resolve_catalog_relative_path(repo_root, &seed.source_artifact) else {
        errors.push(format!(
            "seed {} source_artifact must be a relative path without parent components: {}",
            seed.seed_id, seed.source_artifact
        ));
        return false;
    };
    if !resolved.exists() {
        errors.push(format!(
            "seed {} source_artifact does not exist: {}",
            seed.seed_id, seed.source_artifact
        ));
        return false;
    }
    let source_text = match fs::read_to_string(&resolved) {
        Ok(text) => text,
        Err(err) => {
            errors.push(format!(
                "seed {} source_artifact could not be read: {} ({err})",
                seed.seed_id, seed.source_artifact
            ));
            return false;
        }
    };
    let source_json = match serde_json::from_str::<Value>(&source_text) {
        Ok(value) => value,
        Err(err) => {
            errors.push(format!(
                "seed {} source_artifact is not valid JSON: {} ({err})",
                seed.seed_id, seed.source_artifact
            ));
            return false;
        }
    };
    let Some(source_value) = source_json.pointer(&seed.source_value_pointer) else {
        errors.push(format!(
            "seed {} source_value_pointer does not exist in {}: {}",
            seed.seed_id, seed.source_artifact, seed.source_value_pointer
        ));
        return false;
    };
    if !source_value_contains_seed(source_value, &seed.seed_value) {
        errors.push(format!(
            "seed {} seed_value {} was not found at source_value_pointer {} in {}",
            seed.seed_id,
            seed.seed_value.label(),
            seed.source_value_pointer,
            seed.source_artifact
        ));
        return false;
    }
    true
}

fn resolve_catalog_relative_path(repo_root: &Path, raw_path: &str) -> Result<PathBuf> {
    let path = Path::new(raw_path);
    if path.is_absolute() {
        bail!("absolute paths are not allowed");
    }
    let mut resolved = PathBuf::from(repo_root);
    for component in path.components() {
        match component {
            Component::Normal(part) => resolved.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("parent, root, and prefix components are not allowed");
            }
        }
    }
    Ok(resolved)
}

fn validate_expected_artifacts(seed: &MetamorphicWorkloadSeed, errors: &mut Vec<String>) {
    if seed.expected_artifacts.is_empty() {
        errors.push(format!(
            "seed {} must declare expected_artifacts",
            seed.seed_id
        ));
    }
    if !seed
        .expected_artifacts
        .iter()
        .any(|artifact| artifact.required)
    {
        errors.push(format!(
            "seed {} must have at least one required expected_artifact",
            seed.seed_id
        ));
    }
    for artifact in &seed.expected_artifacts {
        validate_nonempty("artifact.path", &artifact.path, errors);
        validate_nonempty("artifact.kind", &artifact.kind, errors);
    }
}

fn build_coverage_row(seed: &MetamorphicWorkloadSeed) -> MetamorphicWorkloadSeedCoverageRow {
    MetamorphicWorkloadSeedCoverageRow {
        seed_id: seed.seed_id.clone(),
        seed_value: seed.seed_value.label(),
        source_kind: seed.source_kind.clone(),
        source_artifact: seed.source_artifact.clone(),
        source_value_pointer: seed.source_value_pointer.clone(),
        relation_type: seed.relation_type.clone(),
        invariant: seed.invariant.clone(),
        proof_consumers: seed.proof_consumers.clone(),
        execution_mode: seed.execution_mode.clone(),
        ack_requirement: seed.ack_requirement.clone(),
        linked_workload_scenarios: seed.linked_workload_scenarios.clone(),
        reproduction_command: seed.reproduction_command.clone(),
        expected_artifact_fields: ["path", "kind", "required"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    }
}

fn source_value_contains_seed(source_value: &Value, seed_value: &SeedValue) -> bool {
    match source_value {
        Value::Number(number) => match seed_value {
            SeedValue::Number(seed) => number.as_u64().is_some_and(|value| value.eq(seed)),
            SeedValue::Symbolic(seed) => number.to_string().contains(seed),
        },
        Value::String(value) => value.contains(&seed_value.label()),
        Value::Array(values) => values
            .iter()
            .any(|value| source_value_contains_seed(value, seed_value)),
        Value::Object(values) => values
            .values()
            .any(|value| source_value_contains_seed(value, seed_value)),
        Value::Bool(_) | Value::Null => false,
    }
}

fn render_counts(out: &mut String, title: &str, counts: &BTreeMap<String, usize>) {
    let _ = writeln!(out, "## {title}");
    for (key, count) in counts {
        let _ = writeln!(out, "- `{key}`: `{count}`");
    }
    let _ = writeln!(out);
}

fn validate_stable_seed_id(seed_id: &str, errors: &mut Vec<String>) {
    if seed_id.is_empty() {
        errors.push("seed_id must not be empty".to_owned());
        return;
    }
    let segments = seed_id.split('_').collect::<Vec<_>>();
    let valid = segments.len() >= 3
        && seed_id
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase())
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        });
    if !valid {
        errors.push(format!(
            "seed_id {seed_id} must be lowercase snake-case with at least three segments"
        ));
    }
}

fn validate_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn validate_nonempty_vec(field: &str, values: &[String], errors: &mut Vec<String>) {
    if values.is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
    for value in values {
        if value.trim().is_empty() {
            errors.push(format!("{field} must not contain empty values"));
        }
    }
}

fn validate_members(
    field: &str,
    values: &[String],
    vocabulary: &BTreeSet<&str>,
    seed_id: &str,
    errors: &mut Vec<String>,
) {
    if values.is_empty() {
        errors.push(format!("seed {seed_id} {field} must not be empty"));
    }
    for value in values {
        if !vocabulary.contains(value.as_str()) {
            errors.push(format!(
                "seed {seed_id} {field} references unknown value {value}"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn fixture_catalog() -> Result<MetamorphicWorkloadSeedCatalog> {
        serde_json::from_str(include_str!(
            "../../../tests/metamorphic-workload-seeds/metamorphic_workload_seed_catalog.json"
        ))
        .context("checked-in metamorphic seed catalog is valid JSON")
    }

    fn validate_fixture(
        catalog: &MetamorphicWorkloadSeedCatalog,
    ) -> MetamorphicWorkloadSeedCatalogReport {
        validate_metamorphic_workload_seed_catalog_with_repo_root(catalog, &repo_root())
    }

    fn first_seed_mut(
        catalog: &mut MetamorphicWorkloadSeedCatalog,
    ) -> Result<&mut MetamorphicWorkloadSeed> {
        catalog
            .seeds
            .first_mut()
            .context("fixture catalog includes at least one seed")
    }

    fn first_two_seeds_mut(
        catalog: &mut MetamorphicWorkloadSeedCatalog,
    ) -> Result<(&mut MetamorphicWorkloadSeed, &mut MetamorphicWorkloadSeed)> {
        let (first, rest) = catalog
            .seeds
            .split_first_mut()
            .context("fixture catalog includes at least one seed")?;
        let second = rest
            .first_mut()
            .context("fixture catalog includes at least two seeds")?;
        Ok((first, second))
    }

    fn seed_by_id<'a>(
        catalog: &'a MetamorphicWorkloadSeedCatalog,
        seed_id: &str,
    ) -> Result<&'a MetamorphicWorkloadSeed> {
        catalog
            .seeds
            .iter()
            .find(|seed| seed.seed_id == seed_id)
            .with_context(|| format!("fixture has seed {seed_id}"))
    }

    fn seed_by_id_mut<'a>(
        catalog: &'a mut MetamorphicWorkloadSeedCatalog,
        seed_id: &str,
    ) -> Result<&'a mut MetamorphicWorkloadSeed> {
        catalog
            .seeds
            .iter_mut()
            .find(|seed| seed.seed_id == seed_id)
            .with_context(|| format!("fixture has seed {seed_id}"))
    }

    fn seed_by_execution_mode_mut<'a>(
        catalog: &'a mut MetamorphicWorkloadSeedCatalog,
        execution_mode: &str,
    ) -> Result<&'a mut MetamorphicWorkloadSeed> {
        catalog
            .seeds
            .iter_mut()
            .find(|seed| seed.execution_mode == execution_mode)
            .with_context(|| format!("fixture has {execution_mode} seed"))
    }

    #[test]
    fn checked_in_catalog_validates_required_contract() -> Result<()> {
        let catalog = fixture_catalog()?;
        let report = validate_fixture(&catalog);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.bead_id, "bd-rchk0.79");
        assert!(report.seed_count >= 7);
        assert!(report.source_kind_count >= MIN_SOURCE_KIND_COUNT);
        assert_eq!(report.source_value_verified_count, report.seed_count);
        assert_ne!(report.dry_run_seed_ids, [] as [String; 0]);
        assert_ne!(report.permissioned_seed_ids, [] as [String; 0]);
        assert_eq!(report.coverage_matrix.len(), report.seed_count);
        assert!(report.coverage_matrix.iter().all(|row| {
            !row.source_value_pointer.is_empty()
                && row
                    .expected_artifact_fields
                    .iter()
                    .any(|field| field.eq("required"))
        }));
        assert!(
            report
                .by_proof_consumer
                .contains_key("swarm_workload_harness")
        );
        Ok(())
    }

    #[test]
    fn render_metamorphic_workload_seed_catalog_markdown_checked_in_catalog_snapshot() -> Result<()>
    {
        let catalog = fixture_catalog()?;
        let report = validate_fixture(&catalog);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.seed_count, 8);
        assert_eq!(report.source_kind_count, 8);
        assert_eq!(report.source_value_verified_count, 8);
        assert_eq!(report.execution_mode_counts.get("analysis_only"), Some(&1));
        assert_eq!(report.execution_mode_counts.get("dry_run"), Some(&6));
        assert_eq!(report.execution_mode_counts.get("permissioned"), Some(&1));

        let markdown = render_metamorphic_workload_seed_catalog_markdown(&report);
        insta::assert_snapshot!(
            "render_metamorphic_workload_seed_catalog_markdown_checked_in_catalog",
            markdown
        );
        Ok(())
    }

    #[test]
    fn metamorphic_workload_seed_catalog_report_json_shape() -> Result<()> {
        let catalog = fixture_catalog()?;
        let report = validate_fixture(&catalog);
        assert!(report.valid, "{:?}", report.errors);
        let json = serde_json::to_string_pretty(&report)?;

        insta::assert_snapshot!("metamorphic_workload_seed_catalog_report_json_shape", json);
        let parsed: MetamorphicWorkloadSeedCatalogReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn source_value_coverage_counts_valid_sources_independent_of_row_errors() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        first_seed_mut(&mut catalog)?.invariant.clear();

        let report = validate_fixture(&catalog);

        assert!(!report.valid);
        assert_eq!(report.source_value_verified_count, report.seed_count);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("invariant must not be empty")),
            "expected invariant validation error, got {:?}",
            report.errors
        );
        Ok(())
    }

    #[test]
    fn rejects_duplicate_seed_ids() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        let (first, second) = first_two_seeds_mut(&mut catalog)?;
        second.seed_id = first.seed_id.clone();
        let report = validate_fixture(&catalog);
        assert!(!report.valid);
        assert_eq!(report.duplicate_seed_ids.len(), 1);
        Ok(())
    }

    #[test]
    fn rejects_missing_source_artifact() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        first_seed_mut(&mut catalog)?.source_artifact =
            "tests/metamorphic-workload-seeds/missing_source.json".to_owned();
        let report = validate_fixture(&catalog);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("source_artifact does not exist"))
        );
        Ok(())
    }

    #[test]
    fn rejects_existing_non_json_source_artifact() -> Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("non_json_source.txt"), "seed: 64001\n")?;

        let mut catalog = fixture_catalog()?;
        catalog.seeds.truncate(1);
        let seed = first_seed_mut(&mut catalog)?;
        seed.source_artifact = "non_json_source.txt".to_owned();
        seed.source_value_pointer = "/seed".to_owned();

        let report =
            validate_metamorphic_workload_seed_catalog_with_repo_root(&catalog, temp.path());
        assert!(!report.valid);
        assert_eq!(report.source_value_verified_count, 0);
        assert!(report.errors.iter().any(|error| {
            error.contains("source_artifact is not valid JSON")
                && error.contains("seed_workload_append_truncate_64001")
        }));
        Ok(())
    }

    #[test]
    fn rejects_missing_source_value_pointer_target() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        first_seed_mut(&mut catalog)?.source_value_pointer =
            "/scenarios/3/missing_seed_field".to_owned();
        let report = validate_fixture(&catalog);
        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("source_value_pointer does not exist")
                && error.contains("seed_workload_append_truncate_64001")
        }));
        Ok(())
    }

    #[test]
    fn rejects_mismatched_numeric_source_value() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        let seed = seed_by_id_mut(&mut catalog, "seed_soak_mount_ext4_1001")?;
        seed.seed_value = SeedValue::Number(9_999_999);
        let report = validate_fixture(&catalog);
        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("seed_value 9999999 was not found")
                && error.contains("seed_soak_mount_ext4_1001")
        }));
        Ok(())
    }

    #[test]
    fn accepts_seed_contained_in_source_command_string() -> Result<()> {
        let catalog = fixture_catalog()?;
        let seed = seed_by_id(&catalog, "seed_workload_append_truncate_64001")?;
        let resolved = resolve_catalog_relative_path(&repo_root(), &seed.source_artifact)?;
        let source_text = fs::read_to_string(&resolved).with_context(|| {
            format!(
                "fixture source artifact is readable: {}",
                resolved.display()
            )
        })?;
        let source_json: Value = serde_json::from_str(&source_text)
            .with_context(|| format!("fixture source artifact is JSON: {}", resolved.display()))?;
        let source_value = source_json
            .pointer(&seed.source_value_pointer)
            .context("fixture source pointer exists")?;
        assert!(source_value_contains_seed(source_value, &seed.seed_value));
        Ok(())
    }

    #[test]
    fn rejects_permissioned_seed_without_ack_requirement() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        let seed = seed_by_execution_mode_mut(&mut catalog, "permissioned")?;
        seed.ack_requirement = None;
        let report = validate_fixture(&catalog);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("must declare ack_requirement"))
        );
        Ok(())
    }

    #[test]
    fn rejects_non_permissioned_seed_with_ack_requirement() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        let seed = seed_by_execution_mode_mut(&mut catalog, "dry_run")?;
        seed.ack_requirement = Some(
            "FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host"
                .to_owned(),
        );

        let report = validate_fixture(&catalog);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("must not declare ack_requirement")
                && error.contains("seed_workload_append_truncate_64001")
        }));
        Ok(())
    }

    #[test]
    fn rejects_non_permissioned_seed_with_permissioned_reproduction_token() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        let seed = seed_by_execution_mode_mut(&mut catalog, "analysis_only")?;
        seed.reproduction_command =
            "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 cargo run -p ffs-harness -- validate-repair-confidence-lab"
                .to_owned();

        let report = validate_fixture(&catalog);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("reproduction_command must not mention permissioned token")
                && error.contains("seed_fault_injection_case_1001")
        }));
        Ok(())
    }

    #[test]
    fn rejects_permissioned_seed_with_malformed_ack_requirement() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        let seed = seed_by_execution_mode_mut(&mut catalog, "permissioned")?;
        seed.ack_requirement = Some("please run the permissioned swarm workload".to_owned());

        let report = validate_fixture(&catalog);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("ack_requirement must be an exact KEY=value env assignment token")
                && error.contains("seed_swarm_tail_latency_7310001")
        }));
        Ok(())
    }

    #[test]
    fn rejects_permissioned_seed_command_missing_declared_ack() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        let seed = seed_by_execution_mode_mut(&mut catalog, "permissioned")?;
        seed.ack_requirement =
            Some("FFS_SWARM_WORKLOAD_REAL_RUN_ACK=alternate-permission-token".to_owned());

        let report = validate_fixture(&catalog);

        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("reproduction_command must include ack_requirement")
                && error.contains("seed_swarm_tail_latency_7310001")
        }));
        Ok(())
    }

    #[test]
    fn rejects_unknown_relation_type() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        first_seed_mut(&mut catalog)?.relation_type = "unknown_relation".to_owned();
        let report = validate_fixture(&catalog);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("relation_type references unknown value"))
        );
        Ok(())
    }

    #[test]
    fn rejects_seed_without_invariant() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        first_seed_mut(&mut catalog)?.invariant.clear();
        let report = validate_fixture(&catalog);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("invariant must not be empty"))
        );
        Ok(())
    }

    #[test]
    fn rejects_seed_without_existing_proof_consumer() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        first_seed_mut(&mut catalog)?.proof_consumers = vec!["unknown_consumer".to_owned()];
        let report = validate_fixture(&catalog);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("proof_consumers references unknown value"))
        );
        Ok(())
    }

    #[test]
    fn rejects_catalog_with_too_few_source_kinds() -> Result<()> {
        let mut catalog = fixture_catalog()?;
        for seed in &mut catalog.seeds {
            seed.source_kind = "workload_corpus".to_owned();
        }
        let report = validate_fixture(&catalog);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("at least 5 source kinds"))
        );
        Ok(())
    }
}
