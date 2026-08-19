#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_btrfs::{
    BTRFS_CHUNK_TREE_OBJECTID, BTRFS_DEV_TREE_OBJECTID, BTRFS_FILE_EXTENT_REG,
    BTRFS_FS_TREE_OBJECTID, BTRFS_FT_REG_FILE, BTRFS_ITEM_CHUNK, BTRFS_ITEM_DEV_ITEM,
    BTRFS_ITEM_DIR_INDEX, BTRFS_ITEM_EXTENT_DATA, BTRFS_ITEM_INODE_ITEM, BTRFS_SEND_STREAM_MAGIC,
    BTRFS_TREE_LOG_OBJECTID,
    BtrfsDeviceSet, SendAttr, SendCommand, SendStreamBuilder, build_chmod_command,
    build_chown_command, build_link_command, build_mkdir_command, build_mkfifo_command,
    build_mkfile_command, build_mknod_command, build_mksock_command, build_removexattr_command,
    build_rename_command, build_rmdir_command, build_setxattr_command, build_subvol_command,
    build_symlink_command, build_truncate_command, build_unlink_command, build_utimes_command,
    build_write_command, parse_send_stream, replay_tree_log, tree_log_root_item,
    walk_chunk_tree, walk_device_tree,
};
use ffs_core::{
    Ext4JournalReplayMode, FIEMAP_EXTENT_UNWRITTEN, FileType, FsOps, OpenFs, OpenOptions,
    RequestScope,
};
use ffs_fuse::{FrankenFuse, MountOptions, mount_background};
use ffs_harness::{
    GoldenReference, ParityReport,
    e2e::{CrashReplaySuiteConfig, FsxStressConfig, run_crash_replay_suite, run_fsx_stress},
    load_sparse_fixture, validate_btrfs_chunk_fixture, validate_btrfs_fixture,
    validate_btrfs_leaf_fixture, validate_dir_block_fixture, validate_ext4_fixture,
    validate_extent_tree_fixture, validate_group_desc_fixture, validate_inode_fixture,
};
use ffs_ondisk::{
    BtrfsChunkEntry, BtrfsKey, BtrfsStripe, BtrfsSuperblock, Ext4GroupDesc, Ext4IncompatFeatures,
    Ext4Superblock, ExtentTree, lookup_in_dir_block_casefold, parse_dev_item, parse_dir_block,
    stamp_dir_block_checksum, verify_dir_block_checksum,
};
use ffs_types::{
    BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, EXT4_CASEFOLD_FL, EXT4_COMPR_FL, EXT4_COMPRBLK_FL,
    EXT4_EXTENTS_FL, EXT4_INLINE_DATA_FL, EXT4_SUPER_MAGIC, EXT4_SUPERBLOCK_OFFSET,
    EXT4_XATTR_INDEX_SECURITY, EXT4_XATTR_INDEX_USER, GroupNumber, InodeNumber, ParseError,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::ffi::OsStrExt,
    path::{Component, Path},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    },
    thread,
    time::{Duration, Instant},
};

const FS_IOC_GET_ENCRYPTION_POLICY_CMD: u32 = 0x400C_6615;
const FSCRYPT_POLICY_V1_SIZE: usize = 12;
const FSCRYPT_CONTEXT_V1_SIZE: usize = 28;
const FSCRYPT_POLICY_V1_VERSION: u8 = 0;
const EXT4_ENCRYPT_INODE_FL: u32 = 0x0000_0800;
const EXT4_ENCRYPTION_XATTR_NAME: &[u8] = b"c";
const EXT4_FALLOC_FL_COLLAPSE_RANGE: i32 = 0x08;
const EXT4_FALLOC_FL_INSERT_RANGE: i32 = 0x20;
const FUSE_MOUNT_STATE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const FUSE_MOUNT_READY_TIMEOUT: Duration = Duration::from_secs(1);
const DISC_REVIEW_AUDIT_DATE: CalendarDate = CalendarDate {
    year: 2026,
    month: 5,
    day: 18,
};
const DISC_REVIEW_FRESHNESS_HORIZON_DAYS: i32 = 90;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance")
        .join("fixtures")
        .join(name)
}

#[test]
fn root_conformance_discrepancies_follow_policy() {
    let docs = include_str!("../../../conformance/DISCREPANCIES.md");
    let sections = active_discrepancy_sections(docs);
    assert!(
        !sections.is_empty(),
        "root DISCREPANCIES.md should document active DISC-NNN divergences"
    );

    for section in sections {
        assert!(
            valid_active_discrepancy_id(section.id),
            "active root divergence id must use DISC-NNN form: {}",
            section.id
        );
        assert!(
            section.has(DISC_FIELD_REFERENCE),
            "{} missing non-empty Reference field",
            section.id
        );
        assert!(
            section.has(DISC_FIELD_OUR_IMPL),
            "{} missing non-empty Our impl field",
            section.id
        );
        assert!(
            section.has(DISC_FIELD_IMPACT),
            "{} missing non-empty Impact field",
            section.id
        );
        assert!(
            section.has(DISC_FIELD_ACCEPTED_RESOLUTION),
            "{} missing ACCEPTED Resolution field",
            section.id
        );
        assert!(
            section.has(DISC_FIELD_TESTS_AFFECTED),
            "{} missing non-empty Tests affected field",
            section.id
        );
        assert!(
            section.has(DISC_FIELD_VALID_REVIEW_DATE),
            "{} missing calendar-valid YYYY-MM-DD Review date field",
            section.id
        );
        if let Some(error) = review_freshness_error(
            &section,
            DISC_REVIEW_AUDIT_DATE,
            DISC_REVIEW_FRESHNESS_HORIZON_DAYS,
        ) {
            panic!("{error}");
        }
    }
}

#[derive(Debug)]
struct DiscrepancySection<'a> {
    id: &'a str,
    fields: u8,
    review_date: Option<CalendarDate>,
    review_date_raw: Option<&'a str>,
    freshness_exemption: Option<&'a str>,
}

const DISC_FIELD_REFERENCE: u8 = 1 << 0;
const DISC_FIELD_OUR_IMPL: u8 = 1 << 1;
const DISC_FIELD_IMPACT: u8 = 1 << 2;
const DISC_FIELD_ACCEPTED_RESOLUTION: u8 = 1 << 3;
const DISC_FIELD_TESTS_AFFECTED: u8 = 1 << 4;
const DISC_FIELD_VALID_REVIEW_DATE: u8 = 1 << 5;

impl<'a> DiscrepancySection<'a> {
    fn new(id: &'a str) -> Self {
        Self {
            id,
            fields: 0,
            review_date: None,
            review_date_raw: None,
            freshness_exemption: None,
        }
    }

    fn record_line(&mut self, line: &'a str) {
        self.mark_if(
            DISC_FIELD_REFERENCE,
            line_has_nonempty_field(line, "- **Reference:**"),
        );
        self.mark_if(
            DISC_FIELD_OUR_IMPL,
            line_has_nonempty_field(line, "- **Our impl:**"),
        );
        self.mark_if(
            DISC_FIELD_IMPACT,
            line_has_nonempty_field(line, "- **Impact:**"),
        );
        self.mark_if(
            DISC_FIELD_ACCEPTED_RESOLUTION,
            line.strip_prefix("- **Resolution:**")
                .is_some_and(|value| value.trim_start().starts_with("ACCEPTED")),
        );
        self.mark_if(
            DISC_FIELD_TESTS_AFFECTED,
            line_has_nonempty_field(line, "- **Tests affected:**"),
        );
        if let Some(value) = line.strip_prefix("- **Review date:**") {
            let value = value.trim();
            self.review_date_raw = Some(value);
            if let Some(review_date) = parse_review_date(value) {
                self.review_date = Some(review_date);
                self.fields |= DISC_FIELD_VALID_REVIEW_DATE;
            }
        }
        if let Some(value) = line.strip_prefix("- **Freshness exemption:**") {
            let value = value.trim();
            if !value.is_empty() {
                self.freshness_exemption = Some(value);
            }
        }
    }

    fn mark_if(&mut self, field: u8, condition: bool) {
        if condition {
            self.fields |= field;
        }
    }

    fn has(&self, field: u8) -> bool {
        self.fields & field != 0
    }
}

fn active_discrepancy_sections<'a>(markdown: &'a str) -> Vec<DiscrepancySection<'a>> {
    let mut sections = Vec::new();
    let mut current: Option<DiscrepancySection<'a>> = None;

    for line in markdown.lines() {
        if let Some(header) = line.strip_prefix("### ") {
            let id = header.split_once(':').map_or(header, |(id, _)| id).trim();
            if id.starts_with("DISC-") {
                push_discrepancy_section(&mut sections, current.take());
                current = Some(DiscrepancySection::new(id));
                continue;
            }
        }

        if let Some(section) = current.as_mut() {
            section.record_line(line.trim_start());
        }
    }

    push_discrepancy_section(&mut sections, current);
    sections
}

fn push_discrepancy_section<'a>(
    sections: &mut Vec<DiscrepancySection<'a>>,
    section: Option<DiscrepancySection<'a>>,
) {
    if let Some(section) = section
        && !section.id.starts_with("DISC-R")
    {
        sections.push(section);
    }
}

fn valid_active_discrepancy_id(id: &str) -> bool {
    id.strip_prefix("DISC-")
        .is_some_and(|suffix| suffix.len() == 3 && suffix.as_bytes().iter().all(u8::is_ascii_digit))
}

fn line_has_nonempty_field(line: &str, field: &str) -> bool {
    line.strip_prefix(field)
        .is_some_and(|value| !value.trim().is_empty())
}

fn valid_yyyy_mm_dd(value: &str) -> bool {
    parse_review_date(value).is_some()
}

fn parse_review_date(value: &str) -> Option<CalendarDate> {
    let (year, month_day) = value.split_once('-')?;
    let (month, day) = month_day.split_once('-')?;

    let year_is_valid = year.len() == 4 && year.as_bytes().iter().all(u8::is_ascii_digit);
    let month_is_valid = month.len() == 2 && month.as_bytes().iter().all(u8::is_ascii_digit);
    let day_is_valid = day.len() == 2 && day.as_bytes().iter().all(u8::is_ascii_digit);

    if !year_is_valid || !month_is_valid || !day_is_valid {
        return None;
    }

    let year = year.parse::<i32>().ok()?;
    let month = month.parse::<u8>().ok()?;
    let day = day.parse::<u8>().ok()?;
    CalendarDate::new(year, month, day)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CalendarDate {
    year: i32,
    month: u8,
    day: u8,
}

impl CalendarDate {
    fn new(year: i32, month: u8, day: u8) -> Option<Self> {
        let days_in_month = days_in_month(year, month)?;
        if year > 0 && day > 0 && day <= days_in_month {
            Some(Self { year, month, day })
        } else {
            None
        }
    }

    fn days_since_ce(self) -> i32 {
        days_before_year(self.year) + days_before_month(self.year, self.month) + i32::from(self.day)
            - 1
    }
}

impl std::fmt::Display for CalendarDate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:04}-{:02}-{:02}",
            self.year, self.month, self.day
        )
    }
}

fn days_in_month(year: i32, month: u8) -> Option<u8> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_before_year(year: i32) -> i32 {
    let previous_year = year - 1;
    (365 * previous_year) + (previous_year / 4) - (previous_year / 100) + (previous_year / 400)
}

fn days_before_month(year: i32, month: u8) -> i32 {
    const COMMON_YEAR_MONTH_STARTS: [i32; 12] =
        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let month_index = usize::from(month - 1);
    let leap_day = i32::from(month > 2 && is_leap_year(year));
    COMMON_YEAR_MONTH_STARTS[month_index] + leap_day
}

fn review_freshness_error(
    section: &DiscrepancySection<'_>,
    audit_date: CalendarDate,
    horizon_days: i32,
) -> Option<String> {
    if let Some(exemption) = section.freshness_exemption
        && !valid_freshness_exemption(exemption)
    {
        return Some(format!(
            "{} review date {} has malformed Freshness exemption; required next action: use `reason=...; owner=...; follow-up=bd-...` or remove the exemption",
            section.id,
            section.review_date_raw.unwrap_or("<missing>")
        ));
    }

    let Some(review_date) = section.review_date else {
        return Some(format!(
            "{} missing calendar-valid Review date; required next action: record a real YYYY-MM-DD date before accepting the divergence",
            section.id
        ));
    };

    let age_days = audit_date.days_since_ce() - review_date.days_since_ce();
    if age_days < 0 {
        return Some(format!(
            "{} review date {} is future-dated relative to audit date {}; required next action: correct the date or re-run the review on that date",
            section.id, review_date, audit_date
        ));
    }

    if age_days > horizon_days && section.freshness_exemption.is_none() {
        return Some(format!(
            "{} review date {} is {} days old, above the {}-day freshness horizon; required next action: re-review and refresh the date or add a structured Freshness exemption with reason, owner, and follow-up bead",
            section.id, review_date, age_days, horizon_days
        ));
    }

    None
}

fn valid_freshness_exemption(value: &str) -> bool {
    let mut has_reason = false;
    let mut has_owner = false;
    let mut has_follow_up = false;

    for part in value.split(';') {
        let Some((key, value)) = part.trim().split_once('=') else {
            return false;
        };
        let value = value.trim();
        match key.trim() {
            "reason" => has_reason = !value.is_empty(),
            "owner" => has_owner = !value.is_empty(),
            "follow-up" => has_follow_up = valid_follow_up_bead(value),
            _ => {}
        }
    }

    has_reason && has_owner && has_follow_up
}

fn valid_follow_up_bead(value: &str) -> bool {
    value
        .strip_prefix("bd-")
        .is_some_and(|suffix| !suffix.is_empty())
}

#[test]
fn review_dates_reject_invalid_calendar_dates() {
    assert!(valid_yyyy_mm_dd("2024-02-29"));
    assert!(!valid_yyyy_mm_dd("2026-02-31"));
    assert!(!valid_yyyy_mm_dd("2026-13-01"));
    assert!(!valid_yyyy_mm_dd("2026-00-01"));
    assert!(!valid_yyyy_mm_dd("2026-01-00"));
}

#[test]
fn active_discrepancy_review_freshness_accepts_fresh_dates() {
    let markdown = active_discrepancy_markdown("DISC-010", "2026-05-18", None);
    let section = only_active_discrepancy_section(&markdown);

    let error = review_freshness_error(
        &section,
        DISC_REVIEW_AUDIT_DATE,
        DISC_REVIEW_FRESHNESS_HORIZON_DAYS,
    );

    assert!(error.is_none(), "{error:?}");
}

#[test]
fn active_discrepancy_review_freshness_rejects_stale_dates() {
    let markdown = active_discrepancy_markdown("DISC-010", "2026-02-16", None);
    let section = only_active_discrepancy_section(&markdown);

    let error = review_freshness_error(
        &section,
        DISC_REVIEW_AUDIT_DATE,
        DISC_REVIEW_FRESHNESS_HORIZON_DAYS,
    )
    .expect("stale review should fail");

    assert!(error.contains("DISC-010"));
    assert!(error.contains("2026-02-16"));
    assert!(error.contains("90-day"));
    assert!(error.contains("required next action"));
}

#[test]
fn active_discrepancy_review_freshness_rejects_future_dates() {
    let markdown = active_discrepancy_markdown("DISC-010", "2026-05-19", None);
    let section = only_active_discrepancy_section(&markdown);

    let error = review_freshness_error(
        &section,
        DISC_REVIEW_AUDIT_DATE,
        DISC_REVIEW_FRESHNESS_HORIZON_DAYS,
    )
    .expect("future review should fail");

    assert!(error.contains("DISC-010"));
    assert!(error.contains("future-dated"));
    assert!(error.contains("2026-05-19"));
}

#[test]
fn active_discrepancy_review_freshness_accepts_structured_exemption() {
    let markdown = active_discrepancy_markdown(
        "DISC-010",
        "2026-02-16",
        Some(
            "reason=legacy fixture frozen until next kernel sample; owner=ffs-harness; follow-up=bd-review-refresh",
        ),
    );
    let section = only_active_discrepancy_section(&markdown);

    let error = review_freshness_error(
        &section,
        DISC_REVIEW_AUDIT_DATE,
        DISC_REVIEW_FRESHNESS_HORIZON_DAYS,
    );

    assert!(error.is_none(), "{error:?}");
}

#[test]
fn active_discrepancy_review_freshness_rejects_malformed_exemption() {
    let markdown = active_discrepancy_markdown(
        "DISC-010",
        "2026-02-16",
        Some("reason=legacy fixture frozen; owner=ffs-harness"),
    );
    let section = only_active_discrepancy_section(&markdown);

    let error = review_freshness_error(
        &section,
        DISC_REVIEW_AUDIT_DATE,
        DISC_REVIEW_FRESHNESS_HORIZON_DAYS,
    )
    .expect("malformed exemption should fail");

    assert!(error.contains("DISC-010"));
    assert!(error.contains("Freshness exemption"));
    assert!(error.contains("follow-up=bd-"));
}

#[test]
fn resolved_disc_r_entries_are_ignored_by_review_freshness_guard() {
    let markdown = r"
## Resolved Divergences

### DISC-R010: stale historical divergence
- **Reference:** reference
- **Our impl:** implementation
- **Impact:** impact
- **Resolution:** FIXED
- **Tests affected:** historical_test
- **Review date:** 2020-01-01
";

    assert!(active_discrepancy_sections(markdown).is_empty());
}

fn active_discrepancy_markdown(
    id: &str,
    review_date: &str,
    freshness_exemption: Option<&str>,
) -> String {
    let exemption = freshness_exemption.map_or_else(String::new, |value| {
        format!("\n- **Freshness exemption:** {value}")
    });
    format!(
        r"
## Active Divergences

### {id}: synthetic divergence
- **Reference:** reference
- **Our impl:** implementation
- **Impact:** impact
- **Resolution:** ACCEPTED -- synthetic test case
- **Tests affected:** synthetic_test
- **Review date:** {review_date}{exemption}
"
    )
}

fn only_active_discrepancy_section(markdown: &str) -> DiscrepancySection<'_> {
    let mut sections = active_discrepancy_sections(markdown);
    assert_eq!(
        sections.len(),
        1,
        "synthetic markdown should yield one section"
    );
    sections.remove(0)
}

#[test]
fn conformance_fixture_provenance_covers_committed_fixtures() {
    let workspace = workspace_root();
    let fixtures = parse_checksum_inventory(
        &workspace
            .join("conformance")
            .join("fixtures")
            .join("checksums.sha256"),
    )
    .keys()
    .cloned()
    .collect::<HashSet<_>>();
    let sections = fixture_provenance_sections(include_str!("../../../conformance/PROVENANCE.md"));

    assert!(
        !sections.is_empty(),
        "conformance/PROVENANCE.md should document fixture provenance sections"
    );

    for section in &sections {
        assert!(
            section.has(FIXTURE_PROVENANCE_CREATED),
            "{} missing non-empty Created field",
            section.header
        );
        assert!(
            section.has(FIXTURE_PROVENANCE_AUTHOR),
            "{} missing non-empty Author field",
            section.header
        );
        assert!(
            section.has(FIXTURE_PROVENANCE_REFERENCE),
            "{} missing non-empty Reference field",
            section.header
        );
        assert!(
            section.has(FIXTURE_PROVENANCE_DESCRIPTION),
            "{} missing non-empty Description field",
            section.header
        );
        assert!(
            section.has(FIXTURE_PROVENANCE_VERIFICATION),
            "{} missing non-empty Verification field",
            section.header
        );
        assert!(
            fixtures.iter().any(|fixture| section.covers(fixture)),
            "{} does not match any committed fixture",
            section.header
        );
    }

    let missing = sorted_names(
        fixtures
            .iter()
            .filter(|fixture| !sections.iter().any(|section| section.covers(fixture)))
            .cloned(),
    );
    assert!(
        missing.is_empty(),
        "conformance/PROVENANCE.md is missing fixture provenance for: {}",
        missing.join(", ")
    );
}

#[test]
fn conformance_golden_provenance_covers_committed_artifacts() {
    let workspace = workspace_root();
    let artifacts = parse_checksum_inventory(
        &workspace
            .join("conformance")
            .join("golden")
            .join("checksums.sha256"),
    )
    .keys()
    .cloned()
    .collect::<HashSet<_>>();
    let sections = golden_provenance_sections(include_str!("../../../conformance/PROVENANCE.md"));

    assert!(
        !sections.is_empty(),
        "conformance/PROVENANCE.md should document golden provenance sections"
    );

    for section in &sections {
        assert!(
            section.has(GOLDEN_PROVENANCE_GENERATED_BY),
            "{} missing non-empty Generated by field",
            section.header
        );
        assert!(
            section.has(GOLDEN_PROVENANCE_SOURCE_IMAGES),
            "{} missing non-empty Source images field",
            section.header
        );
        assert!(
            section.has(GOLDEN_PROVENANCE_MKFS_VERSION),
            "{} missing non-empty mkfs version field",
            section.header
        );
        assert!(
            section.has(GOLDEN_PROVENANCE_COMMAND),
            "{} missing non-empty Command field",
            section.header
        );
        assert!(
            artifacts.iter().any(|artifact| section.covers(artifact)),
            "{} does not match any committed golden artifact",
            section.header
        );
    }

    let missing = sorted_names(
        artifacts
            .iter()
            .filter(|artifact| !sections.iter().any(|section| section.covers(artifact)))
            .cloned(),
    );
    assert!(
        missing.is_empty(),
        "conformance/PROVENANCE.md is missing golden provenance for: {}",
        missing.join(", ")
    );
}

struct FixtureProvenanceSection<'a> {
    header: &'a str,
    fields: u8,
}

struct GoldenProvenanceSection<'a> {
    header: &'a str,
    fields: u8,
}

const FIXTURE_PROVENANCE_CREATED: u8 = 1 << 0;
const FIXTURE_PROVENANCE_AUTHOR: u8 = 1 << 1;
const FIXTURE_PROVENANCE_REFERENCE: u8 = 1 << 2;
const FIXTURE_PROVENANCE_DESCRIPTION: u8 = 1 << 3;
const FIXTURE_PROVENANCE_VERIFICATION: u8 = 1 << 4;

const GOLDEN_PROVENANCE_GENERATED_BY: u8 = 1 << 0;
const GOLDEN_PROVENANCE_SOURCE_IMAGES: u8 = 1 << 1;
const GOLDEN_PROVENANCE_MKFS_VERSION: u8 = 1 << 2;
const GOLDEN_PROVENANCE_COMMAND: u8 = 1 << 3;

const EXACT_PROVENANCE_GOLDENS: &[&str] = &[
    "btrfs_item_payloads.txt",
    "ext4_fscrypt_legacy_policy_transport_discrepancy.json",
];

impl<'a> FixtureProvenanceSection<'a> {
    fn new(header: &'a str) -> Self {
        Self { header, fields: 0 }
    }

    fn record_line(&mut self, line: &str) {
        self.mark_if(
            FIXTURE_PROVENANCE_CREATED,
            line_has_nonempty_field(line, "- **Created:**"),
        );
        self.mark_if(
            FIXTURE_PROVENANCE_AUTHOR,
            line_has_nonempty_field(line, "- **Author:**"),
        );
        self.mark_if(
            FIXTURE_PROVENANCE_REFERENCE,
            line_has_nonempty_field(line, "- **Reference:**"),
        );
        self.mark_if(
            FIXTURE_PROVENANCE_DESCRIPTION,
            line_has_nonempty_field(line, "- **Description:**"),
        );
        self.mark_if(
            FIXTURE_PROVENANCE_VERIFICATION,
            line_has_nonempty_field(line, "- **Verification:**"),
        );
    }

    fn mark_if(&mut self, field: u8, condition: bool) {
        if condition {
            self.fields |= field;
        }
    }

    fn has(&self, field: u8) -> bool {
        self.fields & field != 0
    }

    fn covers(&self, fixture: &str) -> bool {
        self.header
            .split('/')
            .map(str::trim)
            .map(|token| token.split_whitespace().next().unwrap_or(""))
            .any(|pattern| provenance_pattern_matches(pattern, fixture))
    }
}

impl<'a> GoldenProvenanceSection<'a> {
    fn new(header: &'a str) -> Self {
        Self { header, fields: 0 }
    }

    fn record_line(&mut self, line: &str) {
        self.mark_if(
            GOLDEN_PROVENANCE_GENERATED_BY,
            line_has_nonempty_field(line, "- **Generated by:**"),
        );
        self.mark_if(
            GOLDEN_PROVENANCE_SOURCE_IMAGES,
            line_has_nonempty_field(line, "- **Source images:**"),
        );
        self.mark_if(
            GOLDEN_PROVENANCE_MKFS_VERSION,
            line_has_nonempty_field(line, "- **mkfs version:**"),
        );
        self.mark_if(
            GOLDEN_PROVENANCE_COMMAND,
            line_has_nonempty_field(line, "- **Command:**"),
        );
    }

    fn mark_if(&mut self, field: u8, condition: bool) {
        if condition {
            self.fields |= field;
        }
    }

    fn has(&self, field: u8) -> bool {
        self.fields & field != 0
    }

    fn covers(&self, artifact: &str) -> bool {
        self.header
            .split('/')
            .map(str::trim)
            .map(|token| token.split_whitespace().next().unwrap_or(""))
            .any(|pattern| golden_provenance_pattern_matches(pattern, artifact))
    }
}

fn fixture_provenance_sections(markdown: &str) -> Vec<FixtureProvenanceSection<'_>> {
    let mut sections = Vec::new();
    let mut current = None;
    let mut in_fixture_block = false;

    for line in markdown.lines() {
        if let Some(header) = line.strip_prefix("## ") {
            push_fixture_provenance_section(&mut sections, current.take());
            in_fixture_block = matches!(
                header.trim(),
                "ext4 Fixtures"
                    | "btrfs Fixtures"
                    | "NUMA Allocation Fixtures"
                    | "Runtime Console Fixtures"
            );
            continue;
        }

        if !in_fixture_block {
            continue;
        }

        if let Some(header) = line.strip_prefix("### ") {
            push_fixture_provenance_section(&mut sections, current.take());
            current = Some(FixtureProvenanceSection::new(header.trim()));
            continue;
        }

        if let Some(section) = current.as_mut() {
            section.record_line(line.trim_start());
        }
    }

    push_fixture_provenance_section(&mut sections, current);
    sections
}

fn golden_provenance_sections(markdown: &str) -> Vec<GoldenProvenanceSection<'_>> {
    let mut sections = Vec::new();
    let mut current = None;
    let mut in_golden_block = false;

    for line in markdown.lines() {
        if let Some(header) = line.strip_prefix("## ") {
            push_golden_provenance_section(&mut sections, current.take());
            in_golden_block = header.trim() == "Golden Files";
            continue;
        }

        if !in_golden_block {
            continue;
        }

        if let Some(header) = line.strip_prefix("### ") {
            push_golden_provenance_section(&mut sections, current.take());
            current = Some(GoldenProvenanceSection::new(header.trim()));
            continue;
        }

        if let Some(section) = current.as_mut() {
            section.record_line(line.trim_start());
        }
    }

    push_golden_provenance_section(&mut sections, current);
    sections
}

fn push_fixture_provenance_section<'a>(
    sections: &mut Vec<FixtureProvenanceSection<'a>>,
    section: Option<FixtureProvenanceSection<'a>>,
) {
    if let Some(section) = section {
        sections.push(section);
    }
}

fn push_golden_provenance_section<'a>(
    sections: &mut Vec<GoldenProvenanceSection<'a>>,
    section: Option<GoldenProvenanceSection<'a>>,
) {
    if let Some(section) = section {
        sections.push(section);
    }
}

fn provenance_pattern_matches(pattern: &str, artifact: &str) -> bool {
    if pattern == artifact {
        return true;
    }
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return false;
    };
    !prefix.is_empty()
        && !suffix.is_empty()
        && artifact.starts_with(prefix)
        && artifact.ends_with(suffix)
}

fn golden_provenance_pattern_matches(pattern: &str, artifact: &str) -> bool {
    if EXACT_PROVENANCE_GOLDENS.contains(&artifact) {
        pattern == artifact
    } else {
        provenance_pattern_matches(pattern, artifact)
    }
}

#[test]
fn specialized_golden_provenance_rejects_broad_wildcards() {
    assert!(
        provenance_pattern_matches(
            "ext4_*.json",
            "ext4_fscrypt_legacy_policy_transport_discrepancy.json",
        ),
        "raw wildcard matching documents the old false-positive shape"
    );
    assert!(
        !golden_provenance_pattern_matches(
            "ext4_*.json",
            "ext4_fscrypt_legacy_policy_transport_discrepancy.json",
        ),
        "fscrypt transport discrepancy goldens require exact provenance"
    );
    assert!(
        golden_provenance_pattern_matches(
            "ext4_fscrypt_legacy_policy_transport_discrepancy.json",
            "ext4_fscrypt_legacy_policy_transport_discrepancy.json",
        ),
        "an exact specialized golden provenance section should satisfy coverage"
    );
}

#[test]
fn ext4_and_btrfs_fixtures_conform() {
    let ext4_sparse = validate_ext4_fixture(&fixture_path("ext4_superblock_sparse.json"))
        .expect("ext4 sparse fixture");
    let ext4_mkfs = validate_ext4_fixture(&fixture_path("ext4_superblock_mkfs_4096.json"))
        .expect("ext4 mkfs fixture");
    let btrfs = validate_btrfs_fixture(&fixture_path("btrfs_superblock_sparse.json"))
        .expect("btrfs fixture");

    assert_eq!(ext4_sparse.block_size, 4096);
    assert_eq!(ext4_sparse.inodes_count, 1000);
    assert_eq!(ext4_sparse.blocks_count, 100);
    assert_eq!(ext4_sparse.reserved_blocks_count, 10);
    assert_eq!(ext4_sparse.free_blocks_count, 50);
    assert_eq!(ext4_sparse.free_inodes_count, 700);
    assert_eq!(ext4_sparse.first_data_block, 0);
    assert_eq!(ext4_sparse.log_cluster_size, 0);
    assert_eq!(ext4_sparse.cluster_size, 1024);
    assert_eq!(ext4_sparse.blocks_per_group, 32768);
    assert_eq!(ext4_sparse.clusters_per_group, 0);
    assert_eq!(ext4_sparse.inodes_per_group, 8192);
    assert_eq!(ext4_sparse.magic, EXT4_SUPER_MAGIC);
    assert_eq!(ext4_sparse.uuid, [0; 16]);
    assert_eq!(ext4_sparse.volume_name, "frankenfs");
    assert_eq!(ext4_sparse.feature_compat.0, 1);
    assert_eq!(ext4_sparse.feature_incompat.0, 2);
    assert_eq!(ext4_sparse.feature_ro_compat.0, 4);
    assert_eq!(ext4_sparse.checksum, 0);

    assert_eq!(ext4_mkfs.block_size, 4096);
    assert_eq!(ext4_mkfs.log_cluster_size, 2);
    assert_eq!(ext4_mkfs.cluster_size, 4096);
    assert_eq!(ext4_mkfs.blocks_per_group, ext4_mkfs.clusters_per_group);
    assert_eq!(ext4_mkfs.volume_name, "ffs-mkfs");

    assert_eq!(btrfs.csum, [0; 32]);
    assert_eq!(btrfs.fsid, [0; 16]);
    assert_eq!(btrfs.bytenr, 0x1_0000);
    assert_eq!(btrfs.flags, 0);
    assert_eq!(btrfs.magic, BTRFS_MAGIC);
    assert_eq!(btrfs.generation, 10);
    assert_eq!(btrfs.root, 0x2000);
    assert_eq!(btrfs.chunk_root, 0x3000);
    assert_eq!(btrfs.log_root, 0x4000);
    assert_eq!(btrfs.total_bytes, 1_000_000);
    assert_eq!(btrfs.bytes_used, 100_000);
    assert_eq!(btrfs.root_dir_objectid, 6);
    assert_eq!(btrfs.num_devices, 1);
    assert_eq!(btrfs.sectorsize, 4096);
    assert_eq!(btrfs.nodesize, 16384);
    assert_eq!(btrfs.stripesize, 65536);
    assert_eq!(btrfs.compat_flags, 0);
    assert_eq!(btrfs.compat_ro_flags, 0);
    assert_eq!(btrfs.incompat_flags, 0);
    assert_eq!(btrfs.csum_type, 0);
    assert_eq!(btrfs.root_level, 0);
    assert_eq!(btrfs.chunk_root_level, 1);
    assert_eq!(btrfs.log_root_level, 2);
    assert_eq!(btrfs.label, "ffs-lab");
    assert_eq!(btrfs.sys_chunk_array_size, 0);
    assert!(btrfs.sys_chunk_array.is_empty());
}

#[test]
fn ext4_group_desc_fixtures_conform() {
    let gd32 = validate_group_desc_fixture(&fixture_path("ext4_group_desc_32byte.json"), 32)
        .expect("32-byte group desc");
    assert_eq!(gd32.block_bitmap, 5);
    assert_eq!(gd32.inode_bitmap, 6);
    assert_eq!(gd32.inode_table, 7);
    assert_eq!(gd32.free_blocks_count, 200);
    assert_eq!(gd32.free_inodes_count, 1000);
    assert_eq!(gd32.used_dirs_count, 3);
    assert_eq!(gd32.itable_unused, 500);
    assert_eq!(gd32.flags, 4);
    assert_eq!(gd32.checksum, 0xCDAB);
    assert_eq!(gd32.block_bitmap_csum, 0);
    assert_eq!(gd32.inode_bitmap_csum, 0);

    let gd64 = validate_group_desc_fixture(&fixture_path("ext4_group_desc_64byte.json"), 64)
        .expect("64-byte group desc");
    assert_eq!(gd64.block_bitmap, 0x1_0000_0005);
    assert_eq!(gd64.inode_bitmap, 0x2_0000_0006);
    assert_eq!(gd64.inode_table, 0x3_0000_0007);
    assert_eq!(gd64.free_blocks_count, 0x000A_00C8);
    assert_eq!(gd64.free_inodes_count, 0x0014_03E8);
    assert_eq!(gd64.used_dirs_count, 0x0005_0003);
    assert_eq!(gd64.itable_unused, 0x0064_01F4);
    assert_eq!(gd64.flags, 4);
    assert_eq!(gd64.checksum, 0x7856);
    assert_eq!(gd64.block_bitmap_csum, 0);
    assert_eq!(gd64.inode_bitmap_csum, 0);
}

/// bd-o6it9 — conformance contract that the encoder produces
/// kernel-shaped bytes. Distinct from the bd-ov7zr proptest MR
/// `parse(write(gd)) == gd` (encoder/decoder mutual consistency):
/// here we pin `write_to_bytes(gd_from_fixture) == fixture_bytes`,
/// which catches the case where encoder + decoder agree on a wrong
/// offset and round-trip silently while drifting from the on-disk
/// format the kernel writes.
#[test]
fn ext4_group_desc_32byte_fixture_re_encodes_byte_identical() {
    let original = load_sparse_fixture(&fixture_path("ext4_group_desc_32byte.json"))
        .expect("load gd32 fixture");
    assert_eq!(
        original.len(),
        32,
        "32-byte group desc fixture must materialise to exactly 32 bytes"
    );

    let gd = Ext4GroupDesc::parse_from_bytes(&original, 32)
        .expect("parse 32-byte fixture for re-encode");

    let mut encoded = vec![0_u8; 32];
    gd.write_to_bytes(&mut encoded, 32)
        .expect("re-encode parsed 32-byte gd");

    assert_eq!(
        encoded, original,
        "writer must produce byte-identical output to the 32-byte conformance fixture"
    );
}

/// bd-o6it9 — same conformance contract for the 64-byte path, which
/// exercises the lo+hi split (block_bitmap_hi / inode_bitmap_hi /
/// inode_table_hi / free_*_hi / used_dirs_hi / itable_unused_hi at
/// 0x20..0x34, plus the bitmap-csum hi halves at 0x38/0x3A). Drift
/// in any of the hi-half offsets would silently corrupt 64-bit-mode
/// images on every flush.
#[test]
fn ext4_group_desc_64byte_fixture_re_encodes_byte_identical() {
    let original = load_sparse_fixture(&fixture_path("ext4_group_desc_64byte.json"))
        .expect("load gd64 fixture");
    assert_eq!(
        original.len(),
        64,
        "64-byte group desc fixture must materialise to exactly 64 bytes"
    );

    let gd = Ext4GroupDesc::parse_from_bytes(&original, 64)
        .expect("parse 64-byte fixture for re-encode");

    let mut encoded = vec![0_u8; 64];
    gd.write_to_bytes(&mut encoded, 64)
        .expect("re-encode parsed 64-byte gd");

    assert_eq!(
        encoded, original,
        "writer must produce byte-identical output to the 64-byte conformance fixture"
    );
}

#[test]
fn ext4_inode_fixtures_conform() {
    let file_inode = validate_inode_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("regular file inode");
    assert_eq!(file_inode.mode, 0o10_0644);
    assert_eq!(file_inode.uid, 1000);
    assert_eq!(file_inode.gid, 1000);
    assert_eq!(file_inode.size, 1024);
    assert_eq!(file_inode.links_count, 1);
    assert_eq!(file_inode.blocks, 8);
    assert_eq!(file_inode.flags, EXT4_EXTENTS_FL);
    assert_eq!(file_inode.version, 0);
    assert_eq!(file_inode.generation, 42);
    assert_eq!(file_inode.file_acl, 0);
    assert_eq!(file_inode.extra_isize, 32);
    assert_eq!(file_inode.checksum, 0);
    assert_eq!(file_inode.version_hi, 0);
    assert_eq!(file_inode.projid, 0);
    assert_eq!(file_inode.extent_bytes.len(), 60);
    assert_eq!(file_inode.xattr_ibody.len(), 96);
    assert!(file_inode.xattr_ibody.iter().all(|&byte| byte == 0));

    let (file_extent_header, file_extent_tree) =
        ffs_ondisk::parse_extent_tree(&file_inode.extent_bytes)
            .expect("regular file inode extent tree");
    assert_eq!(file_extent_header.magic, 0xF30A);
    assert_eq!(file_extent_header.entries, 1);
    assert_eq!(file_extent_header.max_entries, 4);
    assert_eq!(file_extent_header.depth, 0);
    assert_eq!(file_extent_header.generation, 0);
    let ExtentTree::Leaf(file_extents) = file_extent_tree else {
        panic!("regular file inode should contain leaf extents");
    };
    assert_eq!(file_extents.len(), 1);
    assert_eq!(file_extents[0].logical_block, 0);
    assert_eq!(file_extents[0].actual_len(), 1);
    assert_eq!(file_extents[0].physical_start, 10);
    assert!(!file_extents[0].is_unwritten());

    let dir_inode = validate_inode_fixture(&fixture_path("ext4_inode_directory.json"))
        .expect("directory inode");
    assert_eq!(dir_inode.mode, 0o4_0755);
    assert_eq!(dir_inode.uid, 0);
    assert_eq!(dir_inode.gid, 0);
    assert_eq!(dir_inode.size, 4096);
    assert_eq!(dir_inode.links_count, 2);
    assert_eq!(dir_inode.blocks, 8);
    assert_eq!(dir_inode.flags, EXT4_EXTENTS_FL);
    assert_eq!(dir_inode.version, 0);
    assert_eq!(dir_inode.generation, 1);
    assert_eq!(dir_inode.file_acl, 0);
    assert_eq!(dir_inode.extra_isize, 32);
    assert_eq!(dir_inode.checksum, 0);
    assert_eq!(dir_inode.version_hi, 0);
    assert_eq!(dir_inode.projid, 0);
    assert_eq!(dir_inode.extent_bytes.len(), 60);
    assert_eq!(dir_inode.xattr_ibody.len(), 96);
    assert!(dir_inode.xattr_ibody.iter().all(|&byte| byte == 0));

    let (dir_extent_header, dir_extent_tree) =
        ffs_ondisk::parse_extent_tree(&dir_inode.extent_bytes)
            .expect("directory inode extent tree");
    assert_eq!(dir_extent_header.magic, 0xF30A);
    assert_eq!(dir_extent_header.entries, 1);
    assert_eq!(dir_extent_header.max_entries, 4);
    assert_eq!(dir_extent_header.depth, 0);
    assert_eq!(dir_extent_header.generation, 0);
    let ExtentTree::Leaf(dir_extents) = dir_extent_tree else {
        panic!("directory inode should contain leaf extents");
    };
    assert_eq!(dir_extents.len(), 1);
    assert_eq!(dir_extents[0].logical_block, 0);
    assert_eq!(dir_extents[0].actual_len(), 1);
    assert_eq!(dir_extents[0].physical_start, 20);
    assert!(!dir_extents[0].is_unwritten());
}

#[test]
fn ext4_inline_data_fixture_conforms() {
    // Simple inline data inode (data fits in i_block field)
    let inode = validate_inode_fixture(&fixture_path("ext4_inode_inline_data.json"))
        .expect("inline data inode");
    assert_eq!(inode.mode & 0o17_0000, 0o10_0000, "should be regular file");
    assert_eq!(inode.size, 23, "inline data size should be 23 bytes");
    assert_ne!(
        inode.flags & ffs_types::EXT4_INLINE_DATA_FL,
        0,
        "should have INLINE_DATA flag"
    );

    // Check that extent_bytes contains the inline data ("Hello from inline data!")
    let expected = b"Hello from inline data!";
    assert_eq!(
        &inode.extent_bytes[..expected.len()],
        expected,
        "i_block should contain inline data"
    );
}

#[test]
fn ext4_inline_data_with_continuation_fixture_conforms() {
    // Inline data inode with system.data xattr continuation
    let inode = validate_inode_fixture(&fixture_path(
        "ext4_inode_inline_data_with_continuation.json",
    ))
    .expect("inline data inode with continuation");
    assert_eq!(
        inode.size, 76,
        "inline data size should be 76 bytes (60 + 16)"
    );
    assert_ne!(
        inode.flags & ffs_types::EXT4_INLINE_DATA_FL,
        0,
        "should have INLINE_DATA flag"
    );

    // Check i_block contains 60 bytes of 'A'
    assert!(
        inode.extent_bytes.iter().all(|&b| b == b'A'),
        "i_block should contain 60 bytes of 'A'"
    );

    // Parse ibody xattrs to find system.data continuation
    let xattrs = ffs_ondisk::parse_ibody_xattrs(&inode).expect("parse ibody xattrs");
    let system_data = xattrs
        .iter()
        .find(|x| x.name_index == 7 && x.name == b"data");
    assert!(system_data.is_some(), "should have system.data xattr");

    let continuation = system_data.unwrap();
    assert_eq!(
        continuation.value.len(),
        16,
        "continuation should be 16 bytes"
    );
    assert!(
        continuation.value.iter().all(|&b| b == b'B'),
        "continuation should contain 'B' bytes"
    );
}

#[test]
fn ext4_inline_data_openfs_read_conforms() {
    let fs = open_ext4_inline_data_image("ext4_inode_inline_data.json");
    let cx = Cx::for_testing();

    let data = fs
        .read(&cx, InodeNumber(11), 0, 128)
        .expect("read inline-data file");
    assert_eq!(&data, b"Hello from inline data!");

    let offset = fs
        .read(&cx, InodeNumber(11), 6, 64)
        .expect("read inline-data file at offset");
    assert_eq!(&offset, b"from inline data!");
}

#[test]
fn ext4_inline_data_xattr_continuation_openfs_read_conforms() {
    let fs = open_ext4_inline_data_image("ext4_inode_inline_data_with_continuation.json");
    let cx = Cx::for_testing();

    let data = fs
        .read(&cx, InodeNumber(11), 0, 128)
        .expect("read inline-data continuation file");
    let mut expected = vec![b'A'; 60];
    expected.extend(std::iter::repeat_n(b'B', 16));
    assert_eq!(data, expected);

    let tail = fs
        .read(&cx, InodeNumber(11), 56, 32)
        .expect("read inline-data continuation tail");
    assert_eq!(tail, b"AAAABBBBBBBBBBBBBBBB");
}

#[test]
fn ext4_inline_data_openfs_read_boundaries_conform() {
    let fs = open_ext4_inline_data_image("ext4_inode_inline_data.json");
    let cx = Cx::for_testing();

    let eof_tail = fs
        .read(&cx, InodeNumber(11), 20, 128)
        .expect("read inline-data range crossing EOF");
    assert_eq!(&eof_tail, b"ta!");

    let at_eof = fs
        .read(&cx, InodeNumber(11), 23, 128)
        .expect("read inline-data exactly at EOF");
    assert!(at_eof.is_empty(), "read at inline-data EOF should be empty");

    let past_eof = fs
        .read(&cx, InodeNumber(11), 4096, 128)
        .expect("read inline-data past EOF");
    assert!(
        past_eof.is_empty(),
        "read past inline-data EOF should be empty"
    );

    let fs = open_ext4_inline_data_image("ext4_inode_inline_data_with_continuation.json");
    let continuation_tail = fs
        .read(&cx, InodeNumber(11), 72, 32)
        .expect("read inline-data continuation range crossing EOF");
    assert_eq!(&continuation_tail, b"BBBB");
}

#[test]
fn ext4_inline_data_zero_size_and_extreme_read_bounds_conform() {
    let fs = open_ext4_inline_data_image("ext4_inode_inline_data.json");
    let cx = Cx::for_testing();

    for offset in [0, 6, 23, 4096, u64::MAX] {
        let empty = fs
            .read(&cx, InodeNumber(11), offset, 0)
            .expect("zero-size inline-data read");
        assert!(
            empty.is_empty(),
            "zero-size inline-data read at offset {offset} should be empty"
        );
    }

    let full = fs
        .read(&cx, InodeNumber(11), 0, u32::MAX)
        .expect("oversized inline-data read clamps to inode size");
    assert_eq!(&full, b"Hello from inline data!");

    let extreme = fs
        .read(&cx, InodeNumber(11), u64::MAX - 4, u32::MAX)
        .expect("extreme inline-data offset read");
    assert!(
        extreme.is_empty(),
        "extreme inline-data offset should not over-read"
    );

    let fs = open_ext4_inline_data_image("ext4_inode_inline_data_with_continuation.json");
    for offset in [0, 60, 76, 4096, u64::MAX] {
        let empty = fs
            .read(&cx, InodeNumber(11), offset, 0)
            .expect("zero-size continued inline-data read");
        assert!(
            empty.is_empty(),
            "zero-size continued inline-data read at offset {offset} should be empty"
        );
    }

    let continued_full = fs
        .read(&cx, InodeNumber(11), 0, u32::MAX)
        .expect("oversized continued inline-data read clamps to inode size");
    let mut expected = vec![b'A'; 60];
    expected.extend(std::iter::repeat_n(b'B', 16));
    assert_eq!(continued_full, expected);

    let continued_extreme = fs
        .read(&cx, InodeNumber(11), u64::MAX - 8, u32::MAX)
        .expect("extreme continued inline-data offset read");
    assert!(
        continued_extreme.is_empty(),
        "extreme continued inline-data offset should not over-read"
    );
}

#[test]
fn ext4_inline_data_vfs_lookup_readdir_conforms() {
    let fs = open_ext4_inline_data_image("ext4_inode_inline_data.json");
    let cx = Cx::for_testing();
    let root = InodeNumber(2);

    let entries = fs
        .readdir(&cx, root, 0)
        .expect("readdir inline-data fixture root");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, b".");
    assert_eq!(entries[1].name, b"..");
    assert_eq!(entries[2].name, b"inline.bin");
    assert_eq!(entries[2].ino, InodeNumber(11));
    assert_eq!(entries[2].kind, FileType::RegularFile);

    let attr = fs
        .lookup(&cx, root, OsStr::new("inline.bin"))
        .expect("lookup inline-data file through root directory");
    assert_eq!(attr.ino, InodeNumber(11));
    assert_eq!(attr.kind, FileType::RegularFile);
    assert_eq!(attr.size, 23);
    assert_eq!(attr.blocks, 0);
    assert_eq!(attr.perm, 0o644);
    assert_eq!(attr.nlink, 1);
    assert_eq!(attr.uid, 1000);
    assert_eq!(attr.gid, 1000);

    let (resolved_ino, resolved_inode) = fs
        .resolve_path(&cx, &RequestScope::empty(), "/inline.bin")
        .expect("resolve inline-data file path");
    assert_eq!(resolved_ino, InodeNumber(11));
    assert_ne!(resolved_inode.flags & EXT4_INLINE_DATA_FL, 0);

    let data = fs
        .read(&cx, attr.ino, 0, 128)
        .expect("read inline-data file through looked-up inode");
    assert_eq!(&data, b"Hello from inline data!");

    let fs = open_ext4_inline_data_image("ext4_inode_inline_data_with_continuation.json");
    let attr = fs
        .lookup(&cx, root, OsStr::new("inline.bin"))
        .expect("lookup continued inline-data file through root directory");
    assert_eq!(attr.ino, InodeNumber(11));
    assert_eq!(attr.kind, FileType::RegularFile);
    assert_eq!(attr.size, 76);

    let continuation = fs
        .read(&cx, attr.ino, 0, 128)
        .expect("read continued inline-data file through looked-up inode");
    let mut expected = vec![b'A'; 60];
    expected.extend(std::iter::repeat_n(b'B', 16));
    assert_eq!(continuation, expected);
}

#[test]
fn ext4_inline_data_write_rejects_without_mutating_contents() {
    let mut fs = open_ext4_inline_data_image("ext4_inode_inline_data.json");
    let cx = Cx::for_testing();
    fs.enable_writes(&cx)
        .expect("enable writes for inline-data rejection check");

    let before = fs
        .read(&cx, InodeNumber(11), 0, 128)
        .expect("read inline data before rejected write");
    let err = fs
        .write(&cx, InodeNumber(11), 0, b"mutated")
        .expect_err("inline-data writes are outside the V1 mutation contract");

    assert!(
        matches!(err, ffs_error::FfsError::UnsupportedFeature(ref message)
            if message.contains("inline-data write-side mutation")),
        "expected explicit inline-data UnsupportedFeature, got {err:?}"
    );
    assert_eq!(err.to_errno(), libc::EOPNOTSUPP);

    let after = fs
        .read(&cx, InodeNumber(11), 0, 128)
        .expect("read inline data after rejected write");
    assert_eq!(after, before, "rejected inline write must not mutate data");

    let inode = validate_inode_fixture(&fixture_path("ext4_inode_inline_data.json"))
        .expect("inline data inode fixture");
    assert_ne!(inode.flags & EXT4_INLINE_DATA_FL, 0);
}

#[test]
fn ext4_inline_data_fallocate_rejects_without_mutating_contents() {
    let mut fs = open_ext4_inline_data_image("ext4_inode_inline_data.json");
    let cx = Cx::for_testing();
    fs.enable_writes(&cx)
        .expect("enable writes for inline-data fallocate rejection check");

    let before = fs
        .read(&cx, InodeNumber(11), 0, 128)
        .expect("read inline data before rejected fallocate");
    let err = fs
        .fallocate(&cx, InodeNumber(11), 0, 4096, 0)
        .expect_err("inline-data fallocate is outside the V1 mutation contract");

    assert!(
        matches!(err, ffs_error::FfsError::UnsupportedFeature(ref message)
            if message.contains("inline-data fallocate mutation")),
        "expected explicit inline-data fallocate UnsupportedFeature, got {err:?}"
    );
    assert_eq!(err.to_errno(), libc::EOPNOTSUPP);

    let after = fs
        .read(&cx, InodeNumber(11), 0, 128)
        .expect("read inline data after rejected fallocate");
    assert_eq!(after, before, "rejected fallocate must not mutate data");
}

#[test]
fn ext4_extent_tree_leaf_fixture_conforms() {
    let (header, tree) = validate_extent_tree_fixture(&fixture_path("ext4_extent_tree_leaf.json"))
        .expect("extent tree leaf");

    assert_eq!(header.magic, 0xF30A, "should have extent magic");
    assert_eq!(header.entries, 3, "should have 3 extents");
    assert_eq!(header.max_entries, 4, "max_entries should be 4");
    assert_eq!(header.depth, 0, "should be leaf (depth=0)");

    let extents = match tree {
        ExtentTree::Leaf(extents) => extents,
        ExtentTree::Index(_) => panic!("expected leaf, got index"),
    };

    assert_eq!(extents.len(), 3, "should have 3 extents");

    // Extent 0: logical 0, len 8, physical 256
    assert_eq!(extents[0].logical_block, 0);
    assert_eq!(extents[0].actual_len(), 8);
    assert_eq!(extents[0].physical_start, 256);
    assert!(!extents[0].is_unwritten());

    // Extent 1: logical 8, len 16, physical 264
    assert_eq!(extents[1].logical_block, 8);
    assert_eq!(extents[1].actual_len(), 16);
    assert_eq!(extents[1].physical_start, 264);
    assert!(!extents[1].is_unwritten());

    // Extent 2: logical 24, len 4 (unwritten), physical 280
    assert_eq!(extents[2].logical_block, 24);
    assert_eq!(extents[2].actual_len(), 4);
    assert_eq!(extents[2].physical_start, 280);
    assert!(extents[2].is_unwritten(), "extent 2 should be unwritten");
}

#[test]
fn ext4_extent_tree_index_fixture_conforms() {
    let (header, tree) = validate_extent_tree_fixture(&fixture_path("ext4_extent_tree_index.json"))
        .expect("extent tree index");

    assert_eq!(header.magic, 0xF30A, "should have extent magic");
    assert_eq!(header.entries, 2, "should have 2 index entries");
    assert_eq!(header.max_entries, 3, "max_entries should be 3");
    assert_eq!(header.depth, 1, "should be internal node (depth=1)");
    assert_eq!(header.generation, 1, "generation should be 1");

    let indices = match tree {
        ExtentTree::Index(indices) => indices,
        ExtentTree::Leaf(_) => panic!("expected index, got leaf"),
    };

    assert_eq!(indices.len(), 2, "should have 2 index entries");

    // Index 0: logical 0, leaf block 512
    assert_eq!(indices[0].logical_block, 0);
    assert_eq!(indices[0].leaf_block, 512);

    // Index 1: logical 4096, leaf block 513
    assert_eq!(indices[1].logical_block, 4096);
    assert_eq!(indices[1].leaf_block, 513);
}

#[test]
fn ext4_htree_dx_root_fixture_conforms() {
    let dx_root =
        ffs_harness::validate_htree_dx_root_fixture(&fixture_path("ext4_htree_dx_root.json"))
            .expect("htree DX root");

    assert_eq!(dx_root.hash_version, 1, "should use half_md4 (1)");
    assert_eq!(
        dx_root.indirect_levels, 0,
        "should be single-level (indirect_levels=0)"
    );

    // Should have 3 DX entries: sentinel + 2 real entries
    assert_eq!(dx_root.entries.len(), 3, "should have 3 DX entries");

    // Entry 0: sentinel (hash implicitly 0, block 1)
    assert_eq!(dx_root.entries[0].hash, 0);
    assert_eq!(dx_root.entries[0].block, 1);

    // Entry 1: hash=0x1000, block=2
    assert_eq!(dx_root.entries[1].hash, 0x1000);
    assert_eq!(dx_root.entries[1].block, 2);

    // Entry 2: hash=0x8000, block=3
    assert_eq!(dx_root.entries[2].hash, 0x8000);
    assert_eq!(dx_root.entries[2].block, 3);
}

#[test]
fn ext4_xattr_block_fixture_conforms() {
    let xattrs = ffs_harness::validate_xattr_block_fixture(&fixture_path("ext4_xattr_block.json"))
        .expect("xattr block");

    assert_eq!(xattrs.len(), 2, "should have 2 xattrs");

    let expected_xattrs = [
        (
            EXT4_XATTR_INDEX_USER,
            b"mime".as_slice(),
            "user.mime",
            b"text/plain".as_slice(),
        ),
        (
            EXT4_XATTR_INDEX_SECURITY,
            b"selinux".as_slice(),
            "security.selinux",
            b"system_u:object_r:user_home_t:s0".as_slice(),
        ),
    ];

    for (xattr, (name_index, name, full_name, value)) in xattrs.iter().zip(expected_xattrs) {
        assert_eq!(xattr.name_index, name_index, "xattr namespace drift");
        assert_eq!(xattr.name, name, "xattr raw name drift");
        assert_eq!(xattr.full_name(), full_name, "xattr full name drift");
        assert_eq!(xattr.value, value, "xattr value drift");
    }
}

#[test]
fn ext4_dir_block_fixture_conforms() {
    let entries =
        validate_dir_block_fixture(&fixture_path("ext4_dir_block.json"), 4096).expect("dir block");
    assert_eq!(entries.len(), 3, "fixture should contain 3 live entries");

    let expected_entries = [
        (2_u32, 12_u32, 1_u8, ffs_ondisk::Ext4FileType::Dir, "."),
        (2, 12, 2, ffs_ondisk::Ext4FileType::Dir, ".."),
        (11, 4_072, 9, ffs_ondisk::Ext4FileType::RegFile, "hello.txt"),
    ];

    for (entry, (inode, rec_len, name_len, file_type, name)) in entries.iter().zip(expected_entries)
    {
        assert_eq!(entry.inode, inode, "dir entry inode drift");
        assert_eq!(entry.rec_len, rec_len, "dir entry rec_len drift");
        assert_eq!(entry.name_len, name_len, "dir entry name_len drift");
        assert_eq!(entry.file_type, file_type, "dir entry file_type drift");
        assert_eq!(entry.name_str(), name, "dir entry name drift");
    }
}

#[test]
fn ext4_dir_block_with_tail_fixture_conforms() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_with_tail.json"))
        .expect("load tail fixture");
    let (entries, tail) = parse_dir_block(&data, 4096).expect("parse dir block with tail");
    assert_eq!(entries.len(), 3, "expected 3 directory entries");

    let expected_entries = [
        (2_u32, 12_u32, 1_u8, ffs_ondisk::Ext4FileType::Dir, "."),
        (2, 12, 2, ffs_ondisk::Ext4FileType::Dir, ".."),
        (11, 4_060, 9, ffs_ondisk::Ext4FileType::RegFile, "hello.txt"),
    ];

    for (entry, (inode, rec_len, name_len, file_type, name)) in entries.iter().zip(expected_entries)
    {
        assert_eq!(entry.inode, inode, "tail fixture entry inode drift");
        assert_eq!(entry.rec_len, rec_len, "tail fixture entry rec_len drift");
        assert_eq!(
            entry.name_len, name_len,
            "tail fixture entry name_len drift"
        );
        assert_eq!(
            entry.file_type, file_type,
            "tail fixture entry file_type drift"
        );
        assert_eq!(entry.name_str(), name, "tail fixture entry name drift");
    }

    let tail = tail.expect("expected checksum tail");
    assert_eq!(tail.checksum, 0x1234_5678);
}

#[test]
fn ext4_dir_block_deleted_entry_fixture_conforms() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_deleted_entry.json"))
        .expect("load deleted entry fixture");
    let (entries, tail) = parse_dir_block(&data, 4096).expect("parse dir block");
    assert!(tail.is_none(), "deleted-entry fixture should have no tail");
    assert_eq!(entries.len(), 3, "expected 3 live directory entries");

    let expected_entries = [
        (2_u32, 12_u32, 1_u8, ffs_ondisk::Ext4FileType::Dir, "."),
        (2, 12, 2, ffs_ondisk::Ext4FileType::Dir, ".."),
        (11, 4_060, 9, ffs_ondisk::Ext4FileType::RegFile, "hello.txt"),
    ];

    for (entry, (inode, rec_len, name_len, file_type, name)) in entries.iter().zip(expected_entries)
    {
        assert_eq!(entry.inode, inode, "live dir entry inode drift");
        assert_eq!(entry.rec_len, rec_len, "live dir entry rec_len drift");
        assert_eq!(entry.name_len, name_len, "live dir entry name_len drift");
        assert_eq!(entry.file_type, file_type, "live dir entry file_type drift");
        assert_eq!(entry.name_str(), name, "live dir entry name drift");
    }
}

#[test]
fn ext4_dir_block_truncated_tail_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_truncated_tail.json"))
        .expect("load truncated tail fixture");
    let err = parse_dir_block(&data, 4096).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InsufficientData {
                needed: 12,
                offset: 4088,
                actual: 8
            }
        ),
        "expected exact truncated checksum-tail InsufficientData, got {err:?}"
    );
}

#[test]
fn ext4_dir_block_checksum_stamp_and_verify_fixture_conforms() {
    let mut data = load_sparse_fixture(&fixture_path("ext4_dir_block_with_tail.json"))
        .expect("load checksum tail fixture");
    let csum_seed = 0xA5A5_5A5A;
    let inode = 2_u32;
    let generation = 1_u32;
    stamp_dir_block_checksum(&mut data, csum_seed, inode, generation);
    verify_dir_block_checksum(&data, csum_seed, inode, generation).expect("checksum should verify");
}

#[test]
fn ext4_dir_block_checksum_detects_corruption() {
    let mut data = load_sparse_fixture(&fixture_path("ext4_dir_block_with_tail.json"))
        .expect("load checksum tail fixture");
    let csum_seed = 0xA5A5_5A5A;
    let inode = 2_u32;
    let generation = 1_u32;
    stamp_dir_block_checksum(&mut data, csum_seed, inode, generation);
    data[0] ^= 0xFF;
    let err = verify_dir_block_checksum(&data, csum_seed, inode, generation).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "dir_checksum",
                ..
            }
        ),
        "expected InvalidField(dir_checksum), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_rec_len_too_small_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_rec_len_too_small.json"))
        .expect("load rec_len fixture");
    let err = parse_dir_block(&data, 4096).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "de_rec_len",
                reason: "directory entry rec_len < 12"
            }
        ),
        "expected InvalidField(de_rec_len, rec_len < 12), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_name_len_overflow_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_name_len_overflow.json"))
        .expect("load name_len fixture");
    let err = parse_dir_block(&data, 4096).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "de_name_len",
                reason: "name extends past rec_len"
            }
        ),
        "expected InvalidField(de_name_len, name extends past rec_len), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_rec_len_min12_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_rec_len_too_small_min12.json"))
        .expect("load rec_len min12 fixture");
    let err = parse_dir_block(&data, 4096).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "de_rec_len",
                reason: "directory entry rec_len < 12"
            }
        ),
        "expected InvalidField(de_rec_len, rec_len < 12), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_rec_len_unaligned_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_rec_len_unaligned.json"))
        .expect("load rec_len unaligned fixture");
    let err = parse_dir_block(&data, 4096).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "de_rec_len",
                reason: "directory entry rec_len not 4-byte aligned"
            }
        ),
        "expected InvalidField(de_rec_len, unaligned rec_len), got {err:?}"
    );
}

#[test]
fn ext4_orphan_recovery_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp, image_path) = open_writable_ext4_mkfs(64);
    let root = InodeNumber(2);

    let name = std::ffi::OsString::from("orphan_me.txt");
    let attr = fs
        .create(&cx, root, &name, 0o644, 0, 0)
        .expect("create file");
    let ino = attr.ino;

    drop(fs);

    for command in [
        format!("set_inode_field <{}> links_count 0", ino.0),
        format!("set_super_value last_orphan {}", ino.0),
        "set_super_value state 4".to_owned(),
    ] {
        let debugfs = std::process::Command::new("debugfs")
            .args([
                "-w",
                "-R",
                &command,
                image_path.to_str().expect("utf8 image path"),
            ])
            .output()
            .expect("spawn debugfs for orphan injection");
        assert!(
            debugfs.status.success(),
            "debugfs command {command:?} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&debugfs.stdout),
            String::from_utf8_lossy(&debugfs.stderr)
        );
    }

    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        ..OpenOptions::default()
    };
    let fs2 =
        OpenFs::open_with_options(&cx, &image_path, &opts).expect("open with orphan recovery");

    let res = fs2.read_inode(&cx, ino);
    assert!(
        matches!(res, Err(ffs_error::FfsError::NotFound(_))),
        "Orphaned inode should be deleted during recovery, got {res:?}"
    );
}

#[test]
fn ext4_path_resolution_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp, _image_path) = open_writable_ext4_mkfs(64);
    let root = InodeNumber(2);
    let scope = RequestScope::empty();

    let name_a = std::ffi::OsString::from("a");
    let attr_a = fs.mkdir(&cx, root, &name_a, 0o755, 0, 0).expect("mkdir a");

    let name_b = std::ffi::OsString::from("b");
    let attr_b = fs
        .mkdir(&cx, attr_a.ino, &name_b, 0o755, 0, 0)
        .expect("mkdir b");

    let name_c = std::ffi::OsString::from("c.txt");
    let attr_c = fs
        .create(&cx, attr_b.ino, &name_c, 0o644, 0, 0)
        .expect("create c.txt");

    let (resolved_ino, resolved_inode) = fs
        .resolve_path(&cx, &scope, "/a/b/c.txt")
        .expect("resolve /a/b/c.txt");
    assert_eq!(
        resolved_ino, attr_c.ino,
        "resolved inode number should match created file"
    );
    assert!(
        !resolved_inode.is_dir(),
        "resolved inode should be the regular file, not a directory"
    );

    let (resolved_parent_ino, _) = fs
        .resolve_path(&cx, &scope, "/a/b/../b/c.txt")
        .expect("resolve absolute path with parent traversal");
    assert_eq!(
        resolved_parent_ino, attr_c.ino,
        "absolute path containing '..' should resolve back to the same file"
    );
}

#[test]
fn btrfs_tree_block_checksum_tamper_detection_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp, image_path) = open_btrfs_mkfs(128);

    let sb = fs.btrfs_superblock().expect("btrfs sb");
    let root_logical = sb.root;

    let ctx = fs.btrfs_context().expect("btrfs context");
    let mapping = fs.btrfs_context().expect("btrfs context");
    let mapping = ffs_ondisk::map_logical_to_physical(&mapping.chunks, root_logical)
        .expect("map root logical")
        .expect("root logical covered");

    let mut data = std::fs::read(&image_path).unwrap();
    let offset = usize::try_from(mapping.physical).expect("physical offset should fit usize");
    let corrupt_offset = offset + usize::try_from(ctx.nodesize.min(0x80)).expect("nodesize usize");
    data[corrupt_offset] ^= 0xFF;
    std::fs::write(&image_path, data).unwrap();

    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let reopen = OpenFs::open_with_options(&cx, &image_path, &opts);

    match reopen {
        Ok(fs) => {
            let res = fs.readdir(&cx, InodeNumber(1), 0);
            assert!(
                matches!(
                    res,
                    Err(ffs_error::FfsError::Format(ref detail))
                        if detail.contains("tree_block_csum")
                ),
                "Reading corrupted btrfs tree block should fail checksum verification, got {res:?}"
            );
        }
        Err(ffs_error::FfsError::Format(detail)) => {
            assert!(
                detail.contains("tree_block_csum"),
                "Tampered btrfs image should surface the tree-block checksum failure, got {detail:?}"
            );
        }
        Err(err) => panic!(
            "Tampered btrfs image should fail only on tree-block checksum verification, got {err:?}"
        ),
    }
}

#[test]
fn ext4_dir_block_tail_padding_nonzero_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_tail_padding_nonzero.json"))
        .expect("load tail padding fixture");
    let err = parse_dir_block(&data, 32).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "dir_block_tail",
                reason: "non-zero padding after checksum tail"
            }
        ),
        "expected InvalidField(dir_block_tail, non-zero padding), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_tail_bad_header_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_tail_bad_header.json"))
        .expect("load tail bad header fixture");
    let err = verify_dir_block_checksum(&data, 0, 2, 1).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "dir_block_tail",
                reason: "missing or malformed checksum tail"
            }
        ),
        "expected InvalidField(dir_block_tail, malformed tail), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_casefold_lookup_conforms() {
    let data =
        load_sparse_fixture(&fixture_path("ext4_dir_block.json")).expect("load dir block fixture");
    let entry = lookup_in_dir_block_casefold(&data, 4096, b"HELLO.TXT").expect("casefold lookup");
    assert!(
        entry.as_ref().is_some_and(|e| e.name_str() == "hello.txt"),
        "casefold lookup should match hello.txt"
    );
}

#[test]
fn ext4_casefold_openfs_lookup_is_case_insensitive() {
    let image = build_ext4_casefold_image_with_dir(b"hello.txt");
    let superblock = Ext4Superblock::parse_from_image(&image).expect("parse casefold superblock");
    assert!(
        superblock.has_incompat(Ext4IncompatFeatures::CASEFOLD),
        "test image should advertise CASEFOLD incompat"
    );

    let tmp = tempfile::NamedTempFile::new().expect("create casefold ext4 temp image");
    std::fs::write(tmp.path(), &image).expect("write casefold ext4 image");

    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, tmp.path(), &OpenOptions::default())
        .expect("open casefold ext4 image");

    let root = fs
        .read_inode(&cx, InodeNumber(2))
        .expect("read casefold root");
    assert_ne!(
        root.flags & EXT4_CASEFOLD_FL,
        0,
        "root inode should carry CASEFOLD flag"
    );

    let attr = fs
        .lookup(&cx, InodeNumber(2), OsStr::new("HELLO.TXT"))
        .expect("lookup uppercase casefold name");
    assert_eq!(attr.ino, InodeNumber(11));

    let raw_lookup = fs
        .lookup_name(&cx, &root, b"HeLlO.TxT")
        .expect("device lookup should accept mixed-case bytes")
        .expect("mixed-case lookup should resolve");
    assert_eq!(raw_lookup.inode, 11);
    assert_eq!(raw_lookup.name_str(), "hello.txt");

    let entries = fs
        .readdir(&cx, InodeNumber(2), 0)
        .expect("readdir casefold directory");
    assert!(
        entries
            .iter()
            .any(|entry| entry.ino == InodeNumber(11) && entry.name == b"hello.txt"),
        "readdir should expose the original case-preserved filename"
    );
}

#[test]
fn ext4_fscrypt_nokey_readdir_and_lookup_preserve_raw_bytes() {
    let raw_name = b"\xFFenc\x80";
    let image = build_ext4_encrypt_image_with_dir(raw_name);
    let superblock = Ext4Superblock::parse_from_image(&image).expect("parse encrypted superblock");
    assert!(
        superblock.has_incompat(Ext4IncompatFeatures::ENCRYPT),
        "test image should advertise ENCRYPT incompat"
    );

    let tmp = tempfile::NamedTempFile::new().expect("create encrypted ext4 temp image");
    std::fs::write(tmp.path(), &image).expect("write encrypted ext4 image");

    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, tmp.path(), &OpenOptions::default())
        .expect("open encrypted ext4 image in nokey mode");

    let raw_entries = fs
        .readdir(&cx, InodeNumber(2), 0)
        .expect("readdir raw bytes");
    let encrypted = raw_entries
        .iter()
        .find(|entry| entry.name == raw_name)
        .expect("encrypted entry should preserve raw bytes in readdir");
    assert_eq!(encrypted.ino, InodeNumber(11));

    let attr = fs
        .lookup(&cx, InodeNumber(2), OsStr::from_bytes(raw_name))
        .expect("lookup should accept raw encrypted filename bytes");
    assert_eq!(attr.ino, InodeNumber(11));

    let root = fs.read_inode(&cx, InodeNumber(2)).expect("read root inode");
    let raw_lookup = fs
        .lookup_name(&cx, &root, raw_name)
        .expect("device lookup should parse encrypted entry")
        .expect("encrypted entry should be found");
    assert_eq!(raw_lookup.name, raw_name);
}

#[test]
fn ext4_fscrypt_legacy_policy_transport_discrepancy_conforms() {
    let golden = load_fscrypt_transport_golden();
    let image = build_ext4_fscrypt_policy_image();
    let tmp = tempfile::TempDir::new().expect("tmpdir for fscrypt transport conformance");
    let image_path = tmp.path().join("fscrypt-policy-v1.ext4");
    std::fs::write(&image_path, &image).expect("write fscrypt transport image");

    assert_direct_fscrypt_legacy_policy(&golden, &image_path);
    assert_mounted_fscrypt_legacy_policy(&golden, tmp.path(), &image_path);
}

fn assert_direct_fscrypt_legacy_policy(golden: &Value, image_path: &Path) {
    let cx = Cx::for_testing();
    let open_opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let fs = OpenFs::open_with_options(&cx, image_path, &open_opts)
        .expect("open ext4 fscrypt transport image");
    let fuse = FrankenFuse::new(Box::new(fs));
    let direct_request = [0_u8; FSCRYPT_POLICY_V1_SIZE];
    let policy = fuse
        .dispatch_ioctl_for_fuzzing(
            std::process::id(),
            11,
            0,
            FS_IOC_GET_ENCRYPTION_POLICY_CMD,
            &direct_request,
            0,
        )
        .expect("direct legacy policy ioctl should succeed");
    assert_eq!(
        policy.len(),
        FSCRYPT_POLICY_V1_SIZE,
        "direct dispatch should return a v1 policy payload"
    );
    assert_eq!(
        policy[0],
        golden_u8(golden, "direct_dispatch", "policy_version")
    );
    assert_eq!(
        policy[1],
        golden_u8(golden, "direct_dispatch", "contents_mode")
    );
    assert_eq!(
        policy[2],
        golden_u8(golden, "direct_dispatch", "filenames_mode")
    );
    assert_eq!(policy[3], golden_u8(golden, "direct_dispatch", "flags"));
    assert_eq!(
        hex::encode(&policy[4..12]),
        golden["direct_dispatch"]["master_key_descriptor_hex"]
            .as_str()
            .expect("golden direct master_key_descriptor_hex")
    );
}

fn assert_mounted_fscrypt_legacy_policy(golden: &Value, tmp_path: &Path, image_path: &Path) {
    if !fuse_available() {
        eprintln!("Skipping mounted-path fscrypt transport probe: FUSE prerequisites not met.");
        return;
    }

    let mnt = tmp_path.join("mnt");
    std::fs::create_dir_all(&mnt).expect("create conformance mountpoint");
    let ioctl_trace_path = tmp_path.join("ioctl-ext4-fscrypt-legacy.log");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_with_options(image_path, &mnt, &mount_opts) else {
        eprintln!("Skipping mounted-path fscrypt transport probe: FUSE mount failed.");
        return;
    };

    let report = ext4_get_encryption_policy_ioctl(
        &mnt.join(golden["path"].as_str().expect("golden policy path")),
    );
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == i64::from(libc::EOPNOTSUPP)
    ) {
        assert!(
            !trace_contains_cmd(
                &ioctl_trace,
                u32::from_str_radix(
                    golden["command_hex"]
                        .as_str()
                        .expect("golden command_hex")
                        .trim_start_matches("0x"),
                    16,
                )
                .expect("parse golden command_hex"),
            ),
            "mounted-path unsupported errno should happen before ffs-fuse::ioctl dispatch: \
             trace={ioctl_trace}; report={report}"
        );
        eprintln!(
            "Skipping mounted-path fscrypt transport probe: kernel/VFS returned unsupported errno before ffs-fuse::ioctl: {report}"
        );
        return;
    }
    assert!(
        trace_contains_cmd(
            &ioctl_trace,
            u32::from_str_radix(
                golden["command_hex"]
                    .as_str()
                    .expect("golden command_hex")
                    .trim_start_matches("0x"),
                16,
            )
            .expect("parse golden command_hex"),
        ),
        "mounted-path ioctl should reach ffs-fuse::ioctl: trace={ioctl_trace}; report={report}"
    );
    assert!(
        ioctl_trace.contains(
            golden["mounted_path"]["trace_contains"]
                .as_str()
                .expect("golden mounted trace shape"),
        ),
        "mounted-path ioctl trace should preserve the legacy request shape: {ioctl_trace}"
    );
    assert_eq!(
        report["errno"].as_i64(),
        Some(
            golden["mounted_path"]["errno"]
                .as_i64()
                .expect("golden mounted errno")
        ),
        "mounted-path legacy fscrypt policy ioctl should surface the documented transport errno: {report}"
    );
    assert_eq!(
        report["message"].as_str(),
        Some(
            golden["mounted_path"]["message"]
                .as_str()
                .expect("golden mounted message")
        ),
        "mounted-path legacy fscrypt policy ioctl should surface the documented transport message: {report}"
    );
}

fn command_available(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
        && command_available("python3")
        && command_available("mkfs.ext4")
        && command_available("debugfs")
}

fn mountinfo_unescape(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while let Some(byte) = bytes.get(idx) {
        if *byte == b'\\' {
            if let Some(octal) = idx
                .checked_add(1)
                .zip(idx.checked_add(4))
                .and_then(|(start, end)| bytes.get(start..end))
            {
                if octal.iter().all(|byte| matches!(*byte, b'0'..=b'7')) {
                    let value = octal
                        .iter()
                        .fold(0_u16, |acc, byte| acc * 8 + u16::from(byte - b'0'));
                    if let Ok(byte) = u8::try_from(value) {
                        out.push(byte);
                        idx += 4;
                        continue;
                    }
                }
            }
        }
        out.push(*byte);
        idx += 1;
    }
    out
}

fn mountinfo_has_mountpoint(mountpoint: &Path) -> bool {
    let target = mountpoint.as_os_str().as_bytes();
    fs::read_to_string("/proc/self/mountinfo").is_ok_and(|mountinfo| {
        mountinfo.lines().any(|line| {
            line.split(' ')
                .nth(4)
                .is_some_and(|field| mountinfo_unescape(field) == target)
        })
    })
}

fn wait_for_fuse_mount_ready(mountpoint: &Path) -> bool {
    let start = Instant::now();
    while start.elapsed() < FUSE_MOUNT_READY_TIMEOUT {
        if mountinfo_has_mountpoint(mountpoint) {
            return true;
        }
        let remaining = FUSE_MOUNT_READY_TIMEOUT.saturating_sub(start.elapsed());
        thread::sleep(FUSE_MOUNT_STATE_POLL_INTERVAL.min(remaining));
    }
    mountinfo_has_mountpoint(mountpoint)
}

fn try_mount_ffs_with_options(
    image: &Path,
    mountpoint: &Path,
    mount_opts: &MountOptions,
) -> Option<ffs_harness::stale_mounts::MountGuard> {
    // Self-heal dead mounts leaked by earlier crashed/killed runs.
    ffs_harness::stale_mounts::reap_stale_frankenfs_mounts_once();
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let fs = OpenFs::open_with_options(&cx, image, &opts).expect("open ext4 image");
    match mount_background(Box::new(fs), mountpoint, mount_opts) {
        Ok(session) => {
            if wait_for_fuse_mount_ready(mountpoint) {
                Some(ffs_harness::stale_mounts::MountGuard::new(
                    session, mountpoint,
                ))
            } else {
                eprintln!(
                    "FUSE mount did not become visible after {:?} (skipping conformance mount probe): {}",
                    FUSE_MOUNT_READY_TIMEOUT,
                    mountpoint.display()
                );
                None
            }
        }
        Err(err) => {
            eprintln!("FUSE mount failed (skipping conformance mount probe): {err}");
            None
        }
    }
}

fn ext4_get_encryption_policy_ioctl(path: &Path) -> Value {
    let script = r"
import fcntl, json, sys

FS_IOC_GET_ENCRYPTION_POLICY = 0x400C6615
POLICY_SIZE = 12

with open(sys.argv[1], 'rb', buffering=0) as fh:
    buffer = bytearray(POLICY_SIZE)
    try:
        fcntl.ioctl(fh.fileno(), FS_IOC_GET_ENCRYPTION_POLICY, buffer, True)
        print(json.dumps({
            'policy_version': buffer[0],
            'contents_mode': buffer[1],
            'filenames_mode': buffer[2],
            'flags': buffer[3],
            'master_key_descriptor_hex': buffer[4:12].hex(),
            'policy_hex': buffer.hex(),
        }))
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    ";

    let output = std::process::Command::new("python3")
        .args(["-c", script, path.to_str().expect("path utf8")])
        .output()
        .expect("python3 get encryption policy ioctl");
    assert!(
        output.status.success(),
        "python3 get encryption policy ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode encryption policy ioctl JSON")
}

fn read_ioctl_trace(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn trace_contains_cmd(trace: &str, cmd: u32) -> bool {
    trace.contains(&format!("cmd=0x{cmd:08x}"))
}

fn load_fscrypt_transport_golden() -> Value {
    let golden_path = workspace_root()
        .join("conformance/golden/ext4_fscrypt_legacy_policy_transport_discrepancy.json");
    let text = std::fs::read_to_string(&golden_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", golden_path.display()));
    serde_json::from_str(&text).expect("decode fscrypt transport golden")
}

fn golden_u8(golden: &Value, section: &str, field: &str) -> u8 {
    let value = golden[section][field]
        .as_u64()
        .unwrap_or_else(|| panic!("golden {section}.{field} should be u64"));
    u8::try_from(value)
        .unwrap_or_else(|_| panic!("golden {section}.{field}={value} does not fit in u8"))
}

fn build_fscrypt_context_v1(
    contents_mode: u8,
    filenames_mode: u8,
    flags: u8,
    descriptor: [u8; 8],
    nonce: [u8; 16],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(FSCRYPT_CONTEXT_V1_SIZE);
    context.push(FSCRYPT_POLICY_V1_VERSION);
    context.push(contents_mode);
    context.push(filenames_mode);
    context.push(flags);
    context.extend_from_slice(&descriptor);
    context.extend_from_slice(&nonce);
    context
}

fn build_test_inline_ibody(ibody_len: usize, entries: &[ffs_ondisk::Ext4Xattr]) -> Vec<u8> {
    let mut out = vec![0_u8; ibody_len];
    if entries.is_empty() {
        return out;
    }

    out[0..4].copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());
    let region_capacity = ibody_len
        .checked_sub(4)
        .expect("inline xattr region must include 4-byte header");
    let mut region = vec![0_u8; region_capacity];
    let mut next_entry = 0_usize;
    let mut value_tail = region_capacity;

    for entry in entries {
        let entry_len = (16 + entry.name.len() + 3) & !3;
        let value_start = value_tail
            .checked_sub(entry.value.len())
            .expect("inline xattr value should fit")
            & !3;
        let entry_end_with_term = next_entry
            .checked_add(entry_len + 4)
            .expect("inline xattr entry offset should not overflow");
        assert!(
            entry_end_with_term <= value_start,
            "inline xattr entry table should not overlap values"
        );

        region[value_start..value_start + entry.value.len()].copy_from_slice(&entry.value);
        value_tail = value_start;

        region[next_entry] =
            u8::try_from(entry.name.len()).expect("inline xattr name should fit in u8");
        region[next_entry + 1] = entry.name_index;
        region[next_entry + 2..next_entry + 4].copy_from_slice(
            &u16::try_from(value_start)
                .expect("inline xattr value offset should fit in u16")
                .to_le_bytes(),
        );
        region[next_entry + 8..next_entry + 12].copy_from_slice(
            &u32::try_from(entry.value.len())
                .expect("inline xattr value length should fit in u32")
                .to_le_bytes(),
        );
        region[next_entry + 16..next_entry + 16 + entry.name.len()].copy_from_slice(&entry.name);
        next_entry += entry_len;
    }

    out[4..].copy_from_slice(&region);
    out
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_fscrypt_policy_image() -> Vec<u8> {
    let block_size: u32 = 4096;
    let image_size: u32 = 256 * 1024;
    let mut image = vec![0_u8; image_size as usize];
    let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    let incompat = (ffs_ondisk::Ext4IncompatFeatures::FILETYPE.0
        | ffs_ondisk::Ext4IncompatFeatures::EXTENTS.0
        | ffs_ondisk::Ext4IncompatFeatures::ENCRYPT.0)
        .to_le_bytes();
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat);
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());

    let root_ino = 4 * 4096 + 256;
    image[root_ino..root_ino + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[root_ino + 4..root_ino + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[root_ino + 0x1A..root_ino + 0x1C].copy_from_slice(&3_u16.to_le_bytes());
    image[root_ino + 0x20..root_ino + 0x24]
        .copy_from_slice(&ffs_types::EXT4_EXTENTS_FL.to_le_bytes());
    image[root_ino + 0x80..root_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let root_extent = root_ino + 0x28;
    image[root_extent..root_extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[root_extent + 2..root_extent + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 4..root_extent + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[root_extent + 6..root_extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 12..root_extent + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[root_extent + 16..root_extent + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 18..root_extent + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 20..root_extent + 24].copy_from_slice(&10_u32.to_le_bytes());

    let file_ino = 4 * 4096 + 10 * 256;
    image[file_ino..file_ino + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[file_ino + 4..file_ino + 8].copy_from_slice(&0_u32.to_le_bytes());
    image[file_ino + 0x1A..file_ino + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[file_ino + 0x80..file_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());
    image[file_ino + 0x20..file_ino + 0x24].copy_from_slice(&EXT4_ENCRYPT_INODE_FL.to_le_bytes());

    let context = build_fscrypt_context_v1(1, 4, 0, *b"mkdesc42", *b"0123456789abcdef");
    let ibody = build_test_inline_ibody(
        256 - (128 + 32),
        &[ffs_ondisk::Ext4Xattr {
            name_index: ffs_types::EXT4_XATTR_INDEX_ENCRYPTION,
            name: EXT4_ENCRYPTION_XATTR_NAME.to_vec(),
            value: context,
        }],
    );
    let xattr_off = file_ino + 128 + 32;
    image[xattr_off..xattr_off + ibody.len()].copy_from_slice(&ibody);

    let dir_block = 10 * 4096;
    image[dir_block..dir_block + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir_block + 4..dir_block + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir_block + 6] = 1;
    image[dir_block + 7] = 2;
    image[dir_block + 8] = b'.';

    let dotdot = dir_block + 12;
    image[dotdot..dotdot + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dotdot + 4..dotdot + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dotdot + 6] = 2;
    image[dotdot + 7] = 2;
    image[dotdot + 8] = b'.';
    image[dotdot + 9] = b'.';

    let file_entry = dotdot + 12;
    let file_name = b"policy.txt";
    image[file_entry..file_entry + 4].copy_from_slice(&11_u32.to_le_bytes());
    image[file_entry + 4..file_entry + 6].copy_from_slice(&(4096_u16 - 24).to_le_bytes());
    image[file_entry + 6] = u8::try_from(file_name.len()).expect("policy name should fit u8");
    image[file_entry + 7] = 1;
    image[file_entry + 8..file_entry + 8 + file_name.len()].copy_from_slice(file_name);

    let inode_bitmap = 3 * 4096;
    for bit in [1_usize, 10_usize] {
        image[inode_bitmap + bit / 8] |= 1 << (bit % 8);
    }

    image
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_featured_dir_image(
    raw_name: &[u8],
    incompat_feature: u32,
    root_inode_flags: u32,
) -> Vec<u8> {
    assert!(
        raw_name.len() < 256,
        "raw encrypted ext4 name must fit in a single dirent"
    );

    let block_size: u32 = 4096;
    let image_size: u32 = 256 * 1024;
    let mut image = vec![0_u8; image_size as usize];
    let sb_off = EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    let incompat =
        (Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0 | incompat_feature)
            .to_le_bytes();
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat);
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());

    let ino2 = 4 * 4096 + 256;
    image[ino2..ino2 + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[ino2 + 4..ino2 + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[ino2 + 0x1A..ino2 + 0x1C].copy_from_slice(&3_u16.to_le_bytes());
    image[ino2 + 0x20..ino2 + 0x24]
        .copy_from_slice(&(root_inode_flags | EXT4_EXTENTS_FL).to_le_bytes());
    image[ino2 + 0x80..ino2 + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let root_extent = ino2 + 0x28;
    image[root_extent..root_extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[root_extent + 2..root_extent + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 4..root_extent + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[root_extent + 6..root_extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 12..root_extent + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[root_extent + 16..root_extent + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 18..root_extent + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 20..root_extent + 24].copy_from_slice(&10_u32.to_le_bytes());

    let ino11 = 4 * 4096 + 10 * 256;
    image[ino11..ino11 + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[ino11 + 4..ino11 + 8].copy_from_slice(&5_u32.to_le_bytes());
    image[ino11 + 0x1A..ino11 + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino11 + 0x80..ino11 + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let dir = 10 * 4096;
    image[dir..dir + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir + 6] = 1;
    image[dir + 7] = 2;
    image[dir + 8] = b'.';

    let dir = dir + 12;
    image[dir..dir + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir + 6] = 2;
    image[dir + 7] = 2;
    image[dir + 8] = b'.';
    image[dir + 9] = b'.';

    let dir = dir + 12;
    image[dir..dir + 4].copy_from_slice(&11_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&4072_u16.to_le_bytes());
    image[dir + 6] = u8::try_from(raw_name.len()).expect("casefold test name length fits u8");
    image[dir + 7] = 1;
    image[dir + 8..dir + 8 + raw_name.len()].copy_from_slice(raw_name);

    image
}

fn build_ext4_casefold_image_with_dir(raw_name: &[u8]) -> Vec<u8> {
    build_ext4_featured_dir_image(raw_name, Ext4IncompatFeatures::CASEFOLD.0, EXT4_CASEFOLD_FL)
}

fn build_ext4_encrypt_image_with_dir(raw_name: &[u8]) -> Vec<u8> {
    build_ext4_featured_dir_image(raw_name, Ext4IncompatFeatures::ENCRYPT.0, 0x0008_0000)
}

fn build_ext4_inline_data_image(inode_fixture: &str) -> Vec<u8> {
    let block_size: u32 = 4096;
    let image_size: u32 = 256 * 1024;
    let mut image = vec![0_u8; image_size as usize];
    let sb_off = EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    let incompat = (Ext4IncompatFeatures::FILETYPE.0
        | Ext4IncompatFeatures::EXTENTS.0
        | Ext4IncompatFeatures::INLINE_DATA.0)
        .to_le_bytes();
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat);
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());

    let ino2 = 4 * 4096 + 256;
    image[ino2..ino2 + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[ino2 + 4..ino2 + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[ino2 + 0x1A..ino2 + 0x1C].copy_from_slice(&3_u16.to_le_bytes());
    image[ino2 + 0x20..ino2 + 0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
    image[ino2 + 0x80..ino2 + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let root_extent = ino2 + 0x28;
    image[root_extent..root_extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[root_extent + 2..root_extent + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 4..root_extent + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[root_extent + 6..root_extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 12..root_extent + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[root_extent + 16..root_extent + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 18..root_extent + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 20..root_extent + 24].copy_from_slice(&10_u32.to_le_bytes());

    let inline_inode =
        load_sparse_fixture(&fixture_path(inode_fixture)).expect("load inline inode fixture");
    let ino11 = 4 * 4096 + 10 * 256;
    image[ino11..ino11 + inline_inode.len()].copy_from_slice(&inline_inode);

    let dir = 10 * 4096;
    image[dir..dir + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir + 6] = 1;
    image[dir + 7] = 2;
    image[dir + 8] = b'.';

    let dir = dir + 12;
    image[dir..dir + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir + 6] = 2;
    image[dir + 7] = 2;
    image[dir + 8] = b'.';
    image[dir + 9] = b'.';

    let name = b"inline.bin";
    let dir = dir + 12;
    image[dir..dir + 4].copy_from_slice(&11_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&4072_u16.to_le_bytes());
    image[dir + 6] = u8::try_from(name.len()).expect("inline fixture name length fits u8");
    image[dir + 7] = 1;
    image[dir + 8..dir + 8 + name.len()].copy_from_slice(name);

    image
}

fn open_ext4_inline_data_image(inode_fixture: &str) -> OpenFs {
    let image = build_ext4_inline_data_image(inode_fixture);
    let tmp = tempfile::NamedTempFile::new().expect("create inline-data ext4 temp image");
    std::fs::write(tmp.path(), &image).expect("write inline-data ext4 image");
    let cx = Cx::for_testing();
    OpenFs::open_with_options(&cx, tmp.path(), &OpenOptions::default())
        .expect("open inline-data ext4 image")
}

fn open_btrfs_image(image: &Path) -> OpenFs {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    OpenFs::open_with_options(&cx, image, &opts).expect("open btrfs image")
}

fn open_btrfs_mkfs(size_mb: u64) -> (OpenFs, tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::TempDir::new().expect("tmpdir for btrfs");
    let image = tmp.path().join("conformance.btrfs");
    let file = std::fs::File::create(&image).expect("create btrfs image");
    file.set_len(size_mb.max(128) * 1024 * 1024)
        .expect("size btrfs image");
    drop(file);

    let mkfs = std::process::Command::new("mkfs.btrfs")
        .args(["-f", image.to_str().expect("utf8 image path")])
        .output()
        .expect("spawn mkfs.btrfs");
    assert!(
        mkfs.status.success(),
        "mkfs.btrfs failed: stdout={} stderr={}",
        String::from_utf8_lossy(&mkfs.stdout),
        String::from_utf8_lossy(&mkfs.stderr)
    );

    let fs = open_btrfs_image(&image);
    (fs, tmp, image)
}

/// Build a btrfs image whose root directory already contains `name` holding
/// `contents`, using `mkfs.btrfs -r` exactly the way the mounted comparator
/// seeds its workload fixtures (bd-ftev0).
fn open_btrfs_mkfs_rootdir(
    size_mb: u64,
    name: &str,
    contents: &[u8],
) -> (OpenFs, tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::TempDir::new().expect("tmpdir for btrfs rootdir image");
    let rootdir = tmp.path().join("rootdir");
    std::fs::create_dir_all(&rootdir).expect("create btrfs rootdir fixture");
    std::fs::write(rootdir.join(name), contents).expect("write btrfs rootdir fixture file");

    let image = tmp.path().join("conformance-rootdir.btrfs");
    let file = std::fs::File::create(&image).expect("create btrfs rootdir image");
    file.set_len(size_mb.max(128) * 1024 * 1024)
        .expect("size btrfs rootdir image");
    drop(file);

    let mkfs = std::process::Command::new("mkfs.btrfs")
        .args(["-f", "-q", "-r"])
        .arg(&rootdir)
        .arg(&image)
        .output()
        .expect("spawn mkfs.btrfs -r");
    assert!(
        mkfs.status.success(),
        "mkfs.btrfs -r failed: stdout={} stderr={}",
        String::from_utf8_lossy(&mkfs.stdout),
        String::from_utf8_lossy(&mkfs.stderr)
    );

    let fs = open_btrfs_image(&image);
    (fs, tmp, image)
}

fn mkfs_writable_ext4_image(size_mb: u64) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::TempDir::new().expect("tmpdir for writable ext4");
    let image = tmp.path().join("conformance.ext4");
    let file = std::fs::File::create(&image).expect("create ext4 image");
    file.set_len(size_mb * 1024 * 1024)
        .expect("size ext4 image");
    drop(file);

    let mkfs = std::process::Command::new("mkfs.ext4")
        .args([
            "-F",
            "-b",
            "4096",
            "-O",
            "^metadata_csum,^64bit",
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn mkfs.ext4");
    assert!(
        mkfs.status.success(),
        "mkfs.ext4 failed: stdout={} stderr={}",
        String::from_utf8_lossy(&mkfs.stdout),
        String::from_utf8_lossy(&mkfs.stderr)
    );

    let debugfs = std::process::Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field / mode 040777",
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn debugfs");
    assert!(
        debugfs.status.success(),
        "debugfs failed: stdout={} stderr={}",
        String::from_utf8_lossy(&debugfs.stdout),
        String::from_utf8_lossy(&debugfs.stderr)
    );
    (tmp, image)
}

fn open_writable_ext4_mkfs(size_mb: u64) -> (OpenFs, tempfile::TempDir, std::path::PathBuf) {
    let (tmp, image) = mkfs_writable_ext4_image(size_mb);
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, &image, &opts).expect("open writable ext4 image");
    fs.enable_writes(&cx).expect("enable writes on ext4 image");
    assert!(fs.is_writable(), "test ext4 image should be writable");
    (fs, tmp, image)
}

fn patch_ext4_active_mmp(image_path: &Path, mmp_block: u64, seq: u32) {
    let mut image = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .expect("open ext4 image for MMP patching");

    let mut superblock = vec![0_u8; ffs_types::EXT4_SUPERBLOCK_SIZE];
    image
        .seek(SeekFrom::Start(
            u64::try_from(EXT4_SUPERBLOCK_OFFSET).expect("superblock offset fits u64"),
        ))
        .expect("seek ext4 superblock");
    image
        .read_exact(&mut superblock)
        .expect("read ext4 superblock");

    let mut feature_incompat_bytes = [0_u8; 4];
    feature_incompat_bytes.copy_from_slice(&superblock[0x60..0x64]);
    let feature_incompat = u32::from_le_bytes(feature_incompat_bytes) | Ext4IncompatFeatures::MMP.0;
    superblock[0x60..0x64].copy_from_slice(&feature_incompat.to_le_bytes());
    superblock[0x166..0x168].copy_from_slice(&5_u16.to_le_bytes());
    superblock[0x168..0x170].copy_from_slice(&mmp_block.to_le_bytes());

    image
        .seek(SeekFrom::Start(
            u64::try_from(EXT4_SUPERBLOCK_OFFSET).expect("superblock offset fits u64"),
        ))
        .expect("seek ext4 superblock for rewrite");
    image
        .write_all(&superblock)
        .expect("rewrite ext4 superblock");

    let mut mmp = vec![0_u8; 4096];
    mmp[0x00..0x04].copy_from_slice(&ffs_ondisk::ext4::EXT4_MMP_MAGIC.to_le_bytes());
    mmp[0x04..0x08].copy_from_slice(&seq.to_le_bytes());
    mmp[0x08..0x10].copy_from_slice(&1_700_000_123_u64.to_le_bytes());
    mmp[0x10..0x18].copy_from_slice(b"ffs-node");
    mmp[0x50..0x60].copy_from_slice(b"/dev/conformance");
    mmp[0x70..0x72].copy_from_slice(&5_u16.to_le_bytes());

    image
        .seek(SeekFrom::Start(mmp_block * 4096))
        .expect("seek ext4 MMP block");
    image.write_all(&mmp).expect("write ext4 MMP block");
    image.flush().expect("flush ext4 MMP patch");
}

fn enable_e2compr_for_inode(fs: &OpenFs, cx: &Cx, ino: InodeNumber, flags: u32) {
    let mut inode = fs
        .read_inode(cx, ino)
        .expect("read inode for e2compr conformance setup");
    inode.flags = flags;
    inode.extent_bytes.fill(0);
    fs.persist_ext4_inode_for_testing(cx, ino, &inode)
        .expect("persist e2compr inode flags for conformance");
}

fn reopen_writable_ext4(image_path: &Path) -> OpenFs {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, image_path, &opts).expect("reopen writable ext4");
    fs.enable_writes(&cx)
        .expect("re-enable writes on ext4 image");
    fs
}

fn ext4_free_block_counters(fs: &OpenFs, cx: &Cx) -> (u64, u64) {
    let sb = fs.ext4_superblock().expect("ext4 superblock");
    let mut bitmap_total = 0_u64;
    let mut gd_total = 0_u64;

    for group in 0..sb.groups_count() {
        let group = GroupNumber(group);
        bitmap_total += u64::from(
            fs.count_free_blocks_in_group(cx, group)
                .expect("count free blocks in group"),
        );
        gd_total += u64::from(
            fs.read_group_desc(cx, group)
                .expect("read group desc for block counters")
                .free_blocks_count,
        );
    }

    (bitmap_total, gd_total)
}

fn assert_generic_112_preallocation_contract(
    label: &str,
    cx: &Cx,
    fs: OpenFs,
    root: InodeNumber,
    image_path: &Path,
    reopen: Option<fn(&Path) -> OpenFs>,
) {
    const PREALLOC_LEN: usize = 16 * 1024;
    const FIRST_WRITE_OFFSET: usize = 4096;
    const SECOND_WRITE_OFFSET: usize = 12 * 1024;
    let file_name = OsStr::new("generic112_prealloc.bin");

    let attr = fs
        .create(cx, root, file_name, 0o644, 0, 0)
        .expect("create generic/112 prealloc probe file");
    let ino = attr.ino;

    fs.fallocate(cx, ino, 0, PREALLOC_LEN as u64, 0)
        .expect("preallocate generic/112 contract range");

    let after_prealloc = fs.getattr(cx, ino).expect("getattr after prealloc");
    assert_eq!(
        after_prealloc.size, PREALLOC_LEN as u64,
        "{label}: plain preallocation should extend the visible file size"
    );

    let zeroed = fs
        .read(
            cx,
            ino,
            0,
            u32::try_from(PREALLOC_LEN).expect("prealloc len should fit u32"),
        )
        .expect("read freshly preallocated file");
    assert_eq!(
        zeroed,
        vec![0; PREALLOC_LEN],
        "{label}: freshly preallocated extents should read back as zeroes"
    );

    let first_payload = b"generic-112-middle-write";
    let second_payload = b"generic-112-tail-write";
    fs.write(cx, ino, FIRST_WRITE_OFFSET as u64, first_payload)
        .expect("write first generic/112 payload");
    fs.write(cx, ino, SECOND_WRITE_OFFSET as u64, second_payload)
        .expect("write second generic/112 payload");
    fs.fsync(cx, ino, 0, false)
        .expect("fsync generic/112 probe file");

    let mut expected = vec![0; PREALLOC_LEN];
    expected[FIRST_WRITE_OFFSET..FIRST_WRITE_OFFSET + first_payload.len()]
        .copy_from_slice(first_payload);
    expected[SECOND_WRITE_OFFSET..SECOND_WRITE_OFFSET + second_payload.len()]
        .copy_from_slice(second_payload);

    let readback = fs
        .read(
            cx,
            ino,
            0,
            u32::try_from(PREALLOC_LEN).expect("prealloc len should fit u32"),
        )
        .expect("read generic/112 probe after writes");
    assert_eq!(
        readback, expected,
        "{label}: writes into preallocated space must preserve surrounding zero-fill"
    );

    let Some(reopen) = reopen else {
        return;
    };

    fs.fsyncdir(cx, root, 0, false)
        .expect("fsync generic/112 parent directory before reopen");
    fs.flush_mvcc_to_device(cx)
        .expect("flush generic/112 mutations before reopen");
    drop(fs);

    let reopened = reopen(image_path);
    let reopened_attr = reopened
        .lookup(cx, root, file_name)
        .expect("lookup generic/112 probe after reopen");
    let reopened_ino = reopened_attr.ino;
    assert_eq!(
        reopened_attr.size, PREALLOC_LEN as u64,
        "{label}: preallocation size contract must survive reopen"
    );

    let reopened_readback = reopened
        .read(
            cx,
            reopened_ino,
            0,
            u32::try_from(PREALLOC_LEN).expect("prealloc len should fit u32"),
        )
        .expect("read generic/112 probe after reopen");
    assert_eq!(
        reopened_readback, expected,
        "{label}: preallocated unwritten extents and later writes must survive reopen"
    );
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_extent_test_image() -> Vec<u8> {
    let block_size: u32 = 4096;
    let image_size: u32 = 256 * 1024;
    let mut image = vec![0_u8; image_size as usize];
    let sb_off = EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    let incompat: u32 = Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0;
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat.to_le_bytes());
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());
    image[sb_off + 0xFE..sb_off + 0x100].copy_from_slice(&32_u16.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());
    image[gd_off + 0x0C..gd_off + 0x0E].copy_from_slice(&64_u16.to_le_bytes());
    image[gd_off + 0x0E..gd_off + 0x10].copy_from_slice(&128_u16.to_le_bytes());

    let ino11_off: usize = 4 * 4096 + 10 * 256;
    image[ino11_off..ino11_off + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[ino11_off + 4..ino11_off + 8].copy_from_slice(&14_u32.to_le_bytes());
    image[ino11_off + 0x1A..ino11_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino11_off + 0x20..ino11_off + 0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
    image[ino11_off + 0x80..ino11_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let e = ino11_off + 0x28;
    image[e..e + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[e + 2..e + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[e + 4..e + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[e + 6..e + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[e + 12..e + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[e + 16..e + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[e + 18..e + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[e + 20..e + 24].copy_from_slice(&13_u32.to_le_bytes());

    let d = 13 * 4096;
    image[d..d + 14].copy_from_slice(b"Hello, extent!");

    let ino12_off: usize = 4 * 4096 + 11 * 256;
    image[ino12_off..ino12_off + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[ino12_off + 4..ino12_off + 8].copy_from_slice(&14_u32.to_le_bytes());
    image[ino12_off + 0x1A..ino12_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino12_off + 0x20..ino12_off + 0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
    image[ino12_off + 0x80..ino12_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let e = ino12_off + 0x28;
    image[e..e + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[e + 2..e + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[e + 4..e + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[e + 6..e + 8].copy_from_slice(&1_u16.to_le_bytes());
    image[e + 12..e + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[e + 16..e + 20].copy_from_slice(&14_u32.to_le_bytes());
    image[e + 20..e + 22].copy_from_slice(&0_u16.to_le_bytes());

    let leaf = 14 * 4096;
    image[leaf..leaf + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[leaf + 2..leaf + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[leaf + 4..leaf + 6].copy_from_slice(&340_u16.to_le_bytes());
    image[leaf + 6..leaf + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[leaf + 12..leaf + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[leaf + 16..leaf + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[leaf + 18..leaf + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[leaf + 20..leaf + 24].copy_from_slice(&15_u32.to_le_bytes());

    let d = 15 * 4096;
    image[d..d + 14].copy_from_slice(b"Index extent!\n");

    let bitmap = 2 * 4096;
    image[bitmap + 1] = 0xE0;

    image
}

fn write_jbd2_header(block: &mut [u8], block_type: u32, sequence: u32) {
    const JBD2_MAGIC: u32 = 0xC03B_3998;
    block[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    block[4..8].copy_from_slice(&block_type.to_be_bytes());
    block[8..12].copy_from_slice(&sequence.to_be_bytes());
}

#[allow(clippy::too_many_arguments)]
fn write_jbd2_superblock_v2(
    block: &mut [u8],
    block_size: u32,
    max_len: u32,
    first_log_block: u32,
    start_sequence: u32,
    start_block: u32,
    num_fc_blocks: u32,
    feature_incompat: u32,
) {
    write_jbd2_header(block, 4, 0);
    block[12..16].copy_from_slice(&block_size.to_be_bytes());
    block[16..20].copy_from_slice(&max_len.to_be_bytes());
    block[20..24].copy_from_slice(&first_log_block.to_be_bytes());
    block[24..28].copy_from_slice(&start_sequence.to_be_bytes());
    block[28..32].copy_from_slice(&start_block.to_be_bytes());
    block[40..44].copy_from_slice(&feature_incompat.to_be_bytes());
    block[84..88].copy_from_slice(&num_fc_blocks.to_be_bytes());
}

fn build_fc_tag(tag_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + payload.len());
    bytes.extend_from_slice(&tag_type.to_le_bytes());
    bytes.extend_from_slice(
        &u16::try_from(payload.len())
            .expect("fast-commit payload length should fit")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(payload);
    bytes
}

fn build_fc_inode_update_transaction(ino: u32, tid: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(build_fc_tag(0x09, &[0; 16]));
    bytes.extend(build_fc_tag(0x06, &ino.to_le_bytes()));
    let mut tail = [0_u8; 8];
    tail[..4].copy_from_slice(&tid.to_le_bytes());
    bytes.extend(build_fc_tag(0x08, &tail));
    bytes
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_fast_commit_test_image() -> Vec<u8> {
    const JBD2_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x0000_0020;
    const EXT4_COMPAT_HAS_JOURNAL: u32 = 0x0000_0004;
    const EXT4_COMPAT_FAST_COMMIT: u32 = 0x0000_0400;

    let mut image = build_ext4_extent_test_image();
    let sb_off = EXT4_SUPERBLOCK_OFFSET;

    let compat = u32::from_le_bytes([
        image[sb_off + 0x5C],
        image[sb_off + 0x5D],
        image[sb_off + 0x5E],
        image[sb_off + 0x5F],
    ]);
    image[sb_off + 0x5C..sb_off + 0x60].copy_from_slice(
        &(compat | EXT4_COMPAT_HAS_JOURNAL | EXT4_COMPAT_FAST_COMMIT).to_le_bytes(),
    );
    image[sb_off + 0xE0..sb_off + 0xE4].copy_from_slice(&8_u32.to_le_bytes());

    let ino8_off: usize = 4 * 4096 + 7 * 256;
    image[ino8_off..ino8_off + 2].copy_from_slice(&0o100_600_u16.to_le_bytes());
    image[ino8_off + 4..ino8_off + 8].copy_from_slice(&(6_u32 * 4096).to_le_bytes());
    image[ino8_off + 0x1A..ino8_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino8_off + 0x20..ino8_off + 0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
    image[ino8_off + 0x80..ino8_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let extent = ino8_off + 0x28;
    image[extent..extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[extent + 2..extent + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[extent + 4..extent + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[extent + 6..extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[extent + 12..extent + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[extent + 16..extent + 18].copy_from_slice(&6_u16.to_le_bytes());
    image[extent + 18..extent + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[extent + 20..extent + 24].copy_from_slice(&20_u32.to_le_bytes());

    let journal_sb = 20 * 4096;
    write_jbd2_superblock_v2(
        &mut image[journal_sb..journal_sb + 4096],
        4096,
        6,
        1,
        1,
        1,
        2,
        JBD2_FEATURE_INCOMPAT_FAST_COMMIT,
    );

    let j_desc = 21 * 4096;
    write_jbd2_header(&mut image[j_desc..j_desc + 4096], 1, 1);
    image[j_desc + 12..j_desc + 16].copy_from_slice(&15_u32.to_be_bytes());
    image[j_desc + 16..j_desc + 20].copy_from_slice(&0x0000_0008_u32.to_be_bytes());

    let j_data = 22 * 4096;
    image[j_data..j_data + 16].copy_from_slice(b"JBD2-REPLAY-TEST");

    let j_commit = 23 * 4096;
    write_jbd2_header(&mut image[j_commit..j_commit + 4096], 2, 1);

    let fc_payload = build_fc_inode_update_transaction(42, 1);
    let fc_block = 24 * 4096;
    image[fc_block..fc_block + fc_payload.len()].copy_from_slice(&fc_payload);

    image
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_truncated_fast_commit_test_image() -> Vec<u8> {
    let mut image = build_ext4_fast_commit_test_image();
    let fc_block = 24 * 4096;
    let mut truncated = Vec::new();
    truncated.extend(build_fc_tag(0x09, &[0; 16]));
    truncated.extend(build_fc_tag(0x06, &42_u32.to_le_bytes()));
    image[fc_block..fc_block + 4096].fill(0);
    image[fc_block..fc_block + truncated.len()].copy_from_slice(&truncated);
    image
}

fn open_ext4_fast_commit_image(truncated: bool) -> (OpenFs, tempfile::TempDir) {
    let image = if truncated {
        build_ext4_truncated_fast_commit_test_image()
    } else {
        build_ext4_fast_commit_test_image()
    };
    let tmp = tempfile::TempDir::new().expect("tmpdir for ext4 fast-commit image");
    let image_path = tmp.path().join("fast-commit.ext4");
    std::fs::write(&image_path, &image).expect("write ext4 fast-commit image");
    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, &image_path, &OpenOptions::default())
        .expect("open ext4 fast-commit image");
    (fs, tmp)
}

fn open_ext4_mkfs_no_extents_with_large_file(
    size_mb: u64,
) -> (OpenFs, tempfile::TempDir, InodeNumber) {
    let tmp = tempfile::TempDir::new().expect("tmpdir for writable ext4 no extents");
    let image = tmp.path().join("conformance_no_extents.ext4");
    let file = std::fs::File::create(&image).expect("create ext4 image");
    file.set_len(size_mb * 1024 * 1024)
        .expect("size ext4 image");
    drop(file);

    let mkfs = std::process::Command::new("mkfs.ext4")
        .args([
            "-F",
            "-b",
            "4096",
            "-O",
            "^64bit,^extents",
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn mkfs.ext4");
    assert!(
        mkfs.status.success(),
        "mkfs.ext4 failed: stdout={} stderr={}",
        String::from_utf8_lossy(&mkfs.stdout),
        String::from_utf8_lossy(&mkfs.stderr)
    );

    let debugfs = std::process::Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field / mode 040777",
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn debugfs");
    assert!(
        debugfs.status.success(),
        "debugfs failed: stdout={} stderr={}",
        String::from_utf8_lossy(&debugfs.stdout),
        String::from_utf8_lossy(&debugfs.stderr)
    );

    let first_offset = 45_056_usize;
    let second_offset = 4_240_000_usize;
    let payload_len = 8_192_usize;
    let host_file = tmp.path().join("large_indirect_host.bin");
    let mut payload = vec![0_u8; second_offset + payload_len];
    payload[first_offset..first_offset + payload_len].fill(0xBB);
    payload[second_offset..second_offset + payload_len].fill(0xDD);
    std::fs::write(&host_file, payload).expect("write host indirect payload");

    let write_cmd = format!(
        "write {} /large_indirect.bin",
        host_file.to_str().expect("utf8 host payload path")
    );
    let debugfs = std::process::Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &write_cmd,
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn debugfs large file write");
    assert!(
        debugfs.status.success(),
        "debugfs large file write failed: stdout={} stderr={}",
        String::from_utf8_lossy(&debugfs.stdout),
        String::from_utf8_lossy(&debugfs.stderr)
    );

    let debugfs = std::process::Command::new("debugfs")
        .args([
            "-R",
            "stat /large_indirect.bin",
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn debugfs stat");
    assert!(
        debugfs.status.success(),
        "debugfs stat failed: stdout={} stderr={}",
        String::from_utf8_lossy(&debugfs.stdout),
        String::from_utf8_lossy(&debugfs.stderr)
    );
    let stat_stdout = String::from_utf8_lossy(&debugfs.stdout);
    let ino = stat_stdout
        .lines()
        .find_map(|line| line.strip_prefix("Inode:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|token| token.parse::<u64>().ok())
        .map(InodeNumber)
        .expect("extract inode number from debugfs stat output");

    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        ..OpenOptions::default()
    };
    let fs = OpenFs::open_with_options(&cx, &image, &opts).expect("open indirect ext4 image");
    (fs, tmp, ino)
}

#[test]
fn ext4_indirect_block_addressing_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp, ino) = open_ext4_mkfs_no_extents_with_large_file(64);
    let inode = fs.read_inode(&cx, ino).expect("read inode");
    assert_eq!(
        inode.flags & EXT4_EXTENTS_FL,
        0,
        "inode must not have extents flag (indirect block addressing)"
    );

    // 12 direct blocks (48 KB).
    // Read 8KB crossing from direct block 11 to single-indirect block 12.
    // 11 * 4096 = 45056
    let payload1 = vec![0xBB_u8; 8192];
    let readback1 = fs
        .read(&cx, ino, 45_056, 8_192)
        .expect("read direct to single-indirect boundary");

    // 12 direct + 1024 single indirect = 1036 blocks = 4243456 bytes.
    // Read 8KB crossing from single-indirect to double-indirect.
    let payload2 = vec![0xDD_u8; 8192];
    assert_eq!(
        &readback1[..],
        payload1.as_slice(),
        "readback from single-indirect must match"
    );

    let readback2 = fs
        .read(&cx, ino, 4_240_000, 8_192)
        .expect("read single to double-indirect boundary");
    assert_eq!(
        &readback2[..],
        payload2.as_slice(),
        "readback from double-indirect must match"
    );
}

#[allow(clippy::too_many_lines)]
#[test]
fn ext4_e2compr_write_readback_conforms_for_gzip_and_lzo() {
    let cx = Cx::for_testing();
    let (mut fs, _tmp, image_path) = open_writable_ext4_mkfs(64);
    let root = InodeNumber(2);

    for (method_idx, label, byte) in [(20_u8, "gzip", b'G'), (10_u8, "lzo", b'L')] {
        let name = std::ffi::OsString::from(format!("e2compr_{label}.bin"));
        fs.create(&cx, root, &name, 0o644, 0, 0)
            .expect("create compressed ext4 file");
        fs.flush_mvcc_to_device(&cx)
            .expect("flush created ext4 file before e2compr rewrite");
        drop(fs);
        fs = reopen_writable_ext4(&image_path);

        let attr = fs
            .lookup(&cx, root, &name)
            .expect("lookup created ext4 file before e2compr rewrite");
        let mut e2compr_flags = fs
            .read_inode(&cx, attr.ino)
            .expect("inode before e2compr setup")
            .flags;
        e2compr_flags |= EXT4_COMPR_FL;
        e2compr_flags &= !EXT4_INLINE_DATA_FL;
        e2compr_flags &= !EXT4_EXTENTS_FL;
        e2compr_flags &= !((0x7_u32 << 23) | (0x1F_u32 << 26));
        e2compr_flags |= 2_u32 << 23;
        e2compr_flags |= u32::from(method_idx & 0x1F) << 26;

        enable_e2compr_for_inode(&fs, &cx, attr.ino, e2compr_flags);
        drop(fs);
        fs = reopen_writable_ext4(&image_path);

        let attr = fs
            .lookup(&cx, root, &name)
            .expect("lookup e2compr test file after reopen");
        let inode_after_setup = fs
            .read_inode(&cx, attr.ino)
            .expect("inode after e2compr test setup");
        assert_ne!(
            inode_after_setup.flags & EXT4_COMPR_FL,
            0,
            "{label}: e2compr setup must set COMPR_FL before write-side conformance",
        );
        assert_eq!(
            inode_after_setup.flags & EXT4_EXTENTS_FL,
            0,
            "{label}: e2compr setup must clear EXTENTS_FL before write-side conformance",
        );
        // The historic e2compr method field overlaps the later
        // EXT4_INLINE_DATA_FL bit assignment, so write-side conformance must
        // validate behavior rather than the raw aliased flag word.

        let (baseline_free_blocks, baseline_gd_free_blocks) = ext4_free_block_counters(&fs, &cx);
        let first = vec![byte; 4096];
        fs.write(&cx, attr.ino, 0, &first)
            .expect("first compressed write");

        let (after_first_free_blocks, after_first_gd_free_blocks) =
            ext4_free_block_counters(&fs, &cx);
        let inode_after_first = fs
            .read_inode(&cx, attr.ino)
            .expect("inode after first compressed write");
        let readback_first = fs
            .read(&cx, attr.ino, 0, 4096)
            .expect("readback after first compressed write");

        assert!(
            inode_after_first.flags & EXT4_COMPRBLK_FL != 0,
            "{label}: compressed write should mark COMPRBLK"
        );
        assert!(
            after_first_free_blocks < baseline_free_blocks,
            "{label}: compressed write should consume at least one block"
        );
        assert!(
            after_first_gd_free_blocks < baseline_gd_free_blocks,
            "{label}: compressed write should update group descriptor free-block counters"
        );
        assert_eq!(
            &readback_first[..first.len()],
            first.as_slice(),
            "{label}: read path should return first compressed payload"
        );

        let second = vec![byte.wrapping_add(1); 4096];
        fs.write(&cx, attr.ino, 0, &second)
            .expect("second compressed write");

        let (after_second_free_blocks, after_second_gd_free_blocks) =
            ext4_free_block_counters(&fs, &cx);
        let inode_after_second = fs
            .read_inode(&cx, attr.ino)
            .expect("inode after compressed rewrite");
        let readback_second = fs
            .read(&cx, attr.ino, 0, 4096)
            .expect("readback after compressed rewrite");

        assert_eq!(
            after_second_free_blocks, after_first_free_blocks,
            "{label}: rewrite should reuse compressed blocks without leaking space"
        );
        assert_eq!(
            after_second_gd_free_blocks, after_first_gd_free_blocks,
            "{label}: group descriptor free-block counters should remain stable on rewrite"
        );
        assert_eq!(
            inode_after_second.blocks, inode_after_first.blocks,
            "{label}: rewrite should preserve inode i_blocks accounting"
        );
        assert_eq!(
            &readback_second[..second.len()],
            second.as_slice(),
            "{label}: read path should return rewritten compressed payload"
        );
    }
}

#[test]
fn ext4_fallocate_zero_range_zeroes_target_range() {
    let cx = Cx::for_testing();
    let (fs, _tmp, _image_path) = open_writable_ext4_mkfs(64);
    let root = InodeNumber(2);

    let attr = fs
        .create(&cx, root, OsStr::new("zero_range.bin"), 0o644, 0, 0)
        .expect("create ext4 zero-range file");
    let ino = attr.ino;

    let mut payload = vec![b'A'; 12 * 1024];
    payload[4096..8192].fill(b'B');
    payload[8192..].fill(b'C');
    fs.write(&cx, ino, 0, &payload)
        .expect("seed ext4 zero-range file");

    fs.fallocate(&cx, ino, 4096, 4096, libc::FALLOC_FL_ZERO_RANGE)
        .expect("zero-range middle block");

    let readback = fs
        .read(
            &cx,
            ino,
            0,
            u32::try_from(payload.len()).expect("payload length should fit u32"),
        )
        .expect("read zero-range ext4 file");
    assert_eq!(readback.len(), payload.len());
    assert_eq!(&readback[..4096], &payload[..4096]);
    assert!(readback[4096..8192].iter().all(|&byte| byte == 0));
    assert_eq!(&readback[8192..], &payload[8192..]);

    let inode = fs.read_inode(&cx, ino).expect("read zero-range inode");
    assert_eq!(
        inode.size,
        payload.len() as u64,
        "ZERO_RANGE without KEEP_SIZE should preserve size when the range stays within EOF"
    );
}

#[test]
fn ext4_fallocate_collapse_range_shifts_tail_and_shrinks_file() {
    let cx = Cx::for_testing();
    let (fs, _tmp, _image_path) = open_writable_ext4_mkfs(64);
    let root = InodeNumber(2);

    let attr = fs
        .create(&cx, root, OsStr::new("collapse_range.bin"), 0o644, 0, 0)
        .expect("create ext4 collapse-range file");
    let ino = attr.ino;

    let block = 4096_u64;
    let block_len = usize::try_from(block).expect("block size should fit usize");
    let chunk_a = vec![0xAA; block_len];
    let chunk_b = vec![0xBB; block_len];
    let chunk_c = vec![0xCC; block_len];
    let chunk_d = vec![0xDD; block_len];
    fs.write(&cx, ino, 0, &chunk_a).expect("write chunk A");
    fs.write(&cx, ino, block, &chunk_b).expect("write chunk B");
    fs.write(&cx, ino, 2 * block, &chunk_c)
        .expect("write chunk C");
    fs.write(&cx, ino, 3 * block, &chunk_d)
        .expect("write chunk D");

    fs.fallocate(&cx, ino, block, block, EXT4_FALLOC_FL_COLLAPSE_RANGE)
        .expect("collapse middle block");

    let after = fs.getattr(&cx, ino).expect("getattr after collapse");
    assert_eq!(after.size, 3 * block);

    let mut expected = Vec::with_capacity(3 * block_len);
    expected.extend_from_slice(&chunk_a);
    expected.extend_from_slice(&chunk_c);
    expected.extend_from_slice(&chunk_d);
    let readback = fs
        .read(
            &cx,
            ino,
            0,
            u32::try_from(expected.len()).expect("expected length should fit u32"),
        )
        .expect("read collapsed ext4 file");
    assert_eq!(
        readback, expected,
        "COLLAPSE_RANGE should remove the selected block and shift the tail left"
    );
}

#[test]
fn ext4_fallocate_collapse_range_reaching_eof_rejects_without_mutation() {
    let cx = Cx::for_testing();
    let (fs, _tmp, _image_path) = open_writable_ext4_mkfs(64);
    let root = InodeNumber(2);

    let attr = fs
        .create(&cx, root, OsStr::new("collapse_range_eof.bin"), 0o644, 0, 0)
        .expect("create ext4 collapse-range EOF file");
    let ino = attr.ino;

    let block = 4096_u64;
    let block_len = usize::try_from(block).expect("block size should fit usize");
    let chunk_a = vec![0x11; block_len];
    let chunk_b = vec![0x22; block_len];
    let mut payload = Vec::with_capacity(2 * block_len);
    payload.extend_from_slice(&chunk_a);
    payload.extend_from_slice(&chunk_b);
    fs.write(&cx, ino, 0, &payload)
        .expect("seed collapse EOF file");

    let err = fs
        .fallocate(&cx, ino, block, block, EXT4_FALLOC_FL_COLLAPSE_RANGE)
        .expect_err("collapse range reaching EOF should fail");
    assert_eq!(err.to_errno(), libc::EINVAL);

    let after = fs.getattr(&cx, ino).expect("getattr after failed collapse");
    assert_eq!(
        after.size,
        u64::try_from(payload.len()).expect("payload length should fit u64"),
        "failed COLLAPSE_RANGE must not change file size"
    );
    let readback = fs
        .read(
            &cx,
            ino,
            0,
            u32::try_from(payload.len()).expect("payload length should fit u32"),
        )
        .expect("read after failed collapse");
    assert_eq!(
        readback, payload,
        "failed COLLAPSE_RANGE must not mutate file data"
    );
}

#[test]
fn ext4_fallocate_insert_range_inserts_hole_and_grows_file() {
    let cx = Cx::for_testing();
    let (fs, _tmp, _image_path) = open_writable_ext4_mkfs(64);
    let root = InodeNumber(2);

    let attr = fs
        .create(&cx, root, OsStr::new("insert_range.bin"), 0o644, 0, 0)
        .expect("create ext4 insert-range file");
    let ino = attr.ino;

    let block = 4096_u64;
    let block_len = usize::try_from(block).expect("block size should fit usize");
    let chunk_a = vec![0xAA; block_len];
    let chunk_b = vec![0xBB; block_len];
    let chunk_c = vec![0xCC; block_len];
    fs.write(&cx, ino, 0, &chunk_a).expect("write chunk A");
    fs.write(&cx, ino, block, &chunk_b).expect("write chunk B");
    fs.write(&cx, ino, 2 * block, &chunk_c)
        .expect("write chunk C");

    fs.fallocate(&cx, ino, block, block, EXT4_FALLOC_FL_INSERT_RANGE)
        .expect("insert middle hole");

    let after = fs.getattr(&cx, ino).expect("getattr after insert");
    assert_eq!(after.size, 4 * block);

    let mut expected = Vec::with_capacity(4 * block_len);
    expected.extend_from_slice(&chunk_a);
    let hole = vec![0; block_len];
    expected.extend_from_slice(&hole);
    expected.extend_from_slice(&chunk_b);
    expected.extend_from_slice(&chunk_c);
    let readback = fs
        .read(
            &cx,
            ino,
            0,
            u32::try_from(expected.len()).expect("expected length should fit u32"),
        )
        .expect("read inserted ext4 file");
    assert_eq!(
        readback, expected,
        "INSERT_RANGE should insert a zero-reading hole and shift the tail right"
    );
}

#[test]
fn ext4_generic_112_preallocation_contract_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp, image_path) = open_writable_ext4_mkfs(64);
    assert_generic_112_preallocation_contract(
        "ext4",
        &cx,
        fs,
        InodeNumber(2),
        &image_path,
        Some(reopen_writable_ext4),
    );
}

#[test]
fn btrfs_generic_112_preallocation_contract_conforms() {
    let cx = Cx::for_testing();
    let (mut fs, _tmp, image_path) = open_btrfs_mkfs(128);
    fs.enable_writes(&cx)
        .expect("enable writes on btrfs generic/112 image");
    assert!(
        fs.is_writable(),
        "btrfs generic/112 image should be writable"
    );
    assert_generic_112_preallocation_contract("btrfs", &cx, fs, InodeNumber(1), &image_path, None);
}

#[test]
fn btrfs_fallocate_does_not_prealloc_over_live_data_conforms() {
    let cx = Cx::for_testing();
    let (mut fs, _tmp, _image_path) = open_btrfs_mkfs(128);
    fs.enable_writes(&cx)
        .expect("enable writes on btrfs live-data prealloc image");

    let attr = fs
        .create(
            &cx,
            InodeNumber(1),
            OsStr::new("btrfs_prealloc_live_data.bin"),
            0o644,
            0,
            0,
        )
        .expect("create btrfs live-data prealloc file");
    let live = vec![0x42_u8; 8192];
    fs.write(&cx, attr.ino, 0, &live)
        .expect("write live btrfs extent");

    fs.fallocate(&cx, attr.ino, 4096, 4096, 0)
        .expect("preallocate already-live btrfs range");

    let mut scope = RequestScope::empty();
    let extents = <OpenFs as FsOps>::fiemap(&fs, &cx, &mut scope, attr.ino, 0, u64::MAX)
        .expect("fiemap btrfs live-data prealloc file");
    assert_eq!(
        extents.len(),
        1,
        "preallocation over live data must not add an overlapping unwritten extent"
    );
    assert_eq!(extents[0].logical, 0);
    assert_eq!(extents[0].length, 8192);
    assert_eq!(
        extents[0].flags & FIEMAP_EXTENT_UNWRITTEN,
        0,
        "live data extent must remain initialized after overlapping prealloc"
    );

    let readback = fs
        .read(&cx, attr.ino, 0, 8192)
        .expect("read live btrfs file after overlapping prealloc");
    assert_eq!(readback, live);
}

/// bd-ftev0: the mounted comparator's `fsync-journal-commit` workload rewrites a
/// file that `mkfs.btrfs -r` placed in the image, and every positioned write
/// returned `EIO`. The file already owns a data extent that mkfs allocated, so
/// this exercises the overwrite path (free the old extent, allocate a new one)
/// rather than the fresh-file path the other btrfs write tests cover.
#[test]
fn btrfs_positioned_write_over_mkfs_populated_file_conforms() {
    let cx = Cx::for_testing();
    let seed = [0xF5_u8; 4096];
    let (mut fs, _tmp, _image) = open_btrfs_mkfs_rootdir(512, "fsync.bin", &seed);
    fs.enable_writes(&cx)
        .expect("enable writes on btrfs rootdir-populated image");

    let attr = fs
        .lookup(&cx, InodeNumber(1), OsStr::new("fsync.bin"))
        .expect("lookup mkfs-populated btrfs file");
    assert_eq!(attr.size, 4096, "fixture file should carry mkfs content");
    assert_eq!(
        fs.read(&cx, attr.ino, 0, 4096)
            .expect("read mkfs-populated btrfs file"),
        seed,
        "fixture content must differ from every payload written below"
    );

    // Eight 4 KiB positioned writes to offset 0, exactly like the workload.
    for index in 0..8_u8 {
        let payload = [index.wrapping_mul(17).wrapping_add(3); 4096];
        let written = fs
            .write(&cx, attr.ino, 0, &payload)
            .unwrap_or_else(|err| panic!("positioned write {index} over btrfs file: {err}"));
        assert_eq!(written, 4096, "short positioned write on iteration {index}");
        fs.fsync(&cx, attr.ino, 0, false)
            .unwrap_or_else(|err| panic!("fsync after positioned write {index}: {err}"));
        let readback = fs
            .read(&cx, attr.ino, 0, 4096)
            .unwrap_or_else(|err| panic!("read back positioned write {index}: {err}"));
        assert_eq!(
            readback, payload,
            "iteration {index} must observe its own bytes, not the previous content"
        );
        assert_eq!(
            fs.getattr(&cx, attr.ino)
                .unwrap_or_else(|err| panic!("getattr after write {index}: {err}"))
                .size,
            4096,
            "overwriting in place must not change the file size on iteration {index}"
        );
    }
}

#[test]
fn ext4_fast_commit_replay_openfs_evidence_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp) = open_ext4_fast_commit_image(false);

    let replay = fs
        .ext4_journal_replay()
        .expect("journal replay outcome should be present");
    let fc = fs
        .ext4_fast_commit_replay()
        .expect("fast-commit evidence should be present");

    assert_eq!(replay.committed_sequences, vec![1]);
    assert_eq!(replay.stats.replayed_blocks, 1);
    assert_eq!(fc.reserved_fc_blocks, 2);
    assert!(fc.bytes_collected >= 32);
    assert_eq!(fc.replay.transactions_found, 1);
    assert_eq!(fc.replay.last_tid, 1);
    assert_eq!(fc.replay.operations.len(), 1);
    assert_eq!(
        format!("{:?}", fc.replay.operations),
        "[InodeUpdate(42, [])]"
    );
    assert_eq!(fc.replay.incomplete_transactions, 0);
    assert!(!fc.replay.fallback_required);
    assert_eq!(fc.replay.blocks_scanned, 1);

    let target = fs
        .read_block_vec(&cx, ffs_types::BlockNumber(15))
        .expect("read replayed data block");
    assert_eq!(&target[..16], b"JBD2-REPLAY-TEST");
}

#[test]
fn ext4_fast_commit_truncated_stream_falls_back_to_jbd2_only() {
    let cx = Cx::for_testing();
    let (fs, _tmp) = open_ext4_fast_commit_image(true);

    let replay = fs
        .ext4_journal_replay()
        .expect("journal replay outcome should be present");
    let fc = fs
        .ext4_fast_commit_replay()
        .expect("fast-commit evidence should be present");

    assert_eq!(replay.committed_sequences, vec![1]);
    assert_eq!(replay.stats.replayed_blocks, 1);
    assert_eq!(fc.reserved_fc_blocks, 2);
    assert_eq!(fc.replay.transactions_found, 0);
    assert_eq!(fc.replay.last_tid, 0);
    assert!(fc.replay.operations.is_empty());
    assert_eq!(fc.replay.incomplete_transactions, 1);
    assert!(fc.replay.fallback_required);
    assert_eq!(fc.replay.blocks_scanned, 1);

    let target = fs
        .read_block_vec(&cx, ffs_types::BlockNumber(15))
        .expect("read replayed data block after fallback");
    assert_eq!(&target[..16], b"JBD2-REPLAY-TEST");
}

include!("conformance/btrfs.rs");

#[test]
fn ext4_mmp_block_fixture_conforms() {
    let mmp = ffs_harness::validate_mmp_block_fixture(&fixture_path("ext4_mmp_block.json"))
        .expect("MMP block");

    assert_eq!(mmp.magic, 0x004D_4D50, "should have MMP magic");
    assert_eq!(mmp.seq, 0xFF4D_4D50, "should have clean seq");
    assert_eq!(mmp.time, 1_700_000_000, "time should be 1700000000");
    assert_eq!(mmp.nodename, "ffs-node-01", "nodename should match");
    assert_eq!(mmp.bdevname, "/dev/nvme0n1", "bdevname should match");
    assert_eq!(mmp.check_interval, 5, "check_interval should be 5");
    assert_eq!(
        mmp.checksum, 0xB0AF_6BEB,
        "fixture checksum should match seed 0xAABBCCDD"
    );

    // Verify status decoding
    assert_eq!(
        mmp.status(),
        ffs_ondisk::Ext4MmpStatus::Clean,
        "status should be Clean"
    );
}

#[test]
fn ext4_active_mmp_write_open_is_rejected() {
    let (_tmp, image_path) = mkfs_writable_ext4_image(64);
    patch_ext4_active_mmp(&image_path, 2048, 42);

    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        ..OpenOptions::default()
    };
    let err = OpenFs::open_with_options(&cx, &image_path, &opts)
        .expect_err("active ext4 MMP state must refuse write-participating open");

    assert!(
        matches!(err, ffs_error::FfsError::UnsupportedFeature(ref message)
            if message.contains("another writer may be active")
                && message.contains("instead of participating in periodic MMP heartbeat updates")),
        "expected explicit active-MMP UnsupportedFeature, got {err:?}"
    );
    assert_eq!(err.to_errno(), libc::EOPNOTSUPP);
}

#[test]
fn parity_report_totals_are_consistent() {
    let report = ParityReport::current();
    let implemented_sum: u32 = report.domains.iter().map(|d| d.implemented).sum();
    let total_sum: u32 = report.domains.iter().map(|d| d.total).sum();

    assert_eq!(implemented_sum, report.overall_implemented);
    assert_eq!(total_sum, report.overall_total);
}

#[test]
fn ext4_reference_image_opens_with_journal_replay_segments() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let image_path = workspace.join("conformance/golden/ext4_8mb_reference.ext4");

    if !image_path.exists() {
        println!(
            "Skipping test: golden image {} not found.",
            image_path.display()
        );
        return;
    }

    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, &image_path, &OpenOptions::default())
        .expect("open ext4 golden image with journal replay");
    let replay = fs
        .ext4_journal_replay()
        .expect("journal-enabled reference image should expose replay outcome");

    assert!(
        replay.stats.scanned_blocks > 0,
        "journal replay should scan at least one journal block"
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn validate_checksum_manifest_artifacts(
    manifest_path: &Path,
    artifacts_dir: &Path,
    artifact_kind: &str,
    tracked_extensions: &[&str],
) {
    let listed_files = parse_checksum_inventory(manifest_path);
    assert!(
        !listed_files.is_empty(),
        "{} should list {} files",
        manifest_path.display(),
        artifact_kind
    );

    for (filename, expected_digest) in &listed_files {
        assert!(
            has_tracked_extension(Path::new(filename), tracked_extensions),
            "{artifact_kind} checksum manifest should only track {} files: {filename}",
            tracked_extension_message(tracked_extensions)
        );
        let path = artifacts_dir.join(filename);
        let data = fs::read(&path)
            .unwrap_or_else(|e| panic!("{artifact_kind} {filename} missing or unreadable: {e}"));
        assert!(
            !data.is_empty(),
            "{artifact_kind} {filename} should be non-empty"
        );
        let actual_digest = sha256_hex(&data);
        assert_eq!(
            actual_digest, *expected_digest,
            "{artifact_kind} {filename} digest mismatch"
        );
    }

    let mut actual_artifacts = Vec::new();
    collect_tracked_artifacts(
        artifacts_dir,
        artifacts_dir,
        tracked_extensions,
        &mut actual_artifacts,
    );

    for artifact_file in &actual_artifacts {
        assert!(
            listed_files.contains_key(artifact_file),
            "{artifact_kind} {artifact_file} exists but is not listed in {}",
            manifest_path.display()
        );
    }
}

/// Recursively collect tracked artifact files under `dir`, naming each by its
/// path relative to `base` with `/` separators so the name matches the
/// committed checksum manifest (which lists nested fixtures by path-relative
/// name; see bd-3vink). Subdirectories are descended into; non-tracked files
/// (e.g. the manifest itself) are skipped.
fn collect_tracked_artifacts(
    dir: &Path,
    base: &Path,
    tracked_extensions: &[&str],
    out: &mut Vec<String>,
) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("read dir entry in {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            collect_tracked_artifacts(&path, base, tracked_extensions, out);
        } else if has_tracked_extension(&path, tracked_extensions) {
            let relative = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push(relative);
        }
    }
}

fn has_tracked_extension(path: &Path, tracked_extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            tracked_extensions
                .iter()
                .any(|tracked| ext.eq_ignore_ascii_case(tracked))
        })
}

fn tracked_extension_message(tracked_extensions: &[&str]) -> String {
    tracked_extensions
        .iter()
        .map(|extension| format!(".{extension}"))
        .collect::<Vec<_>>()
        .join(" or ")
}

fn assert_panics_with<F>(case: F, expected: &str)
where
    F: FnOnce() + std::panic::UnwindSafe,
{
    let panic = match std::panic::catch_unwind(case) {
        Ok(()) => panic!("expected panic containing {expected:?}"),
        Err(panic) => panic,
    };
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("<non-string panic>");
    assert!(
        message.contains(expected),
        "expected panic containing {expected:?}, got {message:?}"
    );
}

fn checksum_manifest_negative_cases_fail_closed() {
    assert_panics_with(
        checksum_manifest_requires_tracked_text_artifacts,
        "golden btrfs_item_payloads.txt exists but is not listed in",
    );
    assert_panics_with(
        checksum_manifest_rejects_malformed_digest,
        "digest should be 64 lowercase hex characters",
    );
    assert_panics_with(
        checksum_manifest_rejects_missing_file_name,
        "checksum line missing file name",
    );
    assert_panics_with(
        checksum_manifest_rejects_extra_fields,
        "checksum line should have exactly two fields",
    );
    assert_panics_with(
        checksum_manifest_rejects_duplicate_entries,
        "duplicate file entry: listed.json",
    );
    assert_panics_with(
        checksum_manifest_rejects_parent_directory_escape,
        "relative artifact path without absolute or parent-directory components",
    );
    assert_panics_with(
        checksum_manifest_rejects_absolute_paths,
        "relative artifact path without absolute or parent-directory components",
    );
}

#[test]
#[should_panic(expected = "golden btrfs_item_payloads.txt exists but is not listed in")]
fn checksum_manifest_requires_tracked_text_artifacts() {
    let tmp = tempfile::TempDir::new().expect("tmpdir for checksum manifest negative test");
    let artifact_dir = tmp.path();
    fs::write(artifact_dir.join("listed.json"), b"{}").expect("write listed JSON artifact");
    fs::write(artifact_dir.join("btrfs_item_payloads.txt"), b"payload")
        .expect("write unlisted text artifact");

    let listed_digest = sha256_hex(b"{}");
    fs::write(
        artifact_dir.join("checksums.sha256"),
        format!("{listed_digest}  listed.json\n"),
    )
    .expect("write checksum manifest");

    validate_checksum_manifest_artifacts(
        &artifact_dir.join("checksums.sha256"),
        artifact_dir,
        "golden",
        &["json", "txt"],
    );
}

#[test]
#[should_panic(expected = "digest should be 64 lowercase hex characters")]
fn checksum_manifest_rejects_malformed_digest() {
    let tmp = tempfile::TempDir::new().expect("tmpdir for malformed digest manifest test");
    let manifest = tmp.path().join("checksums.sha256");
    fs::write(&manifest, "not-a-sha256  listed.json\n").expect("write checksum manifest");

    parse_checksum_inventory(&manifest);
}

#[test]
#[should_panic(expected = "checksum line missing file name")]
fn checksum_manifest_rejects_missing_file_name() {
    let tmp = tempfile::TempDir::new().expect("tmpdir for missing filename manifest test");
    let manifest = tmp.path().join("checksums.sha256");
    let digest = sha256_hex(b"{}");
    fs::write(&manifest, format!("{digest}\n")).expect("write checksum manifest");

    parse_checksum_inventory(&manifest);
}

#[test]
#[should_panic(expected = "checksum line should have exactly two fields")]
fn checksum_manifest_rejects_extra_fields() {
    let tmp = tempfile::TempDir::new().expect("tmpdir for extra-field manifest test");
    let manifest = tmp.path().join("checksums.sha256");
    let digest = sha256_hex(b"{}");
    fs::write(&manifest, format!("{digest}  listed.json  extra\n"))
        .expect("write checksum manifest");

    parse_checksum_inventory(&manifest);
}

#[test]
#[should_panic(expected = "duplicate file entry: listed.json")]
fn checksum_manifest_rejects_duplicate_entries() {
    let tmp = tempfile::TempDir::new().expect("tmpdir for duplicate manifest test");
    let manifest = tmp.path().join("checksums.sha256");
    let digest = sha256_hex(b"{}");
    fs::write(
        &manifest,
        format!("{digest}  listed.json\n{digest}  listed.json\n"),
    )
    .expect("write checksum manifest");

    parse_checksum_inventory(&manifest);
}

#[test]
#[should_panic(expected = "relative artifact path without absolute or parent-directory components")]
fn checksum_manifest_rejects_parent_directory_escape() {
    let tmp = tempfile::TempDir::new().expect("tmpdir for path escape manifest test");
    let manifest = tmp.path().join("checksums.sha256");
    let digest = sha256_hex(b"{}");
    fs::write(&manifest, format!("{digest}  ../escape.json\n")).expect("write checksum manifest");

    parse_checksum_inventory(&manifest);
}

#[test]
#[should_panic(expected = "relative artifact path without absolute or parent-directory components")]
fn checksum_manifest_rejects_absolute_paths() {
    let tmp = tempfile::TempDir::new().expect("tmpdir for absolute path manifest test");
    let manifest = tmp.path().join("checksums.sha256");
    let digest = sha256_hex(b"{}");
    fs::write(&manifest, format!("{digest}  /tmp/escape.json\n")).expect("write checksum manifest");

    parse_checksum_inventory(&manifest);
}

#[test]
fn checksum_manifest_accepts_nested_paths() {
    // Nested relative paths are legitimate — fixtures live in subdirectories
    // such as conformance/fixtures/numa_allocation_placement/ (bd-3vink). The
    // manifest must track them by their path-relative name.
    let tmp = tempfile::TempDir::new().expect("tmpdir for nested path manifest test");
    let manifest = tmp.path().join("checksums.sha256");
    let digest = sha256_hex(b"{}");
    fs::write(&manifest, format!("{digest}  nested/listed.json\n"))
        .expect("write checksum manifest");

    let inventory = parse_checksum_inventory(&manifest);
    assert_eq!(
        inventory.get("nested/listed.json").map(String::as_str),
        Some(digest.as_str()),
        "nested manifest entry should parse to its path-relative name"
    );
}

/// CI gate: verify that every fixture listed in checksums.sha256 exists,
/// is non-empty, and that its SHA-256 digest matches the committed manifest.
#[test]
fn fixture_checksum_manifest_is_complete() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    validate_checksum_manifest_artifacts(
        &workspace.join("conformance/fixtures/checksums.sha256"),
        &workspace.join("conformance/fixtures"),
        "fixture",
        &["json"],
    );
}

/// CI gate: verify that every golden file listed in checksums.sha256 exists,
/// is non-empty, and that its SHA-256 digest matches the committed manifest.
#[test]
fn golden_checksum_manifest_is_complete() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    validate_checksum_manifest_artifacts(
        &workspace.join("conformance/golden/checksums.sha256"),
        &workspace.join("conformance/golden"),
        "golden",
        &["json", "txt"],
    );
}

/// Full conformance gate pass (bd-2jk.14).
///
/// This is the single CI gate test that exercises every conformance
/// surface in one deterministic pass: all fixture parsers, checksum
/// manifests, golden references, fuzz corpus, and parity report.
/// Must complete in < 60 seconds.
#[test]
fn full_conformance_gate_pass() {
    let start = std::time::Instant::now();

    // 1) All committed fixture parsers + spot checks.
    ext4_and_btrfs_fixtures_conform();
    ext4_group_desc_fixtures_conform();
    ext4_group_desc_32byte_fixture_re_encodes_byte_identical();
    ext4_group_desc_64byte_fixture_re_encodes_byte_identical();
    ext4_inode_fixtures_conform();
    ext4_inline_data_fixture_conforms();
    ext4_inline_data_with_continuation_fixture_conforms();
    ext4_inline_data_openfs_read_conforms();
    ext4_inline_data_xattr_continuation_openfs_read_conforms();
    ext4_inline_data_openfs_read_boundaries_conform();
    ext4_inline_data_zero_size_and_extreme_read_bounds_conform();
    ext4_inline_data_vfs_lookup_readdir_conforms();
    ext4_inline_data_write_rejects_without_mutating_contents();
    ext4_inline_data_fallocate_rejects_without_mutating_contents();
    ext4_extent_tree_leaf_fixture_conforms();
    ext4_extent_tree_index_fixture_conforms();
    ext4_htree_dx_root_fixture_conforms();
    ext4_xattr_block_fixture_conforms();
    ext4_dir_block_fixture_conforms();
    ext4_dir_block_with_tail_fixture_conforms();
    ext4_dir_block_deleted_entry_fixture_conforms();
    ext4_dir_block_truncated_tail_fixture_rejected();
    ext4_dir_block_checksum_stamp_and_verify_fixture_conforms();
    ext4_dir_block_checksum_detects_corruption();
    ext4_dir_block_rec_len_too_small_fixture_rejected();
    ext4_dir_block_name_len_overflow_fixture_rejected();
    ext4_dir_block_rec_len_min12_fixture_rejected();
    ext4_dir_block_rec_len_unaligned_fixture_rejected();
    ext4_dir_block_tail_padding_nonzero_fixture_rejected();
    ext4_dir_block_tail_bad_header_fixture_rejected();
    ext4_dir_block_casefold_lookup_conforms();
    ext4_casefold_openfs_lookup_is_case_insensitive();
    ext4_fscrypt_nokey_readdir_and_lookup_preserve_raw_bytes();
    ext4_fscrypt_legacy_policy_transport_discrepancy_conforms();
    btrfs_tree_block_checksum_tamper_detection_conforms();
    ext4_orphan_recovery_conforms();
    ext4_path_resolution_conforms();
    ext4_fallocate_zero_range_zeroes_target_range();
    ext4_fallocate_collapse_range_shifts_tail_and_shrinks_file();
    ext4_fallocate_collapse_range_reaching_eof_rejects_without_mutation();
    ext4_fallocate_insert_range_inserts_hole_and_grows_file();
    ext4_generic_112_preallocation_contract_conforms();
    btrfs_generic_112_preallocation_contract_conforms();
    btrfs_fallocate_does_not_prealloc_over_live_data_conforms();
    ext4_e2compr_write_readback_conforms_for_gzip_and_lzo();
    ext4_indirect_block_addressing_conforms();
    ext4_fast_commit_replay_openfs_evidence_conforms();
    ext4_fast_commit_truncated_stream_falls_back_to_jbd2_only();
    ext4_reference_image_opens_with_journal_replay_segments();
    btrfs_send_stream_multi_command_conforms();
    btrfs_send_stream_unknown_command_preserves_attrs_as_unspec();
    btrfs_send_stream_rejects_missing_end_command();
    btrfs_transparent_decompression_zlib_regular_extent_conforms();
    btrfs_transparent_decompression_lzo_regular_extent_conforms();
    btrfs_transparent_decompression_zstd_regular_extent_conforms();
    btrfs_subvolume_mount_root_alias_conforms();
    btrfs_tree_log_replay_multilevel_conforms();
    btrfs_tree_log_replay_skips_when_log_root_absent();
    btrfs_chunk_tree_walk_adds_and_sorts_new_chunks();
    btrfs_device_tree_walk_enumerates_all_devices();
    btrfs_multi_device_raid6_read_conforms();
    btrfs_multi_device_raid10_read_conforms();
    btrfs_multi_device_raid5_read_conforms();
    btrfs_multi_device_dup_read_conforms();
    btrfs_multi_device_raid1_read_falls_back_to_second_mirror();
    btrfs_multi_device_raid0_dispatches_to_correct_stripe();
    btrfs_chunk_mapping_fixture_conforms();
    btrfs_leaf_fixture_conforms();
    btrfs_fstree_leaf_fixture_conforms();
    btrfs_roottree_leaf_fixture_conforms();
    btrfs_devitem_fixture_conforms();
    ext4_mmp_block_fixture_conforms();
    ext4_active_mmp_write_open_is_rejected();

    // 2) Policy docs and checksum manifests are bidirectionally complete.
    root_conformance_discrepancies_follow_policy();
    conformance_fixture_provenance_covers_committed_fixtures();
    conformance_golden_provenance_covers_committed_artifacts();
    fixture_checksum_manifest_is_complete();
    golden_checksum_manifest_is_complete();
    checksum_manifest_negative_cases_fail_closed();

    // 3) Conformance and legacy goldens deserialize successfully and satisfy basic invariants.
    let workspace = workspace_root();
    validate_golden_jsons(workspace);
    validate_legacy_fixture_goldens(workspace);

    // 4) Fuzz corpus is populated.
    assert_fuzz_corpus_populated(workspace);

    // 5) Parity report at 100%, internally consistent, and deterministic.
    assert_parity_report_100_percent();
    parity_report_totals_are_consistent();

    // 6) Time bound.
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 60,
        "conformance gate should complete in < 60s, took {elapsed:?}"
    );
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
}

fn validate_golden_jsons(workspace: &Path) {
    let golden_dir = workspace.join("conformance/golden");

    let ext4_golden_names = [
        "ext4_64mb_sparse_super.json",
        "ext4_htree_dirindex.json",
        "ext4_64mb_reference.json",
        "ext4_dir_index_reference.json",
        "ext4_8mb_reference.json",
    ];
    for name in &ext4_golden_names {
        let text = std::fs::read_to_string(golden_dir.join(name))
            .unwrap_or_else(|e| panic!("golden {name} unreadable: {e}"));
        let golden: GoldenReference =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("golden {name} invalid: {e}"));
        assert!(golden.version >= 1, "golden {name} version should be >= 1");
        assert!(
            !golden.source.is_empty(),
            "golden {name} source should be non-empty"
        );
    }

    let btrfs_golden_names = ["btrfs_small.json", "btrfs_medium.json", "btrfs_large.json"];
    for name in &btrfs_golden_names {
        let text = std::fs::read_to_string(golden_dir.join(name))
            .unwrap_or_else(|e| panic!("golden {name} unreadable: {e}"));
        let golden: Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("golden {name} invalid: {e}"));
        assert_eq!(
            golden.get("filesystem").and_then(Value::as_str),
            Some("btrfs"),
            "golden {name} filesystem should be btrfs"
        );
        for numeric in ["sectorsize", "nodesize", "generation"] {
            assert!(
                golden.get(numeric).and_then(Value::as_u64).is_some(),
                "golden {name} missing numeric field {numeric}"
            );
        }
        assert!(
            golden
                .get("label")
                .and_then(Value::as_str)
                .is_some_and(|label| !label.is_empty()),
            "golden {name} label should be non-empty"
        );
    }

    let fscrypt_transport_name = "ext4_fscrypt_legacy_policy_transport_discrepancy.json";
    let text = std::fs::read_to_string(golden_dir.join(fscrypt_transport_name))
        .unwrap_or_else(|e| panic!("golden {fscrypt_transport_name} unreadable: {e}"));
    let golden: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("golden {fscrypt_transport_name} invalid: {e}"));
    validate_fscrypt_transport_discrepancy_golden(fscrypt_transport_name, &golden);
}

fn parse_checksum_inventory(path: &Path) -> HashMap<String, String> {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("checksum inventory {} unreadable: {err}", path.display()));
    let mut inventory = HashMap::new();
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let (digest, file_name) = parse_checksum_inventory_line(line);
        assert!(
            inventory
                .insert(file_name.to_owned(), digest.to_owned())
                .is_none(),
            "checksum inventory {} has duplicate file entry: {file_name}",
            path.display()
        );
    }
    inventory
}

fn parse_checksum_inventory_line(line: &str) -> (&str, &str) {
    let mut parts = line.split_whitespace();
    let digest = parts
        .next()
        .unwrap_or_else(|| panic!("checksum line missing digest: {line}"));
    let file_name = parts
        .next()
        .unwrap_or_else(|| panic!("checksum line missing file name: {line}"));
    assert!(
        parts.next().is_none(),
        "checksum line should have exactly two fields: {line}"
    );
    assert!(
        valid_checksum_digest(digest),
        "checksum line digest should be 64 lowercase hex characters: {line}"
    );
    assert!(
        valid_checksum_manifest_filename(file_name),
        "checksum line file name must be a relative artifact path without absolute or parent-directory components: {line}"
    );
    (digest, file_name)
}

fn valid_checksum_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_checksum_manifest_filename(file_name: &str) -> bool {
    let path = Path::new(file_name);
    // Allow nested relative paths (e.g. `numa_allocation_placement/foo.json`) so
    // the manifest can track fixtures in subdirectories (bd-3vink), while still
    // rejecting absolute paths and `..`/`.` traversal — every component must be
    // a plain `Normal` segment.
    let mut components = path.components().peekable();
    !path.is_absolute()
        && components.peek().is_some()
        && components.all(|component| matches!(component, Component::Normal(_)))
}

fn sorted_names(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut names = names.into_iter().collect::<Vec<_>>();
    names.sort();
    names
}

fn require_nonempty_string_field<'a>(golden: &'a Value, file_name: &str, field: &str) -> &'a str {
    let value = golden
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("golden {file_name} missing string field {field}"));
    assert!(
        !value.is_empty(),
        "golden {file_name} field {field} should be non-empty"
    );
    value
}

#[derive(Clone, Copy)]
struct LegacyExt4FixtureProfile {
    file_name: &'static str,
    volume_name: &'static str,
    size_mib: u64,
    block_size: u64,
    blocks_count: u64,
    inodes_count: u64,
    features: &'static [&'static str],
}

#[derive(Clone, Copy)]
struct LegacyBtrfsFixtureProfile {
    file_name: &'static str,
    label: &'static str,
    size_mib: u64,
    sectorsize: u64,
    nodesize: u64,
    generation: u64,
}

const LEGACY_EXT4_CONTENT_ENTRIES: &[&str] = &[
    "/README.txt file",
    "/dir1 directory",
    "/dir1/file1.bin file size 256",
    "/dir1/dir2 directory",
    "/dir1/dir2/file2.txt file",
    "/symlink symlink target dir1/file1.bin",
];

const LEGACY_EXT4_PROFILES: &[LegacyExt4FixtureProfile] = &[
    LegacyExt4FixtureProfile {
        file_name: "ext4_small.json",
        volume_name: "ext4_small",
        size_mib: 16,
        block_size: 4096,
        blocks_count: 4096,
        inodes_count: 4096,
        features: &["extent", "filetype"],
    },
    LegacyExt4FixtureProfile {
        file_name: "ext4_medium.json",
        volume_name: "ext4_medium",
        size_mib: 64,
        block_size: 4096,
        blocks_count: 16_384,
        inodes_count: 16_384,
        features: &["extent", "filetype", "dir_index"],
    },
    LegacyExt4FixtureProfile {
        file_name: "ext4_large.json",
        volume_name: "ext4_large",
        size_mib: 128,
        block_size: 4096,
        blocks_count: 32_768,
        inodes_count: 32_768,
        features: &["extent", "filetype", "dir_index", "sparse_super"],
    },
];

const LEGACY_BTRFS_PROFILES: &[LegacyBtrfsFixtureProfile] = &[
    LegacyBtrfsFixtureProfile {
        file_name: "btrfs_small.json",
        label: "btrfs_small",
        size_mib: 256,
        sectorsize: 4096,
        nodesize: 16_384,
        generation: 8,
    },
    LegacyBtrfsFixtureProfile {
        file_name: "btrfs_medium.json",
        label: "btrfs_medium",
        size_mib: 512,
        sectorsize: 4096,
        nodesize: 16_384,
        generation: 8,
    },
    LegacyBtrfsFixtureProfile {
        file_name: "btrfs_large.json",
        label: "btrfs_large",
        size_mib: 1024,
        sectorsize: 4096,
        nodesize: 16_384,
        generation: 8,
    },
];

fn legacy_ext4_profile(file_name: &str) -> Option<LegacyExt4FixtureProfile> {
    LEGACY_EXT4_PROFILES
        .iter()
        .copied()
        .find(|profile| profile.file_name == file_name)
}

fn legacy_btrfs_profile(file_name: &str) -> Option<LegacyBtrfsFixtureProfile> {
    LEGACY_BTRFS_PROFILES
        .iter()
        .copied()
        .find(|profile| profile.file_name == file_name)
}

fn assert_exact_u64_field(golden: &Value, file_name: &str, field: &str, expected: u64) {
    let actual = golden
        .get(field)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("golden {file_name} missing numeric field {field}"));
    assert_eq!(
        actual, expected,
        "golden {file_name} field {field} no longer matches the declared fixture profile"
    );
}

fn assert_exact_str_field(golden: &Value, file_name: &str, field: &str, expected: &str) {
    let actual = golden
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("golden {file_name} missing string field {field}"));
    assert_eq!(
        actual, expected,
        "golden {file_name} field {field} no longer matches the declared fixture profile"
    );
}

fn assert_expected_json_fields(golden: &Value, file_name: &str, expected_fields: &[&str]) {
    let object = golden
        .as_object()
        .unwrap_or_else(|| panic!("golden {file_name} should be a JSON object"));
    let actual = sorted_names(object.keys().cloned());
    let expected = sorted_names(expected_fields.iter().map(|field| (*field).to_owned()));
    assert_eq!(
        actual, expected,
        "golden {file_name} changed its legacy inspect summary schema"
    );
}

fn validate_legacy_ext4_inspect_golden(file_name: &str, golden: &Value) {
    let profile = legacy_ext4_profile(file_name)
        .unwrap_or_else(|| panic!("unexpected legacy ext4 inspect golden {file_name}"));
    assert_expected_json_fields(
        golden,
        file_name,
        &[
            "block_size",
            "blocks_count",
            "filesystem",
            "inodes_count",
            "volume_name",
        ],
    );
    assert_eq!(
        golden.get("filesystem").and_then(Value::as_str),
        Some("ext4"),
        "golden {file_name} filesystem should be ext4"
    );
    assert_exact_u64_field(golden, file_name, "block_size", profile.block_size);
    assert_exact_u64_field(golden, file_name, "blocks_count", profile.blocks_count);
    assert_exact_u64_field(golden, file_name, "inodes_count", profile.inodes_count);
    assert_exact_str_field(golden, file_name, "volume_name", profile.volume_name);
}

fn validate_legacy_btrfs_inspect_golden(file_name: &str, golden: &Value) {
    let profile = legacy_btrfs_profile(file_name)
        .unwrap_or_else(|| panic!("unexpected legacy btrfs inspect golden {file_name}"));
    assert_expected_json_fields(
        golden,
        file_name,
        &[
            "filesystem",
            "generation",
            "label",
            "nodesize",
            "sectorsize",
        ],
    );
    assert_eq!(
        golden.get("filesystem").and_then(Value::as_str),
        Some("btrfs"),
        "golden {file_name} filesystem should be btrfs"
    );
    assert_exact_u64_field(golden, file_name, "sectorsize", profile.sectorsize);
    assert_exact_u64_field(golden, file_name, "nodesize", profile.nodesize);
    assert_exact_u64_field(golden, file_name, "generation", profile.generation);
    assert_exact_str_field(golden, file_name, "label", profile.label);
}

fn validate_fast_commit_fixture_golden(file_name: &str, golden: &Value) {
    let scenario_id = require_nonempty_string_field(golden, file_name, "scenario_id");
    assert_eq!(
        scenario_id,
        file_name.trim_end_matches(".json"),
        "golden {file_name} scenario_id should match file stem"
    );
    require_nonempty_string_field(golden, file_name, "description");

    let payload = require_nonempty_string_field(golden, file_name, "fast_commit_hex");
    let compact = payload
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();
    assert!(
        compact.len() % 2 == 0,
        "golden {file_name} fast_commit_hex should have even hex length"
    );
    assert!(
        compact.chars().all(|ch| ch.is_ascii_hexdigit()),
        "golden {file_name} fast_commit_hex should contain only hex digits"
    );

    let expected = golden
        .get("expected")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("golden {file_name} missing expected object"));
    for field in [
        "transactions_found",
        "last_tid",
        "blocks_scanned",
        "incomplete_transactions",
    ] {
        assert!(
            expected.get(field).and_then(Value::as_u64).is_some(),
            "golden {file_name} expected.{field} should be numeric"
        );
    }
    assert!(
        expected
            .get("fallback_required")
            .and_then(Value::as_bool)
            .is_some(),
        "golden {file_name} expected.fallback_required should be boolean"
    );

    let operations = expected
        .get("operations")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("golden {file_name} expected.operations should be an array"));
    for (idx, operation) in operations.iter().enumerate() {
        let kind = operation
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("golden {file_name} operation[{idx}] missing kind"));
        match kind {
            "inode_update" => {
                assert!(
                    operation.get("ino").and_then(Value::as_u64).is_some(),
                    "golden {file_name} inode_update[{idx}] should include ino"
                );
            }
            "add_range" => {
                for field in ["ino", "logical_block", "len", "physical_block"] {
                    assert!(
                        operation.get(field).and_then(Value::as_u64).is_some(),
                        "golden {file_name} add_range[{idx}] missing numeric field {field}"
                    );
                }
            }
            "create" => {
                for field in ["parent_ino", "ino"] {
                    assert!(
                        operation.get(field).and_then(Value::as_u64).is_some(),
                        "golden {file_name} create[{idx}] missing numeric field {field}"
                    );
                }
                let name = operation
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("golden {file_name} create[{idx}] missing name"));
                assert!(
                    !name.is_empty(),
                    "golden {file_name} create[{idx}] name should be non-empty"
                );
            }
            _ => panic!("golden {file_name} operation[{idx}] has unknown kind {kind}"),
        }
    }
}

fn assert_text_contains(text: &str, label: &str, needle: &str) {
    assert!(
        text.contains(needle),
        "{label} should contain legacy fixture contract marker: {needle}"
    );
}

fn validate_legacy_fixture_contract_sources(workspace: &Path) {
    let readme_path = workspace.join("tests/fixtures/README.md");
    let ext4_script_path = workspace.join("scripts/fixtures/make_ext4_fixtures.sh");
    let btrfs_script_path = workspace.join("scripts/fixtures/make_btrfs_fixtures.sh");
    let verify_script_path = workspace.join("scripts/verify_golden.sh");

    let readme = fs::read_to_string(&readme_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", readme_path.display()));
    let ext4_script = fs::read_to_string(&ext4_script_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", ext4_script_path.display()));
    let btrfs_script = fs::read_to_string(&btrfs_script_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", btrfs_script_path.display()));
    let verify_script = fs::read_to_string(&verify_script_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", verify_script_path.display()));

    assert_text_contains(
        &readme,
        "tests/fixtures/README.md",
        "Legacy ext4 inspect JSON files are summary goldens.",
    );
    assert_text_contains(
        &readme,
        "tests/fixtures/README.md",
        "Legacy btrfs inspect JSON files are structural-only goldens.",
    );
    assert_text_contains(
        &verify_script,
        "scripts/verify_golden.sh",
        "legacy summary/structural fixture goldens",
    );

    for profile in LEGACY_EXT4_PROFILES {
        let stem = profile.file_name.trim_end_matches(".json");
        let features = profile.features.join(",");
        assert_text_contains(
            &readme,
            "tests/fixtures/README.md",
            &format!("| {stem} | {} MiB | `{features}`", profile.size_mib),
        );
        assert_text_contains(
            &ext4_script,
            "scripts/fixtures/make_ext4_fixtures.sh",
            &format!(
                "create_image \"{stem}\" {} \"{features}\"",
                profile.size_mib
            ),
        );
    }

    for entry in LEGACY_EXT4_CONTENT_ENTRIES {
        assert_text_contains(&readme, "tests/fixtures/README.md", entry);
    }
    for command in [
        "mkdir dir1",
        "mkdir dir1/dir2",
        "write $tmp_dir/README.txt README.txt",
        "write $tmp_dir/file1.bin dir1/file1.bin",
        "write $tmp_dir/file2.txt dir1/dir2/file2.txt",
        "symlink symlink dir1/file1.bin",
        "bs=256 count=1",
    ] {
        assert_text_contains(
            &ext4_script,
            "scripts/fixtures/make_ext4_fixtures.sh",
            command,
        );
    }

    for profile in LEGACY_BTRFS_PROFILES {
        let stem = profile.file_name.trim_end_matches(".json");
        assert_text_contains(
            &readme,
            "tests/fixtures/README.md",
            &format!("| {stem} | {} MiB | Default", profile.size_mib),
        );
        assert_text_contains(
            &btrfs_script,
            "scripts/fixtures/make_btrfs_fixtures.sh",
            &format!("create_image \"{stem}\" {}", profile.size_mib),
        );
    }
    for command in [
        "WITH_CONTENT=false",
        "mkfs.btrfs -f -L \"$name\"",
        "Skipping content population",
    ] {
        assert_text_contains(
            &btrfs_script,
            "scripts/fixtures/make_btrfs_fixtures.sh",
            command,
        );
    }
}

fn validate_fscrypt_transport_discrepancy_golden(file_name: &str, golden: &Value) {
    assert_eq!(
        golden.get("scenario_id").and_then(Value::as_str),
        Some("ext4_fscrypt_legacy_policy_transport_discrepancy"),
        "golden {file_name} scenario_id should match the fscrypt transport contract"
    );
    assert_eq!(
        golden.get("filesystem").and_then(Value::as_str),
        Some("ext4"),
        "golden {file_name} filesystem should be ext4"
    );
    assert_eq!(
        golden.get("command_hex").and_then(Value::as_str),
        Some("0x400c6615"),
        "golden {file_name} command_hex should freeze the legacy ioctl number"
    );
    assert_eq!(
        golden.get("path").and_then(Value::as_str),
        Some("policy.txt"),
        "golden {file_name} path should freeze the mounted-path target"
    );

    let direct = golden
        .get("direct_dispatch")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("golden {file_name} missing direct_dispatch object"));
    assert_eq!(
        direct.get("expected").and_then(Value::as_str),
        Some("success"),
        "golden {file_name} direct_dispatch.expected should be success"
    );
    assert_eq!(
        direct.get("request_shape").and_then(Value::as_str),
        Some("legacy_iow_in_len_12_out_size_0"),
        "golden {file_name} should freeze the legacy _IOW request shape"
    );
    for field in ["policy_version", "contents_mode", "filenames_mode", "flags"] {
        assert!(
            direct.get(field).and_then(Value::as_u64).is_some(),
            "golden {file_name} direct_dispatch.{field} should be numeric"
        );
    }
    assert_eq!(
        direct
            .get("master_key_descriptor_hex")
            .and_then(Value::as_str),
        Some("6d6b646573633432"),
        "golden {file_name} should freeze the v1 master-key descriptor"
    );

    let mounted = golden
        .get("mounted_path")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("golden {file_name} missing mounted_path object"));
    assert_eq!(
        mounted.get("expected").and_then(Value::as_str),
        Some("transport_eio"),
        "golden {file_name} mounted_path.expected should document the transport-layer EIO"
    );
    assert_eq!(
        mounted.get("errno").and_then(Value::as_i64),
        Some(i64::from(libc::EIO)),
        "golden {file_name} mounted_path.errno should freeze the transport-layer EIO"
    );
    assert_eq!(
        mounted.get("message").and_then(Value::as_str),
        Some("[Errno 5] Input/output error"),
        "golden {file_name} mounted_path.message should freeze the Python ioctl surface"
    );
    assert_eq!(
        mounted.get("trace_contains").and_then(Value::as_str),
        Some("in_len=12 out_size=0"),
        "golden {file_name} mounted_path.trace_contains should freeze the restricted-FUSE request shape"
    );
}

fn validate_legacy_fixture_goldens(workspace: &Path) {
    let golden_dir = workspace.join("tests/fixtures/golden");
    let checksum_inventory = parse_checksum_inventory(&golden_dir.join("checksums.txt"));
    validate_legacy_fixture_contract_sources(workspace);
    let actual_json_files = sorted_names(
        fs::read_dir(&golden_dir)
            .unwrap_or_else(|err| panic!("read legacy golden dir {}: {err}", golden_dir.display()))
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                (path.extension().is_some_and(|ext| ext == "json")).then(|| {
                    entry.file_name().into_string().unwrap_or_else(|_| {
                        panic!("non-utf8 file name in {}", golden_dir.display())
                    })
                })
            }),
    );
    let actual_json_set = actual_json_files.iter().cloned().collect::<HashSet<_>>();
    let checksum_json_set = checksum_inventory.keys().cloned().collect::<HashSet<_>>();

    let missing_from_checksums =
        sorted_names(actual_json_set.difference(&checksum_json_set).cloned());
    assert!(
        missing_from_checksums.is_empty(),
        "tests/fixtures/golden/checksums.txt is missing entries for: {}",
        missing_from_checksums.join(", ")
    );

    let extra_checksum_entries =
        sorted_names(checksum_json_set.difference(&actual_json_set).cloned());
    assert!(
        extra_checksum_entries.is_empty(),
        "tests/fixtures/golden/checksums.txt references missing files: {}",
        extra_checksum_entries.join(", ")
    );

    for file_name in actual_json_files {
        let text = fs::read_to_string(golden_dir.join(&file_name))
            .unwrap_or_else(|err| panic!("legacy golden {file_name} unreadable: {err}"));
        let golden: Value = serde_json::from_str(&text)
            .unwrap_or_else(|err| panic!("legacy golden {file_name} invalid: {err}"));

        if file_name.starts_with("ext4_fast_commit_") {
            validate_fast_commit_fixture_golden(&file_name, &golden);
        } else if file_name.starts_with("ext4_") {
            validate_legacy_ext4_inspect_golden(&file_name, &golden);
        } else if file_name.starts_with("btrfs_") {
            validate_legacy_btrfs_inspect_golden(&file_name, &golden);
        } else {
            panic!("unexpected legacy golden fixture {file_name}");
        }
    }
}

#[test]
fn legacy_fixture_goldens_are_checksum_covered_and_structurally_valid() {
    validate_legacy_fixture_goldens(workspace_root());
}

fn assert_fuzz_corpus_populated(workspace: &Path) {
    let corpus_dir = workspace.join("tests/fuzz_corpus");
    let corpus_count = std::fs::read_dir(&corpus_dir)
        .expect("read fuzz_corpus dir")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "bin"))
        .count();
    assert!(
        corpus_count >= 50,
        "expected >= 50 fuzz corpus samples, found {corpus_count}"
    );
}

fn assert_parity_report_100_percent() {
    let report = ParityReport::current();
    assert_eq!(report.overall_implemented, report.overall_total);
    assert!(
        (report.overall_coverage_percent - 100.0).abs() < f64::EPSILON,
        "overall coverage should be 100%, got {}%",
        report.overall_coverage_percent
    );
    for domain in &report.domains {
        assert_eq!(
            domain.implemented, domain.total,
            "domain '{}' not at 100%: {}/{}",
            domain.domain, domain.implemented, domain.total
        );
    }

    // Deterministic: second run yields identical report.
    let report2 = ParityReport::current();
    assert_eq!(report.overall_implemented, report2.overall_implemented);
    assert_eq!(report.overall_total, report2.overall_total);
    assert_eq!(report.domains.len(), report2.domains.len());
}

#[test]
#[ignore = "stress integration; run explicitly with --ignored"]
fn crash_replay_suite_short_integration() {
    let config = CrashReplaySuiteConfig {
        schedule_count: 20,
        min_operations: 100,
        max_operations: 1000,
        base_seed: 0xFF5E_ED00_0000_0001,
        output_dir: None,
    };
    let report = run_crash_replay_suite(&config).expect("run crash replay suite");
    assert_eq!(report.schedule_count, config.schedule_count);
    assert_eq!(report.failed_schedules, 0);
    assert_eq!(report.passed_schedules, config.schedule_count);
}

#[test]
#[ignore = "stress integration; run explicitly with --ignored"]
fn fsx_stress_short_integration() {
    let config = FsxStressConfig {
        operation_count: 500,
        seed: 0xF5A5_7E55_0000_0001,
        max_file_size_bytes: 8 * 1024 * 1024,
        corruption_every_ops: 100,
        full_verify_every_ops: 100,
        output_dir: None,
    };
    let report = run_fsx_stress(&config).expect("run fsx stress");
    assert!(report.passed, "failure: {:#?}", report.failure);
    assert_eq!(report.operations_executed, config.operation_count);
    assert!(report.failure.is_none());
}
