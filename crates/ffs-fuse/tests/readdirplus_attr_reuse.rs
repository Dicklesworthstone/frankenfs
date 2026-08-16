//! bd-q0xnl acceptance: readdirplus must not re-derive attributes per entry.
//!
//! The worst vs-incumbent row (btrfs readdir+stat, 7.728937x) was measured to be
//! DAEMON-WORK-bound rather than round-trip-bound: forcing readdirplus cuts real
//! FUSE boundary crossings by ~33% and wall moved +0.1%. The cost that actually
//! binds is `ops.getattr` per entry, which the readdirplus handler pays once per
//! entry per readdir — measured at `20106` getattr for 20001 entries even when the
//! client never stats anything (`ls -U`), against `197` under AUTO. Two `ls -lU`
//! passes in one mount cost `60212` getattr forced vs `20394` under AUTO, i.e.
//! 2.95x the daemon work for identical output, because the handler re-derives
//! attributes the kernel already holds in a valid cache.
//!
//! The lever is to serve those attributes from what the readdir walk already
//! materialised instead of issuing a fresh `ops.getattr` per entry.
//!
//! # Why this test is `#[ignore]`d
//!
//! It asserts the POST-lever shape and therefore FAILS on today's code, which is
//! the point: it is the acceptance criterion, written before the fix so the fix
//! has a definition it cannot drift from. Remove the `#[ignore]` in the same
//! commit that lands the lever. It is deliberately NOT written to assert today's
//! behaviour — a test that pins the defect would have to be rewritten to land the
//! fix, which is how acceptance criteria quietly become whatever was implemented.
//!
//! Run it with:
//!   cargo test -p ffs-fuse --test readdirplus_attr_reuse -- --ignored

const LIB_RS: &str = include_str!("../src/lib.rs");

/// Extract the body of the `readdirplus` handler.
///
/// Structural rather than behavioural because exercising readdirplus needs a real
/// FUSE mount plus a fixture image, which cannot run in the ordinary unit gate —
/// the same reason the silent-zero metrics defect (bd-viil0) went unnoticed. The
/// counted evidence for the cost lives in `scripts/fuse_readdirplus_work_ab.sh`;
/// this only pins that the per-entry call site is gone from the source.
fn readdirplus_body() -> &'static str {
    let after = LIB_RS
        .split_once("fn readdirplus(")
        .expect("readdirplus handler must exist")
        .1;
    // Stop at the next top-level `fn ` at the same indentation, so we do not read
    // into neighbouring handlers.
    match after.find("\n    fn ") {
        Some(end) => &after[..end],
        None => after,
    }
}

/// The lever: no fresh `ops.getattr` inside the per-entry loop of readdirplus.
#[test]
#[ignore = "bd-q0xnl acceptance: fails until the readdirplus attr-reuse lever lands"]
fn readdirplus_does_not_call_ops_getattr_per_entry_bd_q0xnl() {
    let body = readdirplus_body();
    assert!(
        !body.contains("ops.getattr("),
        "readdirplus still issues a fresh ops.getattr per entry. Measured cost of \
         this call site: 20106 getattr for 20001 entries even when the client never \
         stats (ls -U), and 60212 vs 20394 getattr across two ls -lU passes -- 2.95x \
         the daemon work for identical output, on the row with the worst \
         vs-incumbent ratio in the campaign. Serve the attributes from what the \
         readdir walk already materialised instead."
    );
}

/// Guard against the cheapest wrong way to satisfy the test above: dropping
/// attributes from the reply entirely. That would turn readdirplus into readdir
/// with extra steps, and the kernel would issue a lookup per entry again --
/// trading the daemon-work cost straight back for the crossing cost the same
/// measurement showed is NOT what binds.
#[test]
#[ignore = "bd-q0xnl acceptance: paired with the test above; enable together"]
fn readdirplus_still_supplies_attributes_and_a_ttl_bd_q0xnl() {
    let body = readdirplus_body();
    assert!(
        body.contains("ATTR_TTL"),
        "readdirplus must still hand the kernel a TTL with each entry; without it \
         the kernel re-looks-up every entry and the lever has moved cost rather \
         than removed it"
    );
    assert!(
        body.contains("reply.add("),
        "readdirplus must still add entries to the reply"
    );
}
