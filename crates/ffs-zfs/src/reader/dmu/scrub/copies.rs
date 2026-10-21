//! Fresh physical-copy audit after the ordinary DMU reader validates a pointer.
//!
//! Never use recovery success to certify the copies it did not read. Every
//! ordinary DVA, supplied replica and active RAIDZ column is checked separately.
//! P/Q/R equations follow OpenZFS zfs-2.3.0 module/zfs/vdev_raidz.c's mathematical
//! description; no native implementation code is reused. A parity mismatch does
//! not identify which physical sector is wrong (padding is not checksummed).

use super::super::super::pool::raidz::NativeMap;
use super::{BlockPointer, Cx, FfsError, Objects, Result, checkpoint, corrupt, unsupported};
use crate::reader::{DATA_OFFSET, RaidzGroup};
use ffs_ondisk::zfs::gang::{GangHeader, HEADER_BYTES};

const MAX_POINTER_FAULTS: usize = 128;

#[derive(Default)]
pub(super) struct Audit {
    pub work_bytes: u64,
    pub copies: u64,
    pub columns: u64,
    pub parity_checked: u64,
    pub parity_unverified: u64,
    pub faults: Vec<FfsError>,
}

struct Replica {
    member: usize,
    copy: usize,
    offset: u64,
}

enum Plan {
    Replicas(Vec<Replica>),
    Stripes(Vec<NativeMap>),
}

/// Gang headers describe fragments of an already transformed stream. Their
/// embedded identity checksum is NOT the owning block's payload checksum.
struct Contents<'a> {
    pointer: &'a BlockPointer,
    header: Option<&'a GangHeader>,
    header_allocations: &'a [u64],
}

impl Contents<'_> {
    fn physical_bytes(&self) -> usize {
        if self.header.is_some() { HEADER_BYTES } else { self.pointer.physical_bytes() }
    }

    fn decoded_bytes(&self) -> usize {
        if self.header.is_some() { HEADER_BYTES } else { self.pointer.logical_bytes() }
    }

    fn verify(&self, bytes: &[u8]) -> Result<()> {
        if let Some(expected) = self.header {
            let actual = GangHeader::parse(bytes, self.pointer, self.header_allocations)
                .map_err(|error| super::parse(&error))?;
            // An embedded checksum binds identity, not the unique contents
            // of that identity. Valid-but-divergent replicas must not choose
            // different fragment graphs during the same audit.
            if actual.children() != expected.children() {
                return Err(corrupt("gang header replica disagrees with the admitted fragment graph"));
            }
        } else {
            self.pointer.decode(bytes).map_err(|error| super::parse(&error))?;
        }
        Ok(())
    }
}

fn add_work(total: &mut u64, bytes: u64) -> Result<()> {
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| corrupt("redundancy audit work overflows"))?;
    Ok(())
}

/// Internal caller contract: the ordinary checked DMU path has already
/// admitted this exact pointer, immutable topology and all its declared DVAs.
/// Its cache is keyed by the complete pointer. This routine never replaces
/// that admission and never supplies traversal bytes to the walker.
fn plan(view: &Objects, contents: &Contents<'_>) -> Result<(Plan, u64)> {
    let bp = contents.pointer;
    if bp.gang() != contents.header.is_some() {
        return Err(corrupt("gang audit pointer/header identity disagrees"));
    }
    let dvas = if bp.gang() {
        bp.gang_dvas(contents.header_allocations)
    } else {
        bp.regular_dvas()
    }.map_err(|error| super::parse(&error))?;
    let mut work = 0_u64;
    if let Some(group) = &view.config.raidz_members
        && group.parity != 0
    {
        let mut maps = Vec::with_capacity(dvas.len());
        for dva in dvas {
            let map = NativeMap::new(
                dva.offset,
                contents.physical_bytes(),
                view.config.ashift,
                group.members.len(),
                group.parity,
            )?;
            // Count reads, assembly, decode, and a conservative bound on all
            // byte-wise parity multiply/XOR work, before issuing any audit I/O.
            for column in map.columns() {
                add_work(&mut work, column.bytes as u64)?;
            }
            add_work(&mut work, map.allocated_bytes())?;
            add_work(&mut work, contents.decoded_bytes() as u64)?;
            for column in &map.columns()[..group.parity] {
                let operations = (column.bytes as u64)
                    .checked_mul(group.members.len() as u64)
                    .and_then(|bytes| bytes.checked_mul(3))
                    .ok_or_else(|| corrupt("RAIDZ parity audit work overflows"))?;
                add_work(&mut work, operations)?;
            }
            maps.push(map);
        }
        return Ok((Plan::Stripes(maps), work));
    }
    let mut replicas = Vec::new();
    for (copy, dva) in dvas.iter().enumerate() {
        let offset = DATA_OFFSET
            .checked_add(dva.offset)
            .ok_or_else(|| corrupt("replica audit offset overflows"))?;
        if let Some(group) = &view.config.raidz_members {
            let member = group
                .members
                .get(dva.vdev as usize)
                .ok_or_else(|| corrupt("audit DVA has no admitted striped vdev"))?
                .supplied_index;
            replicas.push(Replica { member, copy, offset });
        } else {
            for member in 0..view.pool.leaves().len() {
                replicas.push(Replica { member, copy, offset });
            }
        }
    }
    for _ in &replicas {
        add_work(&mut work, contents.physical_bytes() as u64)?;
        add_work(&mut work, contents.decoded_bytes() as u64)?;
    }
    Ok((Plan::Replicas(replicas), work))
}

fn fault(audit: &mut Audit, location: &str, error: FfsError) -> Result<()> {
    if matches!(error, FfsError::Cancelled) {
        return Err(FfsError::Cancelled);
    }
    // A gang tree can contain many nodes. Bound the per-DMU-pointer ledger
    // before it reaches the walker's separate issue cap. An explicit coverage
    // error ensures an early stop can never masquerade as an intact tree.
    if audit.faults.len() >= MAX_POINTER_FAULTS {
        if audit.faults.len() == MAX_POINTER_FAULTS {
            audit.faults.push(unsupported(
                "gang audit diagnostic budget reached; remaining copies are not fully checked",
            ));
        }
        return Ok(());
    }
    let detail = format!("{location}: {error}");
    audit.faults.push(match error {
        FfsError::Io(error) => FfsError::Io(std::io::Error::new(error.kind(), detail)),
        FfsError::UnsupportedFeature(_) => unsupported(detail),
        _ => corrupt(detail),
    });
    Ok(())
}

pub(super) fn verify(
    cx: &Cx,
    view: &Objects,
    bp: &BlockPointer,
    remaining_work: u64,
) -> Result<Option<Audit>> {
    checkpoint(cx)?;
    if bp.gang() {
        let work_bytes = view.pool.gang_audit_work(&view.config, bp)?;
        if work_bytes > remaining_work {
            return Ok(None);
        }
        let mut audit = Audit { work_bytes, ..Audit::default() };
        let mut planned_work = 0;
        let result = view.pool.visit_gang_audit(cx, &view.config, bp, |pointer, header, allocations| {
            let contents = Contents { pointer, header, header_allocations: allocations };
            let (node_plan, node_work) = plan(view, &contents)?;
            add_work(&mut planned_work, node_work)?;
            // Keep at least half of the reservation for manifest acquisition.
            // Aggregate ASIZE bounds the complete validated manifest, not a
            // contiguous read beginning at the leader's first header.
            if planned_work > work_bytes / 2 {
                return Err(corrupt("gang audit plan exceeds its reserved work envelope"));
            }
            audit_plan(cx, view, &contents, node_plan, &mut audit)?;
            Ok(audit.faults.len() <= MAX_POINTER_FAULTS)
        });
        if let Err(error) = result {
            fault(&mut audit, "gang tree audit", error)?;
        }
        checkpoint(cx)?;
        return Ok(Some(audit));
    }
    let contents = Contents { pointer: bp, header: None, header_allocations: &[] };
    let (plan, work_bytes) = plan(view, &contents)?;
    if work_bytes > remaining_work {
        return Ok(None);
    }
    let mut audit = Audit { work_bytes, ..Audit::default() };
    audit_plan(cx, view, &contents, plan, &mut audit)?;
    checkpoint(cx)?;
    Ok(Some(audit))
}

fn audit_plan(
    cx: &Cx,
    view: &Objects,
    contents: &Contents<'_>,
    plan: Plan,
    audit: &mut Audit,
) -> Result<()> {
    match plan {
        Plan::Replicas(replicas) => {
            for replica in replicas {
                checkpoint(cx)?;
                let member = view.pool.leaves().get(replica.member)
                    .ok_or_else(|| corrupt("audit replica has no supplied member"))?;
                audit.copies += 1;
                let result = member.read(cx, replica.offset, contents.physical_bytes())
                    .and_then(|bytes| contents.verify(&bytes));
                if let Err(error) = result {
                    fault(audit, &format!("DVA {}, supplied member {}, offset {}",
                        replica.copy, replica.member, replica.offset), error)?;
                }
            }
        }
        Plan::Stripes(maps) => {
            let group = view.config.raidz_members.as_ref()
                .ok_or_else(|| corrupt("RAIDZ audit lost its admitted mapping"))?;
            for (copy, map) in maps.iter().enumerate() {
                checkpoint(cx)?;
                audit_stripe(cx, view, contents, group, map, copy, audit)?;
            }
        }
    }
    checkpoint(cx)
}

fn audit_stripe(
    cx: &Cx,
    view: &Objects,
    contents: &Contents<'_>,
    group: &RaidzGroup,
    map: &NativeMap,
    copy: usize,
    audit: &mut Audit,
) -> Result<()> {
    audit.copies += 1;
    let mut columns: Vec<Option<Vec<u8>>> = Vec::with_capacity(map.columns().len());
    for column in map.columns() {
        checkpoint(cx)?;
        if column.bytes == 0 {
            columns.push(None);
            continue;
        }
        audit.columns += 1;
        let member = group.members.get(column.child_id)
            .ok_or_else(|| corrupt("audit column has no native child"))?;
        let offset = DATA_OFFSET.checked_add(column.offset)
            .ok_or_else(|| corrupt("audit column address overflows"))?;
        let result = match view.pool.leaves().get(member.supplied_index) {
            Some(leaf) => leaf.read(cx, offset, column.bytes),
            None => Err(corrupt(format!("absent RAIDZ child GUID {}", member.guid))),
        };
        match result {
            Ok(bytes) => columns.push(Some(bytes)),
            Err(error) => {
                fault(audit, &format!("DVA {copy}, RAIDZ child {}, GUID {}, offset {offset}",
                    column.child_id, member.guid), error)?;
                columns.push(None);
            }
        }
    }
    let slices: Vec<_> = columns.iter().map(Option::as_deref).collect();
    // Verify the actual data columns, not reconstructed substitutes. A healthy
    // read elsewhere cannot validate these data/parity equations. When data is
    // missing or bad, retain the precise read errors and mark parity unverified.
    let data = map.assemble(&slices, &[])
        .and_then(|bytes| contents.verify(&bytes));
    if let Err(error) = data {
        fault(audit, &format!("DVA {copy}, unreconstructed RAIDZ data"), error)?;
        audit.parity_unverified += group.parity as u64;
        return Ok(());
    }
    for parity in 0..group.parity {
        checkpoint(cx)?;
        let Some(actual) = columns[parity].as_deref() else {
            audit.parity_unverified += 1;
            continue;
        };
        audit.parity_checked += 1;
        if !parity_matches(cx, &slices[group.parity..], actual, parity)? {
            let child = map.columns()[parity].child_id;
            fault(audit, &format!("DVA {copy}, parity equation {parity}, child {child}"),
                corrupt("mismatch against checksum-valid data; parity or unchecked padding may be damaged"))?;
        }
    }
    checkpoint(cx)
}

/// Horner evaluation of P/Q/R over each padded stripe byte. Short columns
/// contribute zero after their length; skip-only columns are not terms.
fn parity_matches(cx: &Cx, data: &[Option<&[u8]>], actual: &[u8], row: usize) -> Result<bool> {
    for (offset, &expected) in actual.iter().enumerate() {
        if offset.is_multiple_of(4096) {
            checkpoint(cx)?;
        }
        let mut value = 0_u8;
        for bytes in data.iter().flatten() {
            for _ in 0..row {
                value = value.wrapping_shl(1) ^ if value & 0x80 == 0 { 0 } else { 0x1D };
            }
            value ^= bytes.get(offset).copied().unwrap_or(0);
        }
        if value != expected {
            return Ok(false);
        }
    }
    checkpoint(cx)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod gang;

    #[test]
    fn parity_equations_cover_high_bits_unequal_lengths_and_independent_gf_products() {
        fn product(mut a: u16, mut b: u16) -> u8 {
            let mut result = 0_u16;
            while b != 0 {
                if b & 1 != 0 { result ^= a; }
                a <<= 1;
                if a & 0x100 != 0 { a ^= 0x11D; }
                b >>= 1;
            }
            u8::try_from(result).unwrap()
        }
        let cx = Cx::for_testing();
        for width in 1..=7 {
            let data: Vec<Vec<u8>> = (0..width).map(|column| {
                (0..257 - column * 17).map(|byte| ((byte * 19 + column * 113) % 256) as u8).collect()
            }).collect();
            let mut slices: Vec<_> = data.iter().map(|bytes| Some(bytes.as_slice())).collect();
            slices.push(None); // native skip-only column has no polynomial term
            for row in 0..3 {
                let mut expected = vec![0; 257];
                for (column, bytes) in data.iter().enumerate() {
                    let mut coefficient = 1_u8;
                    for _ in 0..(width - column - 1) * row {
                        coefficient = product(u16::from(coefficient), 2);
                    }
                    for (at, &byte) in bytes.iter().enumerate() {
                        expected[at] ^= product(u16::from(byte), u16::from(coefficient));
                    }
                }
                assert!(parity_matches(&cx, &slices, &expected, row).unwrap());
                for at in [0, 128, 256] {
                    expected[at] ^= 1;
                    assert!(!parity_matches(&cx, &slices, &expected, row).unwrap());
                    expected[at] ^= 1;
                }
            }
        }
    }

    #[test]
    fn parity_verification_preserves_cancellation() {
        let cx = Cx::for_testing();
        cx.cancel_with(asupersync::types::CancelKind::User, Some("parity audit"));
        assert!(matches!(parity_matches(&cx, &[Some(&[0x80])], &[0x1D], 1), Err(FfsError::Cancelled)));
    }
}
