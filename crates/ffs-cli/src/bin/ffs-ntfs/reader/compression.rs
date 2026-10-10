//! Native compressed DATA mapping: raw units, sparse units, and LZNT1 prefixes.
//! Runs are retained once; neither admission nor reads expand a large sparse
//! file into one heap object per unit. A read stages at most one 64 KiB unit.

use super::{Cx, NtfsGeometry, NtfsRun, Result, Source, buffer, checkpoint, corrupt, parse, unsupported};
use ffs_ondisk::lznt1::decompress_unit;

const UNIT_CLUSTERS: u64 = 16;

#[derive(Debug)]
pub(super) struct CompressedStorage {
    runs: Vec<NtfsRun>,
    unit_bytes: usize,
    mapped_clusters: u64,
}

#[derive(Debug)]
struct Span {
    offset: u64,
    bytes: usize,
}

struct UnitPlan {
    spans: Vec<Span>,
    stored_bytes: usize,
    logical_bytes: usize,
}

impl CompressedStorage {
    /// Called only after the ordinary assembler has checked complete VCN/LCN
    /// coverage, stream sizes, flags, self-aliases and the global run budget.
    pub(super) fn new(geometry: &NtfsGeometry, runs: Vec<NtfsRun>) -> Result<Self> {
        if geometry.cluster_bytes() > 4096 {
            return Err(unsupported("native NTFS compression requires clusters at most 4 KiB"));
        }
        let end = runs.last().map_or(0, |run| run.vcn + run.clusters);
        if !end.is_multiple_of(UNIT_CLUSTERS) {
            let tail_start = end / UNIT_CLUSTERS * UNIT_CLUSTERS;
            if runs.iter().any(|run| run.vcn + run.clusters > tail_start && run.lcn.is_none()) {
                return Err(corrupt(0, "partial final compression unit must contain raw data only"));
            }
        }
        // A physical prefix can be fragmented, but once a unit becomes sparse
        // no later physical cluster may occur until the NEXT unit. Checking
        // transitions rather than enumerating units also bounds huge holes.
        for pair in runs.windows(2) {
            if pair[0].lcn.is_none()
                && pair[1].lcn.is_some()
                && !pair[1].vcn.is_multiple_of(UNIT_CLUSTERS)
            {
                return Err(corrupt(0, "physical cluster follows sparse padding within a compressed unit"));
            }
        }
        Ok(Self {
            runs,
            unit_bytes: geometry.cluster_bytes() as usize * UNIT_CLUSTERS as usize,
            mapped_clusters: end,
        })
    }

    pub(super) fn read_into(
        &self,
        source: &Source,
        geometry: &NtfsGeometry,
        cx: &Cx,
        initialized: u64,
        offset: u64,
        output: &mut [u8],
    ) -> Result<()> {
        checkpoint(cx)?;
        output.fill(0);
        let initialized_count = initialized.saturating_sub(offset).min(output.len() as u64) as usize;
        let mut done = 0;
        while done < initialized_count {
            checkpoint(cx)?;
            let logical = offset + done as u64;
            let unit_start = logical / self.unit_bytes as u64 * self.unit_bytes as u64;
            let within = (logical - unit_start) as usize;
            let count = (initialized_count - done).min(self.unit_bytes - within);
            let plan = self.plan(geometry, cx, unit_start)?;
            let destination = &mut output[done..done + count];
            if plan.stored_bytes == plan.logical_bytes {
                // A fully allocated unit contains literal file bytes, even if
                // its leading bytes happen to look like an LZNT1 header.
                read_spans(source, cx, &plan.spans, within, destination)?;
            } else if plan.stored_bytes != 0 {
                let mut packed = buffer(plan.stored_bytes)?;
                read_spans(source, cx, &plan.spans, 0, &mut packed)?;
                checkpoint(cx)?;
                let decoded = decompress_unit(&packed, self.unit_bytes)
                    .map_err(|error| parse(&error))?;
                checkpoint(cx)?;
                // Validate all initialized bytes in this unit, not just the
                // particular requested prefix. Early termination is corruption,
                // never a reason to synthesize missing initialized data.
                let required = initialized.saturating_sub(unit_start).min(self.unit_bytes as u64) as usize;
                if decoded.len() < required {
                    return Err(corrupt(unit_start, "LZNT1 data ends before the initialized unit boundary"));
                }
                destination.copy_from_slice(&decoded[within..within + count]);
            }
            // Wholly sparse units and bytes beyond ValidDataLength stay zero
            // without issuing data I/O. Sparse suffixes of packed units do NOT
            // represent logical zeroes: the decoder reconstructs those bytes.
            done += count;
        }
        checkpoint(cx)
    }

    fn plan(&self, geometry: &NtfsGeometry, cx: &Cx, unit_start: u64) -> Result<UnitPlan> {
        let cluster_bytes = u64::from(geometry.cluster_bytes());
        let mut vcn = unit_start / cluster_bytes;
        let end = vcn.checked_add(UNIT_CLUSTERS)
            .ok_or_else(|| corrupt(unit_start, "compression-unit VCN overflow"))?
            .min(self.mapped_clusters);
        if vcn >= end {
            return Err(corrupt(unit_start, "compression unit starts beyond mapped data"));
        }
        let logical_bytes = ((end - vcn) * cluster_bytes) as usize;
        let mut index = self.runs.partition_point(|run| run.vcn <= vcn).checked_sub(1)
            .ok_or_else(|| corrupt(unit_start, "missing compression-unit mapping"))?;
        let mut spans = Vec::new();
        let mut stored_bytes = 0;
        let mut sparse = false;
        while vcn < end {
            checkpoint(cx)?;
            let run = self.runs.get(index)
                .ok_or_else(|| corrupt(unit_start, "short compression-unit mapping"))?;
            let run_end = run.vcn.checked_add(run.clusters)
                .ok_or_else(|| corrupt(unit_start, "compression run overflow"))?;
            if vcn < run.vcn || vcn >= run_end {
                return Err(corrupt(unit_start, "gap in compression-unit mapping"));
            }
            let count = run_end.min(end) - vcn;
            if let Some(lcn) = run.lcn {
                if sparse {
                    return Err(corrupt(unit_start, "data follows a compressed unit's sparse suffix"));
                }
                let physical_cluster = lcn.checked_add(vcn - run.vcn)
                    .ok_or_else(|| corrupt(unit_start, "compressed physical offset overflow"))?;
                let offset = geometry.cluster_offset(physical_cluster).map_err(|error| parse(&error))?;
                let bytes = (count * cluster_bytes) as usize;
                spans.push(Span { offset, bytes });
                stored_bytes += bytes;
            } else {
                sparse = true;
            }
            vcn += count;
            index += 1;
        }
        Ok(UnitPlan { spans, stored_bytes, logical_bytes })
    }
}

/// Copy from the concatenation of physical spans. For a raw unit this serves
/// only the requested initialized range; for packed input it gathers the full
/// allocated prefix without reading the sparse suffix or adjacent partitions.
fn read_spans(
    source: &Source,
    cx: &Cx,
    spans: &[Span],
    mut skip: usize,
    output: &mut [u8],
) -> Result<()> {
    let mut done = 0;
    for span in spans {
        checkpoint(cx)?;
        if skip >= span.bytes {
            skip -= span.bytes;
            continue;
        }
        let count = (output.len() - done).min(span.bytes - skip);
        if count != 0 {
            let offset = span.offset.checked_add(skip as u64)
                .ok_or_else(|| corrupt(span.offset, "compressed span offset overflow"))?;
            source.read(cx, offset, &mut output[done..done + count])?;
            done += count;
        }
        skip = 0;
        if done == output.len() {
            break;
        }
    }
    if done != output.len() {
        return Err(corrupt(0, "compressed unit spans do not cover requested bytes"));
    }
    checkpoint(cx)
}

#[cfg(test)]
mod tests;
