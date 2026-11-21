//! Transactional `$Secure` (Record 9) manager: `$SDS` dual-stripe mirror appends
//! (`SDS_COPY_DISTANCE = 256 KiB`), `$SII` (`0x10`) and `$SDH` (`0x12`) view-index
//! updates, hash-verified deduplication, and MS-DTYP security inheritance.

use std::collections::BTreeMap;

use asupersync::Cx;
use ffs_error::Result;
use ffs_ondisk::ntfs::view_index::ViewCollation;
use ffs_ondisk::ntfs::{DATA, NtfsGeometry, NtfsRun};
use ffs_ondisk::ntfs_security::{
    NtfsSecurityDescriptor, NtfsSecurityHeader, SDS_COPY_DISTANCE, SDS_HEADER_BYTES,
    encode_sds_entry, next_sds_primary_offset, security_hash,
};

use super::catalog::{
    EditableCatalog, EditableDataStream, EditableStreamStorage, coalesce_physical_spans,
    normalize_ntfs_runs, physical_spans_of_runs, stage_runs_writes,
};
use super::dir_index::DirPrePayloadWrite;
use super::view_index::{EditableViewIndex, ViewRawEntry, rebalance_view_index_tree};
use super::{NtfsTransactionEngine, checkpoint, corrupt, parse_err, read_mapped_runs, unsupported};

pub(super) const SII_NAME: [u16; 4] = [36, 83, 73, 73]; // $SII
pub(super) const SDH_NAME: [u16; 4] = [36, 83, 68, 72]; // $SDH
pub(super) const SDS_NAME: [u16; 4] = [36, 83, 68, 83]; // $SDS

/// In-transaction mutable state for Record 9 (`$Secure`).
pub(super) struct SecureStoreState {
    pub(super) sii_entries: Vec<ViewRawEntry>,
    pub(super) sdh_entries: Vec<ViewRawEntry>,
    pub(super) sds_runs: Vec<NtfsRun>,
    pub(super) sds_data_bytes: u64,
    pub(super) sds_init_bytes: u64,
    /// Staged descriptor bytes written within this transaction (`primary_offset -> descriptor`).
    staged_descriptors: BTreeMap<u64, Vec<u8>>,
    next_security_id: u32,
    primary_tail_end: u64,
    pub(super) modified: bool,
}

fn encode_header_20(h: NtfsSecurityHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&h.hash.to_le_bytes());
    out.extend_from_slice(&h.security_id.to_le_bytes());
    out.extend_from_slice(&h.offset.to_le_bytes());
    out.extend_from_slice(&h.length.to_le_bytes());
    out
}

impl SecureStoreState {
    /// Load `$Secure` (Record 9) `$SII`, `$SDH`, and `$SDS` into an editable state.
    pub(super) fn load(
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        secure_cat: &EditableCatalog,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let sii_view = secure_cat
            .view_indexes
            .iter()
            .find(|v| v.index_name == SII_NAME)
            .ok_or_else(|| corrupt(0, "$Secure missing $SII view index"))?;
        let sdh_view = secure_cat
            .view_indexes
            .iter()
            .find(|v| v.index_name == SDH_NAME)
            .ok_or_else(|| corrupt(0, "$Secure missing $SDH view index"))?;
        let sds_stream = secure_cat
            .data_streams
            .iter()
            .find(|s| s.name == SDS_NAME)
            .ok_or_else(|| corrupt(0, "$Secure missing $SDS data stream"))?;

        let (sds_runs, sds_data_bytes, sds_init_bytes) = match &sds_stream.storage {
            EditableStreamStorage::NonResident {
                runs,
                sparse,
                compressed,
                encrypted,
                data_bytes,
                initialized_bytes,
                ..
            } => {
                if *sparse || *compressed || *encrypted {
                    return Err(unsupported("$Secure:$SDS must be plain non-resident"));
                }
                (runs.clone(), *data_bytes, *initialized_bytes)
            }
            EditableStreamStorage::Resident(_) => {
                return Err(corrupt(0, "$Secure:$SDS must be non-resident"));
            }
        };

        let sii_entries = engine.collect_view_index_entries(cx, sii_view)?;
        let sdh_entries = engine.collect_view_index_entries(cx, sdh_view)?;

        let mut max_id: u32 = 255;
        let mut max_primary_end: u64 = 0;
        for entry in &sii_entries {
            if entry.key.len() != 4 || entry.data.len() != 20 {
                return Err(corrupt(0, "invalid $Secure:$SII entry dimensions"));
            }
            let hdr = NtfsSecurityHeader::parse(&entry.data).map_err(|err| parse_err(&err))?;
            max_id = max_id.max(hdr.security_id);
            let end = hdr
                .offset
                .checked_add(u64::from(hdr.length))
                .ok_or_else(|| corrupt(0, "$SDS header offset overflow"))?
                .next_multiple_of(16);
            max_primary_end = max_primary_end.max(end);
        }

        Ok(Self {
            sii_entries,
            sdh_entries,
            sds_runs,
            sds_data_bytes,
            sds_init_bytes,
            staged_descriptors: BTreeMap::new(),
            next_security_id: max_id
                .checked_add(1)
                .ok_or_else(|| corrupt(0, "$Secure security_id exhausted u32"))?,
            primary_tail_end: max_primary_end,
            modified: false,
        })
    }

    /// Resolve a `security_id` from `$SII` + `$SDS`, returning its validated descriptor bytes.
    pub(super) fn read_descriptor_by_id(
        &self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        security_id: u32,
    ) -> Result<Vec<u8>> {
        let key = security_id.to_le_bytes();
        let entry = self
            .sii_entries
            .iter()
            .find(|e| e.key.as_slice() == key)
            .ok_or_else(|| corrupt(0, "security_id missing from $Secure:$SII"))?;
        let header = NtfsSecurityHeader::parse(&entry.data).map_err(|err| parse_err(&err))?;
        self.read_descriptor_by_header(engine, cx, header)
    }

    fn read_descriptor_by_header(
        &self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        header: NtfsSecurityHeader,
    ) -> Result<Vec<u8>> {
        if let Some(staged) = self.staged_descriptors.get(&header.offset) {
            return Ok(staged.clone());
        }
        let len = header.length as usize;
        let mirror_off = header.offset + SDS_COPY_DISTANCE;
        if mirror_off + u64::from(header.length) > self.sds_init_bytes {
            return Err(corrupt(
                header.offset,
                "$Secure:$SDS mirror entry lies beyond initialized_bytes",
            ));
        }
        let primary = read_mapped_runs(
            &engine.device,
            cx,
            &engine.geometry,
            &self.sds_runs,
            header.offset,
            len,
        )?;
        let mirror = read_mapped_runs(
            &engine.device,
            cx,
            &engine.geometry,
            &self.sds_runs,
            mirror_off,
            len,
        )?;
        if primary != mirror {
            return Err(corrupt(
                header.offset,
                "$Secure:$SDS primary and mirror copies disagree",
            ));
        }
        let desc = header.descriptor(&primary).map_err(|err| parse_err(&err))?;
        Ok(desc.to_vec())
    }

    /// Intern `descriptor_bytes` in `$Secure`, reusing an existing `security_id`
    /// when a byte-identical descriptor already exists in `$SDH`/`$SDS`, or allocating
    /// a fresh `security_id` and staging primary + `+256 KiB` mirror writes via COW.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn intern_descriptor<FAlloc>(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        descriptor_bytes: &[u8],
        pre_payload_writes: &mut Vec<DirPrePayloadWrite>,
        freed_clusters: &mut Vec<(u64, u64)>,
        mut alloc_clusters: FAlloc,
    ) -> Result<u32>
    where
        FAlloc: FnMut(u64) -> Result<Vec<(u64, u64)>>,
    {
        checkpoint(cx)?;
        let _ = NtfsSecurityDescriptor::parse(descriptor_bytes).map_err(|err| parse_err(&err))?;
        let hash = security_hash(descriptor_bytes);
        let hash_prefix = hash.to_le_bytes();

        // Deduplicate against all existing descriptors with matching 32-bit hash.
        for sdh in &self.sdh_entries {
            if sdh.key.len() == 8 && sdh.key[0..4] == hash_prefix {
                let hdr = NtfsSecurityHeader::parse(&sdh.data).map_err(|err| parse_err(&err))?;
                if usize::try_from(hdr.length).ok()
                    == Some(SDS_HEADER_BYTES + descriptor_bytes.len())
                {
                    let existing = self.read_descriptor_by_header(engine, cx, hdr)?;
                    if existing == descriptor_bytes {
                        return Ok(hdr.security_id);
                    }
                }
            }
        }

        let entry_len = u32::try_from(SDS_HEADER_BYTES + descriptor_bytes.len())
            .map_err(|_| corrupt(0, "$SDS entry length overflow"))?;
        let primary_off = next_sds_primary_offset(self.primary_tail_end, entry_len)
            .map_err(|err| parse_err(&err))?;
        let mirror_off = primary_off
            .checked_add(SDS_COPY_DISTANCE)
            .ok_or_else(|| corrupt(0, "$SDS mirror offset overflow"))?;

        let new_id = self.next_security_id;
        self.next_security_id = self
            .next_security_id
            .checked_add(1)
            .ok_or_else(|| corrupt(0, "$Secure security_id overflow"))?;

        let header = NtfsSecurityHeader {
            hash,
            security_id: new_id,
            offset: primary_off,
            length: entry_len,
        };
        let encoded_entry =
            encode_sds_entry(header, descriptor_bytes).map_err(|err| parse_err(&err))?;

        // Stage BOTH primary and mirror writes via COW into `self.sds_runs`, keeping
        // `$SDS` plain (non-sparse) and fully initialized up through `mirror_off + encoded_entry.len()`.
        self.cow_write_sds_patches(
            engine,
            cx,
            &[(primary_off, &encoded_entry), (mirror_off, &encoded_entry)],
            pre_payload_writes,
            freed_clusters,
            &mut alloc_clusters,
        )?;

        let header_20 = encode_header_20(header);
        self.sii_entries.push(ViewRawEntry {
            key: new_id.to_le_bytes().to_vec(),
            data: header_20.clone(),
        });
        let mut sdh_key = Vec::with_capacity(8);
        sdh_key.extend_from_slice(&hash.to_le_bytes());
        sdh_key.extend_from_slice(&new_id.to_le_bytes());
        self.sdh_entries.push(ViewRawEntry {
            key: sdh_key,
            data: header_20,
        });
        self.staged_descriptors
            .insert(primary_off, descriptor_bytes.to_vec());
        self.primary_tail_end = primary_off + encoded_entry.len() as u64;
        self.modified = true;
        Ok(new_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn cow_write_sds_patches<FAlloc>(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        patches: &[(u64, &[u8])],
        pre_payload_writes: &mut Vec<DirPrePayloadWrite>,
        freed_clusters: &mut Vec<(u64, u64)>,
        alloc_clusters: &mut FAlloc,
    ) -> Result<()>
    where
        FAlloc: FnMut(u64) -> Result<Vec<(u64, u64)>>,
    {
        let cb = u64::from(engine.geometry.cluster_bytes());
        let old_total_vcns: u64 = self.sds_runs.iter().map(|r| r.clusters).sum();
        let max_end = patches
            .iter()
            .map(|(off, bytes)| *off + bytes.len() as u64)
            .max()
            .unwrap_or(self.sds_data_bytes)
            .max(self.sds_data_bytes);
        let target_vcns = max_end.div_ceil(cb);

        // Identify the distinct cluster VCNs we must COW-write (both patched clusters and
        // any newly extended gap clusters in `[old_total_vcns .. target_vcns)`).
        let mut dirty_vcns: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for vcn in old_total_vcns..target_vcns {
            dirty_vcns.insert(vcn, vec![0_u8; cb as usize]);
        }
        for &(off, bytes) in patches {
            let start_vcn = off / cb;
            let end_vcn = (off + bytes.len() as u64).div_ceil(cb);
            for vcn in start_vcn..end_vcn {
                let cluster_buf = match dirty_vcns.entry(vcn) {
                    std::collections::btree_map::Entry::Occupied(o) => o.into_mut(),
                    std::collections::btree_map::Entry::Vacant(v) => {
                        let byte_off = vcn * cb;
                        let mut existing = vec![0_u8; cb as usize];
                        if byte_off < self.sds_init_bytes {
                            let to_read = (self.sds_init_bytes - byte_off).min(cb) as usize;
                            let raw = read_mapped_runs(
                                &engine.device,
                                cx,
                                &engine.geometry,
                                &self.sds_runs,
                                byte_off,
                                to_read,
                            )?;
                            existing[..to_read].copy_from_slice(&raw);
                        }
                        v.insert(existing)
                    }
                };
                let c_start = vcn * cb;
                let c_end = c_start + cb;
                let ov_start = off.max(c_start);
                let ov_end = (off + bytes.len() as u64).min(c_end);
                if ov_start < ov_end {
                    let dst_off = (ov_start - c_start) as usize;
                    let src_off = (ov_start - off) as usize;
                    let cnt = (ov_end - ov_start) as usize;
                    cluster_buf[dst_off..dst_off + cnt]
                        .copy_from_slice(&bytes[src_off..src_off + cnt]);
                }
            }
        }

        // Group contiguous dirty VCN runs so allocation stays compact.
        let mut intervals: Vec<(u64, Vec<u8>)> = Vec::new();
        for (vcn, buf) in dirty_vcns {
            if let Some(last) = intervals.last_mut()
                && last.0 + (last.1.len() as u64 / cb) == vcn
            {
                last.1.extend_from_slice(&buf);
            } else {
                intervals.push((vcn, buf));
            }
        }

        // Apply each contiguous dirty VCN interval via COW splice.
        for (start_vcn, combined_bytes) in intervals {
            let cnt = (combined_bytes.len() as u64) / cb;
            let spans = alloc_clusters(cnt)?;
            let mut stage_runs = Vec::with_capacity(spans.len());
            let mut sv = 0_u64;
            for &(lcn, scnt) in &spans {
                stage_runs.push(NtfsRun {
                    vcn: sv,
                    clusters: scnt,
                    lcn: Some(lcn),
                });
                sv += scnt;
            }
            stage_runs_writes(
                &engine.geometry,
                &stage_runs,
                &combined_bytes,
                pre_payload_writes,
            )?;

            let end_vcn = start_vcn + cnt;
            let mut next_runs = Vec::new();
            let mut displaced = Vec::new();
            for run in &self.sds_runs {
                let r_start = run.vcn;
                let r_end = run.vcn + run.clusters;
                if r_start < start_vcn {
                    next_runs.push(NtfsRun {
                        vcn: r_start,
                        clusters: r_end.min(start_vcn) - r_start,
                        lcn: run.lcn,
                    });
                }
                let ov_start = r_start.max(start_vcn);
                let ov_end = r_end.min(end_vcn);
                if ov_start < ov_end
                    && let Some(base_lcn) = run.lcn
                {
                    displaced.push((base_lcn + (ov_start - r_start), ov_end - ov_start));
                }
                if r_end > end_vcn {
                    let tail_start = r_start.max(end_vcn);
                    next_runs.push(NtfsRun {
                        vcn: tail_start,
                        clusters: r_end - tail_start,
                        lcn: run.lcn.map(|b| b + (tail_start - r_start)),
                    });
                }
            }
            let mut ins_vcn = start_vcn;
            for &(lcn, scnt) in &spans {
                next_runs.push(NtfsRun {
                    vcn: ins_vcn,
                    clusters: scnt,
                    lcn: Some(lcn),
                });
                ins_vcn += scnt;
            }
            next_runs.sort_unstable_by_key(|r| r.vcn);
            self.sds_runs = normalize_ntfs_runs(next_runs);
            freed_clusters.extend(coalesce_physical_spans(displaced));
        }

        self.sds_data_bytes = max_end;
        self.sds_init_bytes = max_end;
        Ok(())
    }

    /// Rebalance `$SII` and `$SDH` and write back `$SII`, `$SDH`, and `$SDS` into
    /// `$Secure`'s [`EditableCatalog`].
    pub(super) fn flush_into_catalog<FAlloc>(
        self,
        geometry: &NtfsGeometry,
        secure_cat: &mut EditableCatalog,
        max_root_value_bytes: usize,
        pre_payload_writes: &mut Vec<DirPrePayloadWrite>,
        freed_clusters: &mut Vec<(u64, u64)>,
        mut alloc_clusters: FAlloc,
    ) -> Result<()>
    where
        FAlloc: FnMut(u64, u64) -> Result<Vec<(u64, u64)>>,
    {
        if !self.modified {
            return Ok(());
        }
        // Free old external INDX clusters for $SII and $SDH before replacing them.
        for view in &secure_cat.view_indexes {
            if (view.index_name == SII_NAME || view.index_name == SDH_NAME)
                && let Some((ref a0_runs, _, _)) = view.external
            {
                freed_clusters.extend(physical_spans_of_runs(a0_runs));
            }
        }
        let reb_sii = rebalance_view_index_tree(
            geometry,
            &SII_NAME,
            ViewCollation::U32,
            self.sii_entries,
            max_root_value_bytes,
            &mut alloc_clusters,
        )?;
        let reb_sdh = rebalance_view_index_tree(
            geometry,
            &SDH_NAME,
            ViewCollation::U32Pair,
            self.sdh_entries,
            max_root_value_bytes,
            &mut alloc_clusters,
        )?;
        pre_payload_writes.extend(reb_sii.pre_payload_writes);
        pre_payload_writes.extend(reb_sdh.pre_payload_writes);

        replace_or_push_view_index(&mut secure_cat.view_indexes, reb_sii.view_index);
        replace_or_push_view_index(&mut secure_cat.view_indexes, reb_sdh.view_index);

        let new_sds = EditableDataStream {
            name: SDS_NAME.to_vec(),
            storage: EditableStreamStorage::NonResident {
                runs: self.sds_runs,
                sparse: false,
                compressed: false,
                encrypted: false,
                compression_unit: 0,
                data_bytes: self.sds_data_bytes,
                initialized_bytes: self.sds_init_bytes,
            },
        };
        if let Some(slot) = secure_cat
            .data_streams
            .iter_mut()
            .find(|s| s.name == SDS_NAME)
        {
            *slot = new_sds;
        } else {
            secure_cat.data_streams.push(new_sds);
        }
        let _ = DATA;
        Ok(())
    }
}

fn replace_or_push_view_index(list: &mut Vec<EditableViewIndex>, replacement: EditableViewIndex) {
    if let Some(existing) = list
        .iter_mut()
        .find(|v| v.index_name == replacement.index_name)
    {
        *existing = replacement;
    } else {
        list.push(replacement);
    }
}
