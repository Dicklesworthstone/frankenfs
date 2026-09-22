# On-image raw parity integrity

Full-block raw repair symbols now require a committed, generation-bound BLAKE3
integrity manifest. This is separate from the external `FFSRQSC2` sidecar format.
It changes the existing `RepairGroupStorage` path used by on-image recovery; it
does not reserve new filesystem blocks or enable default mounted repair.

## Storage and publication

The existing two descriptor blocks retain their 48-byte `RepairGroupDescExt`
prefix. The remaining space stores a versioned manifest: `RQHASH01`, the emitted
symbol count, a checksum-bucket width, a BLAKE3 manifest checksum, and BLAKE3
checksums for consecutive physical parity slots. The bucket width grows when
there are more parity slots than fit as individual digests in a descriptor.
Descriptor blocks must be at least 128 bytes. No validation block or additional
allocator space is implicitly consumed.

A refresh requires a strictly greater generation. Before any parity is
overwritten, BOTH descriptor slots receive a pending `RQPEND01` record and the
device is synced. Parity is then written and synced, and every parity block is
read back against the intended input bytes, including zero padding. Only after
that verification are both committed manifests written and synced.

This is fail-closed in-place publication, not double-buffered parity. A crash
can leave the group unavailable for recovery. Both pending copies prevent an
older descriptor from authorizing a partly overwritten parity region. A
publication error can also occur after a new generation became durable; reread
the stored state before retrying.

## Recovery and regeneration

Recovery considers only the newest checksum-valid descriptor generation. It
requires a valid integrity manifest for that generation and does not fall back
to older raw parity when the newest generation is pending, unsealed or damaged.
One valid same-generation manifest copy can survive damage to the other.
Unreadable descriptor slots are fatal because they could hide a newer record.

A checksum mismatch invalidates the entire affected bucket. Degraded recovery
can also discard a bucket containing media-unreadable parity. Surviving symbols
keep their physical-slot encoding IDs. Explicit symbol counts distinguish valid
all-zero symbols from unused slots. Insufficient surviving equations fail before
source writeback. The recovery orchestrator rechecks the generation after
decoding and before passing recovered bytes to the writeback authority.

Old unsealed raw generations are deliberately NOT accepted for recovery. Do not
regenerate protection from already damaged or untrusted source data: that would
merely protect the wrong bytes. After independently establishing a known-good
source, `read_refresh_descriptor` supplies the metadata high-water mark, even
for an interrupted refresh. A subsequent `write_repair_symbols` must use a
strictly higher generation. The metadata-only method never authorizes recovery.

## Boundaries

Parity integrity does not establish source freshness after legitimate client
writes, and descriptor rereads are not an atomic exclusion primitive. Callers
must still prevent concurrent repair writers and provide the source-freshness
contract. The mounted writeback authority remains responsible for serializing
source mutations. Framed (sub-block) symbol storage retains its existing
header/generation protocol; these new payload manifests apply to raw storage.
The checksums detect accidental damage, not maliciously authenticated records.

`cargo test -p ffs-repair storage::integrity` exercises parity damage, descriptor
replication, unsealed-generation refusal, cancellation, explicit regeneration,
and every write/sync cut in a refresh under two persistence models. The broader
`cargo test -p ffs-repair` also exercises real RaptorQ recovery and the existing
pipeline, ownership and sidecar regressions. Test execution and results must be
reported for the actual tested revision; the existence of a test is not a pass.
