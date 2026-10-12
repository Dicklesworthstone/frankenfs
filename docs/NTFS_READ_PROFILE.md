# Experimental NTFS 3.1 MFT and stream read profile

`ffs-ntfs` implements native offline image reads using `ffs-ondisk::ntfs` and
`ffs-block::ByteDevice`. It does not delegate data reads to ntfs-3g, a kernel
filesystem or a mounted image. This companion binary includes a restricted
read-only `FsOps`/FUSE mount, but is not yet an `OpenFs` backend or writable
filesystem. It traverses native directory
indexes and resolves paths using the image's own UpCase table. Ordinary native
LZNT1-compressed nonresident DATA uses the same numeric and path read commands.
Relative native symbolic links can be resolved inside the image or presented
through the mounted `readlink` operation. Reparse metadata remains inspectable
for providers whose file contents are not supported. Native security descriptors
can be inspected or extracted by MFT record identity through the shared $Secure
catalog or a legacy SECURITY_DESCRIPTOR attribute.

## Commands

Use the repository's prescribed RCH build workflow:

```sh
rch exec -- cargo build -p ffs-cli --bin ffs-ntfs

ffs-ntfs inspect volume.img --offline-image
ffs-ntfs ls volume.img / --offline-image
ffs-ntfs ls volume.img /nested --offline-image
ffs-ntfs read volume.img /nested/file.txt --offline-image > extracted.bin
ffs-ntfs read volume.img /nested/file.txt --offline-image --stream note
ffs-ntfs read volume.img /nested/file.txt --offline-image --stream-utf16 d800,0061
ffs-ntfs readlink volume.img /nested/link --offline-image
ffs-ntfs record volume.img 24 --offline-image
ffs-ntfs streams volume.img 24 --offline-image --sequence 7
ffs-ntfs security volume.img 24 --offline-image --sequence 7
ffs-ntfs security volume.img 24 --offline-image --raw > descriptor.bin
ffs-ntfs cat volume.img 24 --offline-image > extracted.bin
ffs-ntfs cat volume.img 24 --offline-image --stream note > alternate.bin
ffs-ntfs cat volume.img 24 --offline-image --stream-utf16 d800,0061 > native-name.bin
ffs-ntfs cat volume.img 24 --offline-image --sequence 7 --start 507 --bytes 1031
ffs-ntfs cat disk.img 24 --offline-image --offset 1048576 --length 67108864

# Existing empty mountpoint; backing image must stay offline and immutable.
ffs-ntfs mount volume.img /mnt/ntfs --offline-image --uid 1000 --gid 1000
fusermount3 -u /mnt/ntfs
```

Record numbers are MFT identities, not byte offsets. `record` reports the
attributes physically contained in the selected FILE record, including native
UTF-16 names; it is not a flattened extension-catalog listing. Its DATA admission
checks and `cat`/`read` operate on the assembled base file. Select streams through
the base record, not an arbitrary extension record. UTF-16 names that cannot be
represented as UTF-8 retain their exact code units in JSON. `--stream` selects an
exact UTF-16 encoding of the supplied Unicode name. `--stream-utf16` selects the
original native code units directly, including unpaired surrogates. Supply one
comma-separated argument of four-digit hexadecimal units: JSON `name_utf16`
`[55296, 97]` is selected with `--stream-utf16 d800,0061`. Both numeric `cat` and
path `read` support this selector; they reject using both options together.
Omitting both options, or supplying an empty selector, selects unnamed DATA.
Names are limited to 255 non-NUL UTF-16 units. Selection remains exact rather
than case-insensitive. An optional sequence number detects stale references.
`record` also reports the base file's assembled `reparse_point`, including the
native tag, optional GUID bytes, exact UTF-16 substitute/display names for links,
or an unknown provider's opaque payload. Inspecting this metadata does not grant
DATA access. `readlink` follows intermediate supported links and retains the
final link's own record; it emits the relative substitute target with native
backslash separators converted to `/`.

## Complete DATA stream catalog

`streams` enumerates logical DATA streams through the selected base file's
complete validated ATTRIBUTE_LIST. It discovers named streams that exist only
in extension records and groups continuation attributes into one row per exact
native UTF-16 name. The rows are ordered by those code units; case folding and
lossy replacement are not used. An unnamed stream has an empty name. A name that
cannot be represented as UTF-8 has JSON `name: null` while `name_utf16` retains
every original code unit. Use `--stream` for a Unicode name or `--stream-utf16`
for its exact native units on either `cat` or `read`; the latter allows extraction
of streams whose JSON `name` is null.

Each row reports `attribute_extents` and `read_profile`. Admitted metadata
includes resident/nonresident storage, logical size, initialized length and
physical allocation bytes. Resident DATA reports zero separately allocated
bytes because its value occupies the FILE record. Unsupported storage or an
invalid stream mapping remains visible with `admitted: false` and its refusal
reason. The command does not omit unreadable streams from an otherwise valid
catalog.

Catalog identity corruption, an unreadable extension or cancellation fails the
whole command before JSON is emitted. Inspection reads the catalog and FILE
records, including their resident values, but does not read nonresident DATA
payloads. Metadata admission therefore does not certify subsequent data I/O,
compressed payload validity, or native provider support. The existing 4 MiB
ATTRIBUTE_LIST, 16 MiB extension-record and 65,536 assembled-run limits apply.

Numeric extraction and catalog admission share the same reparse/EFS checks and
STANDARD_INFORMATION validation, including metadata in extensions. A reparse
flag without its native reparse value is corrupt. STANDARD_INFORMATION remains
optional in the numeric inspection profile; when present, it must be a unique,
unnamed, untransformed resident value of the admitted native size. For a
directory, the ENCRYPTED file attribute specifies the default for new children;
an unencrypted named directory stream remains readable, while the stream's own
ENCRYPTED storage flag still requires an EFS provider. The mounted view follows
the same directory-default rule: native directory metadata and unencrypted
children remain readable, while encrypted files and DATA streams retain their
provider refusal.

## Implemented data path

Boot parsing checks sector/cluster geometry, both record-size encodings,
selected-volume bounds and primary/mirror bootstrap locations. MFT FILE records
have every 512-byte-stride update-sequence trailer checked before restoration.
Attribute parsing checks used-byte boundaries, names, resident values,
nonresident headers, unique instances and the terminating marker.

The reader bootstraps the unnamed MFT DATA stream, requires record-zero
agreement with MFTMirr, and reads subsequent records through the MFT runlist,
including a fragmented MFT. It checks file-reference identity, sequence and
in-use state and reads version/flags from VOLUME_INFORMATION.

Resident and nonresident DATA streams support exact named-stream selection,
signed backward LCN deltas, fragmentation, sparse holes and ValidDataLength zero
tails. All mappings are validated before extraction; logical EOF never exposes
allocation slack. Reads coalesce within a physical run, locate runs by binary
search and cap each returned buffer at 16 MiB. Invalid mappings, storage errors
and cancellation are errors, not successful short reads. Already streamed stdout
prefixes may remain after later I/O errors.

## Native compressed DATA

Nonresident DATA with ordinary compression method 1 uses 16-cluster units on
512..4096-byte clusters. Each unit is classified from the assembled runlist,
not from a magic byte in its contents: fully allocated units are literal data,
wholly sparse units produce zeroes without data I/O, and allocated prefixes
followed by sparse padding contain LZNT1 bytes. Physical prefixes can be
fragmented, including across attribute extents and backward LCN deltas. Sparse
padding is not exposed as logical zeroes after a packed prefix.

The decoder validates chunk signatures, token lengths, dictionary distances,
independent 4 KiB windows and output bounds. Forward overlapping matches are
supported. Short intermediate chunks have native zero padding; an early final
terminator never invents missing initialized bytes. Even a prefix read rejects
a packed unit that cannot reconstruct its full initialized logical range.

Only units touched by the initialized part of a request are read. Raw units
serve the requested subrange directly; packed units use bounded input/output
buffers of at most 64 KiB each. There is no per-unit index proportional to file
size: admission scans the bounded runlist and reads binary-search into it.
Large sparse files therefore do not allocate millions of unit descriptors.
Final partial units are admitted when fully raw; partial sparse/packed mappings
and physical clusters following sparse padding within the same unit are refused.

Compressed named streams and extension-backed mappings share the ordinary
attribute catalog and EOF/ValidDataLength rules. Compression methods other than
LZNT1, noncanonical unit sizes, clusters above 4 KiB, EFS and compressed non-DATA
attributes remain refused. Resident attributes carrying nonresident storage
flags remain refused. MFT data must still be untransformed. WOF/system compression
and other reparse-backed formats are not ordinary LZNT1 DATA support.

## ATTRIBUTE_LIST and extension records

A list can be resident or disk-backed; its complete mapping must be stored in the
base FILE record. The reader parses the entire initialized logical list, resolves
referenced records through the MFT, and checks the record/sequence, target instance,
attribute type, native name, and starting VCN. Every extension must point back to
the exact base record generation. Repeated resident attributes such as FILE_NAME
hard links remain separate instances, not one concatenated stream.

Catalog validation is bidirectional: each list entry must have its target, and
all attributes in the base and referenced extensions must be listed, except the
base's ATTRIBUTE_LIST itself. Unlisted attributes, missing instances, stale
references, foreign owners and recursive lists are refused. The list is never
used to redirect an extension into a different file.

Nonresident extents are assembled in VCN order. Gaps, overlaps, conflicting flags,
physical self-aliasing and incomplete coverage are rejected before publishing a
stream. Sizes come only from VCN zero; undefined continuation size fields cannot
change EOF or initialized length. Each extent restarts its relative LCN decoding.
Sparse and uninitialized ranges retain the same no-physical-read zero semantics.

MFT bootstrap uses a private, initially incomplete map. A referenced extension
record is read only when its entire initialized range is already mapped. The
reader repeatedly processes newly reachable extents, including dependencies that
are not in VCN order, until the complete DATA map can be validated through the
ordinary assembler. A no-progress dependency, stale record, torn fixup, logical
or physical alias, or exceeded work budget is an error; no physical address is
guessed from record number and no incomplete map is returned. The reconstructed
mapping must still reproduce the original record-zero bootstrap bytes.

These checks establish the admitted read-side relationships, not recovery,
allocation ownership across different files, or complete volume consistency.

## Native directories and path resolution

`ls` enumerates resident INDEX_ROOT and multi-level INDEX_ALLOCATION trees rather
than scanning the MFT for plausible parent references. Child VBNs, bitmap bits,
initialized allocation ranges, update-sequence protection and terminal records
are checked. Cycles, shared child nodes and unreachable allocated index blocks
are refused. Each directory key must match the target record's sequence and a
resident FILE_NAME identity, including its parent and namespace. FILE_NAME,
INDEX_ROOT, INDEX_ALLOCATION and BITMAP selection includes validated extensions.
Index ordering is not certified; enumeration visits the complete admitted tree
before lookup.

Path resolution starts at MFT record 5 and loads the native 65,536-entry UpCase
table from record 10, including ATTRIBUTE_LIST-backed DATA. Exact names are
preferred; Win32/DOS names fold through that table. POSIX names remain exact-only.
DOS aliases retain their native record identity. Conflicting folded matches are
refused. JSON listings retain separate native namespace entries, so a short alias
and long name may identify the same file. Unrepresentable UTF-16 names retain
raw code units; numeric inspection remains available. Reparse traversal is
dispatched using the assembled base-file catalog, including reparse attributes
stored in extension records. Supported relative links use the target policy
below; unknown providers do not fall through to ordinary DATA reads.

Each directory is limited to 65,536 keys, 16,384 allocation blocks and depth 32,
with at most 256 path components. The entire directory and referenced FILE_NAME
identities must be readable; a corrupt or unsupported target can cause the
listing/lookup to fail rather than publish a partially validated result. Index
block geometry must match the boot profile. Sub-cluster index blocks use 512-byte
VBN units even on a larger-sector volume. Parent traversal (`..`) supplied
directly in a CLI image path remains refused. A relative link may contain `..`:
the resolver follows the native directory stack and rejects attempts to move
above the selected volume root. The mount resolves ordinary directory parents
from native FILE_NAME references.

## Relative symbolic links and reparse providers

The native parser recognizes symbolic-link tag `0xA000000C` and junction/mount
point tag `0xA0000003`. It validates the complete reparse value, the native
16 KiB maximum, exact payload length, symbolic-link flags, and aligned UTF-16
substitute/display ranges. The ranges are relative to the native PathBuffer;
their order is unrestricted and their optional NUL terminators are not part of
the names. Unpaired UTF-16 surrogates are retained for JSON inspection. Unknown
tags retain their opaque bytes and, for the GUID form, their native GUID.
Reparse values can be resident or nonresident, but must be fully initialized,
unnamed and untransformed. Native STANDARD_INFORMATION reparse flags must agree
with the presence of the attribute when that metadata is available.

Path reads resolve only native symbolic links marked relative. The substitute
name is authoritative; the display name cannot redirect a read. Absolute NT,
drive-qualified and UNC paths, junction targets, stream-qualified targets, and
unknown providers remain unsupported. Host presentation requires lossless UTF-8,
at most 4,095 target bytes and at most 255 bytes per component. The in-image
resolver never opens a host path. It limits a resolution to 63 link expansions,
256 cumulative components and 65,536 cumulative path bytes. Cycles fail with
`ELOOP`; dangling targets remain valid link metadata but fail a following read.
A trailing slash still requires the resolved object to be a directory.

Numeric `cat`, path reads and mounted file reads enforce the same provider
boundary. A file carrying reparse metadata cannot expose its own DATA as if it
were resolved file contents, including named streams or metadata found in an
extension. On regular files, EFS-marked STANDARD_INFORMATION is also refused
before data I/O, even when the DATA attribute itself appears unencrypted. A
directory's ENCRYPTED flag describes the default for new children, not encrypted
directory indexes. Ordinary native LZNT1
compression remains a separate supported storage form; WOF/system compression
and cloud placeholders need their own providers.

The mounted view returns supported relative link targets to the host kernel
using ordinary symlink semantics, including `..`. A host process can therefore
follow a link beyond the mount's root; the mount is not a sandbox. This differs
from CLI image-path resolution, which confines traversal to the selected volume.
Directory symlinks are presented as symlinks, not as directories whose own
indexes must be traversed. A valid opaque reparse object remains visible in its
parent listing, while access that requires its provider returns an explicit
unsupported error. Malformed metadata still fails directory validation.

## Read-only native mount

`ffs-ntfs mount` uses the existing `ffs-fuse` transport. FUSE node 1 maps to the
native root (MFT record 5); other nodes encode the record number and sequence.
DOS aliases and hard links share one inode. Stale or noncanonical references,
directory cycles and inconsistent native parents are errors, not alternate roots.

The adapter provides lookup, getattr, paginated readdir, regular-file reads,
relative-link readlink, read-only open admission, statfs and non-writing
synchronization. Unnamed DATA
uses the same resident, fragmented, sparse, compressed and extension-aware reader
as CLI extraction. Named streams remain available through CLI `--stream`, not an
invented mounted `file:stream` namespace. SEEK_DATA/SEEK_HOLE use the conservative
projection of data before EOF and a hole at EOF, including compressed files.

STANDARD_INFORMATION supplies all four UTC timestamps at 100-nanosecond
precision, including supported times before the Unix epoch. File size comes from
the validated unnamed stream, allocation from physical clusters, and generation
from the native sequence. Resident DATA has no separately allocated data blocks.
Directory size zero is a host projection; external index allocation is counted.
Capacity and free-object counts come from the native volume and MFT bitmaps,
excluding padding bits and refusing uninitialized, sparse or compressed bitmaps.

Ownership and modes are deliberately synthetic: configured uid/gid, 0555
directories, 0444 regular files and 0777 symbolic links. This is NOT native
SID/DACL enforcement. `allow_other` is disabled. Unresolved reparse providers
and encrypted EFS files or DATA streams are refused rather than exposed as
ordinary plaintext files. An encryption-default directory remains traversable.
Unrepresentable UTF-16 or names beyond the host's
255-byte limit cause refusal, not lossy aliases. Use the numeric/JSON CLI for
forensic metadata that the mounted namespace cannot represent.

Only fully validated immutable metadata is cached. Exact and native-UpCase lookup
indexes use binary search; directory continuation clones at most 256 entries
from a retained snapshot rather than re-reading the tree for each page. Caches
retain at most 4,096 inode attributes, eight stream maps and 64 directory snapshots.
Directory rows/name-index payloads have a combined 16 MiB retention limit;
oversized snapshots are served without retention. This is not a total-process
memory limit: in-flight requests and map/Arc bookkeeping also consume memory.
Stream maps retain the reader's existing per-stream run limits. Cache hits check
cancellation; device reads and parsing never occur under the cache mutex. Data
I/O and its errors are not replaced by cached success. No speedup is claimed
without measured execution.

Mounting does not establish that an image is quiescent. Shared advisory locks do
not exclude a kernel mount or an unrelated writer. The image must remain
unchanged for the whole mount lifetime; cached metadata is not live coherence.
The mounted implementation has not yet been executed in the authoring environment.

## Native security descriptor inspection

`ffs-ntfs security IMAGE RECORD --offline-image [--sequence N]` resolves the
selected file's native security descriptor and reports its exact bytes,
descriptor control flags, owner and group SIDs, and SACL/DACL presence,
offset, revision and ACE count. The report identifies either the shared
`secure_sds` source with its security ID, native hash and SDS offset, or the
legacy `security_descriptor_attribute` source. Optional partition
`--offset` and `--length` limits apply through the existing image reader.
`--raw` writes only the exact self-relative descriptor bytes, without JSON
or the surrounding SDS entry header.

The report also retains the exact extended STANDARD_INFORMATION field in
`standard_security_id`: zero remains zero, while null denotes the legacy
48-byte form without that field. `legacy_attribute_present` records whether
the old descriptor attribute coexists with the selected source. When a nonzero
ID selects shared security, `secure_reference` includes record 9 and its native
sequence. The existing `security_id` field continues to identify the shared
source and stays null for legacy descriptors; no legacy fallback is attempted
when a nonzero reference is corrupt.

The reader validates STANDARD_INFORMATION from the complete base/extension
catalog. A nonzero native security ID is resolved through record 9, $Secure,
using its $SII index and $SDS stream. Legacy 48-byte STANDARD_INFORMATION, or
a zero security ID in the extended form, uses the unnamed
SECURITY_DESCRIPTOR attribute. Extension identities, sequence numbers, mapping
continuations and resident/nonresident streams retain the existing catalog
validation.

The shared-index traversal validates the complete reachable $SII tree before
returning a match. It checks ULONG collation, key and entry-header agreement,
strict key ordering and parent ranges, INDX update-sequence fixups, allocated
bitmap membership, cycles and shared children. The bitmap must cover every
block in INDEX_ALLOCATION, including when a resident root has no children and
all bitmap bits are clear. An iterative traversal limits
the path to 32 child levels, 16,384 index blocks, 65,536 keys and 64 MiB of
index reads. Index allocation and bitmap streams must be initialized and
untransformed. SDS may contain unmapped gaps outside the selected descriptor;
the selected primary and duplicate ranges must be physically mapped and
initialized.

Each SDS entry starts on a 16-byte boundary and stays within its native
256 KiB section. The reader validates its length, security ID, hash and primary
offset against $SII, then reads the duplicate 256 KiB later. Both copies must
be byte-identical, including their headers, before descriptor bytes are
returned. The native rotating-word hash is checked over the descriptor.
An inconsistent or missing copy fails the operation; this command performs
no repair and chooses no preferred copy.

The self-relative descriptor parser requires revision 1, DWORD-aligned
descriptor and SDS entry lengths, valid bounded and aligned component offsets,
native SID bounds, and supported ACL revisions with complete ACE envelopes. It preserves SID authority and subauthority
values, all descriptor bytes and opaque ACE bodies. Absent ACLs, NULL ACLs
and present empty ACLs remain distinct in JSON. Descriptors are bounded to
128 KiB. Native ACL inspection does not evaluate permissions or map SIDs
onto host accounts; the mounted view continues to use its existing explicit
host ownership policy.

SACL and DACL objects retain their original `present`, `offset`, `revision`
and `ace_count` fields and add explicit `state`, native `size`, ordered `aces`
and `unused_bytes`. Each ACE preserves its numeric `kind`, inheritance/audit
`flags`, byte `size`, and remaining `opaque_bytes`. Recognized simple and
object allow/deny/audit layouts, callback variants, mandatory labels, resource
attributes and scoped policy IDs expose their bounded native mask and trustee
SID. Object ACEs additionally preserve presence flags and the exact 16-byte
object/inherited-object GUID fields; they require ACL revision 4. Known ACEs
with missing or malformed SIDs, reserved object-presence bits, or the wrong
system/discretionary ACL role are refused before output.

Unknown or reserved ACE layouts retain their entire body with `layout: opaque`
and null decoded fields. Callback conditions, claims, extra native bytes and
unused ACL space are preserved without evaluation. ACE order is never changed,
SIDs are not resolved to host users, and masks are not translated into Unix
permissions. Every JSON report explicitly includes `access_evaluated: false`.
All selected native framing, hash, copy and index checks finish before raw or
JSON descriptor output begins.

Security metadata remains inspectable for files whose DATA requires an
unsupported provider. This command does not read that file's DATA, bypass
the DATA provider boundary or implement EFS/WOF/cloud-provider contents.
All normal offline-image, shared-lock and immutable-image requirements apply.

Native format references:
[NTFS-3G layout definitions](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/include/ntfs-3g/layout.h)
and [NTFS-3G security handling](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/libntfs-3g/security.c).
Descriptor and ACE framing also follows Microsoft's MS-DTYP
[SECURITY_DESCRIPTOR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d),
[ACL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428),
[ACE_HEADER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586),
[object ACE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe)
and [callback ACE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c9579cf4-0f4a-44f1-9444-422dfb10557a)
specifications. These define native structure, not a host access policy.

## Admission limits and exclusions

Only immutable, offline regular files, NTFS 3.1, 512..4096-byte sectors,
clusters up to 64 KiB and FILE/index record sizes up to 64 KiB are admitted.
Compressed DATA has the narrower cluster/unit profile described above.
The MFT bootstrap record must fit in the initial physical run. MFT indices
above u32::MAX and records outside initialized MFT data are not exposed.

Attribute lists are bounded to 4 MiB and 65,536 entries. Extension record storage
is bounded to 16 MiB per catalog. The assembled stream is limited to 65,536 runs,
not 65,536 runs per extension. MFT discovery admits at most 131,072 dependency
probes and 1,048,576 cumulative mapping-merge units. These are explicit resource
limits, not maximum sizes of the native NTFS format.

The list's own mapping cannot be recursively extended through other FILE records.
Unsupported compression profiles, EFS, unknown attribute flags and nonzero volume
flags remain refused. Sparse-only attributes accept zero or four as their
frame-unit encoding. No writes, repairs, log replay, volume-flag changes or device
flushes occur. A shared advisory lock does not exclude unrelated writers.

A zero volume-flags field and matching record-zero mirror are **not** proof of
a clean $LogFile, absence of hibernation, complete MFTMirr consistency, or global
allocation/index integrity. The caller must supply a quiescent image. This is
not a recovery or filesystem-check tool. Absolute Windows target mapping,
external reparse providers, compressed writes, native security enforcement,
generic OpenFs routing and NTFS mutation remain
separate work. The restricted mount above is not full NTFS qualification.

## Validation

```sh
rch exec -- cargo test -p ffs-ondisk ntfs
rch exec -- cargo test -p ffs-ondisk lznt1
rch exec -- cargo test -p ffs-cli --bin ffs-ntfs
python3 scripts/verify_ntfs_read.py --binary target/debug/ffs-ntfs
python3 scripts/verify_ntfs_mount.py --binary target/debug/ffs-ntfs
```

The runner creates a new scratch image with mkntfs, seeds it with ntfscp, gets
independent MFT identities with ntfsls, and compares bytes with ntfscat. It covers
small/large/empty files, directory listings, namespace-aware path reads, named
streams, unaligned ranges and explicit partition boundaries, checking unchanged
image hashes and retaining command logs. It never modifies an existing image.

It also creates 32 additional named streams on one file. The ATTRIBUTE_LIST
returned independently by `ntfscat -a 0x20` must contain real extension-record
references for those streams. Merely creating many single-record names is not
accepted as coverage. All 32 streams are compared by numeric and path/ranged
reads, including an extension stream inside a selected partition. Missing tools,
a formatter that does not produce the requested layout, and candidate failures
are failures, not successful skips.

The compressed cases create additional fresh images with `mkntfs -C` at 512- and
4096-byte cluster sizes. Dense nonzero and mixed random/zero/repeating payloads
are copied using ntfscp and independently read using ntfscat. The native MFT,
also extracted by ntfscat, must demonstrate a nonresident method-1 DATA stream
and real physical-allocation savings for the dense nonzero file. A compression
flag on a wholly raw substitute cannot earn this coverage. Numeric reads, path
reads, unit/chunk boundary ranges, EOF and unchanged image hashes are checked.
These cases do not certify every native unit topology or Windows interoperability.

Delivery evidence for the compression increment: Python syntax compilation,
runner `--help`, and one positive/five negative constructed tests of the Python
native-allocation evidence helper passed. Rust compilation/tests, rustfmt/Clippy
and native-image execution remain unavailable in the authoring environment.
The Python helper checks do not execute the Rust decoder or a native filesystem.
Added code and tests are not a passing conformance or Windows-interchange claim.

The native runner does not force fragmented MFT bootstrap, split mapping-pair
continuations, EFS images or directory-extension layouts; those mechanisms
have separate constructed Rust fixtures and still require native evidence.
The Rust regressions cover resident/disk-backed lists, named/resident values
in extensions, split fragmented and sparse mappings, stale or mismatched catalogs,
physical aliases, partial coverage, cancellation, unchanged image bytes, MFT
out-of-order dependency resolution and refusal, extended indexes/FILE_NAMEs,
extended UpCase data and reparse attributes hidden in extensions. Compression
regressions add malformed tokens, displacement-width boundaries, raw/sparse/packed
unit transitions, fragmented and split-attribute units, initialized-length refusal,
large sparse files, raw final partial units, and full 64 KiB output units.
Existing boot, stream, namespace, and read-only failure tests remain intact.

Reparse regressions add native byte-range parsing, display/substitute distinction,
unpaired-surrogate preservation, GUID payloads, truncated/unaligned buffers,
relative and directory links, real mapped target bytes, bounded loops and
dangling paths, in-image parent traversal/root refusal, the distinct mounted
`..` policy, nonresident reparse cancellation, and opaque-directory listing.
Numeric unnamed/named DATA admission tests require provider/EFS refusal before
any data I/O. Existing unknown-provider tests retain their refusal assertions
and now use a valid opaque tag instead of the reserved zero tag. These are
constructed Rust fixtures; they do not establish Windows-created reparse
interchange or actual mounted reparse execution.

The mount runner requires real Linux FUSE and creates 320 native files with
mkntfs/ntfscp, comparing every seeded file independently with ntfscat. It checks
repeated mounted directory enumeration, attributes, whole-file hashes, unaligned
reads, EOF, native statfs and EROFS write-open refusal. It repeats the workload
on an explicitly selected volume surrounded by partition sentinels, and checks
whole-image hashes after unmount. Mounted operations run in a timed child; logs,
images and failures are retained. Missing prerequisites fail, not skip. This
runner exercises ordinary native files, not compressed or extension fixtures;
those remain separate workloads in the existing reader runner and Rust tests.

Mount delivery evidence: Python syntax compilation and mount-runner `--help`
passed. Rust compilation/tests, rustfmt/Clippy and real/native mounted runs were
not executed here because the required tools and FUSE are absent. Eleven FsOps
regressions plus CLI mount parsing are added, not claimed passed. They cover
record/sequence identities, hard links/aliases, parent lookup, native names and
times, fragmented/compressed reads, EOF, directory cookies, bitmap padding,
write rejection, cancellation, cache reuse/eviction and root-alias refusal.

## Stream catalog validation

Seven added reader regressions cover resident and disk-backed catalogs,
continuation grouping, extension-only named streams, allocation accounting,
unsupported streams retained beside readable streams, lossless native names,
catalog corruption, cancellation, extension-backed reparse/SI metadata,
directory encryption defaults and malformed STANDARD_INFORMATION. A CLI
regression covers offline-image acknowledgement, record identity and sequence
selection. The existing numeric-provider and relative-link regressions remain
intact.

Stream-catalog delivery evidence (2026-10-11): these changes and fixtures were
reviewed against complete GitHub source blobs, including concurrent reparse
implementation changes. Rust compilation, the new tests, rustfmt, Clippy and
native-image execution could not run because the executor was disconnected.
These are authored regression cases, not passing test results or native
interoperability evidence. Earlier validation results below describe their
respective increments and do not validate this stream-catalog change.

## Numeric DATA provider boundary

Numeric `cat` and DATA admission now inspect the complete validated base and
extension catalog for REPARSE_POINT before selecting either unnamed or named
DATA. Unsupported reparse providers, including WOF/system compression and cloud
placeholders, cannot bypass the path reader's provider boundary by using an MFT
record number. Their backing DATA is not exposed as decoded file contents.
Metadata inspection remains available; no provider implementation is implied.

The regression
`numeric_data_reads_enforce_base_and_extension_reparse_providers` covers
unnamed nonresident and named resident DATA, base and extension reparse metadata,
and benign non-reparse controls. Device traces assert admission reads only the
necessary extension metadata and no file payload.

Delivery evidence (2026-10-11): the source change and fixtures received independent
review, and complete GitHub file blobs were read back and compared with the base.
The Rust regression, formatting, workspace checks, Clippy and UBS could not run:
the executor disconnected after storage exhaustion; the earlier offline Cargo
attempt also lacked a required dependency. These added tests are not execution
or native Windows interoperability evidence.

Subsequent relative-symlink implementation validation on 2026-10-11: the complete
`ffs-ondisk` library suite passed 790 tests, including the reparse parser. The
parser library also passed Clippy with warnings denied, and workspace formatting
passed before the executor disconnected. CLI compilation was killed while
building `asupersync` under the shared memory limit; the engine regressions and
native mounted reparse workload have not run. UBS could not complete because
its helper downloads failed integrity checks. This evidence does not establish
native Windows reparse interoperability.

## Lossless stream-selector validation

Two parser regressions and one CLI regression exercise exact UTF-16 units,
unpaired surrogates, Unicode supplementary characters, the 255-unit limit,
malformed hexadecimal input, NUL refusal, unnamed defaults and mutually
exclusive selectors for numeric and path extraction. Source review confirms
both commands pass the selected units directly to the existing DATA reader.

Delivery evidence (2026-10-11): complete source blobs and their changes were
reviewed independently. Rust compilation, these tests, formatting, Clippy, UBS
and native-image execution remain unexecuted because the executor is offline.
No new native interoperability or mounted execution result is claimed.

## Mounted encryption-default directory validation

The mounted adapter applies the native directory ENCRYPTED flag as an
inheritance default. Directory lookup, enumeration, attributes and reads of
unencrypted children remain available. Actual encrypted files and DATA storage
still require an EFS provider and are refused before payload I/O.

Constructed FsOps regressions cover marked directories and plaintext child
access alongside file-wide and per-stream encrypted refusals. A stream-reader
regression also feeds the new raw UTF-16 selector into native catalog selection
and verifies exact bytes without substituting a different native name.

Delivery evidence (2026-10-11): source and fixture review only. Rust compilation,
these regressions, formatting, workspace checks, Clippy, UBS and native mounted
execution remain unavailable with the executor offline.

Native directory semantics: Microsoft,
[Handling Encrypted Files and Directories](https://learn.microsoft.com/en-us/windows/win32/fileio/handling-encrypted-files-and-directories).

## Native security descriptor validation

Six pure parser, nine constructed image-reader and two CLI/report regressions
cover legacy and shared descriptors; 48/72-byte STANDARD_INFORMATION; absent,
NULL and empty ACLs; SIDs and malformed component bounds; fragmented SDS data
and ATTRIBUTE_LIST continuations; stale record sequences; malformed, cyclic,
free, unreachable and out-of-range SII children; duplicate/hash/initialized
length/sparse-range failures; cancellation; unsupported-provider metadata
inspection; raw descriptor output; and unchanged backing bytes.

Delivery evidence (2026-10-11): complete source and fixture blobs received
independent review. A separately calculated native rotating-word hash for the
96-byte descriptor fixture is `f1c75d8c`; mapping-pair and primary/duplicate
read offsets were checked independently. These calculations do not execute
the Rust implementation. Rust compilation, the 17 new regressions, formatting,
workspace checks, Clippy, UBS and native-image or Windows interoperability
validation remain unexecuted because the authoring executor is offline.

## Structured native ACE inspection validation

Six additional parser regressions cover ordered deny/inherited trustees and
masks, object/callback/unknown ACE bodies, missing trustee fields, ACL-role and
reserved-field errors, preserved free space, and lengths with unhashed partial
words. Five reader regressions add exact zero/absent SI identity and $Secure
generation, incomplete bitmap coverage without reachable children, corrupted
known trustees behind matching hashes and duplicate bytes, provider refusal on
$Secure itself, and unchanged real image/adjacent bytes. A CLI regression checks
lossless object GUID/callback/opaque JSON and explicit absence of access decisions.
The original six parser, nine reader and two CLI security regressions are retained.

These additions were merged onto the published native-security implementation,
preserving its public fields, iterative index traversal, physically mapped and
initialized descriptor ranges, source precedence and raw extraction. Source and
fixture review are complete. An inherited SID-boundary fixture now distinguishes
a valid 15-subauthority owner ending at byte 88 from an out-of-bounds group ending
at byte 100 in the same 96-byte descriptor; component sharing remains supported.

Execution evidence (2026-10-11): all 12 tests selected by
`cargo test -p ffs-ondisk --lib ntfs_security::tests --locked` passed against the
merged parser, with one compiler thread. The five changed Rust files were parsed
and formatted. Full CLI checks/tests stopped during `asupersync` compilation with
SIGKILL under the shared memory limit, so the new image-reader and report tests
remain unexecuted. Earlier execution of a separate parser draft is not credited
to this implementation. Native Windows descriptor comparison and mounted
SID/DACL enforcement are not claimed.
