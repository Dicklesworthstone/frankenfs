# Explicit native FAT parent-pointer recovery

`ffs-fat repair-parents` corrects existing `.` and `..` cluster pointers when a
complete, unambiguous root-based namespace establishes each directory's actual
identity and parent. This is useful for a directory left with a stale parent
pointer after an interrupted cross-directory move. It does not complete or roll
back the rename, choose between duplicate owners, or follow the damaged pointers.

```sh
ffs-fat repair-parents recovery-copy.img --offline-image --dry-run
ffs-fat repair-parents recovery-copy.img --offline-image
ffs-fat check recovery-copy.img
# Only after examining the remaining findings, use ordinary structural recovery.
ffs-fat recover recovery-copy.img --offline-image
```

This is an explicit offline command and library entry point,
`ffs_fat::reader::recovery::repair_parents`. Dry-run performs the same ownership
and record preflight without writes or synchronization. The image is opened as
a regular file with the existing no-follow, identity and advisory-lock policy.
Sidecars are refused; the command never performs implicit protected read-repair.
Neither locks nor these checks exclude an unrelated kernel or image writer.

Only the first two recognizable, directory-attribute, zero-size dot records of
non-root directories are candidates. Missing/deleted records, substituted names,
nonzero lengths and unknown attributes are refusals, not permission to invent a
record or overwrite a possible file. FAT16 EA-index words and FAT32 reserved
high nibbles are preserved. Root-parent pointers use zero, including FAT32.
Native names never pass through host filename conversion.

A complete diagnostic and independent ownership reconstruction precede writes.
Cross-links, cycles, conflicting selected FAT copies, missing namespace evidence,
truncated findings, hard-error flags and unrelated structural damage are refused.
Proven lost allocation may remain, but is not freed, exported or attached to a
file by this command. Other recovery authorities have no command-line switches
here; ordinary recovery retains its existing refusal of damaged parent links.

The plan fingerprints complete allocated directory storage (including bytes
following end markers), physical directory mappings, every selected allocation
word, and native boot/reserved metadata. Only the proposed pointer fields and
native clean bits are normalized. Reports include the exact before/after 64-byte
dot records and the fingerprints; these are not file-payload checksums.

Immediately before mutation, the complete report and evidence must still match.
Dirty markers are synchronized and verified before any dot record is changed.
Each affected sector is preserved, patched, synchronized and compared in full.
The resulting namespace, allocation, normalized native state and all ownership
counts must agree with preflight, with no parent-link findings remaining.
No file payload or allocation link is rewritten, and no cluster is reclaimed.

A changed image is deliberately left dirty. Subsequent `check` reports that
state; the operator decides whether a separate ordinary `recover` is warranted.
The command does not claim transaction replay, lost-file recovery, rollback,
crash atomicity or proof of pre-existing payload integrity. Failure may leave a
partially repaired dirty image, with no automatic cleanup writes. Interrupted
changes can require another diagnostic pass on a retained copy.

This implementation has authored Rust regressions but has not been compiled or
executed in the authoring environment. Native fsck/mtools/Windows qualification
and kernel-FUSE integration are not established. Test only disposable copies
until those execution checks have been completed.
