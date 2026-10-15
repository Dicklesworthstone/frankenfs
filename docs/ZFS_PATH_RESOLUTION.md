# Confined ZFS image-path resolution

The ZPL CLI now resolves symbolic links within the selected immutable dataset
head or snapshot. This replaces the earlier CLI restriction in
`ZFS_READ_PROFILE.md` that refused all symlink and parent traversal. It does not
change FUSE's host-kernel symlink behavior or claim that a mounted view is a sandbox.

`read` and `ls` follow ancestor and final symbolic links. `stat`, `readlink`,
`listxattr`, and `getxattr` follow ancestor links but inspect the final object
itself. Thus `stat /link` reports the link's metadata, and `getxattr /link
user.note` reads the link's own attribute, not its target's. A trailing slash
requires a directory, including when appended to a symlink; `readlink /link/`
is not an alternative spelling of `readlink /link`.

All six path commands accept `--no-symlinks`. This refuses traversal of any
symbolic link while retaining final-link inspection. It does not relax image,
feature, topology, partition, dataset, or snapshot admission.

```sh
# Linked directories and final links can lead to native file data.
ffs-zfs read pool.img /dirlink/file --offline-image --auto-import --dataset data

# Resolve inside the selected historical root, never the live head.
ffs-zfs read pool.img /link --offline-image --auto-import \
  --dataset data --snapshot before --start 510 --bytes 600

# Read an ancestor link's directory, but report the final link's stored target.
ffs-zfs readlink pool.img /dirlink/link --offline-image --auto-import --dataset data

# Require the extraction path not to traverse any symbolic link.
ffs-zfs read pool.img /file --offline-image --auto-import --dataset data --no-symlinks
```

Relative targets start in the directory where the link was encountered, not its
stored parent. Hard-linked symbolic links can therefore resolve to different
objects through different directories. Absolute targets restart at this selected
dataset's root: `/etc/config` in a link is an image path, never a host path.
The resolver cannot traverse synthetic `.zfs/snapshot` mounts, enter child
datasets, or fall back to a different dataset/snapshot after an error.

Parent components use the validated encountered directory stack. An attempt to
step above the selected root fails explicitly rather than clamping at root or
escaping. `file/..` and `file/.` fail because `file` is not a directory; components
are not erased by lexical normalization. A trailing slash inside a link target
retains its directory requirement before the remaining caller path is processed.
Empty link targets fail with not-found; NUL targets and malformed native metadata
fail instead of selecting the containing directory or a plausible alternate name.
Native byte names and the dataset's UTF8-only policy are preserved.

The resolver performs at most 40 link expansions. It charges at most 256
cumulative nonempty components and 65,536 cumulative input/target bytes, including
already consumed paths. Directory-result work is limited to 64 MiB per resolution,
including repeated/cached listings, in addition to existing per-directory,
DMU, decompression and topology limits. These are work/payload limits, not a
whole-process memory or physical-I/O limit. Repeated visits to a link are legal
within these bounds; an inode-only visited set would incorrectly reject finite
paths such as `again/again/file` when `again` targets `.`.

Directories and link targets use the existing checksum-verified readers for the
selected view. Cancellation terminates the traversal. A path-resolution failure
returns no resolved object; subsequent chunked file extraction retains its
existing streaming contract and may already have written earlier successful
chunks if later file data fails. No backing writes, replay, repair, or host-path
opens are introduced by this resolver. Separately selected sidecar behavior and
mounted host-kernel semantics are not changed.

## Validation status

Eleven constructed DMU/ZPL Rust tests cover policies, relative hard links,
absolute confinement, trailing slashes, loops, long-link checksums and I/O errors,
cancellation, cumulative limits, raw names and malformed directories. Two more
constructed complete mirrored-pool regressions retain historical bytes after
live-head reads, owner drop, replica corruption and cancellation; two CLI tests
cover operation policy and argument retention. These 15 Rust tests have been
authored but not executed in this environment, where Cargo/rustc are unavailable.

An independent Python path-policy model matched real Linux `openat2` with
`RESOLVE_IN_ROOT` in 1,367 cases. Another 184 above-root cases are documented
stricter refusals, not equivalence claims. This is model-versus-kernel evidence,
not execution of the Rust implementation and not native OpenZFS interchange.
Pinned Rust compilation/tests, rustfmt/Clippy and native-image comparisons remain
required. No existing test assertions, support gates or parity claims are relaxed.
