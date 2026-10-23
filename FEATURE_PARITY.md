# FEATURE_PARITY

> **Atomic ext4 hard-link publication:** `ext4_link` now stages the source link
> count, parent inode, directory entry, directory-growth allocation and any
> `O_TMPFILE` orphan predecessor splice in one MVCC transaction. Failed staging
> or commit restores cached allocation state; orphan runtime state changes only
> after publication. Three new regressions cover old snapshots, indexed growth,
> duplicate names, failed orphan splices, retry, reopen and native `e2fsck` checks
> on generated images; the existing tmpfile test also checks head and interior
> splices each publish once. These Rust tests are authored but unexecuted here:
> local Cargo cannot resolve uncached dependencies and shared storage is
> exhausted. Exact pinned formatting and whitespace checks pass. This advances
> the hard-link slice of `bd-9rutw`; the remaining namespace operations and its
> broader request-scope conversion stay open.

> **Native ZFS atomic-exchange recovery:** `Zpl::replay_zil` now decodes native
> `TX_RENAME_EXCHANGE` records separately from ordinary rename and stages both
> names together. File/directory swaps preserve both objects and their contents;
> cross-parent directory link accounting and both ancestry checks are enforced.
> Five new regression functions cover native framing, both byte orders, both log
> checksum layouts, claim boundaries, aliases, nonempty directories, repeated
> replay and whole-view refusal. Exact pinned rustfmt and `git diff --check`
> passed. Rust execution and native OpenZFS interchange remain unverified here:
> local Cargo cannot resolve the uncached dependencies and shared storage is
> exhausted. This advances `bd-ofjn7`; its broader recovery acceptance stays open.
> See `docs/ZFS_ZIL_TOPOLOGY_PROFILE.md` for the operation contract.

> Quantitative feature coverage tracking for FrankenFS.

## 1. Coverage Summary (Current)

> **2026-10-21 native library integration (`bd-native-image-library-s4tde`):**
> FAT, NTFS and ZFS engine source and existing tests now live in dedicated
> library crates. Ordinary companions and protected mounts consume those same
> engines. `ffs::open_read_only` composes their existing `FsOps` adapters with
> ext4/btrfs after six-format ambiguity checking, using bounded read-only image
> authority and explicit native view selection. `OpenFs` itself remains
> ext4/btrfs. Five new facade controls cover constructed native FAT16/32 and ext4
> reads, mutation refusal, volume sentinels, retained locks, ambiguity and invalid
> ZFS/cancellation preflight; two new FAT consumer tests cover repeatable library
> operations without global signal handlers. At frozen `3b464766e`, the facade
> suite executed: 40 passed, zero failed or ignored, including all five new
> facade controls. Merged `ff3dca7ec` passed workspace/all-target checking and
> strict Clippy through RCH. Earlier committed engine runs passed FAT 452,
> NTFS 344 and ZFS 305 tests; both external FAT consumer tests passed. The merged
> ZFS suite passed 315 unit tests and one compiled doctest. Original
> NTFS named-stream facade selection subsequently passed on native-produced
> plain and bounded images at `c6c93513b`: full, ranged, EOF and beyond-EOF reads,
> exact UTF-16 selection, missing/wrong-case names and cancellation through the
> same admitted volume. The unchanged native FAT and NTFS Cargo profile wrappers
> also passed; NTFS executed 203 commands including 32 extension records and
> compressed 512/4096-byte-cluster images. These are native offline-image results.
> The full harness and default benchmarks subsequently passed. The later frozen
> maintenance cut also passed compiler, strict Clippy and formatting gates;
> targeted UBS disposition and publication remain open as described below.
> Acceptance across all mounted formats and extra parity credit are not claimed.
> The bounded native NTFS mounted result below covers its strict read-only slice.
> The older
> six-format `OpenFs` row below still has only its detection-test binding; this
> source integration does not silently promote that binding to mounted proof.

> **Native-producer finding, 2026-10-21:** the explicit facade test executed real
> FAT16/FAT32 comparisons successfully, then failed NTFS admission on FILE
> record flags. The parser omitted native metadata/view-index bits `0x4/0x8`.
> At immutable `dcdc37e37`, the corrected parser selection passed 13 tests and
> the unchanged native-producer facade test passed its FAT16/FAT32/NTFS plain
> and bounded-image scenarios, including exact full/ranged/EOF bytes, write
> refusal and unchanged source hashes. Actual OpenZFS 2.4.1 images then exposed
> heterogeneous MOS ZAP values and uninitialized `$ORIGIN` heads. Both defects
> were corrected without relaxing structural validation. At `bd2fac9c4`, the
> native ZPL 4/5 file and snapshot profiles passed through both the companion and
> standalone public facade: plain/bounded images, exact native bytes/stat/names,
> divergent historical roots, sparse tails, write refusal and unchanged whole
> backing hashes. Repeated snapshot selections are separate processes; the
> example clamps EOF by metadata. This is neither same-instance cache nor
> FrankenFS-mounted proof. Native NTFS namespace/ADS comparisons progressed
> before its compression-fixture oracle incorrectly parsed already-fixed MFT
> bytes as raw. The separately reviewed `--raw` oracle correction retains all
> 47 assertions; the full native rerun subsequently passed at `c6c93513b` as
> described above. Clean-overlay retirement removed the printed remote scratch
> paths; the local full transcript, embedded profile JSON and source receipt
> remain, rather than a claim that those raw scratch paths are still available.

> **Indexed NTFS and full-harness findings, 2026-10-21:** constructed-image
> tests exposed order-dependent acceptance of mismatched FILE_NAME aliases
> sharing one file reference. The immutable old-code control executed one valid
> alias pass and one missing-alias failure; the correction validates every
> candidate identity. The combined source at `dba32085e` plus explicit overlays
> passed all 360 NTFS tests, including nine indexed reader and seven indexed
> FsOps tests, plus 40 facade tests and one compiled facade doctest. Its ignored
> native-producer selection earns no native credit in that command. The later
> borrowed-slice lint correction and current ZFS automatic import source passed
> full workspace/all-target strict Clippy on `990539073` plus explicit overlays.
> The current package rerun passed 747 tests: 40 facade, 24 NTFS CLI, 360 NTFS
> reader and 323 ZFS, with one opt-in native test ignored. The complete fixture
> and census overlay also passed workspace/all-target check, strict Clippy and
> formatting. These package selections do not include doctests. A full genuine-Git
> harness run passed 2,076 unit tests, then reached 98 conformance passes and five
> failures in constructed Btrfs mount images with missing superblock checksums.
> Its final source receipt also failed on Git index stat-cache changes. Neither
> that partial execution nor supported terminal recovery constitutes a passing
> full harness or a valid final source receipt. The constructed image producer
> now emits a checksummed superblock and matching device/chunk inventory. The
> rerun passed all 104 conformance tests, including the five previous failures
> and a new valid-open/checksum-byte/covered-payload corruption control; two
> ignored tests earn no credit. A later failed run retained a valid final source
> receipt after command-scoped Git stat-cache refresh was disabled; its census
> failure exposed stale LOC inventory in three meta modules. The numeric-only
> correction preserves every path, classification and census assertion and earns
> no capability credit. After restoring the accurate README source inventory,
> the complete genuine-Git rerun passed 2,652 tests with zero failures and 11
> ignored, including one compiled doctest, the checksum controls, census and public parity adversarial
> targets. Its final source-content receipt is valid (build
> `30074357740994971`, root
> `7fa320e15e551fd22a4519099db37bbc9250fd8d3480192b519e7241cf071bb9`).
> All 5,007 non-Beads root tracked files matched that frozen input before the
> run. Later FAT parent-repair lint/formatting maintenance has separate passing
> compiler gates below; it is not silently included in that receipt. Production
> admission and old assertions are unchanged.

> **Current public-consumer refresh, 2026-10-21:** Linux ELF
> `e862954f96cf7bfff76fd63d47465cd4b55dd0f1f3e3acb9c08e883b34e4ef48`,
> built from `990539073` plus six explicit overlays, passed 120 public NTFS
> calls and 108 public FAT/ZFS calls on retained native images, including nine
> expected semantic failures. NTFS includes all 32 extension streams and both
> exact selectors. FAT/ZFS replay retains all 164 original command expectations,
> reruns six native FAT reads and compares 50 fresh outputs. All backing hashes
> stayed unchanged. These are source-bound offline results; later shared-main
> FAT recovery changes have separate qualification. EOF is consumer-clamped and
> snapshot selections use separate processes.
> The same ELF subsequently passed 52 more public calls on fresh native ext4
> and btrfs images: two native producers, seven native check/readback commands,
> eight native payload readbacks, 28 public payload comparisons, eight stat and
> eight listing checks, four write refusals and four typed missing-path failures.
> All 61 commands completed with exactly four expected nonzero statuses. Plain
> and bounded backing hashes and all source/tool/ELF hashes stayed unchanged
> during verification. The exact approved probe SHA is
> `7fbdb0d7b3987fcefd3a0250594c7c5652ad845262b35f448f15cdc6ac8265cc`;
> retained CSD evidence is `ext4-btrfs-public-native-2glw4nqx`, with the full
> command in `.beads/pending_tasks.md`. Together these refreshes executed 280
> public calls across ext4, btrfs, FAT16, FAT32, NTFS and ZFS: all six declared
> formats. Mounted acceptance across formats and native write authority are
> separate.

> **Final maintenance verification, 2026-10-22:** complete baseline
> `08226b8cb79755aee243068744eb2abeb743b01d` plus nine explicit overlays,
> fingerprint
> `23f0f687639a1cd61fd8f6de680967c4874ad93e10cde5efd21afec7aee68782`, passed
> workspace/all-target `cargo check` (RCH `30074357740995112`), strict Clippy
> with `-D warnings` (`30074357740995101`) and full `cargo fmt --check`.
> All nine parent-repair regressions also passed (`30074357740995102`), with
> zero failures or ignores and 466 deliberately filtered cases. Remote commands
> and durable wrappers returned zero with terminal acknowledgment. The earlier
> full FAT/facade run passed 515 tests, zero failures and one native opt-in ignore
> on the same production source with the preceding test-iterator spelling
> (overlay `c7dd1dceddd5c96a8074dac509033d585e61bee63b7f980e02308466243234ad`).
> The corrected iterators visit the same sixteen 32-byte records; every old
> assertion and write/sync tripwire remains. The earlier strict Clippy failure
> on three constant `chunks_exact` calls is retained, rather than suppressed.
> Logs are `check-082-array-chunks-vmi114-0113.log`,
> `clippy-complete-082-array-chunks-0101.log`,
> `fmt-082-array-chunks-ts1-0103.log` and
> `tests-082-parent-array-chunks-0101.log` under the local verification log root.
> The later `5c7d8d76b` FAT root-expansion implementation is outside this cut.
>
> Default `cargo bench -j1 -p ffs-harness` also completed with 60 timing intervals
> across `metadata_parse` and `ondisk_parse` (RCH `30074357740994956`, base
> `990539073` plus overlay
> `a7eafb081c533557501747facea8c7567b1b154dcbea9fbff7afb59649f39eea`).
> This is maintenance qualification, with no incumbent-relative speedup claim.
> Fresh targeted UBS over all six changed Rust files still returns one:
> three critical reports, 453 warnings and 157 information items. The three
> critical sites are test-only CLI-variant and read-only write/sync panic
> tripwires. They remain intact; no scanner rule, exclusion, baseline filter or
> assertion was weakened. Independent scanner disposition and publication remain
> open. No clean UBS, functional closure, native writer or field proof is claimed.

> **Native FAT16 root growth, 2026-10-22:** all nine constructed-image root
> regressions passed (`tests-d452-fat-root-expansion-0207.log`). The permanent
> native runner then passed its root-growth component with 532 captured commands
> (530 successful, two expected refusals) on a native-produced 64 MiB image with
> 512-byte sectors. It filled 512 root slots, expanded to 1,024, preserved raw
> records and three payloads, checked native/FrankenFS writer interchange and
> native fsck, and verified identical plain/bounded output with unchanged sources
> and sentinels. The old CLI failed this same component at its unsupported
> `--root-entries` option. The positive CLI SHA-256 is
> `12af1605e9a1e2f9fbd4f22971a9c87a1820401bbc3d1c72b03670c786641b8b`, built
> from `8dae5e14b` plus overlays with fingerprint
> `d1224d035dd49a9089e6981720f81374c280fef275d98b6493ecc9926ee121be`.
> Log: `native-fat-root-workload-8dae-positive-0327.log` under the local
> verification log root. [The feature contract](docs/FAT_ROOT_EXPANSION.md)
> records retained native evidence. This does not qualify the full six-profile
> runner, native 4096-byte-sector relocation, mounted operation, bootability,
> FSInfo repair, later streaming changes or field use.

> **FAT32 FSInfo recovery, 2026-10-22:** all 11 Rust regressions passed with
> zero failures or ignores (RCH `30074357740995216`). The permanent native
> FSInfo component passed 20 captured commands (17 zero, three exact expected
> nonzero) on a private bounded 128 MiB native-produced image with 512-byte
> sectors. Independent whole-file expectations allow only five words per hint
> sector and four dirty markers during repair; separate ordinary recovery then
> restores clean state. Native allocation, three file payloads, native fsck,
> source hashes and neighboring sentinels passed. The first harness run's wrong
> dirty-check exit expectation is retained; the corrected probe requires exit
> one plus the unchanged complete-ownership/four-marker assertions. Source and
> CLI are the same frozen `8dae5e14b`/`d1224d03`/`12af1605` cut above, runner
> `320d1c13`. Log: `native-fat-fsinfo-8dae-fixed-0339.log`; retained native
> evidence and complete hashes are in [the contract](docs/FAT_FSINFO_RECOVERY.md).
> This proves this offline component, with no full-runner, native 4096-byte,
> kernel-FUSE, crash, later-streaming or field qualification.

> **Strict read-only FAT mounts, 2026-10-22:** the unchanged permanent mounted
> case passed real FAT16 and FAT32 FUSE mounts using the same `8dae5e14b`/
> `d1224d03`/`12af1605` CLI and retained native images. Both mounts completed
> three full and three unaligned byte comparisons, three size checks, one
> EROFS write-open refusal and statfs. Both daemons returned zero and unmounted;
> native fsck passed before/after and all 12 source, payload, tool, CLI and
> workload hashes stayed unchanged. Six captured commands plus two owned mount
> daemons ran. Evidence: CSD `/tmp/fat-ro-mount-8dae-5nkor59r/result.json`, local
> `native-fat-ro-mount-8dae-0345.log`. This qualifies the strict `FatFs` mount
> slice, with no facade-mounted routing, writable, crash or field claim.

> **Consumers of the actual operation outputs:** a separate probe passed 20
> public API calls (eight payloads, eight stats, two listings and two write
> refusals) and two more strict read-only FUSE mounts on the expanded FAT16 and
> recovered FAT32 outputs. Mounted checks covered 16 full/range byte comparisons,
> eight sizes, two EROFS refusals and two statfs calls; both daemons exited zero
> and unmounted. Native fsck and all 15 immutable input/tool/executable hashes
> passed. This ran 26 captured commands plus two mount daemons, retaining CSD
> `/tmp/fat-operation-consumers-68fgd5vi/result.json` and local
> `native-fat-operation-output-consumers-0358.log`. The public consumer remains
> the previously qualified `e862954f...e4ef48` ELF; the mount uses `12af1605`.
> Keep those source cuts distinct. This adds actual output consumption, without
> a facade-mounted, writable, crash or field claim.

> **Final root/FSInfo compiler gates:** `8dae5e14b` plus eight overlays,
> fingerprint
> `7262c1db4f99fdb1f5a8887af02a35b2fa3ea2f290900216853e3d81952f81c5`,
> passed workspace/all-target check (`30074357740995264`), strict Clippy with
> `-D warnings` (`30074357740995256`) and full formatting (`30074357740995259`).
> All returned zero with terminal acknowledgment. The earlier FSInfo Clippy
> failures are retained: two production spelling issues, then two test-lint
> issues. The fixes preserve repair authority, values, assertions and faults.
> Changed FSInfo production and test UBS scans return zero; wider public-hash
> and existing test-panic reports still need independent disposition. No clean
> whole-change scan, publication, closure or later-streaming coverage is claimed.
> The eleven FSInfo tests also reran successfully on the final production source
> (`a02d60b9`, RCH `30074357740995253`, zero failed/ignored, 484 filtered).
> Runtime predates only the two test-only literal/fixture-guard edits, which the
> final compiler/Clippy gates compile. Fresh eight-file Rust UBS returns one,
> with two critical no-write/no-sync test panic guards, 491 warnings and 166 info
> items; the Python runner remains one with public-hash comparison reports.

> **Bounded FAT streaming native execution, 2026-10-22:** `ea0bc8afd` plus nine
> overlays (`ed09c13e`), CLI `a45f6380`, and permanent workload `b0645eed` passed
> 118 captured commands on native FAT16/FAT32 and the actual expanded/recovered
> outputs. Four images/fourteen file instances produced 56 path/exact-selector
> comparisons across plain and bounded selections, 14 native references, eight
> filesystem checks and 16 catalogs. All 24 expected selector/cyclic-tail refusals
> returned one with empty stdout; all 15 immutable hashes stayed unchanged.
> RCH build 95285 returned zero/ACKtrue. Full FAT/facade runtime on `ed09c13e`
> passed 548 tests, zero failed, one existing native-tool test ignored (95283).
> After equivalent test-only lint corrections, all ten streaming regressions
> passed again on final `7d13873c` (95310, zero failed/ignored, 495 filtered).
> Final workspace/all-target check (95301), strict Clippy (95296) and formatting
> (95295) returned zero/ACKtrue on that same cut. Native fragmentation,
> 4096-byte sectors, 4 GiB files, mounted streaming, speedup and field use are
> not claimed. Whole-change UBS remains one with 27 critical public-hash/test-
> tripwire reports pending independent disposition; assertions and scanner rules
> remain intact. Exact hashes, source-cut distinctions, evidence and memory/
> lifetime limits are in [the contract](docs/FAT_BOUNDED_FILE_READS.md).

> **Current public reader refresh, 2026-10-22:** RCH build30075807208570969
> returned zero/ACKtrue on `ea0bc8afd` plus final nine-overlay `7d13873c`.
> Public consumer ELF `eed90a44` passed four check groups, 644 captured commands
> including 516 public calls and 29 expected semantic failures. The permanent
> FAT runner's new `--facade-binary` / `Run.public_reads` path (`9f3751c4`)
> passed266 commands on four retained native/expanded/recovered images and
> eight plain/bounded views:168 byte comparisons,28 file stats,16 native-name
> listings,8 write refusals and16 exact failures. All16 input/payload/tool/
> executable hashes remained unchanged. NTFS passed162 commands/120public
> calls,152 comparisons and3 expected failures, including32 extension streams
> and actual compressed inputs. Retained FAT/ZFS passed164 commands/108public
> calls,6 fresh mcopy reads and50 comparisons of fresh outputs, with6 expected
> failures. Retained ext4/btrfs passed52 public calls with exact prior outputs
> and4 expected failures. The latter two groups include capture equivalence;
> no new native pools or ext4/btrfs producer/oracle execution is claimed.
> EOF is consumer-clamped. These results refresh offline public-reader
> execution across all six formats, not facade mounting, mutable/native writer,
> bounded FsOps cache memory, performance, crash or field acceptance. All146
> prior FAT runner predicates remain intact; an empty-success substitute also
> fails the first public listing check (separate planted-negative proof).
> The full producer runner with its new optional argument was not rerun here;
> its permanent public method executed directly on the four retained images.
> Final ten-file UBS returns one with30 critical public-hash/test-tripwire
> reports; all guards remain intact. Exact receipts are in
> `.beads/pending_tasks.md`; scanner disposition and original acceptance remain
> open.

> **Directory cursor Rust qualification, 2026-10-22:** the cursor introduced in
> `7407fea61` now has executed Rust evidence. On `066563d74` plus `7fd8b10b`,
> the unfiltered FAT/facade run passed558 tests with zero failures and one
> existing native opt-in ignore:515 FAT,40 facade,2 external consumers and1
> doctest. Final test-only assertion spelling fixes retain all67 predicates;
> all10 directory tests passed again on `cc181764` (505 other FAT tests filtered,
> no credit for empty filtered facade/integration selections). Final formatting,
> workspace/all-target check and strict Clippy passed on that final cut.
> Controls cover fragmented/fixed roots, late errors and collisions, cancellation,
> complete-chain admission, native names and bounded cursor retention. FsOps
> still materializes complete listings. Final `cc181764` CLI/public binaries
> (`dc4dc81527c4`/`838ee076b942`) subsequently passed the unchanged native runner:
> six producer scenarios, eight public profiles/16 plain-bounded views and all
> 2,832 exact command statuses. The public consumer executed 1,688 calls with
> 1,368 byte comparisons,228 stats,44 listings,16 write refusals and32 expected
> failures. Eight actual read-only FUSE mounts passed, including the expanded
> FAT16 root and recovered FAT32 outputs:112 full/range/stat file cases, eight
> EROFS write-open refusals and eight statfs checks. All mounts exited cleanly;
> backing/sentinel and executor hashes remained unchanged. The first derived
> mounted-file count incorrectly included two files added after unmount; the
> retained correction establishes112, not114. The initial combined binary build
> timed out137 before the successful standalone builds. Directory UBS remains
> red on two preserved test panic tripwires; independent scanner disposition
> and original acceptance remain open. This is bounded Rust/native read evidence,
> with no performance, general writable/crash or field claim. Exact cuts and commands are in
> `.beads/pending_tasks.md`; the API contract is in
> [the FAT read profile](docs/FAT_READ_PROFILE.md).

> **Public NTFS indexed selection, 2026-10-22:** explicit
> `ReadOnlyBackend::Ntfs { indexed_lookup: true }` now selects the existing
> index-directed FsOps constructor; automatic and explicit strict views retain
> their original scope. Public consumer `1cd83f3db33c`, built from `4cae156cc`
> plus production overlay `8343adea`, passed371 exact command statuses:
> 328public calls,43fresh native-tool reads,309byte comparisons and32expected
> failures. Strict/indexed reads cover plain/bounded native inputs,512/4096-byte
> cluster compression,32extension streams and the13-node/two-level native tree.
> All51control hashes remain unchanged; the old consumer fails at the first
> indexed request. This executes current code on retained native inputs with
> fresh native oracles, not newly produced images. The expanded native producer
> regression also passed: ten healthy option/view combinations, four damaged-FILE
> copies and sixteen successful producer/oracle commands. Full facade, example
> and NTFS library suites passed402 tests, zero failures and zero filtered cases;
> the native opt-in case was explicitly executed separately. All525 FAT library
> tests, workspace/all-target checking, strict Clippy and final formatting passed.
> UBS remains red on a retained test tripwire; independent scanner disposition
> and original acceptance remain open. Indexed readdir still validates every
> target. No indexed kernel-mount, whole-directory integrity or performance
> claim follows. Exact receipts are in `.beads/pending_tasks.md` and
> [the indexed lookup profile](docs/NTFS_INDEXED_LOOKUP.md).

> **Native NTFS mounted slice, 2026-10-21:** the current RCH-delivered Linux CLI
> candidate `3effe8ed21c9af9b5b0f537451e9f64fce869d58ce3d986ebbeb6eb0754d9d76`
> passed 27 indexed positive calls, three semantic negatives and 25 byte
> comparisons against retained native plain/bounded and compressed images.
> Four strict default read-only `NtfsFs` FUSE mounts then passed 24 mounted
> full/range/EOF byte comparisons and eight EROFS/ENOENT refusals. All mounts
> exited and unmounted successfully; all four whole backing hashes were
> unchanged. The complete probe executed 47 captured commands and four owned
> mount daemons. Its first attempt failed before mounting because the host's
> fusermount3 profile excludes `/data/ssd`; private mountpoints under its allowed
> `/tmp` location passed without changing policy or assertions. This proves the
> indexed CLI reader and strict mounted adapter slice, with shared retained
> native inputs. That probe does not prove indexed FsOps mounting, public facade mount
> dispatch, multi-branch native index routing, writable safety or a speedup.
> A separate exclusively created 64MiB native image with 256 distinct files
> subsequently passed multi-branch CLI qualification: independent native raw
> streams decode 13 reachable index nodes, 12 leaves and two levels of child
> traversal. Strict and indexed routes passed 14 positive calls, including 12
> full/ranged byte comparisons, and six typed missing-path negatives. Native
> identities/listings and source payloads agree; all read-phase hashes stayed
> unchanged. This separate result establishes functional routing, with no
> performance, indexed FsOps mount, facade mount or FrankenFS writer claim.

> **2026-09-08 audit status:** The following counts are legacy declared-contract
> counts, not current executed results. In particular, the fast-commit row below
> is partial pending external crash-image verification. Public execution-bound
> reporting now separates declarations from nine mapped, bounded ext4 contracts
> executed through `parity --verify ext4-journal` / `--verify ext4-reference`.
> Remaining mappings and canonical gate coverage stay open in `bd-wh1xk` /
> `bd-lc132`; do not interpret `97/97` as
> successful execution or release readiness.
>
> **2026-09-11 canonical gate binding:** §22.1's seven gate commands are now
> executed rather than assumed. `ffs-harness gates --all` runs each named command
> through the same execution-evidence path the parity commands use, and either
> public parity command accepts `--gate all` (or a single `gateN`) to run them
> alongside its suites. Each gate reports `passed`, `failed`, or
> `not_implemented`; a Cargo filter that selects zero tests is
> `not_implemented` — never a pass — and `readiness_verified` requires every
> capability row to carry executed evidence *and* every canonical gate to pass.
> **2026-09-23 (bd-0r0kc):** gate wrappers landed on 2026-09-22 (`526fd92a`).
> gate1, gate2, gate3, gate4 and gate6 run relevant but *partial* subsets of
> their §22.1 criteria (no kernel `ls -laR`/`debugfs` comparison, no thread
> sanitizer, no 128 MB timing); a `passed` for them means "the mapped subset
> passed", not "every criterion is met". The gate5 and gate7 wrappers only
> called unrelated unit tests (load shedding; a CLI error path), so they were
> removed and both gates report `not_implemented` until a real mounted gate
> exists.
> The gate commands, their packages and their filters are pinned to the spec text
> by `canonical_gates::tests::catalog_commands_equal_the_spec_document`, so the
> catalog cannot drift from §22 silently.
>
> **2026-09-12 btrfs execution binding:** the same evidence path now covers btrfs
> through a fourth suite, `--verify btrfs-reference` (`--test btrfs_kernel_reference`),
> with six exact contract mappings for the rows that suite verifies: superblock
> decode, sys_chunk mapping, item payload decode (ROOT/INODE/DIR/EXTENT_DATA),
> read-only tree walk, transparent decompression, and send/receive streams. Each
> mapping names an exact test that compares a generated image against a golden
> captured from btrfs-progs, so nothing is credited from a filename pattern; the
> suite's own consistency test is deliberately left unmapped because it validates
> the fixture schema rather than filesystem behavior. That suite needs btrfs-progs
> installed at the golden's anchor version, otherwise its tests soft-skip and it
> cannot pass — which is why CI selects its parity suites explicitly instead of
> running every suite.
>
> **2026-09-12 ext4 kernel-differential binding:** a fifth suite,
> `--verify ext4-kernel-differential`, runs five separate differential test
> binaries in one Cargo invocation (group descriptors vs e2fsprogs, indirect block
> addressing vs debugfs blockcount, inode flags/uid/gid vs debugfs, directory
> record coalescing, bitmap checksums), and backs two further rows: `ext4 group
> descriptor decode` and `ext4 indirect block addressing`.
>
> **2026-09-12 cross-package suites:** the suite table now carries a package and a
> list of exact module-qualified test names, so evidence can come from the crates
> that own the behavior instead of only from the harness. `--verify mvcc-lib`
> runs four ffs-mvcc unit tests and backs `MVCC snapshot visibility` and `MVCC
> commit sequencing`; `--verify repair-lib` runs four ffs-repair unit tests and
> backs `repair symbol storage I/O (dual-slot generation commit)` and `corruption
> recovery orchestrator + evidence ledger`. Those eight tests need no external
> tools, so CI selects them alongside the ext4 suites (installing e2fsprogs first,
> because a missing tool makes the differential tests report skipped and the step
> fails closed). Running all eight suites in one invocation executes 77 tests and
> verifies thirty exact contracts of 97 declared rows; readiness stays false until
> every row carries such evidence. Three tests in the differential binaries
> exercise rows already credited through `ext4-reference`, and a contract names
> one suite, so they stay executed but unmapped rather than running
> `kernel_reference` twice.
>
> **2026-09-12 FUSE dispatch binding:** `--verify fuse-lib` runs twelve ffs-fuse unit
> tests at the dispatch boundary — where the FUSE ABI behavior actually lives — and
> backs `FUSE getattr`, `FUSE lookup`, `FUSE readdir`, `FUSE read`, `FUSE readlink`
> and `FUSE ioctl FIEMAP / FIBMAP`, plus `FUSE ioctl EXT4_IOC_GETFLAGS`,
> `FUSE ioctl EXT4_IOC_GETVERSION / EXT4_IOC_SETVERSION` and
> `FUSE ioctl EXT4_IOC_SETFLAGS` through the same suite's ioctl dispatch tests.
> The mounted end-to-end tests stay a separate CI job, and the rows that describe
> the live mount (`FUSE mount runtime`, the mount background scrub lifecycle, the
> ABI 7.40 protocol surface) remain unmapped because no dispatch test can establish
> them.
>
> **2026-09-12 CLI and btrfs ownership:** two more suites put evidence where the
> behavior lives. `--verify cli-e2e` runs whole-binary end-to-end tests from
> `crates/ffs-cli/tests/cli_e2e.rs`, which spawn the built `ffs` executable and
> assert on its observable output, backing `CLI inspect command`, `CLI info
> command`, `CLI fsck command` and `CLI repair command`. `--verify btrfs-lib` runs
> ffs-btrfs unit tests backing `btrfs chunk tree walking`, `btrfs device tree
> discovery`, `btrfs delayed refs parity`, `btrfs crash consistency (WB-I1/WB-I2)`
> and `btrfs metadata writeback serialization`. The same increment added
> `FUSE ioctl FS_IOC_GETFSLABEL / FS_IOC_SETFSLABEL` and
> `FUSE ioctl EXT4_IOC_MOVE_EXT` to `fuse-lib`; the MOVE_EXT row's contract is the
> donor-registration lifecycle and the rejection log fields, because that is what
> the tests actually witness. All ten suites in one invocation execute 96 tests and
> verify forty-one exact contracts of 97 declared rows; readiness stays false.
>
> **2026-09-12 mechanism-level bindings:** `mvcc-lib` grew the conflict-detection and
> copy-on-write tests, backing `FCW conflict detection` (disjoint blocks commit,
> the conflicting block fails with a populated error) and `COW block rewrite path`
> (repeated rewrites land on distinct physical blocks). A new `--verify journal-lib`
> suite runs ffs-journal unit tests and backs `ext4 fast commit replay` (inode body
> carried through replay, forced fallback on unsupported head features) and
> `ext4 JBD2 checksum verification` (commit and descriptor checksums round-trip,
> tampering is detected, replay refuses a block whose data checksum disagrees).
> All eleven suites in one invocation execute 110 tests and verify forty-eight exact
> contracts of 97 declared rows; readiness stays false. The same pass added
> `ext4 path resolution` (a kernel-created image's paths resolve to the inode
> holding the kernel-written content), `FUSE ABI 7.40 protocol surface` (the
> vendored fuser surface exposes the ABI it claims) and
> `FUSE pwritev2/io_uring RWF write intent propagation` (append/no-append offset
> semantics, conflicting flags refused before mutation, read-strict io_uring
> switch).
>
> **2026-09-12 on-disk decode ownership:** a twelfth suite, `--verify ondisk-lib`
> (package ffs-ondisk), backs `ext4 feature flag validation` (unknown compat bits
> accounted for), `ext4 casefold (case-insensitive dirs)` (unicode folds including
> the capital-sigma rule, and a casefold-rebuilt htree stays fold-navigable),
> `btrfs btree header decode` (header parsed at its kernel-documented offsets),
> `btrfs leaf item metadata decode` and `btrfs internal node parsing` (leaf and
> internal items round-trip with keys intact). All twelve suites in one invocation
> execute 117 tests and verify fifty-three exact contracts of 97 declared rows;
> readiness stays false.
>
> **2026-09-12 retention, SSI and infrastructure rows:** `mvcc-lib` grew nine tests
> backing `version retention policy` (bounded chains; pressure advances the oldest
> snapshot only when allowed, refusing at critical pressure with a pinned snapshot)
> and `SSI dangerous-structure detection` (the structure accumulates across records,
> detection stops at the first complete one, and read-only, disjoint and
> empty-write-set cases never form one). Two further suites cover the rows that
> describe the harness itself, which is the only place those rows may draw evidence
> from: `--verify conformance` backs `fixture conformance harness` (fixture and
> golden provenance, and the ext4/btrfs fixtures conform) and
> `--verify profile-artifacts` backs `benchmark harness` (the canonical criterion
> artifacts are committed and structured). With `bd-ljrbw`, all 97 declared
> capability rows across `ext4`, `btrfs`, `FAT16/FAT32`, `NTFS`, `ZFS`, and `TUI`
> are mapped 1:1 to exact contracts in `PARITY_CONTRACTS` across 17 parity suites,
> and all 7 canonical §22.1 gates (`gate1`–`gate7`) have executable gate tests.
>
> **Repair integration update:** explicit request contexts now reach attached
> refresh lifecycles, and failed/cancelled refresh batches preserve pending work.
> Scrub no longer regenerates symbols from detected corruption or recovers from
> known-dirty groups. Full-device reports retain findings outside repair coverage.
> These on-image pipeline fixes do not establish default repair, reserved native
> storage, or mounted restart freshness; `bd-11a8t` / `bd-j7a4e` remain incomplete.
>
> **Native ext4 allocation ownership (`bd-11a8t`, partial evidence 2026-10-13):**
> `ffs native-prepare` now stages allocator-owned per-group tails through an
> immutable unwritten-extent inode, including digest capacity and dual descriptor
> slots, in one internal JBD2 transaction. Cold discovery verifies persisted
> mappings, checksums, allocation and metadata exclusion. Preparation reports
> `protection_active=false`; it does not encode symbols or enable mounted repair.
> RCH core `native_` selection passed 10/10 tests with mandatory native oracles:
> eight groups force an external owner extent node, ordinary allocation avoids
> every tail, existing payload survives, and `e2fsck` accepts checkpointed and
> post-commit-crash replayed ownership. Checksum damage, freed owner/node bitmap
> bits, occupied tails and malformed journals are rejected. Core/journal `jbd2_`
> selection passed 9 + 85 tests, including unchanged-image preflight refusal.
> The pre-fix production run failed that regression because recovery markers
> changed before NoSpace rejection. Source: base `6f9620e7f` plus overlay
> `23febbb70a1c5f447ccb491f3df6b84f0cce79029ce3474d96247252d1f43c56`;
> jobs `j-30062613555576837` and `j-30062613555576838`. Full CLI/journal job
> `j-30062613555576841` passed 393 + 296 tests with no skips. Public CLI build
> `j-30062613555576843` produced binary SHA256
> `d855f4ef96b72a5d5a2d6abcf2dc789c6baf97e760f590ec1d825512b0c0bc76`:
> an actual 64 MiB image preparation/check preserved its payload, passed native
> `e2fsck -fn`, and left the image unchanged on checks and duplicate refusal.
> Its JSON reports eight owned groups and inactive protection. Artifacts are
> retained at `/data/tmp/ffs-chartreusestone-resume38-native-cli-artifacts`.
> A subsequent test-only decimal-to-hex spelling correction preserves the exact
> asserted value; overlay `237d6e32b6d728bbd46d64f6b8e380092a6f9144aa92c7269e057138115a5195`
> passed all 10 native tests again in `j-30062613555576845` and workspace/all-targets
> check in `j-30062613555576846`. Two subsequent test-counter renames preserve
> every value and assertion. Final overlay
> `7a303256ad788b080ebf6fb703e5bd4e9f977839028b7ea1d3063ff7c8d3cfaa`
> passed strict workspace/all-targets Clippy in `j-30062613555576847` and all
> 296 journal tests in `j-30062613555576848`. Formatting also passes. This is
> real-format in-memory-device/native-tool and offline public
> CLI evidence, including a planted crash, not mounted native self-healing.
> Native freshness fencing, encoding, Btrfs ownership and default activation
> remain open on the original Bead.
>
> **Native ext4 source validation (`bd-11a8t`, partial evidence 2026-10-13):**
> explicit offline `ffs native-validate --initialize` now persists per-source
> BLAKE3 digests in owned validation storage; the default command checks them
> without writing. Preparation journals an explicit Prepared whole-plan record.
> Initialization durably binds every group's expected root before local
> publication, then writes and verifies pending/sealed tables outside source
> coverage. Interrupted retries refuse changed sources, missing authority or
> damaged records; successful retries sync even when seals are already visible.
> Source, table and ownership-header integrity reads bypass the block cache.
> Final RCH `native_` selection passed 17 core + 9 CLI tests with mandatory
> native oracles and no ignored tests. Controls include real file-data corruption
> still accepted by metadata-only `e2fsck`, five write interruptions, volatile
> versus durable sync failures, late-group changes and warmed-cache corruption.
> Two test-only planted-red runs against earlier production reproduced incorrect
> success: protocol job `j-30062613555576852` failed four controls; ownership-cache
> job `j-30062613555576858` failed its selected repeat-check control. Final source
> is base `41bc4c2d81b93f379bc324f690c43d046698f013` plus overlay
> `dbdcfa0c4c4d8791ac5ddfba80cf735c56fb5103f4922a79e115f83572adc6a6`:
> native job `j-30062613555576860`, strict workspace/all-target Clippy
> `j-30062613555576859` and workspace/all-target check
> `j-30062613555576862` all passed; formatting also passed. Full CLI/journal job
> `j-30062613555576864` passed 394 + 296 tests with zero failures or ignored tests
> on that same source. Public CLI build
> `j-30062613555576861` produced binary SHA256
> `37feec9cbe0f90d3689b26f6e94ceaae95fa1bc7264332b94120e8b6ff62a304`.
> Its actual 64 MiB/eight-group image run checked 60,183 source blocks,
> preserved the existing payload and left check/idempotent initialization
> images unchanged. After payload block 4417 was corrupted, checking and
> initialization refused without changing the image; `e2fsck -fn` still
> accepted its metadata. Artifacts are retained at
> `/data/tmp/ffs-chartreusestone-resume39-native-cli-artifacts-M1WFos`.
> This is offline real-image and planted-fault evidence. At that revision, symbol
> encoding, durable mounted freshness, Btrfs ownership and default repair were incomplete;
> successful validation reports `protection_active=false`. The bead remains open.

> **Offline native parity (`bd-11a8t`, implementation under validation):**
> `native-encode` now connects sealed source validation, strict descriptor
> admission and generation-bound `FFSRPR01` publication. `native-recover`
> connects digest-validated reconstruction to a read-only capture and new output
> file. Five real-format core controls and six CLI controls are authored;
> Source-bound RCH workspace/all-target Clippy `j-30063314843205638` and
> locked workspace/all-target check `j-30063314843205639` passed, as did
> formatting. Both used base `54df4474c010adab56607d4769ebb016af09c161`
> plus overlay `0b10d340a837a43e6d4091b967f400d613cd362dd5bdda0f407821effb9c92b2`.
> Full repair library job `j-30063314843205640` passed 635 tests with zero
> failures, ignored or filtered tests, including five direct-encoder controls
> and seven strict raw-admission controls. Public build `j-30063314843205645`
> produced worker/retrieved binary SHA256
> `d61fe0a113f2c901dd30f27782e20b06771cb49a39707e185eef3805bc78c99e`.
> Its actual fresh 4 MiB/two-group ext4 run encoded 3,755 source blocks and
> 206 repair blocks at generations `[1, 1]`. Cold checks and repeat encoding
> preserved exact image bytes; native fsck and existing payload checks passed.
> An inadequate budget and changed-source requests refused without image changes.
> After planting damage in payload block 212, reconstruction exported the exact
> 1,024-byte sealed baseline into a new file while leaving the image unchanged;
> an existing output path refused without overwriting it. Metadata-only
> `e2fsck -fn` still accepted the damaged image. Artifacts are retained at
> `/data/tmp/ffs-chartreusestone-resume40-native-cli-artifacts-KmXLsh`.
> This is executed offline real-image/planted-fault evidence, not mounted
> freshness or current-data rollback authority. Full CLI job
> `j-30063314843205647` passed all 400 tests with zero failures, ignored or
> filtered tests on the same source. Native core job `j-30063314843205644`
> was cancelled during dependency compilation and recovered with exit 137;
> no core tests ran. Its unchanged-source retry was refused before submission
> by RCH disk admission. Resumed job `j-30063314843205648` executed the same
> frozen source and passed all 22 selected native core tests: zero failures,
> ignored or measured tests, 1,484 filtered out. This includes all five new
> real-format parity and interrupted-publication controls. Its log is
> `/tmp/ffs-chartreusestone-resume41-native-core1.log`, SHA256
> `e8b14bdc9c14ee0c493b3305de62a1111c58bda5488c70fec93a75829a2b10fd`.
> These tests use real ext4 format and instrumented write/sync fault boundaries;
> they do not establish mounted freshness or hardware crash behavior.
> This partial path admits at most 56,403 source blocks per group, full-block
> symbols of 1,024–65,535 bytes, repair count no greater than source count and
> a checked working budget; oversized groups and 64 KiB symbols are refused.
> Broader native coverage remains a V1 requirement.
> No measured parity percentage or mounted/default repair credit is added.

> **Explicit native write freshness (`bd-11a8t`, partial executed evidence):**
> optional core activation and CLI `--native-repair-memory-mib` connect a single
> protected physical device before constructor recovery. Intended digests derive
> from verified beforeimages and caller writes. A durable Dirty fence precedes
> source mutation; sync verifies all intended and untouched sources before exact
> next-epoch plan/table/parity publication. The compactor shares its caller's
> device Arc. Eight new real-format freshness controls, one compactor authority
> control and one CLI admission/wiring control accompany the implementation.
> Source-bound native core job `j-30063538684821511` passed all 30 selected tests,
> including all eight new controls: zero failures, ignored or measured tests,
> 1,485 filtered out. Shared-compactor job `j-30063538684821512` passed both
> supplied-device authority and existing WAL replay/checkpoint controls, with
> zero failures or ignored tests. Full actual-bin job `j-30063538684821513`
> passed all 401 CLI and 130 FAT tests with zero failures, ignored, measured
> or filtered tests, including the CLI admission/wiring control and all 17 FAT
> creation/growth/name regressions. Each used the combined source below.
> Workspace/all-target compiler check `j-30063538684821505` passed on frozen
> base `f56a350e8b8b45b8b80804e537654a608571ca9d` plus overlay
> `b0de9273011e9c2402a60476d47e256f3d2d30a0095d5ac1d681ab2969b3b8c4`.
> Earlier strict Clippy attempts failed on an existing FAT verification guard
> and five FAT test lints. Equivalent guard/assertion spelling fixes preserve
> every condition. Combined source (base `401fd7402296a0af55f94a07f55a9d1313cd120b`,
> overlay `0e707e9b2f919d59e61d92eca7b23a2d1ac18cfbd8e149bc29a5f9aabdf113f0`)
> passed strict workspace/all-target Clippy `j-30063538684821508` and locked
> workspace/all-target check `j-30063538684821509`; formatting also passed.
> Public build `j-30063538684821510` produced independently matching worker/local
> binary SHA256 `15bd80678f4d25425fe5beb258c3a1ec1e944a4ae1f596f9b08a882ce913445c`.
> A fresh 4 MiB/two-group/1 KiB ext4 actual-FUSE probe passed overwrite,
> new-file inode/block allocation, acknowledged file and directory fsync,
> graceful unmount, cold current-byte/parity verification, independent
> `debugfs` payload equality and `e2fsck -fn`. Generations advanced `[1, 1]`
> to `[9, 9]`, with owner inode 14, 3,755 source blocks and 206 repair blocks.
> The explicit profile uses native/rw, 256 MiB, no background scrub, disabled
> periodic commit, noatime and `FFS_AUTO_UNMOUNT=0`. The first auto-unmount
> attempt failed before mounting because this host disallows `allow_other`;
> that failure is retained and earns no mounted qualification.
> Public read-only recovery from a separately damaged copy exported the exact
> newly fsynced 1,024-byte payload block at generation 9, while both healthy
> and damaged image hashes remained unchanged. Artifacts are retained at
> `/data/tmp/ffs-chartreusestone-resume41-native-mount-artifacts-097Zf8`;
> successful mount log SHA256
> `76d1003baca56728a620c76002d75f3cda0845d69b3b3f066f2baefec17d490a`.
> This is actual mounted execution plus offline planted-file-data recovery
> on a small test image, not hardware power-cut or default repair evidence.
> No performance win or measured parity percentage is claimed.
> Default activation, automatic read repair, interrupted-epoch reconciliation,
> Btrfs ownership and internal dense-solver cancellation latency remain open.

> **Mount worker ownership (`bd-11a8t`, partial evidence 2026-10-12):** ordinary
> CLI scrub and periodic commit now use caller-owned asupersync child regions.
> Shutdown cancels both workers, drains their physical I/O completion receipts,
> preserves worker errors, and retains exclusive image ownership for background
> repair even with read-only client access. At frozen source
> `bc4da5d98a4a3686f2c7fce241ec2ff3f622b525`, RCH job `30059820987973758`
> passed 27 selected unit/real-image controls, including four new controls for
> parent cancellation, queued cancellation, late I/O errors, and panic/Drop
> cleanup. Both real-FUSE tests passed: ordinary unmount drains active workers
> within the existing deadline and preserves clean fsck/readback, while periodic
> commit survives SIGKILL with its disabled negative control. FUSE and filesystem
> oracles were mandatory; no selected test failed or was ignored. The earlier
> job `30059820987973701` failed normal unmount because AppArmor denied the
> `/data/tmp` fixture location; the unchanged test passed with `TMPDIR=/tmp`.
> The passing execution log is `ffs-chartreusestone-resume27-worker-tests.log`.
> RCH job `30059820987973772` subsequently passed the full workspace/all-targets
> compiler check on `5dfc2040c` plus overlay `d14d9f3c` (the same repair source as
> the regeneration tests below). The merged-source checks and tests below also
> retain this coverage. These results do not
> complete native storage, default activation, restart freshness, or the wider
> core/FUSE worker migration on the original bead.

> **Periodic/pressure durability (`bd-dj725`, executed controls; recovery regression open 2026-10-18):**
> RCH `30067604894777420` passed five worker units and four real-FUSE controls
> on `20b10aad4` plus its 58-path reviewed overlay: omitted ext4/btrfs defaults,
> explicit 1-second intervals, equal-duration disabled controls, SIGKILL/remount
> byte checks, native checkers, worker drain, and 2 GiB without fsync. The daemon
> VmHWM was 930,744 KiB against the prospectively fixed 1,048,576 KiB ceiling.
> An older different-host run exceeded that same ceiling; no optimization win
> or universal RSS guarantee follows from this single passing run. On immutable
> `05e3dc76b`, RCH `30067604894777435` passed 24 core controls, including direct
> and unmanaged operations, metadata/data pressure, orphan finalization,
> subvolume/snapshot durability, first/final sync failure retries, concurrent
> writers, and raw-MVCC recovery. Sharded data and checkpointed COW debt use a
> configurable 128 MiB default, acknowledged only after final superblock sync.
> RCH `30067604894777436` passed five worker units and four live controls,
> including timer-disabled btrfs pressure-on/off SIGKILL/remount/checker arms,
> but FAILED the unchanged RSS ceiling: VmHWM 1,210,912 KiB after 2 GiB without
> fsync, against 1,048,576 KiB. Subsequent relative assertions did not execute.
> Both timer helpers were then tightened from interval plus three seconds to
> the original interval plus one second. RCH `30067604894777437` passed both
> real-FUSE timer probes on immutable `e8b250af9`, preserving default/configured
> and equally long disabled arms, native checkers, and fresh-remount byte checks.
> A test-only overlay on `e8b250af9` reproduced an epoch-reclamation backlog
> (RCH `30067604894777439`): after readers unpinned, one collection reclaimed
> 7,168 of 32,769 versions. Commit `076772e09` batches at most 64 moved
> versions per callback under the same epoch pin, retaining grace protection,
> per-version counters, collection budgets, resident cap, and allocator decay.
> Independent review and frozen-workspace formatting passed. RCH
> `30067604894777441` passed five worker units and five real-FUSE controls on
> immutable `076772e09`, including the tightened timer and pressure crash arms.
> After 2 GiB without fsync, VmHWM was 701,944 KiB against the unchanged
> 1,048,576 KiB ceiling; eviction-disabled VmHWM was 3,366,868 KiB, and all
> three original relative assertions also passed. This is one source-qualified
> live measurement, with the earlier losses retained. Strict workspace/all-targets
> Clippy passed on the same source as RCH `30067604894777442`. Full backend MVCC
> RCH `30067604894777440` passed all 607 tests, with zero failures or ignores,
> including protected-reader refusal and actual payload release after unpinning.
> Fresh immutable `866fa911e` has identical Rust and manifests to `076772e09`.
> Strict RCH `30067604894777452` passed `cargo check --workspace --all-targets`,
> and `30067604894777458` passed all 24 selected core/native-oracle controls:
> zero failures or ignores, 1,509 filtered, 94.82 seconds. Both receipts identify
> tree `d438817021858525402420c44c307915bf411064`, with no overlays. The earlier
> failed disk probes remain recorded; a private RCH configuration placed both
> source and target on hz3's separate `/tmp` tmpfs after its actual
> `sbh check /tmp --need 20G` passed. No disk threshold changed. Core attempt
> `30067604894777457` failed source-namespace initialization before compilation
> and ran zero tests; the unchanged retry passed through the normal guards.
> A reviewer outside the implementation checked the source and retained original
> execution output. Initial fresh independent execution was blocked: both hz3
> attempts stopped at namespace initialization before compilation, and the
> alternative vmi1227854 tmpfs lane passed its disk probe but hit the normal
> 300-second queue timeout while another project occupied its slots. Those
> attempts ran zero tests. After that other job finished, strict RCH
> `30067604894777472` independently executed the same frozen command on
> vmi1227854: 24 passed, zero failed or ignored, 1,509 filtered, 14.69 seconds,
> with the same source tree and no-overlay receipt. Its cold compilation took
> 49 minutes 30 seconds. This repeats existing coverage rather than adding 24
> unique controls, and does not qualify the later recovery candidate. Contributor
> cross-reviews are not counted as independent final certification. The
> seven-file UBS scan remains partial/red (13 critical reports); no clean scan
> is claimed. These source-qualified controls do not advance a global parity
> percentage, universal RSS bound, latency guarantee or performance win.
>
> Repository Actions are restored. Hosted CI `39084434442` on `866fa911e`
> passed formatting, strict Clippy and compiler checks, but its workspace test
> step failed: core reported 1,578 passed, one failed and 25 ignored. The failing
> `sharded_mvcc_store_evidence_ledger_records_commits_and_aborts_bd_7ssc7`
> asserted adaptive contention counters under a fixed policy that deliberately
> skips recording them. The original workspace-baseline bead `bd-vuzzq` is
> reopened; its separately reviewed test-only correction and full baseline
> verification are pending. No whole-workspace green result is claimed.
> The same source's xfstests run `39084434440` completed the ext4 job, but the
> btrfs job reached its unchanged 60-minute limit during `generic/027` disk-full
> recovery. Artifact `12121423186` records repeated pressure-commit `ENOSPC`
> failures. This is an unresolved recovery regression against the earlier
> `bd-x4h1q` qualification, not a btrfs suite pass; the original durability item
> remains open while its relationship to the new pressure path is investigated.
> The retained mount log records 15,155 failed pressure attempts over 39 minutes
> 14 seconds before the first recovery commit. Pending COW/data accounting debt
> rose during that interval; it is not RSS. Stable rolled-back physical
> allocation does not establish a new allocator leak. Candidate `374f4604c`
> coalesces failed pressure retries until another configured work budget, while
> an ordinary allocation refusal after real freeing progress can request a
> boundary even with pressure disabled. Admission, post-rollback failure debt
> and latch publication share allocator-write exclusion. Explicit/periodic
> boundaries remain available without that budget. Native planted-ENOSPC,
> unchanged-refusal and recovered-name/payload controls passed independent RCH
> `30067604894777493`: 27 passed, zero failed or ignored, 1,508 filtered,
> 65.54 seconds, tree `d57766d01ab47457f73c9fa192c5a1c395624dcf`, no overlays.
> This includes both first/final sync ENOSPC and the earlier 24 controls.
> The test-only old-runtime probe `30067604894777489` failed both selected
> negatives: the ledger assertion and pressure retry after unlink. These native
> injected failures are not real metadata exhaustion. Two runs on hz3 stopped before
> compilation (SSH timeout, then namespace initialization); neither is a test
> result. Those native runs did not qualify mounted `generic/027`; its later
> hosted completion is recorded below.
> Original real-volume recovery test `btrfs_creates_get_enospc_once_commits_run_out_of_space`
> separately passed independent RCH `30067604894777494` on the same frozen source:
> one passed, zero failed or ignored, 1,534 filtered, 165.64 seconds. It fills a
> 128 MiB image, unlinks its files, then requires fsync and new create/write/read
> success. It does not replace mounted `generic/027`. Subsequent test-helper
> cleanup replaces three constant-formatted tool names with identical literal
> executables, preserving all arguments and assertions; it has separate source
> review, with final runtime gates still pending. Before cleanup, scoped UBS
> reported three inherited constant-tool false positives and 13,856 warnings.
> The final scoped scan exits zero: no critical reports, 13,856 warnings and
> 2,922 informational reports. Neither that result nor the earlier partial/red
> seven-file scan establishes a globally clean tree.
> Hosted follow-up on published `75ec3254f`: xfstests run `39093406212`
> completed the actual btrfs `generic/027` in 2,634 seconds. Retained artifact
> `12125251312` contains all 100 iterations in `generic/027.full`, no 027
> mismatch, and subsequent tests through `generic/241`. Its SHA-256 is
> `46e9a1337a8b3439f4e2944f98dd8d3d6a320076020a58c8212de3dbd7c1594c`.
> Independent review accepted closure of original `bd-x4h1q` on these two
> executed recovery conditions; broader durability and workspace items remain open.
> The job later reached its unchanged one-hour limit; this is not a complete
> btrfs-suite pass. `generic/015` still reports free space of 3,456 outside
> its required 175,760.64–179,311.36 range. The ext4 job completed successfully.
> No performance win is claimed from a comparison between separate runs.
> The same source's workspace CI `39093406215` failed the unchanged
> chunk-growth test's growth-disabled control at create `fill41359.dat`;
> its integration binary reported two passed, one failed and one ignored.
> The growth-enabled candidate and its kernel checks were never reached.
> Independent review identified the test's intended single-boundary workload
> interacting with automatic pressure commits. A three-line, separately owned
> candidate disables pressure in both arms while preserving all 60,000 creates,
> explicit control ENOSPC, default candidate growth and native/kernel checks.
> It remains unlanded and unexecuted; it does not qualify default pressure
> scheduling. Original workspace-baseline acceptance remains open.

> **Filesystem sync ioctl connection (`bd-8u2a5`, native-qualified 2026-10-18):**
> The existing ioctl dispatch reached the default `FsOps::sync_fs` success
> response because `OpenFs` had no override. The original bead is reopened.
> Its override now uses a full btrfs commit in both ordinary and ephemeral
> modes, and the existing ext4 direct/JBD2 checkpoint paths. Cancellation and
> read-only refusal precede I/O; failed boundaries do not acknowledge work.
> Regression-only source `39e247621` failed RCH `30067604894777499`: zero passed,
> one failed, 1,535 filtered, 1.73 seconds, because sync issued no barrier.
> Corrected candidate `cafe23fc0` passed RCH `30067604894777502`: 30 passed,
> zero failed or ignored, 1,507 filtered, 150.45 seconds, no overlays,
> tree `3c2896cc4be2ed11b678afaa84955e6e4f85339a`. Two new native test
> functions cover full-image readback, both btrfs modes, sync/start/wait calls,
> first/final EIO retry, cancellation, and ext4 direct/journaled checkpoints;
> the other 28 repeat existing controls, including real 128 MiB ENOSPC recovery.
> An earlier candidate failed compilation due to two unqualified `Ordering`
> uses and ran zero tests; the explicit qualification corrected those errors.
> Full frozen-source formatting passes. The mandatory FUSE invocation was
> refused by normal RCH slot admission before compilation or tests; local
> fallback was refused. Mounted SIGKILL/checker/remount proof and final
> workspace checks remain required on this original bead.
> A separate, independently owned scanner correction in `51f1db273` inlines
> Cargo's identical compile-time executable path and annotates one trusted
> benchmark executable sink. An adjacent untrusted executable remains detected.
> The exception loses this heuristic at that sink; a future untrusted caller
> invalidates it. No runtime assertions or ignored-test status changed, and
> benchmark hashes are identity witnesses, not authorization. Matched-context
> CLI scans changed from two critical reports to zero; the full working CLI
> retains 389 warnings and 112 informational reports. The manifest-free
> 16-critical diagnostic and earlier three-file nonzero scan remain recorded.
> Final code snapshot `285de1141` passes full-workspace formatting and the
> three-file static UBS scan: zero critical reports, 14,388 warnings and
> 3,099 informational reports, exit zero.
> These helper edits do not relabel the `cafe23fc0` runtime receipt or establish
> a globally clean scan, a parity-percentage increase, or ordinary `syncfs`
> delivery. Latest published `2a50f1449` passes hosted CI `39095726991`
> formatting, strict all-target Clippy and compiler checks. Its workspace tests
> and mounted qualification remain outstanding. Further compilation is blocked
> by failed storage preflights; no guard or workload was reduced.

> **Protected scrub integration (`bd-11a8t`, controls verified 2026-10-12):**
> `ffs-protected-mount` now shares the ordinary CLI's child-region worker and
> completion drain. Both source scans and parity maintenance use its child
> context. Four added controls cover local-stop isolation and running/queued
> parent cancellation, alongside the 25 existing scrub controls. All 29 passed in
> RCH job `30059820987973812` on base `10554dc68` plus overlay `d83601d389a6`.
> The same invocation passed 34 ordinary CLI/repair, 106 FAT, 113 NTFS, 115 ZFS
> and two ordinary-mount FUSE tests: 399 total, no failures, ignores or skips.
> Log: `ffs-chartreusestone-resume29-integrated-tests6.log`. Workspace/all-targets
> checking passed on the identical source in RCH job `30059820987973806`.
> Strict workspace/all-targets Clippy passed in RCH job `30062009357697036`,
> followed by the compiler check in `30062009357697038`. Both used base
> `fa547bdf3` plus overlay `a247339f089f59793f4e4bb1dac24304353c25c978d572e15c7fe218a221dd96`,
> including the repair publication fix and behavior-preserving lint corrections.
> Logs: `ffs-chartreusestone-resume35-clippy5.log` and
> `ffs-chartreusestone-resume35-workspace-check3.log`. RCH job
> `30062009357697037` passed all 407 selected CLI tests on that source: FAT 113,
> NTFS 124, protected mount 48 and ZFS 122, with no failures, ignores or skips.
> Log: `ffs-chartreusestone-resume35-cli-tests2.log`. On the same source, RCH job
> `30062009357697039` passed all 72 selected on-disk FAT/RAIDZ/LZX/nvlist/ZPL/gang
> and NTFS EA tests, including all 16 gang cases, with no failures or ignores.
> Log: `ffs-chartreusestone-resume35-parser-tests.log`. These are unit, fixture
> and captured-vector results. RCH job `30062009357697042` passed both protected
> real-FUSE lifecycle cases on the same source and independently hashed binaries.
> Source and parity scans completed before foreground reads: ext4 verified 32 MiB
> across 128 groups in 4.070 s; Btrfs verified 128 MiB across 512 groups in 31.243 s.
> Both passed normal unmount, daemon exit, restart/readback, unchanged image/archive
> hashes, archive verification and independent ext4/Btrfs checks. The tests ran as
> root, with required FUSE/oracles and unchanged deadlines. The preceding job
> `30062009357697041` failed startup because the worker's FUSE configuration
> disallowed non-root `allow_other`, which fuser adds for automatic unmount;
> it supplied no scrub proof. No source or host configuration changed for the rerun.
> Logs: `ffs-chartreusestone-resume35-protected-fuse.log` and
> `ffs-chartreusestone-resume35-protected-fuse-root.log` (SHA-256
> `9cd45da6a5386564dcbf593a3dbac5d9822e8f06d8894ffaf5c3bcc8b3971786`).
> These are privileged healthy-sidecar lifecycle results; they do not demonstrate
> native repair ownership, crash freshness or mounted corruption recovery.
> The first integrated run stopped on a malformed NTFS sparse-attribute fixture
> before protected tests. Its correction retains all rejection and zero-payload
> read checks and strengthens the sparse refusal reason; the corrected case
> passed in that earlier 113-test NTFS cohort and the current 124-test cohort.
> The original failure remains recorded.
> Native storage, default activation and mounted native corruption/restart
> acceptance remain open.

> **Protected parity scheduling (`bd-11a8t`, 2026-10-13):** parity maintenance
> now attempts a complete pass after each source scan, before the configured
> interval. Previously only 64 steps ran per interval: 512 groups needed nine
> source cycles, including final publication. The geometry-derived attempt
> budget retains 64-step batches and stops the cycle on completion, contention,
> pending writes, cancellation, shutdown or error. Repeated epoch resets cannot
> create an unbounded retry or a false completed-pass report. Final archive
> rebuild still holds the serializer across a full-image scan; this change does
> not establish a foreground I/O latency bound.
> A real 129-group archive with damaged tail parity reproduced the old timeout
> in RCH job `30062009357697044`: one selected test failed after 30.22 s on
> `287f5ccc9` plus test-only overlay `81be0e8cc296`. The first attempt (`7043`)
> failed malformed fixture geometry and supplies no scheduling evidence; the
> corrected fixture respects the existing geometry gate. With the fix, RCH job
> `30062009357697045` passed all 54 protected CLI tests, including repaired
> archive reopen/tail reconstruction, batch boundaries, epoch churn, writer
> deferral and cancellation. Command: `cargo test -p ffs-cli --bin
> ffs-protected-mount -- --nocapture`, executed remotely with one Cargo job and
> debug information disabled. Source: `287f5ccc97d2283d049a1a5312c87a3c030e1e1c`
> plus four-file overlay
> `9a9401d807120135c5a4603e129420e61d38bf545e747871600d919bb2e1a1fa`.
> Logs: `ffs-chartreusestone-resume36-red2.log` and
> `ffs-chartreusestone-resume36-cli-tests.log`. On the same source, RCH job
> `30062009357697046` passed all 622 repair-library tests (`cargo test -p
> ffs-repair --lib -- --nocapture`), and `30062009357697047` passed
> `cargo check --workspace --all-targets`. Logs:
> `ffs-chartreusestone-resume36-repair-tests.log` and
> `ffs-chartreusestone-resume36-check.log`. Strict workspace/all-targets Clippy
> (`cargo clippy --workspace --all-targets -- -D warnings`) passed unchanged on
> `vmi1227854`, RCH job `30062009357697049`, remote/wrapper exit 0. Log:
> `/data/tmp/ffs-chartreusestone-resume36-clippy2.log`. The earlier `hz4` Clippy
> job `7048` stalled under measured shared I/O pressure and was cancelled with
> terminal recovery acknowledged; it supplies neither a lint pass nor a source
> failure. Formatting also passed.
> RCH job `30062009357697052` passed both strengthened real-FUSE lifecycle
> cases on the same source: 2 passed, 0 failed/ignored, 292 filtered. The first
> source/parity cycle covered Btrfs 128 MiB/512 groups and ext4 32 MiB/128 groups.
> Both retained ordinary unmount, exact 65,553-byte restart readback, unchanged
> image/archive hashes, archive verification and native filesystem checks.
> Command: `cargo test -p ffs-harness --test fuse_e2e --
> scrub_lifecycle_bd_11a8t --nocapture --test-threads=1`, through RCH on `hz4`
> with required FUSE/oracles and Cargo's sudo runner. Public binaries were built
> by RCH job `30062009357697051`; worker and retrieved executable hashes matched.
> Log: `/data/tmp/ffs-chartreusestone-resume36-fuse.log` (SHA-256
> `5396b826cc744e7e40bd4f3f52cd7b69aa3743589a6f7a1c8c4b05fb6dbdb7c0`);
> images, archives and mount logs are retained in
> `/data/tmp/ffs-chartreusestone-resume36-protected-hz4/`.
> This is privileged healthy-sidecar evidence, not mounted corruption or a
> comparative benchmark. Native ownership, default activation and native
> corruption/restart acceptance remain open on the original bead.

> **Protected periodic durability (`bd-11a8t`, partial evidence 2026-10-13):**
> writable `ffs-protected-mount` now shares the ordinary mount's periodic commit
> worker: ext4 defaults to 5 seconds and Btrfs to 30 seconds, including without
> scrub. `--commit-interval-secs` overrides the interval; zero disables it and
> requires `--rw`. Both workers receive cancellation before either is drained,
> and release their filesystem ownership before the final checkpoint. Scheduling
> intervals do not establish a crash-loss deadline or replace acknowledged fsync.
> The old protected binary reproduced the missing publication while an unsynced
> writer remained open: RCH job `30062390921920513` failed its selected ext4
> scenario after the 120-second observation window, with unchanged image and
> archive hashes. The final harness strengthens the observation to two completed
> ticks before capture, independent archive/native filesystem checks and a second
> mounted readback; its live execution is recorded separately below.
> Validation also exposed two concrete defects: chunk-item parsing synthesized
> tree-root object ID 3 instead of chunk-item object ID 256, and dropping a repair
> ownership transaction could retain its OS lock while a duplicate descriptor was
> alive. The parser now emits 256 and passes strict serialization/readback. The
> transaction explicitly unlocks at scope exit, including post-lock cancellation;
> independent acquisition still fails while the transaction is active. Its real
> duplicate-descriptor regression failed on old production in RCH job
> `30062390921920525`, then passed with the fix. Nine synthetic CLI Btrfs fixtures
> were corrected to supply the device identities and committed inventory already
> required by normal admission; existing CLI assertions and rejection checks were
> retained. A defective parser assertion was independently reviewed against the
> format constants and corrected from 3 to literal 256, adding strict roundtrips.
> Final affected-suite command: `cargo test -p ffs-repair -p ffs-cli -p ffs-btrfs
> --lib --bin ffs-cli --bin ffs-protected-mount -- --nocapture`, through RCH on
> `hz4`, job `30062390921920526`, remote/wrapper exit 0. Results: 623 repair,
> 387 ordinary CLI, 57 protected CLI and 481 Btrfs tests passed; one existing
> manual timing benchmark remains ignored. Source: `e5bc215f2f7c3598bc996a1eb3165a0152354d55`
> plus eight-file overlay
> `a645cbe84539b51cd865f0a07baff0e5e1887cb12d901fe3f2f5b14015a01907`.
> Log: `/data/tmp/ffs-chartreusestone-resume37-final-tests.log`.
> On the same source, strict workspace/all-targets Clippy passed with
> `-D warnings` in RCH job `30062390921920527` on `vmi1227854`,
> remote/wrapper exit 0. Log: `/data/tmp/ffs-chartreusestone-resume37-clippy6.log`.
> Final workspace/all-targets `cargo check` passed on the same source in RCH job
> `30062390921920529` on `vmi1227854`, remote/wrapper exit 0. Log:
> `/data/tmp/ffs-chartreusestone-resume37-check-final2.log`.
> Formatting and the dependency-cycle check also passed.
> RCH job `30062390921920528` built both public binaries on `hz3`; worker and
> retrieved SHA-256 hashes match: `ffs-protected-mount`
> `c4f48fae994de10dde6a015b3c455e8e8a1e38ce948fb7f900d1856c58056b68`,
> `ffs-image-repair`
> `ca18cef6f0f7f4ca502a35a4f811a5396aca8d097c56619f10a8310c454a846a`.
> RCH job `30062390921920530` passed all six real-FUSE protected CLI cases on
> `hz3`: 6 passed, 0 failed/ignored, 290 filtered, 185.69 seconds. Command:
> `cargo test -p ffs-harness --test fuse_e2e -- protected_sidecar_cli_
> --nocapture --test-threads=1`, with required FUSE/native oracles and Cargo's
> sudo runner. The new periodic cases kept the writer open without explicit
> fsync; two default ticks completed in 10,727 ms for ext4 and 62,019 ms for
> Btrfs. Captured image/archive pairs passed independent archive verification,
> native filesystem checks and exact 65,553-byte readback through a second
> mount before original shutdown. Existing corruption/restart and scrub cases
> also passed. Across the suite, 16 mounts exited normally and two deliberate
> startup-mismatch controls refused with exit 4; no forced/lazy unmount was used.
> Log: `/data/tmp/ffs-chartreusestone-resume37-fuse-hz3.log`, SHA-256
> `7ee633b029428f895081921747c0d2ca315482a035f2c28f7167ff10ee70f5df`.
> Images, archives and mount outputs are retained in
> `/data/tmp/ffs-chartreusestone-resume37-protected-hz3/`; both periodic capture
> pairs independently hash-match the worker artifacts.
> This is privileged, explicit compatibility-sidecar evidence; it does not
> demonstrate native/default activation or survival of a power failure.
> These controls do not complete native repair storage ownership, default
> activation, durable pre-write freshness or native mounted corruption/restart
> acceptance. The original bead remains open.

> **Explicit regeneration (`bd-11a8t`, verified controls 2026-10-12):** the CLI
> ext4 and Btrfs rebuild paths now use the existing descriptor high-water reader
> to resume interrupted symbol publication. They freshly scan each source range
> and refuse incomplete coverage or detected corruption before encoding. New
> controls cover durable pending generations, corrupt/ambiguous descriptors,
> generation exhaustion, incompatible geometry, I/O/cancellation errors, and a
> real checksummed ext4 directory corruption followed by regeneration. RCH job
> `30059820987973769` passed all five new controls, two existing repair regressions,
> the 27 lifecycle/image controls and both real-FUSE tests: 34 + 2 passed, none
> failed or ignored. The source was `5dfc2040c` plus the test-local block-device
> imports, frozen by overlay fingerprint
> `d14d9f3cf0dd03645709b05d9d238ae67ab3dd0d09a3c7c26f189147d9ac5b76`;
> the log is `ffs-chartreusestone-resume27-rebuild-tests2.log`. The initial
> unmodified source failed compilation on those missing test imports and ran no
> tests. The regeneration controls use real files, a planted interrupted write,
> and a checksummed ext4 image; they do not prove mounted native repair or full
> source authentication. The same source passed the full workspace/all-targets
> compiler check in RCH job `30059820987973772`; its log is
> `ffs-chartreusestone-resume27-workspace-check.log`.
>
> **Repair refresh publication (`bd-11a8t`, unit controls verified 2026-10-12):**
> the pipeline now relies on storage's descriptor publication and sync instead
> of issuing another fallible descriptor write afterward. Generation exhaustion
> returns a typed error before encoding, preserving data and the dirty state.
> RCH job `30059820987973826` passed all 622 repair library tests, including two
> new regressions for publication and the last valid/exhausted generations.
> Source: base `fa547bdf3` plus pipeline overlay
> `8e2eb8c509b9deda35d3d77cff6196ac95702f6c97da87e8d273aeeb8047ecfa`;
> log: `ffs-chartreusestone-resume33-repair-tests.log`. These tests use real
> codec/storage logic with an in-memory device and simulated sync boundary.
> They do not prove hardware durability, mounted recovery or native freshness.
> Later evidence-ledger writes remain fallible after publication.
>
> **Merged execution evidence (2026-10-12):** source `30c41fe2` plus seven
> formatting corrections (overlay `5681abf2e3fe57e15b8b33199881aa51ef1fd11378b8cd789fea08660f53f8a5`)
> passed workspace/all-targets check in RCH job `30059820987973781`. Job
> `30059820987973783` passed 171 tests: 34 repair/lifecycle controls, 59 FAT
> reader/OEM controls, 76 ZFS reader controls, and both real-FUSE lifecycle
> tests. Job `30059820987973787` passed 28 on-disk FAT/RAIDZ controls. None
> failed or was ignored. FAT/ZFS reader cases use constructed images and direct
> filesystem operations; they do not prove native FAT/OpenZFS mounted
> interoperability. Logs are `ffs-chartreusestone-resume27-workspace-check-merged2.log`,
> `ffs-chartreusestone-resume27-integrated-tests.log`, and
> `ffs-chartreusestone-resume27-ondisk-tests.log`. The first merged check attempt
> was refused by RCH memory admission before execution; capacity later recovered
> without intervention. The subsequent `767054ae` merge adds upstream NTFS LZX
> and ZFS user attributes. Strict Clippy job `30059820987973791` found three
> incoming codec lints; checked LZX position conversion and equivalent RAIDZ
> iteration/mask passing address them without allowances. Revalidation and the
> new regressions remain pending: subsequent RCH requests timed out before
> compiler execution because the admitted worker's slots were occupied.
> Source `277776282` then integrated the upstream gang-header parser. Review
> found its scalar header-allocation argument rejected valid replicas on vdevs
> with different sector sizes. The parser now validates allocation per DVA;
> all 13 original controls and checksum goldens remain, with three added
> unequal-allocation/count controls. These 16 tests await Rust execution.
> Strict Clippy job `30059820987973795` ran on `277776282` plus overlay
> `680c30f1f285d1ad32e13e58d18011eb97521b0dd4db1f5a9a4fb38dd099bed2`
> and found two incoming gang-parser lints. Explicit generation ranges and a
> renamed checksum buffer address them; the unchanged strict gate still needs
> to pass. Full formatting passes, and independent source review preserves the
> parser-only scope: existing mounted readers still refuse gang I/O.
> The original native storage/default activation/restart requirements remain
> open. No capacity guard or validation gate was weakened.
>
> **Compatibility repair (`bd-7zjfh`, verified 2026-10-11):** FFSRQSC2 sidecars
> are the compatibility-mode repair substrate, exposed through the explicit
> `ffs-protected-mount` binary. Native mode retains the allocator-owned,
> per-group on-image target in `bd-11a8t`. Both production-CLI FUSE tests,
> `protected_sidecar_cli_ext4_corruption_restart_bd_7zjfh` and
> `protected_sidecar_cli_btrfs_corruption_restart_bd_7zjfh`, passed through RCH
> at `c85b828c934e654e8d486a03fc6d3463d2aa476a`: two passed, none failed or
> ignored, with FUSE and filesystem oracles required. Each repairs a cold
> post-admission fault to exact payload and whole-image bytes, checks read-only
> refusal, verifies and remounts an independent image/archive pair captured
> immediately after fsync, then repairs newly written bytes after clean restart.
> Startup mismatch returns exit 4 without altering either file. All successful
> mounts exit normally without forced or lazy cleanup, and all independent
> `e2fsck -f -n` / `btrfs check --readonly` checks pass. Journalled ext4 now
> attaches its internal writer and syncs JBD2 cleanup before acknowledging fsync;
> two protected CLI and four core journal controls passed separately at
> `044077a2622ccf0137a19937fcd55eb9f4d4907c`. The mounted log is
> `/tmp/ffs-chartreusestone-resume21-7zjfh-mounted.log`, SHA256
> `ff5173a06b609728d38e21a90bf012a35946be7cf47bdef2834b3c4ef67a6a29`.
> This proves explicit single-image sidecar mounts, not default self-healing,
> native ownership, multi-device repair or recovery from an unfinished epoch.
>
> **Repair-tail safety (`bd-plamw`, verified 2026-10-11):** complete requested
> symbol/descriptor plans now fail closed before their first write. Explicit
> rebuild admission precedes journal/superblock recovery; unsafe mounted repair
> refuses worker startup while detection-only scrub retains its groups. Ext4
> allocation proof includes reserved metadata, checksummed lazy groups and cluster
> granularity; Btrfs requires one unambiguous chunk for the complete aligned
> physical span, unique physical ownership across chunks and DUP copies, a clean
> allocation view and exclusion of reserved superblock stripes.
> `FFS_REPAIR_TAIL_UNSAFE` carries structured refusal evidence. Eight core
> allocation controls and 23 selected CLI controls passed: the CLI results
> comprise 20 unchanged controls at `aa2345fc` and three corrected fixture
> controls at `6953d969`; core controls passed at `6953d969`.
> Real kernel-filled ext4 and Btrfs images reached 4 KiB ENOSPC, with FIEMAP
> proving written payload in each refused tail. Offline repair returned exit 4;
> background repair returned exit 1 before mounting or creating its ledger.
> All four whole-image hashes and both complete file manifests matched for
> each filesystem; both pre/post `e2fsck -f -n` or `btrfs check --readonly`
> checks returned zero, with successful read-only kernel readback and cleanup.
> The ext4 case passed at harness `f79583f2`; Btrfs passed at `c437fcdc`.
> Both used the unchanged `6953d969` CLI, SHA256
> `74ade1470382b365c5d194f761691a23739491216c852671e891ffd8141a6086`.
> Retained execution logs: `/data/tmp/ffs-chartreusestone-resume14-p0-live4.log`
> (ext4 passed; that batch remains red for the old Btrfs mount-option error)
> and `/data/tmp/ffs-chartreusestone-resume14-p0-live5.log` (Btrfs: one passed,
> none failed or ignored). Independent Agent Mail review 1608 records source
> provenance, hashes and earlier failed fixture runs; no assertion was relaxed.
> This is an interim interlock: repair tails are still not allocator-reserved,
> ordinary on-image read-write mounted repair remains refused, and native storage
> is still required. Explicit compatibility sidecar mounts use the separate path
> described above.
>
> **Btrfs fsync update:** full transaction commits now flush committed MVCC
> file data before publishing extent metadata and checksums. A real non-inline
> payload previously failed checksum verification after fsync and reopen; the
> regression now passes alongside six tree-log crash/replay tests in
> `crates/ffs-core/tests/btrfs_tree_log_leak.rs` and
> `crates/ffs-core/tests/btrfs_tree_log_crash_replay.rs`. This repairs a missing
> durability step; full-workspace and external crash certification remain open.
>
> **Ext4 symlink update:** inode allocation, target data and directory publication
> now commit together. The mounted 4095-byte target regression no longer returns
> EAGAIN. `readlink` distinguishes a 60-byte extent-backed target from inline
> storage, and creation rejects targets that cannot fit with NUL in one filesystem
> block. Scoped 1 KiB/4 KiB image tests verify boundary behavior, reopen and clean
> e2fsck results; htree name collisions preserve allocation counts and the commit
> sequence. This does not establish open-unlink lifetime or workspace acceptance;
> `bd-vuzzq` remains incomplete.

| Domain | Implemented | Total Tracked | Coverage |
|--------|-------------|---------------|----------|
| ext4 metadata parsing | 27 | 27 | 100.0% |
| btrfs metadata parsing | 27 | 27 | 100.0% |
| MVCC/COW core | 14 | 14 | 100.0% |
| FUSE surface | 19 | 19 | 100.0% |
| self-healing durability policy | 10 | 10 | 100.0% |
| **Overall** | **97** | **97** | **100.0%** |

> **Canonical source:** This Coverage Summary table in `FEATURE_PARITY.md` is the
> single source of truth for implemented/total counts. `ParityReport::current()`
> in `ffs-harness` parses this file, and a CI test
> (`parity_report_matches_feature_parity_md`) enforces the mapping.
>
> **Interpretation rule:** "100% coverage" means every capability row in the
> tracked V1 denominator has a defined, implemented, and tested contract. That
> contract may be success, bounded partial behavior, or deterministic
> rejection. Unsupported operations that are intentionally part of the V1
> surface therefore remain compatible with 100% tracked parity when their
> rejection behavior is itself implemented and validated.
>
> **Boundary rule:** this table measures the tracked V1 feature denominator.
> It does not certify production readiness, current xfstests pass rate,
> performance targets, or every future hardening task. Operational bridge items
> are tracked through support-state accounting, which distinguishes validated,
> experimental, detection-only, dry-run-only, parse-only, single-device-only,
> basic-coverage, disabled, opt-in-mutating, unsupported, deferred, and
> host-blocked states before public docs or release gates can strengthen a
> claim. The checked-in release-gate policy
> (`tests/release-gates/release_gate_policy_v1.json`) is the machine-readable
> map from those public claim classes to proof-bundle lanes, thresholds, kill
> switches, remediation beads, or explicit non-goals.
>
> **Adaptive runtime boundary:** optional backpressure/per-core mount runtime
> remains default-off and does not strengthen `swarm.responsiveness` or any
> public readiness wording from local dry-run evidence. Any upgrade requires a
> fresh proof-bundle `adaptive_runtime` lane with `accepted_large_host` evidence,
> clean cleanup, and the permissioned runner/validator artifacts linked by
> `bd-jv6pj.6`.

## 2. Tracked Capability Matrix

| Capability | Legacy Reference | Status | Notes |
|------------|------------------|--------|-------|
| ext4 superblock decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ext4`, including `s_mmp_*`, flex-group sizing, reserved GDT fields, `s_backup_bgs`, and quota-inode metadata parsing (`s_usr_quota_inum`, `s_grp_quota_inum`, `s_prj_quota_inum`) with feature-aware accessors. Test coverage in `crates/ffs-harness/tests/kernel_reference.rs::ext4_kernel_vs_ffs_superblock`. |
| ext4 inode core decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ext4`. Test coverage in `crates/ffs-harness/tests/conformance.rs` via inode metadata reads. |
| ext4 extent header decode | `fs/ext4/ext4_extents.h` | ✅ | Implemented in `ffs-ext4`. Test coverage in `crates/ffs-harness/tests/kernel_reference.rs` via extent tree parsing. |
| ext4 extent entry decode | `fs/ext4/ext4_extents.h` | ✅ | Implemented in `ffs-ext4`, with `crates/ffs-harness/tests/kernel_reference.rs` now differentially comparing `collect_extents` against `debugfs blocks` on generated contiguous and deterministic two-extent reference files. |
| ext4 feature flag validation | `fs/ext4/super.c` | ✅ | Mount validation includes supported incompat/ro_compat policy plus conservative MMP enforcement: clean MMP state mounts, and `fsck`, active-writer, or unsafe/unknown MMP states reject deterministically with `EOPNOTSUPP` because FrankenFS V1 does not participate in periodic MMP heartbeat updates. Test coverage in `crates/ffs-harness/tests/conformance.rs` via mount acceptance tests. |
| ext4 group descriptor decode | `fs/ext4/ext4.h` | ✅ | Implemented in `ffs-ondisk` (`Ext4GroupDesc`), including bitmap checksum fields. Test coverage in `crates/ffs-harness/tests/ext4_group_desc_kernel_reference.rs`. |
| ext4 directory entry parsing | `fs/ext4/dir.c` | ✅ | Implemented in `ffs-ondisk`. Test coverage in `crates/ffs-harness/tests/conformance.rs` via readdir operations. |
| ext4 inode device read | `fs/ext4/inode.c` | ✅ | `OpenFs::read_inode` via `ByteDevice`. Test coverage in `crates/ffs-harness/tests/conformance.rs` via inode reads. |
| ext4 path resolution | `fs/ext4/namei.c` | ✅ | `OpenFs::resolve_path` handles absolute paths, including `..` parent traversal via on-disk directory entries. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` verifies multi-level nested resolution and absolute dot-dot traversal. |
| ext4 bitmap free space reading | `fs/ext4/balloc.c` | ✅ | `OpenFs::free_space_summary`, bitmap-derived free block/inode counts, bitmap checksum verification, and allocator-side reservation of sparse/flex metadata blocks. Test coverage in `crates/ffs-harness/tests/conformance.rs` via free-space checks. |
| ext4 journal replay parity | `fs/ext4/ext4_jbd2.c` | ✅ | Journal replay and write-side transaction integration are implemented and validated through harness + E2E coverage in `crates/ffs-harness/tests/ext4_journal_recovery.rs`. |
| ext4 allocator parity | `fs/ext4/mballoc.c` | ✅ | Allocator mutation path is implemented with persistence, correctness guards, and validated mutation coverage in `crates/ffs-harness/tests/conformance.rs`. |
| ext4 orphan recovery parity | `fs/ext4/orphan.c` | ✅ | Mount-time orphan cleanup implemented in `ffs-core` (`OpenFs::maybe_recover_ext4_orphans`): tolerant chain traversal (cycle/out-of-range guardrails), delete-or-truncate recovery actions, and superblock orphan-state clearing (`s_last_orphan`, `EXT4_ORPHAN_FS`). Read-only orphan diagnostics remain available via `OpenFs::read_ext4_orphan_list` + CLI inspect output. Test coverage in `crates/ffs-core/src/lib.rs::open_fs_recovers_deleted_ext4_orphan_inode`, `open_fs_recovers_truncated_ext4_orphan_inode`, `open_fs_recovers_orphan_list_with_invalid_head` (10 orphan tests total). |
| btrfs superblock decode | `fs/btrfs/disk-io.c` | ✅ | Implemented in `ffs-ondisk`, including sector/node/stripe size-field validation, zero-capacity, zero-device, and impossible `bytes_used > total_bytes` accounting rejection, root/chunk/log tree-level validation against the kernel maximum level, and fail-closed checksum-type validation for the currently supported CRC32C superblock format. Test coverage in `crates/ffs-harness/tests/btrfs_kernel_reference.rs::btrfs_small_superblock_and_root_tree_match_golden`. |
| btrfs btree header decode | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-ondisk`. Test coverage in `crates/ffs-harness/tests/conformance.rs` via tree traversal. |
| btrfs leaf item metadata decode | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-ondisk`. Test coverage in `crates/ffs-harness/tests/conformance.rs` via item parsing. |
| btrfs internal node parsing | `fs/btrfs/ctree.c` | ✅ | `parse_internal_items` in `ffs-ondisk`. Test coverage in `crates/ffs-harness/tests/conformance.rs` via multilevel tree walks. |
| btrfs sys_chunk mapping | `fs/btrfs/volumes.c` | ✅ | `map_logical_to_physical` in `ffs-ondisk`, with proptest + metamorphic coverage in `crates/ffs-ondisk/src/btrfs.rs` for translation covariance, chunk-order permutation invariance, and Single-vs-DUP primary mapping equivalence. |
| btrfs read-only tree walk | `fs/btrfs/ctree.c` | ✅ | `walk_tree` in `ffs-btrfs`. Test coverage in `crates/ffs-harness/tests/conformance.rs` via directory/file enumeration. |
| btrfs item payload decode (ROOT/INODE/DIR/EXTENT_DATA) | `fs/btrfs/ctree.c` | ✅ | Implemented in `ffs-btrfs` (`parse_root_item`, `parse_root_ref`, `parse_inode_refs`, `parse_inode_item`, `parse_dir_items`, `parse_xattr_items`, `parse_extent_data`) with direct cargo-fuzz coverage in `fuzz_btrfs_tree_items` for deterministic decode and field-level payload invariants. `parse_root_item()` reads level/UUID fields from the packed kernel layout, invalidates UUID-era fields when `generation_v2` is stale, rejects impossible tree levels, and rejects partial extension-field fragments; `parse_root_ref()` rejects zero-length names and trailing bytes after the declared name; `parse_inode_refs()`, `parse_dir_items()`, and `parse_xattr_items()` reject zero-length names; `parse_dir_items()` rejects nonzero `data_len` payloads that belong to xattr-shaped items instead of directory entries; `parse_inode_item()` rejects payloads that are not the fixed 160-byte `btrfs_inode_item` size and rejects impossible timestamp nanoseconds before they reach `Duration`/`SystemTime` conversion paths; and `parse_extent_data()` rejects unsupported extent compression values, nonzero encryption/other-encoding fields, trailing bytes after fixed regular/prealloc payloads, invalid source-slice arithmetic, and uncompressed regular/prealloc disk ranges that exceed `disk_num_bytes`. |
| btrfs open/validate pipeline | `fs/btrfs/disk-io.c` | ✅ | `BtrfsContext` in `ffs-core`. Test coverage in `crates/ffs-harness/tests/conformance.rs` via mount open operations. |
| btrfs transaction parity | `fs/btrfs/transaction.c` | ✅ | Transaction begin/commit/abort semantics and integration paths are implemented with coverage in unit + E2E suites. |
| btrfs delayed refs parity | `fs/btrfs/delayed-ref.c` | ✅ | `DelayedRefQueue` + `BtrfsRef` model + bounded flush/refcount tracking in `ffs-btrfs::BtrfsExtentAllocator`, with queue/refcount/stress tests, deterministic property coverage, failed-flush atomicity, and checked insert-overflow rejection so retry preserves both the queue and materialized refcounts. The allocator now also exposes fragmentation-aware largest-free-extent discovery from block-group/extent-tree gaps, and `OpenFs::largest_contiguous_free_run` uses that value for btrfs instead of reporting total free bytes as a conservative upper bound. |
| btrfs scrub parity | `fs/btrfs/scrub.c` | ✅ | Scrub validation and repair-path coverage are implemented in the current test matrix. |
| btrfs transparent decompression (ZLIB/LZO/ZSTD) | `fs/btrfs/compression.c` | ✅ | `btrfs_decompress()` in `ffs-core` with flate2 (ZLIB), lzokay-native (LZO), and zstd crates. Inline + regular extent decompression wired into read path, with exact `ram_bytes` decoded-length validation and malformed LZO frame rejection. All 3 codecs supported. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies mounted-root `lookup` plus exact regular-extent reads for ZLIB, LZO, and ZSTD compressed files, including a cross-page read slice through the decompressed view. |
| btrfs subvolume mount | `fs/btrfs/ioctl.c` | ✅ | `BtrfsContext::subvol_objectid` configurable; `walk_btrfs_fs_tree` resolves the requested tree root. `BTRFS_IOC_INO_LOOKUP` now follows the requested `treeid` contract: `treeid=0` reports the mounted subvolume objectid, explicit tree ids walk their matching ROOT_ITEM fs tree, and root-object lookups return a NUL-terminated empty path. Harness coverage still proves the default root alias, and `crates/ffs-cli/src/main.rs` now adds operator-path coverage for named `--subvol` and `--snapshot` selection through the mount open path, including mounted-root `getattr`/`lookup`/`readdir`/`read` behavior scoped to the selected tree. `crates/ffs-harness/tests/fuse_e2e.rs` now adds FUSE E2E coverage (`#[ignore]` requiring sudo) for subvolume/snapshot mount selection proving root scoping to selected tree and `NotFound` errors for missing subvolumes, plus a mounted-path `BTRFS_IOC_INO_LOOKUP` ioctl probe covering `treeid=0` root resolution, seeded workspace path lookup, runtime-created child lookup through the writable COW tree, and missing-object `ENOENT`. Read-write (bd-5elw6) works on the default subvolume, a `--subvol`, or a writable `--snapshot`: the commit publishes the tree under the mounted root's ROOT_ITEM and files its backrefs against that root (`BtrfsAllocState::fs_root_objectid`); a read-only (`-r`) snapshot refuses `--rw`. A subvolume the kernel has snapshotted or relocated (`btrfs balance`) IS writable: `enable_writes` releases the shared on-disk tree kernel-style (`btrfs_release_shared_fs_tree`, `ffs-btrfs::backrefs`; always for a non-default subvolume), and `..._writable_kernel_snapshot_...`, `..._tall_writable_kernel_snapshot_...`, `..._kernel_created_subvolume_...` and `..._balanced_kernel_subvolume_...` check the mounted subvolume's new bytes and the other subvolume's originals, while `fuse_e2e.rs::btrfs_rw_on_a_kernel_snapshotted_default_subvolume_bd_5elw6`, `..._balanced_image_...`, `..._tall_snapshotted_tree_...` and `..._snapshotted_then_balanced_image_...` check `btrfs check` plus kernel reads of the snapshot and live files. **Gap:** a subvolume nested inside the mounted tree is not entered; its entry presents as an empty directory with a synthetic inode (the kernel's unreachable-subvolume shape), and rmdir/rename of it return EPERM (`btrfs_nested_subvolume_link_is_not_aliased_to_a_parent_tree_inode`). The kernel descends into it. |
| ext4 inline data read | `fs/ext4/inline.c` | ✅ | `read_ext4_inline_data()` reads from inode extent_bytes + system.data xattr. `INLINE_DATA` removed from rejected features. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` verifies real `OpenFs::read` behavior for both pure-`i_block` inline payloads and `system.data` xattr continuation payloads, and `crates/ffs-harness/tests/fuse_e2e.rs` now verifies mounted-path ordinary reads plus near-EOF short reads for both storage layouts. |
| ext4 indirect block addressing | `fs/ext4/inode.c` | ✅ | `resolve_indirect_block()` handles direct + single/double/triple indirect pointers. `EXTENTS` no longer required at mount. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies single/double indirect block resolution and I/O boundaries for non-extent inodes. |
| ext4 fallocate range operations | `fs/ext4/extents.c` | ✅ | ZERO_RANGE mode (0x10) zeroes allocated blocks in range via the write path. COLLAPSE_RANGE (0x08) removes a block-aligned interior range, shifts the tail left, shrinks `i_size`, and now rejects ranges that reach EOF with `EINVAL`; INSERT_RANGE (0x20) inserts a zero-reading block-aligned hole inside the file, shifts the tail right, and grows `i_size`. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` verifies `OpenFs::fallocate` zero-range preservation, collapse shifting/shrinking plus EOF rejection with no mutation, and insert hole/growth behavior, while `crates/ffs-harness/tests/fuse_e2e.rs` verifies the real FUSE path emits the `ext4_rw_fallocate_zero_range_zeroes_range` contract while preserving unaffected bytes. |
| ext4 fast commit replay | `fs/ext4/fast_commit.c` | Partial | `replay_fast_commit()` parses committed FC operations. `OpenFs` applies directory/inode updates, inline range deletion and coordinated single-leaf external extent recovery after JBD2 replay. Incomplete application, unsupported growth, unreadable targets and final mapping mismatches now reject recovery; a fallback-marked stream containing committed operations cannot silently become JBD2-only success. `SimulateOverlay` applies into its private overlay; `Skip` remains diagnostic. Memory-device regression cases live under `fast_commit_apply_` and `fast_commit_external_` in `crates/ffs-core/src/lib.rs`; kernel crash-image certification covers one scenario (`fuse_e2e.rs::fast_commit_crash_image_recovery_matches_kernel_bd_9m84h`: created files and an append made durable only by fsync; FrankenFS's recovery equals the kernel's, e2fsck -fn clean). This is a bounded implementation, not full kernel FC compatibility or an execution-derived passing parity count. |
| btrfs tree-log replay | `fs/btrfs/tree-log.c` | ✅ | `replay_tree_log()` in ffs-btrfs walks tree-log tree when `log_root != 0`, returns items for FS tree merge, and is wired into the mount path. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies multilevel log-tree replay through chunk mapping plus the zero-`log_root` fast path, and `fuzz/fuzz_targets/fuzz_btrfs_tree_log.rs` now coverage-fuzzes synthesized tree-log recovery over valid multilevel trees, absent log roots, checksum/structure failures, and equivalent chunk mappings. Kernel-written logs are replayed as a read view with the kernel's name rules (INODE_REF-implied entries, `replay_dir_deletes` over DIR_LOG_INDEX ranges, `unlink_old_inode_refs` for renames across directories), each checked against a kernel recovery of the same crash image in `fuse_e2e.rs::btrfs_kernel_tree_log_*`. **Gap:** INODE_EXTREF items in a log are not replayed; Linux 7.0 committed instead of logging them in every case probed. |
| ext4 casefold (case-insensitive dirs) | `fs/ext4/namei.c` | ✅ | `lookup_in_dir_block_casefold()` with Unicode lowercase comparison. CASEFOLD removed from rejected features. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies real `OpenFs` lookup/readdir behavior on a CASEFOLD-flagged ext4 directory image. |
| ext4 fscrypt (nokey read-only mode) | `fs/ext4/crypto.c` | ✅ | ENCRYPT removed from rejected features. Encrypted filenames shown as raw bytes (nokey mode). Full decryption requires key management not in V1. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` verifies raw-byte `readdir`/`lookup` on an `ENCRYPT`-flagged ext4 image, and `crates/ffs-harness/tests/fuse_e2e.rs` now freezes the same operator-visible mounted-path contract for raw-byte `readdir` plus path lookup. `crates/ffs-core/src/lib.rs` now unit-tests v1 and v2 fscrypt context extraction for `get_encryption_policy_ex()`, plus `ENODATA` on unencrypted inodes. `crates/ffs-fuse/src/lib.rs` unit-tests both the legacy `_IOW` request shape for `FS_IOC_GET_ENCRYPTION_POLICY` and the `_IOWR` `FS_IOC_GET_ENCRYPTION_POLICY_EX` path, including v1 encoding, v2-context passthrough, short-buffer rejection, and `ENODATA` on unencrypted inodes. `crates/ffs-harness/tests/fuse_e2e.rs` also verifies mounted-path `ENODATA` for an unencrypted inode and makes current restricted-FUSE ioctl transport gaps auditable: the request reaches `ffs-fuse::ioctl`, but current kernels can surface `EIO` for the legacy getter's `out_size == 0` shape and for `_EX` variable-size output that this `fuser` reply path cannot renegotiate with retry iovecs. |
| btrfs multi-device RAID | `fs/btrfs/volumes.c` | 🟡 | `OpenOptions::btrfs_device_paths` / repeatable CLI `--btrfs-device` connects validated backings to bootstrap, metadata and file-data reads. Clean multi-device images use device-set routing even without extra paths. Each lone RAID1 survivor passes core/FUSE ordinary, zstd and NODATASUM reads. Every committed chunk requires coverage: RAID1/C3/C4 need one copy; RAID10 needs a survivor in every validated mirror group. Four-device kernel RAID10 tests cover all 14 nonempty proper subsets, with core/FUSE ordinary-data reads for supported subsets and refusal when a group is lost. Three-device C3/four-device C4 kernel images cover all 6/14 proper nonempty subsets through ordinary full-file/unaligned core reads and cold FUSE reads; profile geometry is validated before admission. Mixed mirrored-metadata/RAID0-data images reject missing data devices. No implicit sibling discovery. Healthy RAID0/RAID1/RAID10/C3/C4/RAID5/RAID6 reads pass with each primary; foreign/duplicate attachments and cancelled opens are rejected. RAID1/RAID10/C3/C4 chunk/root/fs-tree and ordinary/zstd corruption tests recover with only the final mirror healthy through core and cold FUSE reads, and refuse all-copy corruption without changing caller output. They also cover unaligned reads, verification opt-out, NODATASUM behavior and refusal when the sole healthy mirror is unattached. The full corruption/missing-device/checksum-codec matrix remains open. Reads use caller `Cx`; cancellation stops retries. Multi-device mounts require clean tree logs and no MVCC WAL. Device-count reconciliation now precedes reader selection, with separate image evidence below. Seed-device inventories and read-only seed/sprout routing have independent kernel/public-CLI evidence below; dirty-image recovery remains unsupported. RAID5/6 reads rebuild up to one/two missing stripes from parity for data and tree nodes; required-FUSE kernel-image tests now cover every tolerated omission through both library mounts and the public CLI, including nested files and both checksum variants. Public CLI clean-device evidence and retained artifacts are detailed below. Multi-device writes remain deferred and refused. |
| btrfs send/receive streams | `fs/btrfs/send.c` | ✅ | `parse_send_stream()` in ffs-btrfs parses the btrfs send stream format (magic, version, per-command CRC32C, required END terminator, 22 command types, attribute TLV encoding). Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` verifies multi-command TLV parsing, missing-END rejection, plus unknown-command fallback to `Unspec` while preserving attributes, and `crates/ffs-harness/tests/btrfs_kernel_reference.rs` differentially compares FrankenFS normalization against upstream `btrfs receive --dump` on a CRC-valid synthetic send stream. |
| btrfs chunk tree walking | `fs/btrfs/volumes.c` | ✅ | `walk_chunk_tree()` in ffs-btrfs walks chunk tree beyond sys_chunk_array for complete chunk map. `parse_chunk_item()` parses individual chunk items, rejects zero stripe device IDs and zero io_align/io_width/sector_size geometry fields at the parser boundary, and rejects trailing bytes after the declared stripe array. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now verifies chunk-tree discovery extends the bootstrap chunk map and returns sorted parsed entries. |
| btrfs device tree discovery | `fs/btrfs/volumes.c`, `fs/btrfs/ioctl.c` | 🟡 | `FS_INFO` and `DEV_INFO` use DEV_ITEM records from the live writable or checksum-verified committed CHUNK_TREE; DEV_TREE holds device extents instead. Validation checks record keys/IDs, UUID uniqueness, filesystem membership and backing identity. Admission reconciles stale nonzero counts; later enumeration validates against that mounted inventory count. `FS_INFO` reports the mounted filesystem's own count and maximum ID, including unused devices but excluding foreign-FSID seeds. `DEV_INFO` accepts every validated inventory ID, including attached seeds, with optional exact UUID and current per-device accounting. Core tests cover maximum IDs, unused devices, corrupt/partial inventories, live allocation and full commit/reopen with independent `btrfs check`; exact inventory checks include `crates/ffs-core/src/lib.rs::tests::btrfs_dev_info_enumerates_unused_sparse_device` and `crates/ffs-core/src/lib.rs::tests::btrfs_dev_info_rejects_incomplete_or_conflicting_inventory`. Tool-generated images cover independent raw-field inventory checks in `crates/ffs-harness/tests/fuse_e2e.rs::btrfs_openfs_ioctl_dev_info_two_device_inventory` and RAID0/RAID1 read-only attachment through FUSE. Explicit attachments are checked against the inventory and chunk stripe identities; foreign seeds additionally bind to their frozen generation. Count-publication image evidence is recorded below. Independent seed/sprout kernel/public-CLI qualification passed, including five matching inventory ioctls; the full multi-device I/O matrix is not complete. |
| btrfs metadata writeback serialization | `fs/btrfs/ctree.c`, `fs/btrfs/extent-tree.c` | ✅ | Full end-to-end serializer infrastructure: `DiskWritebackContext::serialize_node`, `WriteDependencyDag`, `WritebackExecutor`, and `btrfs_full_transaction_commit` now wire through `BtrfsAllocState.extent_alloc.alloc_metadata_for_tree` to allocate real logical addresses from chunk-covered block groups. `DiskWritebackContext::with_allocated_addresses` accepts pre-allocated block→bytenr mappings, and `block_to_bytenr` resolves them. ROOT_TREE is now properly modeled: `BtrfsAllocState.root_tree` tracks ROOT_ITEMs, commit updates the FS_TREE ROOT_ITEM with new location, commits ROOT_TREE, and sets `superblock.root` to ROOT_TREE (not FS_TREE). Coverage in `crates/ffs-btrfs/src/writeback.rs::dag_from_cow_tree_captures_structure` and 32 related writeback DAG tests. |
| btrfs crash consistency (WB-I1/WB-I2) | `fs/btrfs/transaction.c`, `fs/btrfs/disk-io.c` | ✅ | DPOR oracles for WB-I1 (prefix-closed durability) and WB-I2 (atomic generation transition) pass against the `WritebackExecutor` simulator (33 tests including crash-point coverage). The real writeback path now uses allocated logical addresses from chunk-covered block groups, so invariants apply to disk-bound commits. Writeback sequence: FS_TREE nodes → ROOT_ITEM patch → ROOT_TREE nodes → fsync barrier → superblock commit. **ExecutedEvidence:** bd-xuo95.31 executed the writeback-cache crash matrix via DPOR. |
| btrfs RW durability (remount persistence) | `fs/btrfs/super.c` | ✅ | **Durable by default.** Mounted btrfs images accept writes through FUSE, and unmount commits the in-memory CoW trees to disk via `btrfs_full_transaction_commit`. The commit sequence allocates real logical addresses from chunk-covered metadata block groups via `BtrfsAllocState::alloc_metadata_for_tree`, rewrites internal child blockptrs to those addresses via `BtrfsNodeSerializeParams::child_bytenrs`, translates logical→physical via `map_logical_to_physical` for each device write, updates the FS_TREE ROOT_ITEM, commits EXTENT_TREE preserving existing extent accounting (bd-is7m1), commits ROOT_TREE the same way, and patches the on-disk superblock in place. Coverage in `scripts/e2e/ffs_btrfs_rw_durable_remount_e2e.sh` (6/6 mutations survive, byte-exact content); `btrfs inspect-internal dump-tree` cleanly renders both ROOT_TREE and FS_TREE of FrankenFS-written images. |
| ext4 COMPRESSION (e2compr R/W) | `fs/ext4/inode.c` | ✅ | Full bidirectional e2compr support for the V1 codec set. **Read**: cluster detection via `EXT4_COMPRBLK_FL` + sentinel `0xFFFFFFFF` block pointer, 16-byte cluster header parsing (magic `0x8EC7`, method, holemap, checksum, ulen/clen), seeded Adler-32 checksum verification, gzip/LZO decompression, and checked holemap-based block unpacking that rejects unconsumed decoded bytes. **Write**: cluster-aligned compression with automatic fallback to uncompressed when compression doesn't help, holemap construction for zero-block holes, Adler-32 checksumming, sentinel block pointer management. Gzip (flate2, levels 1-9), LZO (lzokay-native), and passthrough none codecs are supported bidirectionally. Rare legacy method indices 0 (`lzv1`), 4 (`bzip2`), and 8 (`lzrw3a`) are explicit V1 exclusions and reject with codec-specific `EOPNOTSUPP` for both compression and decompression. Harness integration coverage in `crates/ffs-harness/tests/conformance.rs` now exercises real ext4 e2compr write/read/rewrite behavior for both gzip and LZO on a writable mkfs image, including COMPRBLK marking and stable free-block accounting across rewrites. |
| ext4 JOURNAL_DEV paired-open | `fs/ext4/super.c` | ✅ | Standalone journal device detection (JOURNAL_DEV incompat flag → clear error with guidance). Data filesystems with non-zero `journal_dev` now support paired-open replay through `OpenOptions::external_journal_path`: UUID and block-size validation, external JBD2 replay into the data device, and deterministic refusal when crash recovery is required but the external journal is missing or mismatched. Harness integration coverage in `crates/ffs-harness/tests/ext4_journal_recovery.rs` exercises paired-open replay plus missing/mismatched journal refusal, and `fuzz/fuzz_targets/fuzz_jbd2_replay.rs` now coverage-fuzzes the main JBD2 descriptor/commit/revoke replay engine over equivalent region and segment layouts. |
| ext4 JBD2 checksum verification | `fs/jbd2/recovery.c` | ✅ | CRC32C verification for JBD2 descriptor, revoke, and commit blocks (V2/V3 features). Implemented in `verify_jbd2_block_checksum()` with V3 UUID-seeded checksums and tail-position validation. Direct `ffs-journal` coverage now proves descriptor/revoke checksum roundtrips, tamper detection, and commit-block V3 UUID-seed validation. |

Ext4 request-scoped truncation now publishes bitmap frees and free-space credits
together, including indirect data and pointer blocks. Aborted or conflicting
requests preserve concurrent allocations; repeated and deferred truncation
credits each free once. Sharded inode preparation likewise publishes its bitmap,
descriptor and initialized slot together. An injected preparation failure leaves
the allocation bitmap, counters, cursor, flags and commit sequence unchanged.
Both defects reproduced before their respective fixes.

At source `24e20f7521fabfbe632801c79884b29636927bdc`, RCH execution passed
32 affected core tests and the CLI default-selection test, with zero failures.
One existing performance measurement remained ignored. Coverage includes both
allocator modes, extent/indirect commit and abort, conflicting/deferred scopes,
concurrent create/delete, directory churn, rename replacement, retained data,
inode-slot merging, and injected file/directory preparation failures followed by
successful reuse. The real formatted-image controls passed `e2fsck`; these are
OpenFs tests, not mounted workload or performance evidence. CLI mounts continue
to enable sharded allocation by default, while raw OpenFs instances start with
the runtime toggle disabled.

The original mounted acceptance also passed at source
`c936e2371e8c336ddd94d0fe80149e5f54405fa6`, with
`FFS_BHH0I_SHARDED=1`: 40 cycles × 2,000 empty files on a 2,048 MiB image,
then four cycles × 300 files × 16 KiB on a 512 MiB image. The unchanged
`scripts/pbyu0_mounted_repro.sh` completed all 81,200 create/delete pairs.
An independent observer required zero unlink/sync errors, normal daemon exit,
the enabled-sharded marker, absent mounts and full `e2fsck -f -n` exit zero
for both images. Logs are
`/tmp/ffs-chartreusestone-resume19-y2t0r-mounted-empty.log` and
`/tmp/ffs-chartreusestone-resume22-y2t0r-mounted-data.log`.
Workspace/all-targets check and strict Clippy passed through RCH at the same
source. These sequential mounted workloads supplement the concurrent core
controls; they make no mounted parallel-throughput claim.

Seed/sprout attachment implementation now has executed core-test evidence in
`btrfs_seed_sprout_admits_only_the_committed_frozen_seed` and
`btrfs_seed_sprout_inherited_handles_recheck_frozen_role`. The fixtures place
metadata and payload only on an explicitly attached, older foreign-FSID seed.
They verify ordinary and encoded reads, nested views, own-filesystem `FS_INFO`,
seed `DEV_INFO`, mutation refusal, unchanged images, seven checksum-correct
identity/role corruptions and inherited-handle revalidation. At source receipt
`c094d0208214e2a29d910bf40ac29a682a5f9a87`, the affected admission/inventory,
seed, RAID, nested-view and Single/DUP cohort passed 42 tests with no failures or
ignored tests through RCH. Workspace/all-targets Clippy with `-D warnings` also
passed at that receipt. These are unit and compiler results, not mounted proof.
The independent mounted seed/sprout test, OS read-only descriptor control and
two-checksum CLI profile rerun subsequently passed as recorded below;
`bd-hk5w3` and `bd-mjxxk` are closed on that executed evidence. Each result
retains its original source and scope.

Standalone btrfs seed protection has unit coverage in
`ffs-core::tests::btrfs_enable_writes_preserves_read_only_seed_devices` and
`ffs-core::tests::btrfs_seed_rejects_public_transaction_and_repair_mutations`.
Both pass: seed files remain readable, ordinary images permit writes, and
seed write admission, transaction publication, repair staging and MVCC
flushes refuse mutation without changing backing bytes. The option matrix
covers skipped validation and ephemeral tree-log mode. The flush test plants
an existing MVCC version; it does not exercise WAL replay. The CLI unit-test
binary's `btrfs_seed_image_reads_but_refuses_write_admission_and_repair` also
passes against a real `mkfs.btrfs`/`btrfstune` image with
`FFS_REQUIRE_ORACLES=1`, unchanged whole-image hashes and `btrfs check --readonly`.
This exercises OpenFs and the CLI scrub setup, not a mounted CLI process.
Seed/sprout routing and standalone `fsck --repair` remain outside that proof.

Device-count reconciliation now validates the committed CHUNK_TREE inventory
before ROOT_TREE traversal or writer selection. Opening normalizes a stale
nonzero count in memory without changing the image; full and tree-log commits
publish the correction. On 2026-10-10, the strict-remote CLI test
`btrfs_device_count_reconciles_real_image_before_read_and_commit` passed all
four CRC32C/xxHash64 × full/tree-log combinations. Each checks advertised counts
1, 2, 3 and `u64::MAX`, exact payload reads, unchanged admission hashes, corrected
durable count/checksum, reopened mutation and an independent read-only
`btrfs check`. An explicit log-root assertion distinguishes the two commit
paths. These are formatted-image OpenFs executions, not count-corruption FUSE
coverage. On 2026-10-11, all 42 affected core controls independently passed at
`6953d96932b2d7e21c4b5c1153f03e8edd7174d4`; the real OS read-only descriptor
control passed at `aa2345fc141197d8e8922c041c869244dcd2a671`. The seed routing
and these controls are unchanged from the live-profile source below. Agent Mail
1595 records the commands, source comparison and logs
`/data/tmp/ffs-jadevalley-seed-p0-units2.log` and
`/data/tmp/ffs-jadevalley-seed-p0-units3.log`. These unit controls supplement
the separate live evidence; the first combined run also contained three repair
fixture failures, corrected and rerun without weakening their assertions.

On 2026-10-11, the independent strict-RCH test
`btrfs_cli_seed_sprout_reads_kernel_generated_files` passed against kernel-created
seed/sprout images with `FFS_REQUIRE_FUSE=1` and `FFS_REQUIRE_ORACLES=1`:
one test passed, none failed/ignored, and no scenarios skipped. It checked four
kernel readbacks, two physical-owner readbacks, thirteen mounted file probes,
five kernel-matching inventory ioctls, `EROFS` for writes/create, wrong-seed
startup refusal and unchanged hashes of all three images. Successful unmount
needed no forced or lazy cleanup. The source receipt was
`a553870d568b6ba4f787c9760adc928bc4da93eb`; CLI SHA256 was
`7f227b27ae4f95d19f33c1e05fd2c78d18e340edd33f48c4d46413ad42558118`.
The run is recorded in Agent Mail message 1583 and the `bd-hk5w3` evidence thread;
its log is `/data/tmp/ffs-jadevalley-seed-live2.log`. This establishes live
seed/sprout read-only routing, not multi-device writes or dirty-image recovery.

The independent public-CLI profile rerun also passed on 2026-10-11: two tests,
zero failures or ignored cases, 78 successful mounts, 82 expected refusals,
1,248 mounted probes and 32 kernel readbacks. It covers CRC32C and xxHash64
for RAID0, RAID1, mixed RAID0-data/mirrored-metadata, RAID10, RAID1C3, RAID1C4,
RAID5 and RAID6, including the documented tolerated device omissions. The
source receipt is `558f106e51c7dc93c6edc187748bdcb9bfce91d0`; CLI SHA256 is
`5956354220aab51d3eb4c7bef361d3b500ae68acc629e3f31d367a71ff17782a`.
The log is `/data/tmp/ffs-jadevalley-seed-profiles2.log`. The earlier seed/sprout
execution above used its separately recorded source and binary.

Attached-device tree reads now reject headers whose filesystem UUID is absent
from the admitted device identities, including checksum-correct foreign blocks.
The identity check runs inside both mirror validation and parity recovery.
On 2026-10-10, the synthetic regressions
`btrfs_metadata_mirrors_reject_foreign_fsid_before_acceptance` and
`btrfs_metadata_parity_rejects_foreign_fsid_before_acceptance` both failed against
the old reader and passed after the fix. They cover zero/foreign IDs, empty
identity inventories, mirror fallback and RAID6 recovery through Q after P
reconstructs a foreign block. A strict-remote `ffs-core --lib` cohort passed
13 tests with `FFS_REQUIRE_ORACLES=1`, including existing cancellation,
generation-inspection and encoded-read checks, degraded RAID5/6 formatted-image
opens, and metadata operations checked by `btrfs check`. These are unit and
formatted-image OpenFs results, not mounted foreign-header evidence.

Singleton/DUP metadata now applies the same identity rule before ROOT_TREE
bootstrap, log replay and node-cache admission. A corrupt referenced extent
tree refuses write admission; unreadable log replay refuses opening. Fresh
generation inspection and shared-tree release retain header fields from the
accepted copy rather than a cached or separately selected block. On 2026-10-10,
a strict-RCH `ffs-core --lib` cohort with `FFS_REQUIRE_ORACLES=1` passed 25 tests
(zero failed/ignored), including seven new singleton cases. These cover
checksum-correct foreign headers, real formatted DUP recovery, shared-reference
conversion, corruption of both log levels, public-MVCC inspection freshness,
and cancellation before another DUP backend read. Existing generation, cache,
tree-log, subvolume and `btrfs check` controls also passed. These are synthetic
and formatted-image executions, not mounted foreign-header injection.

Write admission now also requires the canonical `(2, ROOT_ITEM, 0)` extent root.
Missing or wrongly keyed roots cannot seed an empty allocator, and invalid root
payloads (including zero addresses) return corruption/EIO before writes become
available. Both new regressions failed against the previous missing-root path;
the corrected metadata/admission cohort passed 31 tests with no failures or
ignored cases under strict RCH and `FFS_REQUIRE_ORACLES=1`. Coverage includes
both read-validation options and commit modes, unchanged readable file bytes,
and corruption of both ROOT_TREE copies in a real formatted DUP image. The
synthetic writer fixtures now carry an explicit empty extent tree; they do not
prove complete allocation accounting or durable format compatibility.
The same core source passed four strict mounted tests (`FFS_REQUIRE_FUSE=1`),
emitting six PASS scenarios with no skips: ext4 and btrfs kernel readback of
FrankenFS-written images, btrfs DUP second-copy recovery, kernel tree-log replay,
and writes to snapshotted default and writable snapshot subvolumes. This is
positive compatibility evidence; the damaged-root refusal cases above execute
through OpenFs rather than an injected-corruption mount.
That earlier Btrfs run also reproduced the separately tracked inline-fallocate
data loss and random-fallocate `NoSpace` failures (`bd-zx0fk`). The subsequent
repair and current results are recorded below. Seed/sprout and profile live
qualification and final affected unit results are recorded above.

Raw MVCC writes now invalidate the Btrfs semantic view and its retained nested
views. Subsequent cached reads, metadata operations and allocator use return
`ESTALE`; raw flush/retry remains available, followed by reopening the image.
This covers FCW/SSI publication, caller-staged request scopes, repair writes,
WAL recovery and journal I/O that can change backing bytes before failing.
Empty non-journaled commits preserve the view. The family gate serializes raw
publication with active semantic operations. Btrfs cache eviction skips active
requests instead of waiting on a publisher that needs the same gate.
This implements refusal safety, not transparent cache refresh or newly
qualified multi-device mutation support. Raw external writes through a device
handle remain outside this publication contract.
Both original coherence regressions failed against the old implementation.
At source `ba498483374b70c9767a28c8931a5b2e0f4918a7`, strict RCH execution
passed all 46 selected raw-publication, metadata, mutation and repair controls
(zero failed or ignored). This includes the corrected writable-DATA fixture,
rejected FCW/SSI conflicts and registered-scope eviction. These are unit and
formatter-backed OpenFs checks; the native-thread overlap probes do not establish
LabRuntime/DPOR coverage.

Btrfs inline-to-regular preallocation now preserves the inline file until its
replacement is ready and restores metadata/allocation state if any later step
fails. Regular extent lengths and their checksums cover whole sectors while
KEEP_SIZE preserves the exact file length. The original patterned-data regression
passes through commit, reopen, checksum verification and `btrfs check`; early
conversion ENOSPC and later preallocation ENOSPC both retain the original bytes
and allocation state. An unchanged eleven-operation churn reproduction also
passes on a real formatted image, including exact reclamation accounting across
commit, reopen and external validation.

The randomized fallocate gate retains all 96 cases, operation ranges, unexpected
error rejection and byte/size assertions. Its former DATA-only 512 KiB fixture
could neither satisfy the generated COW workload nor allocate commit metadata.
An independently reviewed, property-local 64 MiB mixed fixture now provides an
explicit generator-derived capacity budget without adding a formatter skip.
This is synthetic model coverage, separate from the formatter-backed proof above.
Two independently reviewed extent/FIEMAP assertions now require the canonical
4096-byte regular extent rather than an invalid unaligned payload length; exact
file sizes, contents and extent flags remain checked.

At source `79d5a09cc54b0088925b4f7fb1fdbefcfc8e0d56`, strict RCH execution of
`cargo test -j2 -p ffs-core --lib -- btrfs --nocapture --test-threads=1` passed
511 tests, failed none and retained 10 existing ignored tests. Mounted controls at the
same production source (receipt `d5f66241e166fd593f944965c52891e4afc15537`)
executed seven positive scenarios across five tests: KEEP_SIZE data preservation,
tree-log recovery, two writable-snapshot modes, ext4/Btrfs kernel readback and
Btrfs DUP recovery. The sixth selected test internally skipped FIEMAP because
the host kernel returned EOPNOTSUPP before dispatch; it is not live FIEMAP proof.
The original `generic/112` AIO/mmap qualification remains unmet: available workers
lack fsx and its AIO/XFS build headers, and the upstream preallocation variants
require an XFS reservation ioctl. `bd-zx0fk` remains open for that original
workload; these results do not establish a new parity percentage.
An independent agent re-executed the 17 critical core regressions at source
`79d5a09` on a second health-checked RCH worker: all passed with required external
oracles enabled. The final source, `ab5a5293554ac8c0c1587c9d4d24cc90acc859ab`,
differs only in two branch reorderings requested by Clippy. It passed workspace
check and Clippy (`--workspace --all-targets`, `-D warnings` for Clippy), formatting,
and a final affected cohort: 94 passed, zero failed, three existing tests ignored.
That cohort covers fallocate, all 12 raw-MVCC regressions and KEEP_SIZE FIEMAP,
including the unchanged 96-case randomized model test with external oracles
required. The ignores cover an ext4 profiler and two previously unsupported or
unreachable ext4 cases; no new ignore or runtime skip was added.

Ext4 xattr parity includes the POSIX ACL namespaces in addition to `user.*` and
`security.*`: `crates/ffs-harness/tests/kernel_reference.rs` now differentially
validates `system.posix_acl_access` and `system.posix_acl_default` against
`debugfs`, while `crates/ffs-harness/tests/fuse_e2e.rs` covers mounted-path
list/get behavior, `XATTR_CREATE`=`EEXIST` and `XATTR_REPLACE`=`ENODATA`
failure semantics for `user.*`, exact public `ENODATA` for missing
`getxattr`/`removexattr` on `user.*`, empty `listxattr` length-0 probe and
exact-fit zero-length success on mounted files with no visible xattrs, plus
missing-default `ENODATA` on the public FUSE surface. `crates/ffs-fuse/src/lib.rs` now also unit-freezes the
shared FUSE dispatcher contract for invalid `setxattr` requests: conflicting
`CREATE|REPLACE`, unsupported flag bits, and nonzero `position` all reject with
exact `EINVAL` before any backend mutation call.

Mounted-path read-only setattr coverage now also freezes the public `EROFS`
contract for `chmod`, `truncate(2)`, and `utime(2)` on both ext4 and btrfs,
including a no-drift postcondition on file bytes and visible metadata.
Mounted-path btrfs read-only namespace coverage now also freezes exact `EROFS`
for `create`, `mkdir`, `link`, and `symlink`, with no directory-entry or seed-file drift.
Mounted-path btrfs read-only regular-file coverage now also freezes exact `EROFS`
for create-via-write and overwrite-on-existing-file paths, with no file-byte or directory-entry drift.
Mounted-path read-only namespace-removal coverage now also freezes exact `EROFS`
for `unlink`, `rmdir`, and `rename` on both ext4 and btrfs, with no
directory-entry drift and no surviving-file data drift.
Mounted-path ext4 namespace-refusal coverage now also freezes exact `ENOTDIR`
for create and mkdir attempts beneath a regular-file parent, with no visible
root-entry or parent-file drift.
Mounted-path ext4 mkdir/rmdir coverage now also freezes parent `st_nlink`
accounting across child-directory creation/removal, with visible root entries
returning to baseline after `rmdir`.
Mounted-path ext4 write-path coverage now also freezes exact `EISDIR` for
opening a directory for write, with no directory-entry drift and no child-file drift.
Mounted-path btrfs write-path coverage now also freezes exact `EISDIR` for
opening a directory for write, with no directory-entry drift and no child-file drift.
Mounted-path unlink-vs-directory coverage now also freezes exact `EISDIR` for
directory targets on both ext4 and btrfs, with no directory-entry or child-file drift.
Mounted-path btrfs namespace-refusal coverage now also freezes exact `ENOTDIR`
for create and mkdir attempts beneath a regular-file parent, with no visible
workspace-entry or parent-file drift.
Mounted-path btrfs symlink refusal coverage now also freezes exact `EEXIST` for
occupied destinations and exact `ENOTDIR` for non-directory parents, with no
visible workspace-entry or parent-file drift.
Mounted-path ext4 `renameat2` flag-rejection coverage now also freezes exact
`EINVAL` for `RENAME_NOREPLACE` and `RENAME_EXCHANGE`, with no source,
destination, or root-entry drift.
Mounted-path btrfs `renameat2` flag-rejection coverage now also freezes exact
`EINVAL` for `RENAME_NOREPLACE` and `RENAME_EXCHANGE`, with no source,
destination, or workspace-entry drift.
Mounted-path ext4 read-only `fallocate` coverage now also freezes exact `EROFS`
for representative preallocate and punch-hole mutation attempts, with no
file-byte or apparent-size drift.
Mounted-path ext4 directory `fallocate` coverage now also freezes exact
`EISDIR`, with no directory-entry drift and no child-file drift regardless of
whether the kernel rejects at directory open or at the `fallocate` boundary.
Mounted-path btrfs read-only `fallocate` coverage now also freezes exact `EROFS`
for representative preallocate and punch-hole mutation attempts, with no
file-byte or apparent-size drift.
Mounted-path btrfs directory `fallocate` coverage now also freezes exact
`EISDIR`, with no directory-entry drift and no child-file drift regardless of
whether the kernel rejects at directory open or at the `fallocate` boundary.
Mounted-path ext4 directory-fd `FIEMAP` coverage now also freezes exact
`EISDIR` once the ioctl reaches FrankenFS userspace, with an explicit soft-skip
for transport-layer `EOPNOTSUPP` before dispatch and no directory or child-file drift.
Mounted-path btrfs directory-fd `FIEMAP` coverage now also freezes exact
`EISDIR` once the ioctl reaches FrankenFS userspace, with an explicit soft-skip
for transport-layer `EOPNOTSUPP` before dispatch and no directory or child-file drift.
Mounted-path read-only `flush` coverage now also freezes success on both ext4
and btrfs, with no file-byte drift and no implied durability boundary.
Mounted-path ext4 namespace refusal coverage now also freezes exact `ENOTDIR`
for `rmdir` on a regular file, distinct from the existing missing-directory and
non-empty-directory contracts.
Mounted-path btrfs namespace refusal coverage now also freezes exact `ENOTDIR`
for `rmdir` on a regular file, distinct from the existing missing-directory and
unlink-vs-directory contracts.
Mounted-path ext4 rename-over-hardlink coverage now also freezes same-inode
destination semantics as a visible no-op: both names stay bound to the original
inode/data and `st_nlink` remains 2.
Mounted-path ext4 rename coverage now also freezes same-name source/destination
semantics as a visible no-op, with no directory-entry drift and no inode/data
drift.
Mounted-path ext4 rename refusal coverage now also freezes exact `EISDIR` for
file-over-directory overwrites and exact `ENOTDIR` for directory-over-file
overwrites, with no root-entry, source-child, or file-byte drift.
Mounted-path ext4 rename refusal coverage now also freezes exact `ENOTEMPTY`
for rename-over-nonempty-directory attempts, with no root-entry, child-entry,
or child-file drift after the rejected overwrite.
Mounted-path btrfs rename coverage now also freezes same-name source/destination
semantics as a visible no-op, with no directory-entry drift and no inode/data
drift.
Mounted-path btrfs rename-over-hardlink coverage now also freezes same-inode
destination semantics as a visible no-op: both names stay bound to the original
inode/data and `st_nlink` remains 2.
Mounted-path btrfs rename refusal coverage now also freezes exact `EISDIR` for
file-over-directory overwrites and exact `ENOTDIR` for directory-over-file
overwrites, with no root-entry, source-child, or file-byte drift.
Mounted-path btrfs rename refusal coverage now also freezes exact `ENOTEMPTY`
for rename-over-nonempty-directory attempts, with no root-entry, child-entry,
or child-file drift after the rejected overwrite.
Mounted-path btrfs cross-parent directory rename coverage now also freezes
parent `st_nlink` accounting: moving a child directory decrements the source
parent, increments the destination parent, and preserves the moved inode.
Mounted-path btrfs hard-link unlink coverage now also freezes `st_nlink`
accounting: removing one hard-link alias deletes only that directory entry,
preserves the surviving inode/data, and restores the survivor link count to 1.
Mounted-path btrfs hard-link refusal coverage now also freezes exact `EPERM`
for directory sources, `ENOTDIR` for non-directory parents, and `EEXIST` for
occupied destinations, with no dirent or source-`st_nlink` drift.
Mounted-path btrfs symlink/refusal coverage now also freezes exact `EINVAL` for
`readlink` on both regular-file and directory non-symlink paths, with no
directory-entry or file-byte drift.
Mounted-path btrfs unlink coverage now also freezes exact `ENOENT` for missing
targets, with no visible workspace-entry or witness-file drift.
Mounted-path btrfs rename refusal coverage now also freezes exact `ENOTDIR`
for rename attempts whose destination parent is a regular file, with no source
or parent-file drift.
Mounted-path btrfs rename coverage now also freezes exact `ENOENT` for missing
source paths, with no visible workspace-entry or witness-file drift.
Mounted-path ext4 symlink/refusal coverage now also freezes exact `EINVAL` for
`readlink` on both regular-file and directory non-symlink paths, with no
directory-entry or file-byte drift.
FUSE/statfs parity now also freezes the ext4 group-descriptor accounting
contract: total geometry still comes from the superblock, while free block and
inode counts are aggregated from live group descriptors so write-side allocation
changes are visible to `statfs` without relying on stale open-time superblock
counters.
FUSE splice/sendfile parity now also has an implemented large-transfer
contract: the mount negotiates splice read/write/move capability bits, the
vendored FUSE ABI exposes `FUSE_COPY_FILE_RANGE`, `FrankenFuse` routes
`copy_file_range` through the MVCC-aware `FsOps` read/write contract with
Linux-compatible validation for flags, negative offsets, and overlapping
same-inode ranges; validated zero-length requests now return `0` without
opening a backend request scope, committing, reading, writing, or invalidating
readahead, matching the Linux no-op contract. Mounted-path coverage writes 16
MiB through `splice(2)` pipe-to-file transfer and verifies byte-for-byte
SHA-256 equality, while direct ext4 and btrfs `copy_file_range(2)` probes now
exercise cross-file offset copies, same-inode non-overlapping copies,
zero-length no-ops, and same-inode overlap `EINVAL`/no-drift behavior through
the mounted FUSE path.
Additional mounted-path probes mirror the local xfstests splice/sendfile cases
that actually exercise this surface (`generic/249`, `generic/591`, and
`generic/680`). The 1 GiB `sendfile(2)` throughput comparison is retained as an
ignored benchmark gate for `bd-qpoys`; the current measured gate emits
`SCENARIO_RESULT|scenario_id=ext4_rw_sendfile_1g_vs_naive_read_write|outcome=PASS`
for the >=2x contract. Coverage-guided parity stress now also includes
`fuzz_fuse_splice_mount`, which exercises the no-live-mount FUSE read/write
and `copy_file_range` dispatch paths used by splice/sendfile-style transfers
while checking deterministic mount-option labels and the explicit
writeback-cache-disabled policy.

RAID5/6 read evidence (`bd-hk5w3`): clean kernel-written three/four-device images
pass full-file, unaligned and cold FUSE reads with every primary. The mapper now
uses Linux's ordered data rotation; the prior device-order selection reproduced
a RAID5 data-checksum failure on that same test. Missing stripe devices are
admitted for RAID5 (≤1 absent) and RAID6 (≤2 absent); degraded data reads are
reconstructed from the surviving slots plus parity (XOR for RAID5, GF(256)
syndrome solve from P+Q for RAID6 dual erasure) and verified against the data
checksum before serving. Tree nodes on a missing column are rebuilt the same
way and accepted only if their own checksum, logical address and structure
verify, so metadata/system chunks are admitted with the same tolerance
(`btrfs_raid56_metadata_opens_degraded_from_parity`: a btrfs-progs RAID5 image
opens without any one device, RAID6 without any one or two, and refuses one
erasure past tolerance). Reconstruction is regression-tested at the unit level
(missing data device, dual erasure, silent corruption repair, coverage
admission matrix) and through FUSE on kernel-built fixtures. On 2026-10-09,
strict RCH execution of `cargo test -j 2 -p ffs-harness --test fuse_e2e
btrfs_attached_devices_read_seeded_files -- --nocapture --test-threads=1`
with `FFS_REQUIRE_FUSE=1` passed both CRC32C and xxHash64 variants without
skips. Each variant requires all three RAID5 single-device omissions and all
ten RAID6 single- or double-device omissions to open and read successfully.
Parent and nested-subvolume payloads match through core and FUSE, encoded
prefixes match through `FsOps`, and all backing-image hashes survive reads
and rejected writes unchanged. The companion public CLI tests also passed on
2026-10-09: `cargo test -j 2 -p ffs-harness --test fuse_e2e
btrfs_cli_attached_devices_read_seeded_files -- --nocapture --test-threads=1`
with `FFS_REQUIRE_FUSE=1`, an independently hashed prebuilt CLI, its source
receipt and a retained artifact directory under the host-permitted `/mnt`.
The two checksum variants completed 78 mounts, 82 expected refusals and 1,248
mounted probes with no skips. They record actual kernel readback, device
FSID/devid/UUID, CLI argv and logs, exit status, errno, readback hashes and
unchanged hashes of every supplied image, including foreign-device negatives.
The CLI uses its default auto-unmount behavior. Seed-device inventories and
the full corruption/profile matrix remain open. The later count-reconciliation
image evidence is recorded separately above; this mounted evidence does not
complete the parent V1 read scope (`bd-hk5w3`).

### 2.1 btrfs Experimental RW Capability Contract (Machine-Checkable)

The table below is the authoritative btrfs experimental RW contract for `bd-h6nz.3.1`.
Each row maps directly to deterministic unit/E2E coverage by stable test/scenario ID.
`supported`, `partially supported`, and `unsupported` classify the expected V1
behavior of that operation, not whether the row is unimplemented.

| Contract ID | Operation / Edge Case | Class | Expected Result |
|-------------|------------------------|-------|-----------------|
| `unit::btrfs_write_create_file` | `create` regular file | supported | success |
| `unit::btrfs_write_mkdir` | `mkdir` | supported | success |
| `unit::btrfs_write_rename` | `rename` (same/cross parent) | supported | success |
| `unit::btrfs_write_setattr_truncate` | `setattr(size)` truncate path | supported | success |
| `unit::btrfs_write_xattr_set_get_list` | `setxattr/getxattr/listxattr` | supported | success |
| `unit::btrfs_write_xattr_respects_create_and_replace_modes` | `setxattr` mode semantics (`Create`/`Replace`) | supported | existing key rejects `Create` with `EEXIST`; missing key rejects `Replace` with `ENOENT` in `ffs-core`, and mounted Linux FUSE remaps that public path to `ENODATA`; mounted-path `getxattr`/`removexattr` on missing `user.*` names also now freeze exact `ENODATA`; mounted-path zero-sized `getxattr`/`listxattr` probes now freeze exact required lengths, undersized buffers return `ERANGE`, and empty `listxattr` now freezes length 0 plus exact-fit zero-length success; read-only mounted-path `setxattr`/`removexattr` now freeze exact `EROFS`; no side effects |
| `unit::btrfs_write_fallocate_basic` | `fallocate` preallocation (`mode=0`) | supported | success |
| `unit::btrfs_write_fallocate_keep_size_does_not_extend_file` | `fallocate` with `FALLOC_FL_KEEP_SIZE` | supported | success, file size unchanged, backing blocks reserved, allocator free space decreases |
| `harness::btrfs_fallocate_does_not_prealloc_over_live_data_conforms` | `fallocate` over initialized btrfs extents | supported | success, preallocation over live data does not insert overlapping unwritten FIEMAP extents, the initialized extent remains initialized, and readback preserves data |
| `unit::btrfs_write_fallocate_punch_hole_zeroes_data` | `fallocate` with `FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE` | supported | success, file size preserved, punched range reads back as zeros, unaffected bytes remain intact |
| `unit::btrfs_write_fallocate_zero_range_zeroes_data` | `fallocate` with `FALLOC_FL_ZERO_RANGE` | supported | success, requested range reads back as zeros, unaffected bytes remain intact |
| `unit::btrfs_write_fallocate_zero_range_keep_size_does_not_extend_file` | `fallocate` with `FALLOC_FL_ZERO_RANGE|FALLOC_FL_KEEP_SIZE` | supported | success, file size unchanged when range extends past EOF |
| `unit::btrfs_write_fallocate_collapse_range_shifts_tail_and_shrinks_file` | `fallocate` with `FALLOC_FL_COLLAPSE_RANGE` | supported | success, aligned range is removed, tail data shifts left, and file size shrinks |
| `unit::btrfs_write_fallocate_insert_range_shifts_tail_and_grows_file` | `fallocate` with `FALLOC_FL_INSERT_RANGE` | supported | success, aligned zero hole is inserted, tail data shifts right, and file size grows |
| `unit::btrfs_write_fallocate_collapse_range_preserves_shifted_prealloc_fiemap` | `FALLOC_FL_COLLAPSE_RANGE` shifting a prealloc extent | supported | success, shifted prealloc remains allocated and reports `FIEMAP_EXTENT_UNWRITTEN` at its new logical offset |
| `unit::btrfs_write_fallocate_insert_range_preserves_shifted_prealloc_fiemap` | `FALLOC_FL_INSERT_RANGE` shifting a prealloc extent | supported | success, inserted range is a hole while shifted prealloc remains allocated and reports `FIEMAP_EXTENT_UNWRITTEN` |
| `unit::btrfs_write_fallocate_collapse_range_reaching_eof_rejects_without_mutation` | `FALLOC_FL_COLLAPSE_RANGE` reaching EOF | supported | `EINVAL`, file size and data preserved |
| `unit::btrfs_write_fallocate_insert_range_at_eof_rejects_without_mutation` | `FALLOC_FL_INSERT_RANGE` at EOF | supported | `EINVAL`, file size and data preserved |
| `unit::btrfs_write_fallocate_range_modes_reject_unaligned_with_einval_without_mutation` | exclusive range modes with unaligned offset/length | supported | `EINVAL`, file size and data preserved |
| `unit::btrfs_write_fallocate_range_modes_reject_invalid_combinations_without_mutation` | exclusive range modes combined with other flags | supported | `EINVAL`, file size and data preserved |
| `unit::btrfs_write_fallocate_unsupported_mode_bits_rejected` | `fallocate` with unsupported mode bits | unsupported | `FfsError::UnsupportedFeature` -> `EOPNOTSUPP` |
| `unit::btrfs_write_fallocate_success_log_contract` | supported fallocate log contract | observability | structured log includes `operation_id`, `scenario_id`, `outcome=applied` |
| `unit::btrfs_write_fallocate_rejection_log_contract` | unsupported fallocate log contract | observability | structured log includes `operation_id`, `scenario_id`, `outcome=rejected`, `error_class` |
| `unit::btrfs_write_fallocate_unsupported_mode_bits_log_contract` | unsupported mode-bits fallocate log contract | observability | structured log includes `operation_id`, `scenario_id=btrfs_rw_fallocate_unsupported_mode_bits`, `outcome=rejected`, `error_class=unsupported_mode_bits` |
| `unit::btrfs_write_fsync_log_contract_success` | `fsync` success log contract | observability | structured log includes `operation_id`, `scenario_id=btrfs_rw_fsync`, `outcome=applied` |
| `unit::btrfs_write_fsync_rejection_log_contract_read_only` | `fsync` read-only rejection log contract | observability | structured log includes `operation_id`, `scenario_id=btrfs_rw_fsync`, `outcome=rejected`, `error_class=read_only` |
| `unit::btrfs_write_fsyncdir_log_contract_success` | `fsyncdir` success log contract | observability | structured log includes `operation_id`, `scenario_id=btrfs_rw_fsyncdir`, `outcome=applied` |
| `e2e::ext4_rw_flush` | FUSE path ext4 flush contract | observability | shell-visible success, file contents remain readable after explicit `flush` + close within the mounted session, emitted `SCENARIO_RESULT` marker, and does not claim a durability boundary |
| `e2e::btrfs_rw_flush` | FUSE path btrfs flush contract | observability | shell-visible success, file contents remain readable after explicit `flush` + close within the mounted session, emitted `SCENARIO_RESULT` marker, and does not claim a durability boundary |
| `e2e::btrfs_rw_fallocate_preallocate_extends_size` | FUSE path btrfs preallocation contract | supported | shell-visible success, file size extends to requested length, data blocks are allocated, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_fallocate_keep_size_preserves_size` | FUSE path btrfs keep-size preallocation contract | supported | shell-visible success, apparent file size is preserved, original bytes remain readable, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_fallocate_punch_hole_keep_size_zeroes_range` | FUSE path punch-hole zero-fill under `KEEP_SIZE` | supported | shell-visible success, file size unchanged, punched range zeroed, unaffected suffix preserved, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_fallocate_zero_range_zeroes_range` | FUSE path zero-range contract | supported | shell-visible success, requested range zeroed, unaffected suffix preserved, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_fallocate_collapse_range` | FUSE path collapse-range contract | supported | shell-visible success, requested aligned range removed, tail shifted left, file size shrunk, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_fallocate_insert_range` | FUSE path insert-range contract | supported | shell-visible success, aligned zero hole inserted, tail shifted right, file size grown, emitted `SCENARIO_RESULT` marker |
| `e2e::btrfs_rw_invalid_punch_hole_without_keep_size_errno_einval` | FUSE path invalid `PUNCH_HOLE` without `KEEP_SIZE` rejection | supported | when the request reaches FrankenFS userspace dispatch, shell-visible errno 22 (`EINVAL`) is frozen with no file-size or data drift; current kernel/FUSE stacks that collapse the invalid mode to errno 95 (`ENOTSUP`/`EOPNOTSUPP`) before dispatch soft-skip after still proving no drift |
| `e2e::btrfs_rw_unsupported_fallocate_mode_bits_errno_eopnotsupp` | FUSE path unsupported mode-bit rejection | unsupported | shell-visible errno 95 (`EOPNOTSUPP`/`ENOTSUP`), emitted `SCENARIO_RESULT` marker, file contents preserved |
| `e2e::ext4_rw_fallocate_preallocate_extends_size` | FUSE path ext4 preallocation contract | supported | shell-visible success, file size extends to requested length, data blocks are allocated, emitted `SCENARIO_RESULT` marker |
| `e2e::ext4_rw_fallocate_keep_size_preserves_size` | FUSE path ext4 keep-size preallocation contract | supported | shell-visible success, apparent file size is preserved, data blocks are allocated, emitted `SCENARIO_RESULT` marker |
| `e2e::ext4_rw_fallocate_punch_hole_keep_size_zeroes_range` | FUSE path ext4 punch-hole zero-fill under `KEEP_SIZE` | supported | shell-visible success, file size unchanged, punched range zeroed, unaffected suffix preserved, emitted `SCENARIO_RESULT` marker |
| `e2e::ext4_rw_fallocate_zero_range_zeroes_range` | FUSE path ext4 zero-range contract | supported | shell-visible success, requested range zeroed, unaffected suffix preserved, emitted `SCENARIO_RESULT` marker |
| `e2e::ext4_rw_invalid_punch_hole_without_keep_size_errno_einval` | FUSE path ext4 invalid `PUNCH_HOLE` without `KEEP_SIZE` rejection | supported | when the request reaches FrankenFS userspace dispatch, shell-visible errno 22 (`EINVAL`) is frozen with no file-size or data drift; current kernel/FUSE stacks that collapse the invalid mode to errno 95 (`ENOTSUP`/`EOPNOTSUPP`) before dispatch soft-skip after still proving no drift |
| `e2e::ext4_rw_unsupported_fallocate_mode_bits_errno_eopnotsupp` | FUSE path ext4 unsupported mode-bit rejection | unsupported | shell-visible errno 95 (`EOPNOTSUPP`/`ENOTSUP`), emitted `SCENARIO_RESULT` marker, file contents preserved |
| `e2e::btrfs_rw_crash_matrix_01_create_alpha_no_fsync` | crash point 1 (create) | crash-consistency | post-crash RO remount invariants verified; `CRASH_MATRIX_EVENT` + `SCENARIO_RESULT` emitted |
| `e2e::btrfs_rw_crash_matrix_02_append_alpha_no_fsync` | crash point 2 (append write) | crash-consistency | post-crash RO remount invariants verified; `CRASH_MATRIX_EVENT` + `SCENARIO_RESULT` emitted |
| `e2e::btrfs_rw_crash_matrix_03_fsync_alpha_and_parent` | crash point 3 (fsync file/parent boundary) | crash-consistency | fsync durability boundary verified with structured sync logs and RO remount invariants |
| `e2e::btrfs_rw_crash_matrix_04_rename_alpha_to_beta_no_fsync` | crash point 4 (rename) | crash-consistency | post-crash rename-state envelope verified (old/new name admissible set) |
| `e2e::btrfs_rw_crash_matrix_05_fsync_rename_parent` | crash point 5 (rename fsync boundary) | crash-consistency | rename durability boundary verified with structured sync logs and RO remount invariants |
| `e2e::btrfs_rw_crash_matrix_06_create_gamma_no_fsync` | crash point 6 (create second file) | crash-consistency | post-crash non-fsync create envelope verified without metadata divergence |
| `e2e::btrfs_rw_crash_matrix_07_fsync_gamma_and_parent` | crash point 7 (second fsync boundary) | crash-consistency | fsync durability boundary verified with structured sync logs and RO remount invariants |
| `e2e::btrfs_rw_crash_matrix_08_unlink_beta_no_fsync` | crash point 8 (unlink beta) | crash-consistency | post-crash non-fsync unlink envelope verified without metadata divergence |
| `e2e::btrfs_rw_crash_matrix_09_unlink_gamma_no_fsync` | crash point 9 (unlink gamma) | crash-consistency | post-crash non-fsync unlink envelope verified without metadata divergence |
| `e2e::btrfs_rw_crash_matrix_10_fsync_unlink_parent` | crash point 10 (unlink fsync boundary) | crash-consistency | unlink durability boundary verified with structured sync logs and RO remount invariants |
| `e2e::ext4_rw_crash_matrix_01_create_alpha_no_fsync` | crash point 1 (create) | crash-consistency | post-crash RO remount tolerates absent-or-empty file state; `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_02_append_alpha_no_fsync` | crash point 2 (append write) | crash-consistency | post-crash RO remount bounds recovered data to the pre-crash payload envelope; `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_03_fsync_alpha_and_parent` | crash point 3 (fsync file/parent boundary) | crash-consistency | durable file data + directory entry survive crash after `fsync` + `fsyncdir`; `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_04_rename_alpha_to_beta_no_fsync` | crash point 4 (rename) | crash-consistency | post-crash rename envelope verified (`alpha` xor `beta` present); `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_05_fsync_rename_parent` | crash point 5 (rename fsync boundary) | crash-consistency | durable rename boundary verified after parent directory fsync; `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_06_unlink_beta_no_fsync` | crash point 6 (unlink beta) | crash-consistency | post-crash non-fsync unlink envelope verified without stale-data divergence; `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_07_truncate_beta_fsync` | crash point 7 (truncate fsync boundary) | crash-consistency | durable truncate boundary verified after post-truncate `fsync`; `CRASH_MATRIX_EVENT` emitted |
| `e2e::ext4_rw_crash_matrix_08_multi_file_interleaved_fsync` | crash point 8 (multi-file interleaving) | crash-consistency | fsynced file survives while later non-fsynced file remains within recovery envelope; `CRASH_MATRIX_EVENT` emitted |

### 2.2 MVCC, Repair, FUSE, CLI and Harness Capabilities

| Capability | Legacy Reference | Status | Notes |
|------------|------------------|--------|-------|
| MVCC snapshot visibility | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` with shard-consistent snapshot isolation (`crates/ffs-mvcc/src/sharded.rs::tests::snapshot_isolation`, `snapshot_reads_consistent_across_shards`). |
| MVCC commit sequencing | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` with monotonic commit sequence ordering and idempotent WAL replay (`crates/ffs-mvcc/src/sharded.rs::tests::commit_snapshots_policy_before_shard_locks`, `crates/ffs-mvcc/src/persist.rs::tests::replay_discards_duplicate_commit_sequence`). |
| FCW conflict detection | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc`; OQ2 (`bd-h6nz.6.2`, corrected by `bd-xuo95.27`) resolves V1.x as FCW+SSI plus bounded SafeMerge. Public `MergeProof` labels collapse to two audited same-block merge mechanisms (`AppendOnly` and range overlay) or FCW fallback (`Unsafe`, `DisjointBlocks`). Deterministic contention evidence remains in `crates/ffs-mvcc/tests/mvcc_stress_suite.rs`; taxonomy guardrails are covered by `crates/ffs-mvcc/src/lib.rs::merge_proof_mechanism_collapses_labels_to_two_merge_algorithms`, `range_overlay_labels_share_the_same_byte_algorithm`, and `range_overlay_labels_reject_undeclared_byte_changes`. |
| SSI dangerous-structure detection | FrankenFS spec §3 | ✅ | Implemented in `ffs-mvcc` for both single-store and sharded commit paths. `bd-xuo95.26` changes SSI from a single stale-read abort guard to true two-edge pivot detection: one inbound rw edge from a concurrent committed reader of the committer's write set plus one outbound rw edge from the committer's read set to a concurrent committed writer. Single-edge stale readers now commit as serializable histories. Coverage includes `ssi_single_incoming_rw_edge_is_allowed`, `ssi_single_outgoing_rw_edge_is_allowed`, `e2e_ssi_two_edge_range_summary_write_skew_prevention`, `lab_ssi_rejects_write_skew`, `sharded::tests::ssi_detects_write_skew`, and `tests/evidence_ledger_integration.rs::ssi_conflict_produces_serialization_conflict_evidence`. |
| version retention policy | FrankenFS spec §3 | ✅ | In-memory retention with `VersionData::Identical` dedup (zero-copy for unchanged blocks), configurable `CompressionPolicy` (dedup + max chain length cap), watermark-safe pruning, chain-pressure handling (oldest-snapshot force-advance + `CommitError::ChainBackpressure`), and crossbeam-epoch deferred reclamation counters/collection (`ebr_stats`, `ebr_collect`) in `ffs-mvcc` (`crates/ffs-mvcc/src/lib.rs::tests::chain_length_bounded_after_many_writes`). |
| COW block rewrite path | FrankenFS spec §3 | ✅ | Allocation-backed COW rewrite path implemented in `ffs-mvcc` (`write_cow`, logical→physical mapping visibility, deferred-free + watermark GC integration; `crates/ffs-mvcc/src/lib.rs::tests::cow_hundred_rewrites_produce_unique_physical_blocks`). |
| durability policy model | FrankenFS spec §4 | ✅ | Bayesian expected-loss selector and adaptive/lazy symbol refresh policies in `ffs-repair` (`crates/ffs-repair/src/pipeline.rs::tests::adaptive_policy_switches_eager_based_on_posterior`). |
| asupersync config mapping | FrankenFS spec §4 | ✅ | `RaptorQConfig` mapping and systematic fountain-code symbol generation in `ffs-repair` (`crates/ffs-repair/src/codec.rs::tests::encode_produces_repair_symbols`). |
| format-aware scrub superblock validation | FrankenFS spec §4 | ✅ | `Ext4SuperblockValidator` + `BtrfsSuperblockValidator` in `ffs-repair`, wired into `ffs-cli scrub` (`crates/ffs-repair/src/scrub.rs::tests::btrfs_superblock_validator_accepts_valid_superblock`). |
| repair symbol storage I/O (dual-slot generation commit) | FrankenFS spec §4 | ✅ | `RepairGroupStorage` in `ffs-repair::storage` with symbol-block validation + torn-generation fallback; OQ3 (`bd-h6nz.6.3`) resolved for V1.x as bounded staleness (lazy 30s default + timeout/adaptive-eager escalation) with deterministic refresh-policy evidence in `crates/ffs-repair/src/pipeline.rs` tests and `scripts/e2e/ffs_repair_recovery_smoke.sh`. `fuzz/fuzz_targets/fuzz_repair_symbols.rs` now coverage-fuzzes the raw repair block header, repair group descriptor, and symbol digest parsers with valid and truncated corpus seeds. |
| corruption recovery orchestrator + evidence ledger | FrankenFS spec §4 | ✅ | `GroupRecoveryOrchestrator` in `ffs-repair::recovery` (decode + explicit `RecoveryWriteback` authority + post-verify + JSON evidence; `crates/ffs-repair/src/pipeline.rs::tests::evidence_ledger_captures_all_events`). `OpenFs::repair_writeback_blocks_via_mounted_mutation_path` now provides the mounted MVCC request-scope authority for recovered physical blocks, rejects stale `expected_current` bytes before staging, and performs durable flush plus verification before repair-symbol refresh. |
| FUSE getattr | FrankenFS spec §9 | ✅ | `FsOps::getattr` via `OpenFs` and `FrankenFuse` (`crates/ffs-fuse/src/lib.rs::tests::conformance_fuse_getattr_metadata_round_trip`). |
| FUSE lookup | FrankenFS spec §9 | ✅ | `FsOps::lookup` via `OpenFs` and `FrankenFuse` (`crates/ffs-fuse/src/lib.rs::tests::conformance_fuse_lookup_metadata_round_trip`). |
| FUSE readdir | FrankenFS spec §9 | ✅ | `FsOps::readdir` via `OpenFs` and `FrankenFuse` (`crates/ffs-fuse/src/lib.rs::tests::conformance_fuse_readdir_directory_round_trip`). |
| FUSE read | FrankenFS spec §9 | ✅ | `FsOps::read` via `OpenFs` and `FrankenFuse` (`crates/ffs-fuse/src/lib.rs::tests::conformance_fuse_read_file_lifecycle_round_trip`). |
| FUSE readlink | FrankenFS spec §9 | ✅ | `FsOps::readlink` via `OpenFs` and `FrankenFuse` (`crates/ffs-fuse/src/lib.rs::tests::conformance_fuse_readlink_directory_round_trip`). |
| FUSE mount runtime | FrankenFS spec §9 | ✅ | Production runtime lifecycle, signal handling, dispatch coverage, and CI-safe skip behavior are implemented; OQ4 (`bd-h6nz.6.4`) is resolved for V1.x with explicit `flush` (non-durable) vs `fsync`/`fsyncdir` (durability boundary) contract and default-off writeback-cache policy. `bd-rchk0.2.1.1` freezes the negative-option proof: CLI-to-FUSE option construction, default/read-only/unsupported modes, unavailable FUSE capability, repeated dry-run attempts, and unrelated mount flags do not forward kernel `writeback_cache`. `bd-8pz7h` adds the dirty-page ordering oracle, `bd-rchk0.2.2` wires the explicit opt-in, `bd-4nobd` adds runtime kill-switch plus stale-gate, config-default, feature-downgrade, and host-manifest refusal, and `bd-rchk0.2.3` adds the twelve-point crash/replay artifact gate plus a mounted ext4 writeback-cache opt-in regression. `--writeback-cache` requires `--rw`, accepted audit-gate JSON, accepted ordering-oracle JSON, accepted crash/replay-oracle JSON, fresh runtime-guard evidence, a matching host/lane manifest, and a disarmed `FFS_WRITEBACK_CACHE_KILL_SWITCH` before the CLI forwards the kernel option to `ffs-fuse`. `crates/ffs-harness/tests/fuse_e2e.rs` now emits `SCENARIO_RESULT` coverage for ext4 (`ext4_rw_flush`, `ext4_rw_fdatasync`, `ext4_rw_fsync`, `ext4_rw_fsyncdir`, `ext4_rw_seek_data_hole`, `ext4_rw_seek_hole_fully_allocated`, `ext4_rw_seek_leading_hole`, `ext4_rw_seek_all_hole`, `writeback_cache_ext4_opt_in_flush_fsyncdir_reopen`) and btrfs (`btrfs_rw_flush`, `btrfs_rw_fdatasync`, `btrfs_rw_fsync`, `btrfs_rw_fsyncdir`, `btrfs_rw_seek_data_hole`, `btrfs_rw_seek_hole_fully_allocated`, `btrfs_rw_seek_leading_hole`, `btrfs_rw_seek_all_hole`) through real file flushes, file- and directory-FD sync calls, mounted writeback-cache opt-in where the host permits FUSE, and mounted-path `SEEK_DATA`/`SEEK_HOLE` probes for punched-hole, fully allocated, leading-hole, and all-hole layouts with EOF `ENXIO` verification. The ext4 syscall-level differential probe now compares the mounted FrankenFS path against a Linux reference directory for file lifecycle, metadata, link, mmap, fsync, offset I/O (`pread`/`pwrite`), `SEEK_END`, `fdatasync`, `utime`, `access`, `openat`-style directory-relative lookup, and normalized `statvfs` semantics; btrfs read-only mounted-path `fsync`, `fdatasync`, and `fsyncdir` now also freeze exact `EROFS` with no data or dirent drift. |
| FUSE mount background scrub lifecycle | FrankenFS spec §4 / §9 | ✅ | `ffs mount` starts a detection-only `ffs-repair::ScrubDaemon` automatically for default read-only mounts, owns cancellation through a mount lifecycle guard, joins the worker on shutdown, and emits structured start/stop/error logs. CLI controls cover `--background-scrub`, `--no-background-scrub`, `--background-scrub-interval-secs`, `--background-scrub-ledger`, and `--background-repair`. Client read-only mounted repair uses explicit direct-device authority and requires a durable ledger, writable backing access, and a completely safe repair-tail plan; bd-plamw strengthens that admission check, verified by the unit and real-image refusal controls above. The CLI refuses read-write mounted repair until repair storage is permanently reserved. The underlying mounted MVCC serializer and stale-snapshot rejection exist, but cannot reserve symbol storage against later allocation. Coverage: `crates/ffs-cli/src/main.rs` mount config/start-stop and unsafe-plan tests, `crates/ffs-core/src/lib.rs` mounted repair-writeback request-scope and deterministic repair/client-write race tests, and `crates/ffs-repair/src/pipeline.rs` repair-enabled, custom-authority, stale expected-current, rejection, and detection-only daemon tests. The original read-write self-healing goal remains outstanding under bd-11a8t. |
| FUSE ABI 7.40 protocol surface | FUSE kernel ABI 7.40 / libfuse 3.x | ✅ | Workspace builds the vendored `fuser` crate with `abi-7-40`, and `FrankenFuse::init` now negotiates `FUSE_SPLICE_READ`, `FUSE_SPLICE_WRITE`, `FUSE_SPLICE_MOVE`, and `FUSE_PASSTHROUGH` with stack depth 1 when the kernel advertises support. The vendored `fuser` protocol layer now exposes opcode 52 (`FUSE_STATX`), parses `fuse_statx_in`, replies with Linux statx-compatible `fuse_statx_out`, and preserves `FileAttr::crtime` as `STATX_BTIME`; `FrankenFuse::statx` routes that opcode through the existing `getattr` backend. The vendored ABI surface also exposes `FUSE_WRITE_KILL_SUIDGID`/legacy `FUSE_WRITE_KILL_PRIV` plus Linux `RWF_*` constants for write-intent propagation. Unit coverage freezes ABI constants, STATX request parsing, birth-time reply encoding, and mounted splice pipe-to-file transfer. |
| FUSE pwritev2/io_uring RWF write intent propagation | `pwritev2(2)`, FUSE `WRITE` request flags | ✅ | `FrankenFuse::write` now decodes synchronous write intent from the FUSE `flags` field (`O_DSYNC`/`O_SYNC`) and routes it through `FsOps::fsync` after the normal MVCC commit, so `RWF_DSYNC` uses a data-sync boundary and `RWF_SYNC` uses a full sync boundary. The implementation deliberately does not treat `fuse_write_in.write_flags` bit 1 as `RWF_DSYNC`, because that bit is already `FUSE_WRITE_LOCKOWNER`; unit coverage freezes that collision and verifies no accidental fsync. `RWF_HIPRI` is treated as a harmless priority/cache hint because bit 0 is also `FUSE_WRITE_CACHE`; coverage freezes that it preserves the normal write contract without sync, NOWAIT, append, or unsupported-intent side effects, and mounted-path ext4 plus btrfs `os.pwritev(..., RWF_HIPRI)` coverage now proves accepted calls preserve caller-offset overwrite semantics. `FUSE_WRITE_KILL_SUIDGID` is likewise kept as a metadata write hint despite sharing raw bit 2 with `RWF_SYNC`; unit coverage freezes that it preserves the normal write contract without an accidental full fsync. `RWF_NOWAIT` uses the non-conflicting RWF bit to attempt inode mutation-lock acquisition without blocking and returns `EAGAIN` when the lock is already held; mounted-path ext4 plus btrfs coverage now proves accepted uncontended `RWF_NOWAIT` calls preserve normal caller-offset overwrite semantics. `RWF_APPEND` and `O_APPEND` resolve the write offset to current EOF under the inode mutation guard, while `RWF_NOAPPEND` preserves the caller offset on an append-open file; the Linux-invalid `RWF_APPEND|RWF_NOAPPEND` combination rejects with `EINVAL` before EOF lookup or mutation. Unsupported non-conflicting write intents that require guarantees FrankenFS does not provide yet (`RWF_ATOMIC` torn-write protection and `RWF_DONTCACHE` cache-bypass/drop semantics) reject with `EOPNOTSUPP` before backend mutation. `crates/ffs-fuse/src/lib.rs` unit tests cover DSync, Sync, flag-collision hints, NOWAIT fast-fail, append, NOAPPEND, invalid append/NOAPPEND conflicts, and unsupported-intent rejection behavior, while `crates/ffs-harness/tests/fuse_e2e.rs` adds mounted-path `os.pwritev(...)` probes for `RWF_DSYNC`, `RWF_SYNC`, `RWF_HIPRI`, `RWF_NOWAIT`, `RWF_APPEND`, `RWF_NOAPPEND`, the invalid `RWF_APPEND|RWF_NOAPPEND` pair, and unsupported `RWF_ATOMIC`/`RWF_DONTCACHE` intents, proving sync writes become immediately readable and survive remount on both ext4 and btrfs, and that harmless hints, NOWAIT uncontended offset writes, append/NOAPPEND offset semantics, and unsupported-intent no-mutation contracts are exercised on both formats when the host permits FUSE and forwards the flags. |
| FUSE inotify rename + dentry notification lifecycle | `fs/notify/fsnotify.c`, `fs/notify/inotify/inotify_user.c`, FUSE notify protocol | ✅ | `FrankenFuse` captures a `fuser::Notifier` during blocking, background, and managed mount setup, then issues `FUSE_NOTIFY_INVAL_ENTRY` for successfully committed `unlink`, `rmdir`, and both old/new directory entries after `rename`. Plain renames deliberately avoid `FUSE_NOTIFY_DELETE`, preserving the kernel/VFS `IN_MOVED_FROM` + `IN_MOVED_TO` cookie-pair contract instead of synthesizing delete/create observations. `crates/ffs-harness/tests/fuse_e2e.rs` now carries mounted-path inotify probes for 100 same-parent renames and a cross-directory rename; both assert non-zero matching cookies and reject `IN_CREATE`, `IN_DELETE`, `IN_Q_OVERFLOW`, and `IN_IGNORED` during plain rename bursts, with the standard CI soft-skip when the current host denies FUSE mounting. |
| FUSE ioctl FIEMAP / FIBMAP | `include/linux/fiemap.h`, `fs/ext4/inode.c::ext4_bmap` | ✅ | `FsOps::fiemap` queries ext4 extent tree via `collect_extents_with_scope` and btrfs extent data items via `btrfs_fiemap_extent_items`. FUSE `ioctl` handler parses `FS_IOC_FIEMAP` (0xC020660B), rejects unsupported request flags with `EBADR`, honors `FIEMAP_FLAG_SYNC` by fsyncing writable mounts before extent lookup, and marshals the fiemap header plus extent array. Legacy `FIBMAP` routes through the same 1-block FIEMAP lookup and now maps holes plus `FIEMAP_EXTENT_UNWRITTEN` prealloc extents to physical block `0`, matching ext4's unwritten-extent bmap contract. `crates/ffs-core` has deterministic btrfs coverage for inline extents (`physical=0`, `FIEMAP_EXTENT_LAST`) and keep-size prealloc extents (`FIEMAP_EXTENT_UNWRITTEN`), while `crates/ffs-fuse` pins FIBMAP written vs unwritten dispatch behavior and `crates/ffs-harness/tests/fuse_e2e.rs` verifies mounted-path FIEMAP reporting for ext4 regular files, ext4 `SYNC` and invalid-request-flag contracts, plus btrfs regular, inline, and keep-size prealloc files. Note: FUSE transport may not deliver these ioctls to userspace on all kernel versions. |
| FUSE ioctl EXT4_IOC_GETFLAGS | `fs/ext4/ioctl.c` | ✅ | `FsOps::get_inode_flags` returns raw ext4 `i_flags` field. FUSE `ioctl` handler dispatches `EXT4_IOC_GETFLAGS` (0x80086601). Harness integration coverage in `crates/ffs-harness/tests/fuse_e2e.rs` now verifies mounted-path `GETFLAGS` on a writable ext4 file. |
| FUSE ioctl EXT4_IOC_GETVERSION / EXT4_IOC_SETVERSION | `fs/ext4/ioctl.c` | ✅ | `FsOps::get_inode_generation` returns ext4 `i_generation`, and `FsOps::set_inode_generation` now updates that field in-place, persists it via `ffs_inode::write_inode`, and keeps the ext4-only contract explicit. `ffs-fuse` dispatches `EXT4_IOC_GETVERSION` (0x80086603) and `EXT4_IOC_SETVERSION` (0x40086604), enforces the 4-byte userspace payload contract, and commits `SETVERSION` through the normal write request scope. `crates/ffs-core` unit tests cover direct ext4 mutation plus reopen persistence, `crates/ffs-fuse` unit tests cover getter encoding and setter routing, and `crates/ffs-harness/tests/fuse_e2e.rs` now proves mounted-path `SETVERSION`/`GETVERSION` roundtrips when the current kernel/FUSE stack forwards the ioctl. The mounted-path test soft-skips with explicit scenario results when the kernel/VFS rejects `GETVERSION` or `SETVERSION` before userspace dispatch. |
| FUSE ioctl EXT4_IOC_SETFLAGS | `fs/ext4/ioctl.c` | ✅ | `FsOps::set_inode_flags` with user-settable flag masking (`EXT4_USER_SETTABLE_FLAGS`). System flags (EXTENTS, HUGE_FILE, etc.) protected. FUSE `ioctl` handler dispatches `EXT4_IOC_SETFLAGS` (0x40086602), requires write mode. Direct `ffs-fuse` dispatch coverage verifies write-scope routing and masked flag persistence; mounted-path E2E in `crates/ffs-harness/tests/fuse_e2e.rs` now covers generic flag roundtrips plus ext4 `EXT4_COMPR_FL` enable-on-empty-file behavior on COMPRESSION-feature images, post-ioctl compressed write/readback, and stable `EOPNOTSUPP` rejection when the COMPRESSION incompat bit is absent. The tests still soft-skip when the current kernel/FUSE stack rejects the write ioctl with `ENOTTY` before userspace dispatch. |
| FUSE ioctl FS_IOC_GETFSLABEL / FS_IOC_SETFSLABEL | `fs/ioctl.c`, ext4 superblock volume name field | ✅ | `OpenFs::get_fs_label` now rereads the ext4 superblock on each request so mounted and direct-image callers observe post-mutation labels instead of the open-time cache. `OpenFs::set_fs_label` rewrites `s_volume_name`, preserves the ext4 16-byte limit, rejects interior NULs with `EINVAL`, and recomputes the superblock checksum when `metadata_csum` is enabled. `ffs-fuse` dispatches `FS_IOC_GETFSLABEL` (0x81009431) and `FS_IOC_SETFSLABEL` (0x41009432), enforces the 256-byte userspace buffer contract, rejects unterminated setter payloads with `EINVAL`, and commits through the normal write request scope. `crates/ffs-core` unit tests cover direct ext4 mutation and reopen persistence; `crates/ffs-fuse` unit tests cover getter sizing plus setter routing; `crates/ffs-harness/tests/fuse_e2e.rs` now proves mounted-path ext4 label updates survive remount, with direct-image verification fallback when the current kernel/FUSE stack blocks remount `GETFSLABEL` before userspace dispatch. |
| FUSE ioctl EXT4_IOC_MOVE_EXT | `fs/ext4/ioctl.c`, kernel ext4 admin-guide ioctl table | ✅ | `ffs-fuse` parses and validates `struct move_extent`, resolves the caller's donor fd from `/proc/<pid>/fd/<n>`, verifies the donor stays on the mounted filesystem, temporarily registers the donor inode for `OpenFs::move_ext`, and emits structured `operation_id` / `scenario_id` / `outcome` / `error_class` logs for success and rejection. `crates/ffs-core` keeps mkfs-backed backend tests for `EBADF`, short moved-length-at-EOF behavior, hole rejection, and middle-range extent swapping, while `crates/ffs-harness/tests/fuse_e2e.rs` now proves mounted-path middle-range exchange plus hole-backed rejection over a real ext4 FUSE mount with ioctl-trace evidence. |
| CLI inspect command | FrankenFS spec §6 | ✅ | Implemented in `ffs-cli` across all 6 supported formats (`crates/ffs-cli/tests/cli_e2e.rs::cli_inspect_ext4_returns_json`, `cli_inspect_btrfs_returns_json`, `crates/ffs-cli/src/main.rs::tests::inspect_output_serializes_all_six_formats_bd_i0gk5`). |
| CLI info command | FrankenFS spec §14.2 | ✅ | `ffs info` implemented in `ffs-cli` with optional `--groups`, `--mvcc`, `--repair`, and `--journal` sections plus `--json` output (`crates/ffs-cli/tests/cli_e2e.rs::cli_info_ext4_shows_superblock`, `cli_info_btrfs_shows_superblock`). |
| CLI dump command | FrankenFS spec §14.4 | ✅ | `ffs dump` implemented in `ffs-cli` with subcommands `superblock`, `group`, `inode`, `extents`, and `dir`, each supporting `--json` and `--hex` (`crates/ffs-cli/src/main.rs::tests::build_dump_dir_output_btrfs_returns_vfs_directory_projection`). |
| CLI fsck command | FrankenFS spec §14.1 | ✅ | `ffs fsck` implemented in `ffs-cli` with `--repair`, `--force`, `--verbose`, `--block-group`, and `--json`; checks include superblock/group-descriptor validation + scoped scrub reporting (`crates/ffs-cli/tests/cli_e2e.rs::cli_fsck_ext4_clean_image`, `cli_fsck_corrupted_superblock_reports_error`), `--block-group` now supports ext4 groups and btrfs block-group indexes (extent-tree discovered), and `--repair` executes ext4 mount-time journal/orphan recovery plus btrfs primary-superblock restoration from validated backup mirrors with post-write scrub verification, including bootstrap recovery when initial btrfs detection fails due to primary-superblock corruption. V1.x write-side repair stays single-host only at any instant, gated by the shared lease-based ownership protocol (`ffs_repair::ownership`): the persistent per-image coordination record (`.<image>.ffs-repair-owner.json`) carries a TTL-bounded lease, expired leases (including foreign crashed-host leases) are taken over, and concurrent claims converge via a deterministic host-id tiebreak. A live foreign lease blocks mutation while still reporting read-only diagnostics. Concurrent multi-host repair, mid-run lease renewal, network symbol exchange, and per-group ownership remain future scope. |
| CLI repair command | FrankenFS spec §14.3 | ✅ | `ffs repair` implemented in `ffs-cli` with `--full-scrub`, `--block-group`, `--rebuild-symbols`, `--verify-only`, `--max-threads`, and `--json` (`crates/ffs-cli/tests/cli_e2e.rs::cli_repair_verify_only_ext4`); ext4 path performs stale-scope selection, block-symbol reconstruction attempts, symbol re-encoding (`--rebuild-symbols` + post-recovery refresh), and post-write verification scrub, while btrfs now supports scoped `--block-group` scrub by discovered block-group index plus primary-superblock restoration from validated backup mirrors, including bootstrap recovery when initial btrfs detection fails due to primary-superblock corruption. V1.x write-side repair stays single-host only at any instant, gated by the shared lease-based ownership protocol (`ffs_repair::ownership`): the persistent per-image coordination record (`.<image>.ffs-repair-owner.json`) carries a TTL-bounded lease with expired-lease takeover and a deterministic host-id tiebreak, surfaced through `repair_coordination` ownership fields in the JSON output. Lease-gated multi-host ownership is distinct from broader multi-host write-side recovery: concurrent repair, network symbol exchange/rebuild, and per-group ownership remain unsupported future scope. |
| fixture conformance harness | FrankenFS spec §7 | ✅ | Implemented in `ffs-harness`, including kernel-reference differential coverage for ext4 xattrs via `debugfs ea_list`/`ea_get` and write-path parity coverage that replays `ea_set` mutations through `ffs-xattr::set_xattr` in `crates/ffs-harness/tests/kernel_reference.rs` |
| benchmark harness | FrankenFS spec §8 | ✅ | Criterion benchmark suite and canonical profile artifact verification in `ffs-harness` (`crates/ffs-harness/tests/profile_artifacts.rs::canonical_profile_artifacts_are_committed_and_structured`). |
| xfstests generic/ext4 subset infrastructure | xfstests (`check`, generic/, ext4/) | ✅ | Curated subset manifests, planner/runner automation, CI planning gate, and regression guard workflow are implemented (`crates/ffs-harness/src/xfstests.rs::tests::xfstests_baseline_manifest_json_shape`, `failure_triage_extracts_products_excludes_non_products_and_merges_duplicates`). The allowlist is revalidated against mounted-path ioctl/fallocate evidence: `ext4/001` is now tracked as likely-pass pending direct xfstests rerun because FrankenFS already proves ZERO_RANGE + FIEMAP separately, while `ext4/005` remains allowlisted only for the narrower unsupported `chattr -e` extent-to-non-extent conversion path. |
| FAT16/FAT32 BPB and cluster geometry parsing | `fs/fat/inode.c` | ✅ | `FatGeometry::parse` validates BPB sector/cluster geometry, active FAT copy, and FAT32 root cluster / FSInfo offsets (`crates/ffs-ondisk/src/fat.rs::tests::geometry_uses_cluster_count_and_volume_relative_offsets`, `fat32_active_copy_and_root_are_validated`). |
| FAT16/FAT32 allocation table entry classification | `fs/fat/fatent.c` | ✅ | `FatKind::decode_entry` classifies free, allocated, reserved, bad, and EOF cluster entries with FAT32 top-nibble masking (`crates/ffs-ondisk/src/fat.rs::tests::allocation_entry_classes_and_reserved_bits`). |
| FAT16/FAT32 directory and LFN sequence decoding | `fs/fat/dir.c` | ✅ | `FatDirectoryStream` reconstructs VFAT long filenames bound by short-name checksum, preserves deleted/end markers, and flags orphan LFN damage (`crates/ffs-ondisk/src/fat.rs::tests::long_name_is_bound_to_its_short_record`, `multi_slot_names_deleted_entries_and_end_marker`). |
| FAT16/FAT32 timestamp and OEM short-name projection | `fs/fat/misc.c` | ✅ | Lossless FAT date/time/centisecond parsing and OEM codepage short-name decoding (`crates/ffs-ondisk/src/fat.rs::tests::directory_timestamp_fields_are_lossless_in_both_dialects`). |
| NTFS boot sector and MFT record USA fixup decoding | `fs/ntfs3/super.c`, `fs/ntfs3/record.c` | ✅ | `NtfsGeometry::parse`, `restore_record`, and `NtfsFileRecord::parse` validate BPB geometry and 512-byte Update Sequence Array sector trailers (`crates/ffs-ondisk/src/ntfs/tests.rs::boot_validates_addressable_range_and_both_record_size_encodings`, `all_trailers_are_checked_and_input_is_never_partially_restored`). |
| NTFS attribute list and non-resident mapping pairs | `fs/ntfs3/attrib.c`, `fs/ntfs3/run.c` | ✅ | `decode_mapping_pairs` and `NtfsAttributeList` decode signed LCN deltas, sparse runs, and multi-record attribute continuations (`crates/ffs-ondisk/src/ntfs/tests.rs::mapping_pairs_handle_backward_deltas_and_sparse_runs_without_resetting_lcn`, `crates/ffs-ondisk/src/ntfs/attribute_list.rs::tests::references_names_and_continuation_vcns_are_lossless`). |
| NTFS index root and INDX B-tree block decoding | `fs/ntfs3/index.c` | ✅ | `NtfsIndexRoot` and `NtfsIndexBlock` parse `$I30` directory B-tree roots, subcluster VBNs, and USA-protected `INDX` blocks (`crates/ffs-ondisk/src/ntfs/index/tests.rs::resident_index_keys_and_subcluster_vbn_units_are_explicit`, `indx_requires_matching_vbn_valid_fixups_and_no_usa_overlap`). |
| NTFS extended attributes and security descriptor catalog | `fs/ntfs3/xattr.c` | ✅ | `NtfsEaCatalog` and `$Secure` `$SDS`/`$SII` stream/index parsers validate EAs, SIDs, and ACL descriptors (`crates/ffs-ondisk/src/ntfs/ea/tests.rs::native_nonzero_final_lengths_preserve_names_binary_values_and_need_count`, `crates/ffs-ondisk/src/ntfs_security/tests.rs::native_descriptor_preserves_owner_group_acl_and_hash`). |
| NTFS $LogFile restart and redo/undo transaction planning | `fs/ntfs3/fslog.c` | ✅ | `parse_ntfs_logfile` and recovery appliers validate RSTR/RCRD pages, transaction tables, and descending-LSN undo plans (`crates/ffs-ondisk/src/ntfs/log_transactions/tests.rs::commit_preserves_winner_data_and_forget_is_not_itself_a_commit`, `crates/ffs-ondisk/src/ntfs/recovery/tests.rs::resident_redo_and_undo_preserve_neighbors_and_do_not_mutate_input`). |
| NTFS transparent compression (LZNT1/XPRESS/LZX) | `fs/ntfs3/lznt.c` | ✅ | Bounded decompression for NTFS LZNT1 compression units and WOF XPRESS/LZX streams (`crates/ffs-ondisk/src/lznt1.rs::tests::raw_chunks_short_chunks_and_end_markers`). |
| ZFS vdev label, nvlist, and uberblock ring validation | `module/zfs/vdev_label.c`, `module/zfs/uberblock.c` | ✅ | Four-label vdev geometry, XDR nvlist pool configuration, salted verifier checksums, and uberblock ring selection (`crates/ffs-ondisk/src/zfs/tests.rs::label_positions_and_uberblock_strides_are_checked`, `salted_labels_reject_copy_to_another_offset_and_damage`). |
| ZFS blkptr, embedded block, and gang header decoding | `module/zfs/zio.c` | ✅ | Regular, embedded, and gang block-pointer validation with Fletcher4/SHA-256/SHA-512t256 checksums (`crates/ffs-ondisk/src/zfs/tests.rs::regular_block_checks_bounds_checksum_and_codec_before_success`, `embedded_lz4_and_lzjb_decode_the_native_byte_sized_payload`). |
| ZFS block compression (LZ4/LZJB/GZIP/ZLE/ZSTD) | `module/zfs/zio_compress.c` | ✅ | ZFS physical and embedded block decompression across LZ4, LZJB, GZIP, ZLE, and framed ZSTD (`crates/ffs-ondisk/src/zfs/tests.rs::zfs_lz4_envelope_literals_matches_and_exact_output`, `crates/ffs-ondisk/src/zfs/zstd_tests.rs::zstd_published_vectors_cover_raw_compressed_sequences_and_multiblock_rle`). |
| ZFS RAIDZ stripe mapping and parity reconstruction | `module/zfs/vdev_raidz.c` | ✅ | `ZfsRaidzMap` column geometry and GF(2^8) single/double/triple parity reconstruction (`crates/ffs-ondisk/src/zfs/raidz/tests.rs::maps_match_twenty_executed_native_function_captures`, `every_single_data_erasure_and_corruption_hypothesis_reconstructs_long_and_short_columns`). |
| ZFS DMU dnode, bonus/spill, and indirect block routing | `module/zfs/dnode.c`, `module/zfs/dmu.c` | ✅ | `ZfsDnodePhys`, `ZfsObjectSetPhys`, bonus/spill buffers, and indirect block tree routing (`crates/ffs-ondisk/src/zfs_dmu.rs::tests::both_orders_preserve_bonus_spill_and_used_units`, `routes_include_root_slot_and_all_indirect_digits_without_overflow`). |
| ZFS MicroZAP and FatZAP directory table resolution | `module/zfs/zap.c`, `module/zfs/zap_micro.c` | ✅ | MicroZAP and FatZAP hash-leaf directory and property table resolution (`crates/ffs-ondisk/src/zfs_dmu.rs::tests::microzap_preserves_raw_names_and_refuses_duplicate_or_incomplete_maps`, `crates/ffs-ondisk/src/zfs_zap/tests.rs::embedded_and_external_tables_resolve_exact_leaf_prefix_ranges`). |
| ZFS ZPL POSIX attributes and System Attribute (SA) layouts | `module/zfs/zfs_sa.c`, `module/zfs/zfs_znode.c` | ✅ | Legacy znode bonus and dynamic SA layout registration decoding for POSIX mode/uid/gid/timestamps/symlinks/xattrs (`crates/ffs-ondisk/src/zfs_zpl/tests.rs::legacy_metadata_retains_native_times_ids_and_inline_links_in_both_orders`, `sa_reordered_layout_and_dynamic_registration_decode_without_fixed_offsets`). |
| multi-format OpenFs auto-detection and read-only VFS mount | FrankenFS spec §6 / §9 | ✅ | Unified 6-format (`ext4`, `btrfs`, `fat16`, `fat32`, `ntfs`, `zfs`) magic auto-detection, `OpenFs` read-only VFS dispatch (`getattr`, `lookup`, `readdir`, `read`, `readlink`, `statfs`), and CLI `inspect`/`info`/`fsck` (`crates/ffs-core/src/lib.rs::tests::detect_all_filesystems_identifies_fat16_fat32_ntfs_and_rejects_ambiguity_bd_i0gk5`). |
| CLI tui live telemetry dashboard and mount-console integration | FrankenFS spec §14.5 | ✅ | Live `OpenFs`/`MvccStore`/`ByteBlockCache`/`ScrubDaemon` telemetry wired into `ffs-tui`, `ffs tui`, and `ffs mount --mount-console` (`crates/ffs-cli/src/main.rs::tests::build_live_tui_and_mount_console_snapshot_populates_real_cache_and_scrub_telemetry`, `crates/ffs-cli/src/mount_console.rs::tests::emit_mount_console_includes_live_dashboard_snapshot_in_summary_markdown`). |

Legend: `✅` implemented. `🚧` partial: infrastructure exists in code but the capability is not end-to-end functional (e.g., not wired into mounted writeback); see the row body for the specific gap.

## 3. Blocking Gaps in the Tracked V1 Matrix

No blocking gaps in the tracked V1 parity matrix.

## 4. Operational Bridge Items Outside the Parity Denominator

These items do not reduce the 97/97 tracked feature count because they are not
additional rows in the current denominator. They are still required before this
project can honestly claim operational readiness beyond the current V1 contract.

| Bead | Area | Status |
|------|------|--------|
| `bd-rchk1` | Docs/status reconciliation | Complete: canonical docs separate tracked parity from runtime readiness |
| `bd-rchk2` | btrfs delayed-reference semantics | Complete: `DISC-004` accepted as a scoped V1 model with retry-safe failed-flush and overflow coverage |
| `bd-rchk3` | xfstests baseline | In progress: 2026-05-05 explicit-path preflight passes and safe dry-run artifacts are recorded; real product pass/fail evidence remains blocked on permissioned execution with `XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices` plus scoped `XFSTESTS_DIR`, `TEST_DIR`, `SCRATCH_MNT`, and `RESULT_BASE` |
| `bd-rchk3.1.1` | xfstests prerequisite preflight | Complete: `ffs_xfstests_preflight_e2e.sh --self-test` exercises current-host and simulated-host manifests, emits stable scenario IDs, validates stdout/stderr/transcript paths, preserves safe remediation/no-auto-install proof, and links the shared capability vocabulary to `bd-rchk3.2` and `bd-rchk3.3` before real xfstests can report a product baseline. |
| `bd-f3hug` | xfstests remediation safety | Complete: preflight rows now carry explicit safe-guidance fields, observed values, preflight/probe ids, no package-manager/install/mount/persistent-path authority, and fixture coverage for missing tooling, permission denial, dpkg locks, worker mismatch, and unsupported local lanes; remediation remains blocked until a fresh follow-up probe proves the intended lane. |
| `bd-suf84` | br dotted-ID tracker roundtrip | Complete: `validate_br_dotted_id_roundtrip.sh` copies the tracker to an isolated fixture and proves `br 0.2.3` preserves `bd-rchk0.5.6` plus `bd-rchk0.5.6.1` through exact no-db lookup, no-db parent update, dependency adds, fresh DB import, DB update, flush-only export, zero dependency cycles, command transcripts, and count-preserving post-flush no-db lookup. |
| `bd-rchk0.4` | Operational QA artifact contract | Complete: `ffs-harness` and E2E helpers now share operational artifact schemas, pass/fail/skip/error vocabulary, strict manifest validation, reusable runner logging, raw stdout/stderr and cleanup-status references, and one-command operational readiness aggregation for JSON/Markdown summaries across proof lanes. |
| `bd-rchk0.1` | Read-write mounted repair serialization | Serializer implemented: recovered source blocks can use the mounted MVCC repair-writeback serializer with stale-snapshot rejection, ledger evidence, and deterministic repair/client-write race controls. This historical completion does not prove safe symbol storage: the CLI currently refuses `--rw --background-repair` until allocator-owned storage under bd-11a8t is implemented. |
| `bd-rchk0.3` | Mount/write operational hardening | Complete: README readiness SLOs now bind mounted ext4/btrfs write claims, `tests/workload-matrix/mounted_write_workload_matrix.json` covers representative mounted write scenarios and explicit unsupported-path outcomes, `tests/workload-matrix/mounted_recovery_matrix.json` records crash/unmount/reopen evidence, and `tests/mounted-write-error-classes/mounted_write_error_classes.json` plus readiness-report consumers keep mounted failure classes actionable without reducing the experimental wording beyond the validated evidence tier. |
| `bd-rchk4` | CI-compatible mounted FUSE coverage | Complete: FUSE capability probes now emit structured skip/error artifacts, the production FUSE lane records worker/kernel/fusermount/mount-option/log/cleanup metadata, the mounted ext4/btrfs scenario matrix has cataloged evidence, and authoritative mounted gates fail closed on unavailable, stale, mismatched, or incomplete lane artifacts while local developer runs preserve explicit host-skip diagnostics. |
| `bd-rchk5` | Performance baselines | Complete: `benchmarks/performance_baseline_manifest.json`, dated 2026-05-03 core and mounted artifacts, `docs/reports/PERFORMANCE_DELTA_CLOSEOUT.md`, and regression/no-reference closeouts (`bd-rchk5.5`, `bd-rchk5.6`, `bd-rchk5.7`, `bd-rchk5.8`) now record measured throughput/latency evidence, host/runtime metadata, explicit missing-reference decisions, and quarantined mounted latency claims instead of unsupported readiness wording. |
| `bd-rchk6` | Mounted self-healing lifecycle | Lifecycle implemented for admitted client read-only `--background-repair --background-scrub-ledger <jsonl>` mounts. The historical serializer proof does not cover allocator-owned symbol storage; read-write mounted repair remains refused, and bd-plamw adds complete-plan startup refusal while bd-11a8t retains the permanent storage requirement. |
| `bd-rchk7` | Fuzz/conformance expansion | Complete: open-ended corpus notes are resolved through the `conformance/COVERAGE.md` inventory, closed repair corpus and mounted repair fixture beads (`bd-rchk7.2`, `bd-rchk7.3`), and the fixed-seed fuzz-smoke gate (`bd-rchk7.4`, `bd-u8hx5`) |
| `bd-rchk0.5` | Ambition/trust proof layer | Complete: all direct ambition beads are closed and the trust layer now has executable evidence for invariant oracles, mounted differential checks, repair confidence, proof bundles, chaos/replay schedules, release gates, workload corpus coverage, operator drills, soak/canary campaigns, ambition evidence mapping, adversarial-image safety, remediation guidance, low-privilege trust demos, and proof-overhead budgets while preserving explicit xfstests and evidence-tier deferrals. |
| `bd-xuo95.19` / `bd-xuo95.20` | ffs-harness module census + ops relocation | Complete: `crates/ffs-harness/module_census.json` classifies all 81 tracked `ffs-harness/src/*.rs` modules by `conformance` vs `meta` after relocating the self-referential ops modules to `tools/ffs-ops`. Current harness split: 23 conformance modules / 29,398 LOC (22.19%) and 58 meta modules / 103,072 LOC (77.81%) out of 132,470 LOC, verified by `crates/ffs-harness/tests/module_census.rs` against the tracked source tree; relocated ops source is under `tools/ffs-ops/src`. |
| `bd-xuo95.21` | ffs-harness meta LOC growth guard | Complete: `tools/ffs-ops harness-loc-growth-guard` compares PR net LOC growth in D1-classified meta harness modules against conformance-module LOC growth plus non-ignored conformance `#[test]` growth, emits a GitHub warning when meta growth exceeds that allowance, and remains warning-only in CI for human review. |
| `bd-rchk0.5.1` | Executable invariant oracle | Complete: `ffs-harness` validates replayable invariant traces for create/write/fsync, nested rename/unlink, extent ownership and overlap rejection, snapshot visibility, journal replay idempotence, and mounted repair writeback authority; the CLI/E2E path emits deterministic replay ids, artifact references, reproduction commands, expected/unexpected failure classes, state hashes, and minimized trace prefixes. |
| `bd-rchk0.5.2` | Mounted differential oracle | Complete: `ffs-harness` validates mounted ext4/btrfs differential oracle reports with normalized kernel/FrankenFS observations, explicit baseline manifests, lane-isolated image and mount paths, narrow expiring allowlists, host-skip classes for FUSE/tooling/permission gaps, btrfs `DefaultPermissions` root-ownership diagnosis, unsupported-scope ownership, raw artifact links, cleanup status, and Markdown/JSON summaries; `scripts/e2e/ffs_mounted_differential_oracle_e2e.sh` emits pass/diff/skip/unsupported/error scenario evidence without treating host capability skips as product failures. |
| `bd-rchk0.5.7` | Real-world workload corpus | Complete: `tests/workload-corpus/p1_workload_corpus.json` provides stable, schema-validated scenarios for editor-save, package extraction, metadata churn, append/truncate replay pressure, mount/unmount/reopen, ext4-specific xattr/dir-index behavior, btrfs DefaultPermissions diagnostics, repair-corruption refusal, unsupported operations, permission boundaries, and expected FUSE host skips; `ffs-harness validate-workload-corpus` emits per-scenario logs, proof-consumer coverage, reproduction commands, and a coverage matrix consumed by differential oracle, crash/replay, repair lab, proof bundle, release gate, readiness report, and performance lanes. |
| `bd-rchk0.2` | Writeback-cache enablement decision | Complete: kernel FUSE `writeback_cache` remains default-off but is now safely exposed only through explicit `--rw --writeback-cache` opt-in guarded by accepted negative-option audit, dirty-page ordering oracle, crash/replay oracle, runtime guard, matching host/lane manifest, and a disarmed kill switch; README, help text, design docs, tests, and feature status agree on the experimental opt-in contract and preserve the fresh xfstests baseline deferral (`bd-rchk3`). |
| `bd-4nobd` | Writeback-cache runtime guard | Complete: `ffs-harness` and `ffs-cli` now require runtime-guard evidence for explicit writeback-cache opt-in, including disarmed `FFS_WRITEBACK_CACHE_KILL_SWITCH`, accepted feature state, CLI-explicit config source, fresh gate hash/TTL, matching host/lane manifest, and stable rejection classes for stale gates, feature downgrades, config-default attempts, host mismatches, and repeated downgrade attempts. |
| `bd-rchk0.2.3` | Writeback-cache crash/replay integration | Complete: `ffs-harness validate-writeback-cache-crash-replay` now records the 12 required crash point IDs, mounted operation trace, raw mount and FUSE options, expected/actual survivor sets, flush/fsync/fsyncdir observations, cancellation and repeated-write classification, stdout/stderr paths, cleanup status, unsupported-combination rejection, and reproduction command; `scripts/e2e/ffs_writeback_cache_audit_e2e.sh` validates accept/reject/report/unit scenarios plus the mounted ext4 opt-in regression with explicit host skip classification. |
| `bd-rchk0.2.4` | Writeback-cache operator documentation | Complete: README limitations/status, `ffs mount --help` comments, and `docs/design-writeback-cache-mvcc.md` now agree that kernel `writeback_cache` is default-off, explicit read-write opt-in only, and gated by accepted audit, ordering, crash/replay, runtime-guard, host/lane, and kill-switch evidence. Operator docs cite validator commands, unit-test groups, E2E scenario IDs, crash/replay artifact fields, and the remaining readiness deferral for a fresh xfstests baseline (`bd-rchk3`); performance and soak/canary wording is now backed by explicit closeouts and quarantines rather than hidden deferrals. |

## 5. Update Rule

Any change touching compatibility behavior MUST update this file in the same patch.

## Native companion increments (2026-10-11)

These implementation entries do not change the legacy ext4/btrfs contract
counts above and do not establish full filesystem or recovery qualification.

| Mode and capability | Implemented scope | Execution evidence for this increment |
|---|---|---|
| NTFS numeric DATA provider admission | Complete base/extension catalog check rejects REPARSE_POINT before selecting unnamed or named DATA, matching the path-read provider boundary. One regression covers eight combinations of provider/control, base/extension location and resident/nonresident stream selection. | Source and fixture review plus exact GitHub blob comparison. Rust regression, formatting, workspace checks, Clippy and UBS remain unexecuted because the authoring executor disconnected; no native-image or Windows interoperability credit. |

### NTFS lossless DATA stream selection

Numeric `cat` and path `read` accept `--stream-utf16` as exact comma-separated
four-digit native code units, including unpaired surrogates reported by the
logical stream catalog. The existing Unicode selector remains available; the
options are mutually exclusive and enforce the native 255-unit name bound.
Parser and CLI regressions are authored and source-reviewed. Rust execution,
formatting, workspace checks, Clippy, UBS and native-image validation remain
unavailable with the executor offline; no execution parity credit is added.

### NTFS mounted encryption-default directories

The read-only mounted view admits native directories whose ENCRYPTED attribute
sets the default for new children. Directory operations and unencrypted child
reads retain normal behavior; actual EFS files and encrypted DATA still fail
before payload I/O. Added FsOps and raw-stream extraction fixtures are
source-reviewed, with Rust/build/fmt/Clippy/UBS and native mounted execution
unavailable while the executor is offline. No executed parity credit is added.

### FAT16/FAT32 native timestamps

Creation date/time and 10 ms increments, access date, and modification date/time
are preserved and exposed through FsOps using the documented UTC wall-clock
projection. Unknown fields retain the epoch sentinel; invalid present fields
identify the directory record. Parser and FsOps regressions cover both dialects,
calendar limits, precision, missing values and error locations. The inherited
cyclic-directory listing assertion is aligned with the full-chain validation.

Seven calendar constants were checked independently through JavaScript date
conversion, and the source/fixtures received independent review and exact blob
comparison. Rust tests, formatting, workspace checks, Clippy and UBS remain
unexecuted with the authoring executor offline; no native or mounted parity
credit is added.

### ZFS native ZLE reads

Native codec 14 now decodes bounded literal and zero runs through physical and
embedded block paths, extending ordinary file, snapshot and mounted reads.
Complete output is required; physical padding remains checksum-protected.
Six parser/block regressions and independent source/reference-fixture checks
cover both byte orders and malformed streams. Rust/build/fmt/Clippy/UBS and
native-image execution remain unavailable with the executor offline; no
executed native parity credit is added. See `docs/ZFS_READ_PROFILE.md`.

### ZFS native SHA-512/256 block checksums

The physical block pipeline admits native checksum 11 using the existing sha2
dependency. Digest words follow the payload byte order, independently of the
pointer container; SHA256 retains its native historical convention. Known-answer
and block-dispatch regressions cover numeric word order, data/checksum damage
and unsupported neighboring algorithms. Source/reference checks are recorded
in `docs/ZFS_READ_PROFILE.md`; Rust/build/fmt/Clippy/UBS and native-image execution
remain unavailable with the executor offline, so no executed parity credit is
added.

Details and commands: `docs/NTFS_READ_PROFILE.md` and `docs/FAT_READ_PROFILE.md`.

### ZFS native GZIP reads

Native compression IDs 5..13 now decode zlib-framed gzip-1 through gzip-9 through
the shared physical and embedded block pipeline, extending ordinary files,
snapshots and read-only mounts. The existing flate2/zlib-rs dependency uses a
fixed logical-size output buffer and requires the complete stream, valid
Adler-32 and exact output length. Physical padding remains checksum-protected;
dictionary requests, other framing, malformed streams and unsupported codecs
remain refused.

Seven parser/block regressions cover independently specified fixed, dynamic and
stored DEFLATE vectors, all native levels, both byte orders and failure bounds.
Source/reference checks are documented in `docs/ZFS_READ_PROFILE.md`.
Rust/build/fmt/Clippy/UBS and native-image execution remain unavailable with the
executor offline, so no executed parity credit is added.

### FAT16/FAT32 lossless native catalog and extraction

`ffs-fat catalog` reports exact short-name bytes and assembled UTF-16 long names,
including names unavailable to the host-path projection. Validated root-to-entry
`--entry-slots` selectors reach nested directories and extract regular files
without choosing an OEM code page or replacing native units. Parent membership,
complete directory parsing, ancestor checks and existing file-allocation/EOF
validation prevent arbitrary image offsets from becoming file identities.
Raw name separators are checked before display decoding.

Three parser/CLI and seven constructed image regressions cover both dialects,
lossless name cases, invalid selectors and structural failures, allocation tails,
cancellation and image immutability. Source/fixture review and exact blob
comparisons completed. Rust/build/fmt/Clippy/UBS and native-image execution remain
unavailable with the executor offline; no executed parity credit is added.
See `docs/FAT_READ_PROFILE.md`.

### NTFS native security descriptors

`ffs-ntfs security` resolves native file security through the complete
base/extension catalog, then the bounded $Secure:$SII index and verified
primary/duplicate $SDS entries, or a legacy SECURITY_DESCRIPTOR attribute.
It reports lossless descriptor bytes, native SIDs and ACL structure, and
supports raw extraction by validated MFT record identity. An iterative
full-tree traversal, allocated-child checks, native hash validation and
strict initialized-range/component bounds fail on inconsistent metadata.
Absent, NULL and empty ACLs remain distinct. This is metadata inspection;
native permission enforcement, SID mapping and mutation remain separate.

Six parser, nine image-reader and two CLI/report regressions are authored
and independently source-reviewed. Native hash and mapping calculations were
checked separately. Rust/build/fmt/Clippy/UBS and native-image execution remain
unavailable with the executor offline; no executed parity credit is added.
See `docs/NTFS_READ_PROFILE.md`.

### ZFS native Zstandard reads

Native codec 16 decodes OpenZFS's big-endian wrapper and magicless Zstandard
frame through the shared physical/embedded pipeline. All native levels and
historical header layouts are supported. Exact single-frame consumption,
fixed LSIZE output, content integrity and explicit 16 MiB advertised-window
bounds reject malformed or oversized streams. Full physical checksums retain
padding coverage; ordinary file, snapshot and mounted reads use this transform.
The per-dataset Zstandard feature does not expand the MOS label allowlist.

Ten regressions cover independent Go/Zstandard vectors, malformed framing and
lengths, dictionary requirements, memory limits and block integrity in both
byte orders. Source/fixture review and exact blob comparisons completed.
Rust/build/fmt/Clippy/UBS and native pool execution remain unavailable with the
executor offline; no executed parity credit is added. See `docs/ZFS_READ_PROFILE.md`.

### FAT16/FAT32 native new-image creation

`ffs-fat format` creates new empty native FAT16/FAT32 volume images with
checked geometry, two mirrored allocation tables, fixed/chained roots, native
labels/serials, and FAT32 boot/FSInfo backups. Atomic exclusive creation refuses
every existing target. Bounded initialization writes and synchronizes metadata
before the primary boot sector, verifies exact metadata and complete allocation
counts through the existing reader/checker on the same locked file, then
synchronizes the parent directory. Failures retain the new file and report its
potentially incomplete state. Existing-volume mutation/recovery remains separate.

Eleven regressions cover geometry boundaries, native layout and readback,
no-overwrite behavior, partial I/O failures, cancellation, synchronization order
and unexpected allocation. Independent source review and arithmetic comparison
against a closed-form FAT sizing equation completed. Rust/build/fmt/Clippy/UBS,
native fsck/mtools and mounted execution remain unavailable with the executor
offline; no executed native-format or interoperability credit is added.
See `docs/FAT_READ_PROFILE.md`.


### ZFS complete-mirror extraction and mounts

Every explicit-root command accepts repeated `--mirror-member` images for one
ordinary top-level mirror of two through eight leaves. The reader checks the
complete native member GUID set, all four labels on each image, topology,
geometry, read features and the selected root candidate. Argument order never
supplies native identity, and configuration paths are never opened on the host.
Mirror addressing uses the same physical offset on each member and native
ashift-rounded DVA sizes. Each physical copy is checksum-verified before use;
I/O/checksum failures try another supplied member, cancellation stops immediately,
and failed data never enter the checked-block cache.

One owned member set now reaches raw MOS/DMU operations, datasets, file reads,
snapshot reads and the existing read-only FsOps/mount adapter. All backing image
paths participate in the mountpoint guard. Eleven constructed engine regressions
and four CLI regressions cover member admission, root agreement, redundant
metadata/data reads, historical roots, cancellation and cache publication.
The changed Rust files were parsed and formatted. Integrated CLI checks/tests
were attempted, including one compiler thread, but `asupersync` compilation
received SIGKILL under the shared memory limit. These new tests and native
OpenZFS/mounted mirror workloads remain unexecuted. No import, degraded-member
selection, repair write, healing or RAIDZ support is implied.
See `docs/ZFS_READ_PROFILE.md` for the native profile and commands.

### NTFS ordered ACE inspection and complete security-index bounds

The existing native `security` command now reports ordered ACE kinds, flags,
access masks, trustee SIDs, object GUID bytes and lossless callback/unknown data.
Known layouts receive complete bounded validation; unused ACL bytes are retained.
The report preserves absent/NULL/present ACL distinctions, the exact zero-versus-
absent STANDARD_INFORMATION security ID, legacy-attribute presence and the native
$Secure sequence. It explicitly records that no access decision was evaluated.

The reader rejects $SII bitmaps that cannot cover every INDEX_ALLOCATION slot,
including leaf roots without children, and rejects descriptor/SDS lengths that
would leave unhashed partial words. The published iterative index traversal,
physical-range validation, shared-descriptor precedence and raw extraction remain.

All 12 merged native-security parser tests executed successfully, including six
new regressions and the corrected inherited SID-boundary fixture. Five new reader
regressions and one report regression are source-reviewed but unexecuted. Changed
Rust sources were parsed/formatted; integrated CLI checks/tests received SIGKILL
while compiling `asupersync` under the shared memory limit. No native Windows,
mounted security-enforcement or full-workspace gate credit is added.
See `docs/NTFS_READ_PROFILE.md` for fields, boundaries and commands.

### ZFS raw Zstandard size admission

A bounded native-header preflight checks the advertised window before libzstd
header parsing and distinguishes an explicit 64-bit content size from library
status sentinels. Oversized windows and declared-size/LSIZE disagreements fail
before frame copying or decoder-context creation. Existing physical checksums,
single-frame consumption, dictionary refusal and exact output bounds remain.

The original ten Zstandard tests and their assertions are retained; an eleventh
covers both frame forms, every zero dictionary-ID width and extreme explicit
sizes. The complete on-disk library suite passed 838 tests with no failures,
and on-disk all-targets Clippy passed with warnings denied. This includes the
merged NTFS security parser. Changed Rust sources were parsed/formatted. UBS
could not execute its installed launcher (permission denied). CLI reader/FsOps,
native OpenZFS and mounted mirror validation remain unexecuted; the parser
results add no native-pool or mounted-readiness claim.

### FAT16/FAT32 complete boot publication and interruption semantics

The native formatter preserves its existing geometry, optional labels, timestamps
and report fields while adding explicit cluster selection and decimal/hex serials.
FAT32 creates complete signed boot-record copies at sectors 0..2 and 6..8. Both
BPBs remain withheld until the mirrored FATs, root, FSInfo and extension sectors
are synchronized; final publication completes backup, primary, file sync and
parent sync without a cancellation checkpoint between those bounded operations.

Ctrl+C cancels the actual context shared by device reads and allocation-loop
checkpoints. Mandatory verification uses the cloned locked file handle after
durability, and an interrupted or failed scan identifies the already initialized,
synchronized image. Existing targets remain refused through exclusive creation.

All eleven original formatter tests remain, with publication/failure loops
extended through parent synchronization. Fourteen additional tests cover native
bytes and allocation, cluster/serial selection, hardlinks, request cancellation,
both boot extensions and original-inode verification. The native runner now tests
formatter-created images through fsck/mtools and exact byte/count/hash comparisons
as well as its existing native-created and optional mounted cases.

The five Rust files passed parsing/formatting checks and the runner passed Python
syntax compilation. Production and all 25 formatter tests received independent
source review. Earlier CLI dependency builds received SIGKILL during `asupersync`
compilation; the merged formatter suite, native interchange and mounted cases
remain unexecuted. UBS
could not execute its installed launcher. On-disk parser tests and Clippy do not
qualify this formatter. See `docs/FAT_READ_PROFILE.md` for the native profile,
commands, interruption outcomes and interoperability limits.

### FAT16/FAT32 populated native image creation

`ffs-fat format --source-dir DIRECTORY` now constructs complete native file and
directory trees in new images. The existing geometry planner and publication
sequence allocate both FAT copies, native short/long names, file and directory
chains, dot/parent entries, zero slack and exact FAT32 FSInfo hints. Preflight
checks native name and file-size limits, FAT16 fixed-root capacity and total
cluster space before exclusive destination creation. Short aliases reserve all
sibling native and long names before selection; the native U+FFFF LFN padding
sentinel is refused before writing.

Retained source handles, namespace/identity checks and SHA-256 checks detect
source replacement or changes during preparation. Both BPBs remain withheld
until planned payloads and metadata are ready and synchronized. After durable
publication, verification uses the original locked output inode, the complete
allocation/namespace checker and every payload through the native FAT reader.
The source contract is bounded and requires a stable tree; it is not a host
snapshot or an existing-volume mutation API.

All 25 existing formatter tests remain, with 15 new substantive regression
groups for layout, names, directory growth, capacity, source races, cancellation,
I/O failures and payload corruption. The native oracle adds populated-image
fsck/mtools extraction and extension, exact names/bytes/counts, source and image
immutability checks and optional mounted reads while preserving previous cases.
The changed Rust files passed parsing/formatting checks, the oracle passed Python
syntax compilation, and two independent source/API reviews found no remaining
concrete defect. CLI compilation remains blocked by `asupersync` receiving SIGKILL
under the shared memory limit. The new formatter tests, native interchange and
mounted cases remain unexecuted. Workspace formatting reports pre-existing
differences in unchanged files; the installed UBS launcher is not executable.
See `docs/FAT_READ_PROFILE.md` for the command, native limits and evidence scope.

### NTFS WOF XPRESS logical file reads

The shared DATA pipeline now reads WOF individual-file-provider XPRESS4K,
XPRESS8K and XPRESS16K contents through numeric reads, path extraction and FsOps.
It uses native sparse unnamed DATA only for logical size and ValidDataLength;
initialized contents come from the validated `WofCompressedData` backing stream.
Fragmented runs and ATTRIBUTE_LIST continuations retain native file identity.
The reader fetches only the adjacent native offsets and the bounded selected
chunk, distinguishes raw chunks by exact stored length, decodes final partial
chunks to their exact logical length, and zero-fills the native uninitialized
tail. Corruption and cancellation never become successful partial payloads.

Explicit named-stream extraction preserves stored bytes for recognized WOF
file providers even when the logical codec is unsupported. LZX logical reads,
WIM/unknown providers and EFS contents remain outside admission. Ordinary native
LZNT1, links, security metadata, stream catalogs and read-only enforcement remain.
WOF files retain regular-file type, hard-link identity and backing allocation in
the filesystem adapter; cached stream metadata does not conceal later I/O errors.

All six new XPRESS decoder tests, including Microsoft's published MS-XCA byte
vectors, passed in the complete 844-test on-disk run. On-disk all-targets Clippy
passed with warnings denied at that decoder-only stage; the later combined
on-disk run with RAIDZ additions passed 850 tests. Nineteen new provider, image-
reader and FsOps regressions received source/API review but remain unexecuted:
workspace check and Clippy both stop while `asupersync` receives SIGKILL under the
shared memory limit. Changed Rust files pass parsing/formatting checks. Workspace
formatting reports pre-existing differences in unchanged files, and the installed
UBS launcher is not executable. Native Windows WOF images and mounted workloads
have not been validated. See `docs/NTFS_READ_PROFILE.md` for precise admission,
commands, native sources and evidence limits.

### ZFS complete ordinary RAIDZ1 reads and reconstruction

One complete ordinary RAIDZ1 group of two through eight explicitly supplied
file/disk leaves now reaches the existing Pool, MOS/DMU, datasets, ZPL, snapshots
and read-only FsOps pipeline. Every member's native GUID, complete label tree
and selected root candidate must agree before native child IDs are bound to
supplied images. Repeated `--member` accepts the complete set, with existing
`--mirror-member` and new `--raidz-member` aliases. The root diagnostic reports
actual data/parity/skip columns and reconstruction identity.

The native mapper implements ashift rounding, short and long columns, parity
address swapping and allocation-only skip sectors. All declared DVAs and every
member allocation extent are checked before payload I/O. Reads try intact data
without parity, then reconstruct one unavailable data column or try bounded
single-column hypotheses after checksum failure. The original PSIZE is checked
before the existing codec path supplies logical bytes. Cancellation stops
immediately; unverified or failed blocks cannot enter the shared checked cache.
Missing members, additional parity levels, dRAID, expanded/nested/replacing
layouts and write/healing/import protocols remain outside admission.

The complete on-disk suite passed 850 tests, including six new RAIDZ tests and
twenty mapping cases captured by compiling and executing the verbatim OpenZFS
zfs-2.3.0 mapping function in an isolated C harness. This is native-function
capture, not native pool or mount validation. The final on-disk all-targets
Clippy run passed with warnings denied. Twelve constructed engine regressions
cover admission, recovery, complete legacy/SA/spill and embedded file graphs,
historical snapshots, cancellation and cache failures; CLI coverage preserves
the existing member-limit/mount guards and tests all alias spellings together.
The changed Rust files passed parsing/formatting checks and independent reviews.
The new CLI/engine regressions remain unexecuted: a further CLI compile retry
again received SIGKILL while building `asupersync`. Workspace formatting reports
13 unchanged files, and UBS could not execute its launcher. Native OpenZFS pool
and kernel FUSE execution remain unverified. See `docs/ZFS_READ_PROFILE.md`.
