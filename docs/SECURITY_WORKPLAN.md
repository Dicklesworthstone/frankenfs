# Security-first native-image work: ordered execution record

Scope: useful native-image inspection with explicit authority, then protected
mutation and recovery. This is a granular continuation record, not a claim that
all project work is complete. Reviewed baseline: `b6b3e1485cdae9144203985e49048a6fb2e7a0bf`;
publish on current main and preserve concurrent work.

## Tracker authority

The canonical tracker is `.beads/issues.jsonl`. Its complete blob was available
for retrieval, and relevant rows were inspected; this is not an exhaustive fresh
execution of every historical acceptance condition. The current environment has
no `br`, Cargo or RCH and cannot safely round-trip the oversized export through a
partial-file write. Do not replace it with a subset. New progress is staged in
`.beads/pending_tasks.md` for canonical import, not represented as canonical
closures. Existing ownership of `bd-11a8t` remains intact.

## P0: remove hidden write authority (implementation in progress)

- [x] Compare current README with actual companion command and opening code.
- [x] Read relevant canonical rows, shared rules, and FAT/native expansion plan.
- [x] Verify `bd-i0gk5`, `bd-q19uk`, and `bd-nu8nf` are closed implementation rows.
- [x] Identify remaining NTFS/ZFS read-only callers of writable sidecar admission.
- [ ] Route NTFS and ZFS callers to the existing `open_read_only` constructor.
- [ ] Preserve native admission, recovery, namespace and existing test behavior.
- [ ] Add caller-path regressions or record the precise missing execution proof.
- [ ] Run targeted Rust checks on the changed consumers and protected-mount.
- [ ] Verify the published source hashes and main ancestry.

## P1: isolated offline reader workflow (implemented; kernel qualification open)

- [x] Reuse existing read-only command paths; no new native parser or Rust runtime.
- [x] Require a trusted native ELF binary and one to eight explicit input aliases.
- [x] Refuse mutation/mount commands, unknown aliases and unused input authority.
- [x] Pin O_RDONLY regular descriptors with shared locks; reject symlinks, FIFOs,
  devices, executable/input aliases and duplicate input inodes.
- [x] Require separate user/PID/network/IPC/UTS/mount namespaces, no capabilities,
  no-new-privileges, no additional user namespaces and no controlling terminal.
- [x] Expose only named inputs, trusted execution/runtime files, two explicit
  runtime device nodes, private proc and size-limited tmpfs; no host-root bind.
- [x] Prevent descriptor-path canonicalization races from selecting another input:
  verify each bound identity/read-only mount inside the sandbox before native exec.
- [x] Copy bootstrap/configuration from sealed memory, and close inherited host
  descriptors before executing the verified reader by descriptor.
- [x] Clear inherited environment; use no shell and no unsandboxed fallback.
- [x] Bound wall time, per-process address/CPU/file/FD use, per-UID process count,
  and combined stdout/stderr; kill the process group on timeout/overflow.
- [x] Record trusted code/input hashes, identities, exact arguments, policy,
  budgets, exit, bounded output hashes and before/after input observations.
- [x] Keep output private and create-new; retain partial evidence and fail closed
  when an exit, post-check or completion record is missing.
- [x] Execute 27 Python tests, including real file permissions/locks, memfd seals,
  subprocess limits, hostile output, descriptor closure and descendant pipes.
- [x] Attempt production entry point: correctly refused root in this environment.
- [ ] Run actual bubblewrap namespace/escape and native-reader integration tests.
  Bubblewrap is absent here; successful user-namespace probing alone is not proof.
- [ ] Qualify aggregate cgroup quotas, syscall filtering and supported host/kernel
  configurations before promoting this to a hostile-production security profile.

Executed test command:

```sh
python3 -I -m unittest discover -s scripts/tests -p test_ffs_inspect_sandbox.py -v
```

Result at initial publication: **27 passed**, Python 3.13. The tests include
explicitly scoped mock status/policy cases; they do not launch bubblewrap or
execute FrankenFS Rust. No performance, native-format or certified containment
claim follows from this result.

## P2: accurate public proposition and documentation (in progress)

- [x] Write the deployment/authority/evidence contract in SECURITY_INSPECTION.md.
- [ ] Rewrite README around native-image access, explicit authority and auditability.
- [ ] Refresh format and command matrix from current dispatch code.
- [ ] Separate detection, read access, native writes, replay and external protection.
- [ ] Explain dependencies, build paths, FUSE/library boundaries and security costs.
- [ ] Mark pending tracker progress and qualification blockers without false closure.
- [ ] Verify referenced repository paths and published changes.

## Next project work, in dependency order

1. **Execute and fix the exact committed readers.** Run read-only sidecar tests,
   companion suites and workspace checks. Reuse independent native images and
   filesystem oracles, not only fixtures and locally modeled algorithms.
2. **Qualify the isolated workflow end to end.** A disposable dedicated user/host
   must prove no source writes, no host-home/socket/device/network access, correct
   mount substitution refusal, descendant teardown and bounded hostile workloads.
3. **Complete backend library extraction and unified admission.** Reuse closed
   `bd-i0gk5` discovery/geometry seams, but independently inspect the remaining
   library-entrypoint acceptance rather than equating an enum with integration.
4. **Complete `bd-ljrbw` mounted/full-stack execution.** Inspect `bd-g49gi` and
   current dependencies first; real mount/restart/independent oracle evidence is
   required. Do not turn a skipped or smaller synthetic test into a passed gate.
5. **Continue default/native protection in its existing owner lane `bd-11a8t`.**
   Remaining generation/restart/cancellation/automatic repair obligations cannot
   be discharged by a sticky error flag or sidecar command alone.
6. **Measure total workflow cost.** Compare equivalent authority, caching,
   durability, image transport and integrity work; full-image audit hashing and
   sidecar refresh are real costs. No universal small-penalty claim.

No essential acceptance condition above is closed, removed from the plan or
silently transferred merely because one implementation patch is published.
