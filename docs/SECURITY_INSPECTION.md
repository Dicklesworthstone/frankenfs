# Isolated offline inspection (experimental)

FrankenFS aims to make native-image access auditable and explicitly authorized.
Userspace and memory-safe first-party Rust are useful foundations, not a sandbox
or proof of filesystem correctness. This profile adds an independent Linux
process boundary around the existing readers. It is not a certified high-assurance
product, a VM boundary, or a substitute for backups and host security maintenance.

## Run an existing reader without giving it ordinary host authority

Install a trusted, current **non-setuid bubblewrap** on a Linux host configured
to permit unprivileged user namespaces. Build the desired FrankenFS executable
separately, using the repository's normal build procedure. Run the supervisor
as a dedicated ordinary user, not root. Python 3.10+ is required; the isolated
`-I` interpreter option avoids inheriting Python import configuration. The
trusted pre-exec verifier additionally requires the system `/usr/bin/python3`
and runs with `-I -S` inside the sandbox; ship both launcher Python files together.

```sh
# These evidence directories must not already exist.
python3 -I scripts/ffs_inspect_sandbox.py \
  --tool ffs-cli --binary target/release/ffs-cli \
  --input disk=/srv/images/disk.img --output audit-inspect \
  -- inspect @disk --json

python3 -I scripts/ffs_inspect_sandbox.py \
  --tool ffs-fat --binary target/release/ffs-fat \
  --input disk=/srv/images/fat.img --output audit-fat-read \
  -- cat @disk /docs/report.txt

python3 -I scripts/ffs_inspect_sandbox.py \
  --tool ffs-ntfs --binary target/release/ffs-ntfs \
  --input disk=/srv/images/ntfs.img --output audit-ntfs-read \
  -- read @disk /docs/report.txt --offline-image

python3 -I scripts/ffs_inspect_sandbox.py \
  --tool ffs-zfs --binary target/release/ffs-zfs \
  --input leaf=/srv/images/zfs-leaf.img --output audit-zfs-inspect \
  -- inspect @leaf --offline-image
```

`NAME=PATH` declares one regular input. `@NAME` (also `--option=@NAME`) is replaced
with `/inputs/NAME` inside the sandbox. Every declared input must be referenced;
undeclared references, duplicate names, duplicate input inodes and executable/input
aliases are refused. Declare an archive separately to use `--sidecar=@archive`.
Native reader admission still applies: a mismatched sidecar is not authority to
roll back legitimate writes, and a ZFS label inventory is not pool-wide admission.

The allowlist admits offline read/inspection commands, not arbitrary executables
from an image, mounts, mutation, salvage or physical repair. The selected binary
and bubblewrap are trusted operator inputs and are hashed; the launcher does not
prove they implement their advertised behavior. Unsupported native commands,
profiles or loader dependencies fail normally. There is **no unsandboxed fallback**.

## Enforced policy and observations

The launcher pins the binary, bubblewrap and images with read-only descriptors.
Input final-component symlinks, devices, directories and FIFOs are rejected before
launch. Shared inode locks exclude cooperating writers. The sandbox bind mounts
the requested sources and runs a trusted pre-exec verifier before the native
reader. This matters because bubblewrap may resolve `/proc/self/fd/N` to a
pathname before binding. The verifier compares each mounted inode against both
the retained descriptor and the captured identity, refuses symlinks and writable
mounts, and checks namespace separation, zero capabilities and no-new-privileges.
Only then does it close inherited host descriptors and execute the verified ELF
reader by descriptor. Bootstrap code/configuration are copied from sealed memory
files into read-only mounts. Path substitution is a refusal, not a different input.

Bubblewrap is required to create separate user, PID, network, IPC and UTS
namespaces, drop all capabilities, disable further user namespaces, and disconnect
from the controlling terminal. Both namespace setup failure and an unsupported
required option are fatal. No network-sharing or weaker compatibility option is
added on failure.

Bubblewrap also installs a seccomp syscall filter (`--seccomp`) beneath those
namespaces. The launcher generates it as a short, straight-line classic BPF
program for x86_64 or aarch64; any other architecture is refused. The filter
kills the process on a foreign ABI (i386, or x32 on x86_64) and returns `EPERM`
for 62 syscalls (58 on aarch64) that no offline reader needs:

- networking (`socket`, `connect`, `bind`, ...);
- access to other processes (`ptrace`, `process_vm_*`, `pidfd_getfd`, `kcmp`);
- mount and namespace changes, including the descriptor mount API;
- handle-based opens (`open_by_handle_at`);
- BPF, perf, `userfaultfd`, `io_uring`, kernel keyrings and `personality`;
- module, kexec, swap, reboot and clock administration.

It also refuses the terminal-injection `ioctl`s `TIOCSTI` and `TIOCLINUX`. Everything
else is allowed, so the filter narrows kernel attack surface rather than
describing a reader's exact needs. The verifier refuses to execute the reader
unless `/proc/self/status` reports an attached filter (`Seccomp: 2`). The
syscall numbers are tested against the installed kernel UAPI headers, and the
program is executed by an independent BPF interpreter in the tests.

The sandbox receives only the explicit binary/inputs, read-only system runtime
library directories, the trusted Python verifier/interpreter, `/dev/null`,
`/dev/urandom`, its own `/proc`, and a size-limited
private `/tmp`. It does not receive host home directories, `/etc`, `/usr/bin`,
agent sockets, `/dev/fuse`, a host root bind, or a writable image/archive bind.
Only the two named runtime device nodes receive device-enabled binds; neither
the host `/dev` directory nor arbitrary devices are exposed.
The sandbox root is remounted read-only; its distinct `/tmp` mount remains private.
The loader runs with a minimal environment, not inherited `LD_*`, `FFS_*`, credentials
or debug settings. Standard input is null. Output is captured as bytes, never
printed unescaped to a terminal by this launcher.

Defaults: 120 seconds total including input hashing, 60 CPU seconds per process,
2 GiB virtual address space per process, 64 descriptors, 64 tasks per sandbox,
a 64 MiB temporary filesystem, 16 GiB total input length, and 64 MiB combined
stdout/stderr. CPU, wall, memory, output and input budgets have explicit CLI
controls. Existing stricter inherited hard limits are never raised. Core dumps
are disabled. On timeout/output overflow the supervisor kills its process group;
bubblewrap's parent-death chain tears down the sandbox PID namespace. A failed
reader or a killed process never earns a successful result.

The task limit is `RLIMIT_NPROC`, applied by the trusted verifier inside the
sandbox's fresh user namespace, immediately before the reader executes. There
the kernel counts only the sandbox's own tasks, so the limit caps the reader's
threads and children. Outside, `RLIMIT_NPROC` counts every task of the real UID;
applied to bubblewrap itself it made namespace creation fail on any account
already running more than 64 tasks.

These are **not aggregate cgroup quotas**. Per-process memory/CPU limits and a
per-sandbox task count do not establish an aggregate per-job memory/CPU
guarantee. Run this profile under a dedicated account with externally enforced
cgroup memory, process and CPU budgets on a host intended for hostile workloads.
A stuck kernel I/O operation can delay process reaping; userspace deadlines are
not kernel liveness proofs.

## Evidence contract

The new mode-0700 output directory contains mode-0600 files:

- `request.json`: policy version, reader, bubblewrap, Python and bootstrap hashes, exact
  mapped argv, resource limits, the syscall filter's SHA-256 and denylist, input
  identities and initial SHA-256 values.
- `stdout.bin` and `stderr.bin`: bounded, untrusted output. A failed operation may
  leave a valid-looking prefix; do not consume it as a successful extraction.
- `result.json`: child exit, limit termination, bubblewrap start/exit observations,
  captured byte counts/hashes, post-run source hashes and the final success flag.

Success requires a zero child exit, bubblewrap execution confirmation, no exhausted
supervision budget, and unchanged retained executable/input contents and
size/mtime/ctime observations. Missing or incomplete result files mean **no
completed result**. Existing outputs are never overwritten, and partial artifacts
are retained on failure. Names in diagnostics are JSON-escaped. Native payload
bytes remain untrusted even when transport and structural validation succeeded.

These manifests are **not signed, independently authenticated, or forensic chain
of custody**. A compromised supervisor or trusted runtime can lie. Hashes show
what was observed, not whether the input was benign. A malicious non-cooperating
host writer is outside the guarantee; a before/after hash is not an immutable
snapshot proof. Prefer a storage-enforced read-only snapshot or copied evidence.
Reading can update access metadata on the *host filesystem containing an image*;
no claim is made that O_RDONLY prevents that host behavior. Native image contents
are a different boundary.

Every input is hashed before and after the run. This is intentional audit work,
not a promise of a small performance penalty: full-image hashing can dominate a
small extraction. No mounted FUSE operation is exercised by this launcher.

## Validation status and release prerequisites

Run the executable policy/file-descriptor/supervisor tests with:

```sh
FFS_REQUIRE_SANDBOX=1 python3 -I -m unittest discover -s scripts/tests -p test_ffs_inspect_sandbox.py -v
```

`FFS_REQUIRE_SANDBOX=1` turns a missing or unusable bubblewrap into a failure
instead of a skip, so a passing run proves the live tests executed.

The unit tests use real child processes, descriptor permissions, locks,
timeout/pipe inheritance, output overflow, environment isolation, sealed
bootstrap memory, substituted mount refusal, descriptor closure and
evidence-file refusal. They also check the filter's syscall numbers against
kernel headers and interpret the filter program for both architectures.

Two live tests run real bubblewrap. The first uses the exact launcher policy,
filter included, with a probe in place of the reader. It observes:

- filter mode 2, no-new-privileges and empty capability sets;
- `EPERM` from `socket(AF_UNIX)` and a `personality` query, both of which
  succeed without the filter;
- no `/home`, `/etc`, `/run` or `/dev/fuse`;
- `EROFS` when writing an input;
- only a loopback interface;
- a task limit that admits 4 threads but caps 20.

The second runs the complete launcher end to end with a stand-in ELF reader.

On 2026-10-16 (kernel 7.0, bubblewrap 0.11.1, Python 3.14, an account running
over 1,000 tasks), all 35 passed. Planted negatives confirmed that the live and
filter tests detect each of these: a dropped filter, a per-UID task limit, a
verifier that no longer requires the filter, and an un-denied `socket`. Before
the task-limit fix, the unmodified launcher could not start a sandbox on that
account at all. Scratch directories are intentionally retained.

Before using this profile for hostile production inputs, qualify the exact
FrankenFS build, bubblewrap binary, runtime libraries, kernel and LSM policy.
Exercise source-write attempts, host-home/socket/device access, network access,
namespace escape attempts, descendant teardown, resource exhaustion and corrupted
native images, together with independent filesystem/readback oracles. Keep the
failures and limits in the evidence record. The ordered remaining work is in
[SECURITY_WORKPLAN.md](SECURITY_WORKPLAN.md).

Primary mechanism references: [bubblewrap's manual](https://github.com/containers/bubblewrap/blob/main/bwrap.xml)
and [Linux resource limits](https://www.man7.org/linux/man-pages/man2/getrlimit.2.html).
