#!/usr/bin/env python3
"""Run existing FrankenFS offline readers with explicit, read-only Linux authority.

Requires bubblewrap; missing isolation is an error, never an unsandboxed fallback.
Run with Python's isolated mode (-I). See docs/SECURITY_INSPECTION.md for the
threat model. The manifest records observations, not authenticated provenance.
"""
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import BinaryIO

TOOLS = {
    "ffs-cli": frozenset({"inspect"}),
    "ffs-fat": frozenset({"inspect", "check", "ls", "cat", "catalog", "extract"}),
    "ffs-ntfs": frozenset({"inspect", "ls", "read", "readlink", "streams", "security", "ea", "record", "cat"}),
    "ffs-zfs": frozenset({"inspect", "root", "object", "object-read", "zap", "datasets", "ls", "stat", "cat", "readlink", "xattr", "snapshots", "zvol-info", "zvol-read", "zvol-seek"}),
}
FORBIDDEN = frozenset({"--rw", "--allow-repair", "--reclaim-lost", "--salvage-to"})
MIB = 1024 * 1024
CHUNK = 64 * 1024


class Refusal(Exception):
    """A failed precondition; no weaker execution mode is permitted."""


@dataclasses.dataclass(frozen=True)
class Limits:
    wall_seconds: int = 120
    cpu_seconds: int = 60
    address_bytes: int = 2048 * MIB
    output_bytes: int = 64 * MIB
    input_bytes: int = 16 * 1024 * MIB
    temporary_bytes: int = 64 * MIB
    processes: int = 64
    descriptors: int = 64

    def validate(self) -> None:
        if any(value <= 0 for value in dataclasses.asdict(self).values()):
            raise Refusal("all resource limits must be positive")
        if self.descriptors < 32 or self.processes < 4 or self.address_bytes < 64 * MIB:
            raise Refusal("limits are too small to start the isolated reader")


def stamp(fd: int) -> dict[str, int]:
    s = os.fstat(fd)
    return {"device": s.st_dev, "inode": s.st_ino, "bytes": s.st_size,
            "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns}


def digest(fd: int, size: int, deadline: float) -> str:
    h = hashlib.sha256()
    at = 0
    while at < size:
        if time.monotonic() >= deadline:
            raise Refusal("time budget exhausted while hashing an input")
        block = os.pread(fd, min(CHUNK, size - at), at)
        if not block:
            raise Refusal("input became shorter while hashing")
        h.update(block)
        at += len(block)
    if time.monotonic() >= deadline or os.fstat(fd).st_size != size:
        raise Refusal("input size changed or time budget exhausted while hashing")
    return h.hexdigest()


def pin_file(stack: contextlib.ExitStack, path: Path, *, executable: bool = False) -> int:
    """Keep a regular O_RDONLY inode, not a path that can be substituted later."""
    named = path.lstat()
    if not stat.S_ISREG(named.st_mode):
        raise Refusal(f"not a regular non-symlink file: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    stack.callback(os.close, fd)
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino) or not stat.S_ISREG(opened.st_mode):
        raise Refusal("input identity changed while opening")
    if executable and (opened.st_mode & 0o111 == 0 or opened.st_mode & (stat.S_ISUID | stat.S_ISGID)):
        raise Refusal("reader must be executable and must not carry set-id bits")
    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    return fd


def input_spec(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or not path or not 1 <= len(name) <= 64 or name in {".", ".."}:
        raise argparse.ArgumentTypeError("input must be NAME=PATH")
    if not all(c.isascii() and (c.isalnum() or c in "_.-") for c in name):
        raise argparse.ArgumentTypeError("input names use ASCII letters, digits, dot, dash or underscore")
    return name, Path(path).absolute()


def reader_arguments(tool: str, args: list[str], names: set[str]) -> list[str]:
    if args and args[0] == "--":
        args = args[1:]
    if tool not in TOOLS or not args or args[0] not in TOOLS[tool]:
        raise Refusal("only the documented offline read commands are allowed")
    if not names or len(names) > 8:
        raise Refusal("supply one to eight explicit inputs")
    for name in names:
        try:
            input_spec(f"{name}=/unused")
        except argparse.ArgumentTypeError as error:
            raise Refusal(str(error)) from error
    if sum(len(arg.encode("utf-8")) + 1 for arg in args) > CHUNK:
        raise Refusal("reader arguments exceed 64 KiB")
    result, used = [], set()
    for arg in args:
        key, separator, value = arg.partition("=")
        if key in FORBIDDEN:
            raise Refusal(f"mutation authority is not allowed: {key}")
        reference = value if separator and key.startswith("--") else arg
        if reference.startswith("@"):
            name = reference[1:]
            if name not in names:
                raise Refusal(f"unknown input reference: {reference}")
            used.add(name)
            mapped = f"/inputs/{name}"
            arg = f"{key}={mapped}" if separator and key.startswith("--") else mapped
        if "\0" in arg:
            raise Refusal("NUL in argument")
        result.append(arg)
    if used != names:
        raise Refusal("every exposed input must be referenced explicitly as @NAME")
    return result


def sandbox_argv(bwrap: Path, binary_fd: int, inputs: list[tuple[str, int]],
                 args: list[str], limits: Limits, status_fd: int,
                 python_fd: int, inner_fd: int, config_fd: int) -> list[str]:
    argv = [str(bwrap), "--unshare-user", "--unshare-pid", "--unshare-net",
            "--unshare-ipc", "--unshare-uts", "--disable-userns", "--assert-userns-disabled",
            "--new-session", "--die-with-parent", "--cap-drop", "ALL", "--clearenv",
            "--setenv", "PATH", "/app", "--setenv", "LANG", "C", "--setenv", "LC_ALL", "C",
            "--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp",
            "--dir", "/app", "--dir", "/inputs", "--dir", "/usr", "--dir", "/dev"]
    # Only runtime libraries, not /usr/bin, /etc, host home, agent sockets or /dev/fuse.
    # Resolving a library-directory symlink is deliberate; input symlinks are refused.
    for path in ("/usr/lib", "/usr/lib64", "/lib", "/lib64"):
        if Path(path).is_dir():
            argv += ["--ro-bind", str(Path(path).resolve()), path]
    for path in ("/dev/null", "/dev/urandom"):
        if not Path(path).exists():
            raise Refusal(f"required runtime device is absent: {path}")
        # Ordinary ro-bind marks device nodes nodev. Expose only these two
        # explicit runtime devices, then prohibit writes to their mountpoints.
        argv += ["--dev-bind", path, path, "--remount-ro", path]
    argv += ["--proc", "/proc", "--size", str(limits.temporary_bytes),
             "--perms", "0700", "--tmpfs", "/tmp",
             "--ro-bind", f"/proc/self/fd/{binary_fd}", "/app/reader",
             "--ro-bind", f"/proc/self/fd/{python_fd}", "/app/python",
             "--ro-bind-data", str(inner_fd), "/app/verify.py",
             "--ro-bind-data", str(config_fd), "/app/config.json"]
    for name, fd in inputs:
        argv += ["--ro-bind", f"/proc/self/fd/{fd}", f"/inputs/{name}"]
    argv += ["--chdir", "/tmp", "--remount-ro", "/", "--json-status-fd", str(status_fd),
             "--", "/app/python", "-I", "-S", "/app/verify.py", "/app/config.json"]
    return argv


def sealed_data(stack: contextlib.ExitStack, data: bytes) -> int:
    if len(data) > CHUNK:
        raise Refusal("trusted bootstrap data exceeds 64 KiB")
    fd = os.memfd_create("ffs-inspection-bootstrap", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    stack.callback(os.close, fd)
    at = 0
    while at < len(data):
        count = os.write(fd, data[at:])
        if count == 0:
            raise OSError("short bootstrap write")
        at += count
    os.lseek(fd, 0, os.SEEK_SET)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    return fd


def _child_limits(limits: Limits) -> None:
    for kind, ceiling in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, limits.cpu_seconds),
                          (resource.RLIMIT_AS, limits.address_bytes),
                          (resource.RLIMIT_FSIZE, limits.output_bytes),
                          (resource.RLIMIT_NPROC, limits.processes),
                          (resource.RLIMIT_NOFILE, limits.descriptors)):
        _, hard = resource.getrlimit(kind)
        value = ceiling if hard == resource.RLIM_INFINITY else min(ceiling, hard)
        resource.setrlimit(kind, (value, value))


def _supervise(argv: list[str], pass_fds: tuple[int, ...], outputs: dict[str, BinaryIO],
               limits: Limits, deadline: float, status_pipe: tuple[int, int] | None = None) -> dict:
    """Single-threaded CLI supervisor. Private test seam is not a public bypass mode."""
    counts = {"stdout": 0, "stderr": 0, "status": 0}
    hashes = {name: hashlib.sha256() for name in ("stdout", "stderr")}
    reason = None
    status = bytearray()
    process = None
    with selectors.DefaultSelector() as selected:
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, pass_fds=pass_fds,
                                       env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                                       start_new_session=True, preexec_fn=lambda: _child_limits(limits))
            if status_pipe is not None:
                os.close(status_pipe[1])
                selected.register(status_pipe[0], selectors.EVENT_READ, "status")
            selected.register(process.stdout, selectors.EVENT_READ, "stdout")
            selected.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selected.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "wall_time_limit"
                    break
                for key, _ in selected.select(min(remaining, 0.25)):
                    chunk = os.read(key.fd, CHUNK)
                    if not chunk:
                        selected.unregister(key.fileobj)
                        continue
                    name = key.data
                    available = (CHUNK - counts["status"] if name == "status" else
                                 limits.output_bytes - counts["stdout"] - counts["stderr"])
                    kept = chunk[:max(0, available)]
                    counts[name] += len(kept)
                    if name == "status":
                        status.extend(kept)
                    else:
                        if outputs[name].write(kept) != len(kept):
                            raise OSError("short write to the evidence output")
                        hashes[name].update(kept)
                    if len(chunk) > available:
                        reason = "status_limit" if name == "status" else "output_limit"
                        break
                if reason:
                    break
            if reason is None:
                try:
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    reason = "wall_time_limit"
        finally:
            if process is not None:
                # Kill the outer process group even if its leader exited while a
                # descendant kept a pipe open. bwrap also kills its PID namespace.
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()
            if status_pipe is not None:
                for fd in status_pipe:
                    with contextlib.suppress(OSError):
                        os.close(fd)
    return {"exit_code": process.returncode, "termination": reason,
            "captured_bytes": counts, "output_sha256": {name: h.hexdigest() for name, h in hashes.items()},
            "sandbox_status": status.decode("utf-8", errors="replace")}


def private_output(path: Path) -> BinaryIO:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "wb")


def write_json(path: Path, value: dict) -> None:
    with private_output(path) as out:
        out.write((json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode())
        out.flush()
        os.fsync(out.fileno())


def status_confirms_execution(text: str, exit_code: int) -> bool:
    try:
        events = [json.loads(line) for line in text.splitlines() if line]
    except (ValueError, TypeError):
        return False
    if not events or not all(isinstance(event, dict) for event in events):
        return False
    started = any(type(event.get("child-pid")) is int and event["child-pid"] > 0 for event in events)
    exits = [event["exit-code"] for event in events if "exit-code" in event]
    return started and len(exits) == 1 and type(exits[0]) is int and exits[0] == exit_code


def execute(binary: Path, tool: str, inputs: list[tuple[str, Path]], args: list[str],
            output: Path, limits: Limits, bwrap: Path) -> int:
    limits.validate()
    if (sys.platform != "linux" or os.geteuid() == 0 or os.getuid() != os.geteuid()
            or os.getgid() != os.getegid()):
        raise Refusal("run as an ordinary non-root Linux user; no privilege escalation is supported")
    names = [name for name, _ in inputs]
    if len(names) != len(set(names)):
        raise Refusal("duplicate input name")
    command = reader_arguments(tool, args, set(names))
    if not bwrap.is_file() or not os.access(bwrap, os.X_OK):
        raise Refusal("bubblewrap is unavailable; refusing unsandboxed execution")
    # Resolve only trusted executables. Never resolve untrusted input symlinks.
    binary, bwrap = binary.resolve(strict=True), bwrap.resolve(strict=True)
    deadline = time.monotonic() + limits.wall_seconds
    with contextlib.ExitStack() as stack:
        binary_fd = pin_file(stack, binary, executable=True)
        bwrap_fd = pin_file(stack, bwrap, executable=True)
        python_fd = pin_file(stack, Path("/usr/bin/python3").resolve(strict=True), executable=True)
        for fd in (binary_fd, bwrap_fd, python_fd):
            if os.pread(fd, 4, 0) != b"\x7fELF":
                raise Refusal("reader, bubblewrap and system Python must be native ELF executables")
        pinned = [(name, pin_file(stack, path)) for name, path in inputs]
        identities = [stamp(fd) for _, fd in pinned]
        distinct = {(s["device"], s["inode"]) for s in identities}
        executables = {(stamp(fd)["device"], stamp(fd)["inode"]) for fd in (binary_fd, bwrap_fd, python_fd)}
        if len(distinct) != len(identities) or distinct & executables:
            raise Refusal("input aliases another input or a trusted executable")
        if sum(s["bytes"] for s in identities) > limits.input_bytes:
            raise Refusal("total input length exceeds the configured budget")
        binary_before = stamp(binary_fd)
        binary_hash = digest(binary_fd, binary_before["bytes"], deadline)
        bwrap_before = stamp(bwrap_fd)
        bwrap_hash = digest(bwrap_fd, bwrap_before["bytes"], deadline)
        python_before = stamp(python_fd)
        python_hash = digest(python_fd, python_before["bytes"], deadline)
        evidence = []
        for (name, fd), before in zip(pinned, identities):
            sha = digest(fd, before["bytes"], deadline)
            if stamp(fd) != before:
                raise Refusal("input changed during initial hashing")
            evidence.append({"name": name, "sandbox_path": f"/inputs/{name}",
                             "identity": before, "sha256_before": sha})
        inner_path = Path(__file__).resolve().with_name("ffs_inspect_sandbox_inner.py")
        inner_source_fd = pin_file(stack, inner_path)
        inner_before = stamp(inner_source_fd)
        if inner_before["bytes"] > CHUNK:
            raise Refusal("trusted bootstrap source exceeds 64 KiB")
        inner_code = os.pread(inner_source_fd, CHUNK, 0)
        if len(inner_code) != inner_before["bytes"] or stamp(inner_source_fd) != inner_before:
            raise Refusal("trusted bootstrap source changed during capture")
        inner_fd = sealed_data(stack, inner_code)
        config = {"binary_fd": binary_fd, "arguments": command,
                  "outer_namespaces": {name: os.stat(f"/proc/self/ns/{name}").st_ino
                                       for name in ("mnt", "user", "pid", "net", "ipc", "uts")},
                  "bindings": [{"fd": binary_fd, "path": "/app/reader", "identity": binary_before},
                               {"fd": python_fd, "path": "/app/python", "identity": python_before},
                               *({"fd": fd, "path": item["sandbox_path"], "identity": item["identity"]}
                                 for item, (_, fd) in zip(evidence, pinned))]}
        config_fd = sealed_data(stack, json.dumps(config, ensure_ascii=True).encode())
        # Existing directories are never reused or overwritten.
        output = output.absolute()
        output.mkdir(mode=0o700)
        request = {"schema_version": 1, "policy": "ffs-offline-reader-v1", "tool": tool,
                   "reader_sha256": binary_hash, "reader_identity": binary_before,
                   "bwrap": str(bwrap), "bwrap_sha256": bwrap_hash,
                   "bwrap_identity": bwrap_before, "arguments": command,
                   "bootstrap_sha256": hashlib.sha256(inner_code).hexdigest(),
                   "python_identity": python_before, "python_sha256": python_hash,
                   "limits": dataclasses.asdict(limits), "inputs": evidence,
                   "status": "requested_not_completed", "authentication": "none",
                   "scope": "read-only contents; advisory locks do not exclude external writers; rlimits are per process"}
        write_json(output / "request.json", request)
        result = {"schema_version": 1, "success": False, "inputs": evidence}
        try:
            with private_output(output / "stdout.bin") as stdout, private_output(output / "stderr.bin") as stderr:
                status_pipe = os.pipe2(os.O_CLOEXEC)
                try:
                    argv = sandbox_argv(Path(f"/proc/self/fd/{bwrap_fd}"), binary_fd, pinned,
                                        command, limits, status_pipe[1], python_fd, inner_fd, config_fd)
                except BaseException:
                    for fd in status_pipe:
                        os.close(fd)
                    raise
                observed = _supervise(argv, (bwrap_fd, binary_fd, python_fd, inner_fd, config_fd,
                                            *(fd for _, fd in pinned), status_pipe[1]),
                                       {"stdout": stdout, "stderr": stderr}, limits, deadline, status_pipe)
                for stream in (stdout, stderr):
                    stream.flush()
                    os.fsync(stream.fileno())
            result.update(observed)
            unchanged = stamp(binary_fd) == binary_before and digest(binary_fd, binary_before["bytes"], deadline) == binary_hash
            unchanged = unchanged and stamp(bwrap_fd) == bwrap_before and digest(bwrap_fd, bwrap_before["bytes"], deadline) == bwrap_hash
            unchanged = unchanged and stamp(python_fd) == python_before and digest(python_fd, python_before["bytes"], deadline) == python_hash
            for item, (_, fd) in zip(evidence, pinned):
                item["sha256_after"] = digest(fd, item["identity"]["bytes"], deadline)
                item["unchanged"] = (stamp(fd) == item["identity"] and item["sha256_after"] == item["sha256_before"])
                unchanged = unchanged and item["unchanged"]
            result["reader_and_inputs_unchanged"] = unchanged
            result["execution_confirmed"] = status_confirms_execution(observed["sandbox_status"], observed["exit_code"])
            result["success"] = (observed["exit_code"] == 0 and observed["termination"] is None
                                 and unchanged and result["execution_confirmed"])
        except (OSError, Refusal, KeyboardInterrupt) as error:
            result["error"] = f"{type(error).__name__}: {error}"
        finally:
            write_json(output / "result.json", result)
            dir_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        return 0 if result["success"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True, choices=sorted(TOOLS))
    parser.add_argument("--binary", type=Path, required=True, help="trusted prebuilt reader executable")
    parser.add_argument("--input", action="append", type=input_spec, required=True, help="NAME=PATH; use @NAME in reader arguments")
    parser.add_argument("--output", type=Path, required=True, help="new private evidence directory; must not exist")
    parser.add_argument("--bwrap", type=Path, default=Path("/usr/bin/bwrap"), help="trusted bubblewrap executable")
    parser.add_argument("--wall-seconds", type=int, default=120)
    parser.add_argument("--cpu-seconds", type=int, default=60)
    parser.add_argument("--memory-mib", type=int, default=2048, help="per-process virtual address limit, not an aggregate cgroup quota")
    parser.add_argument("--output-mib", type=int, default=64, help="combined stdout/stderr cap")
    parser.add_argument("--input-mib", type=int, default=16384, help="combined input size cap; every input is hashed twice")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- READ_COMMAND @INPUT [reader options]")
    args = parser.parse_args()
    limits = Limits(wall_seconds=args.wall_seconds, cpu_seconds=args.cpu_seconds,
                    address_bytes=args.memory_mib * MIB, output_bytes=args.output_mib * MIB,
                    input_bytes=args.input_mib * MIB)
    try:
        return execute(args.binary, args.tool, args.input, args.command, args.output, limits, args.bwrap)
    except (OSError, Refusal, KeyboardInterrupt) as error:
        # JSON escaping keeps hostile filenames from injecting terminal controls.
        print(json.dumps({"success": False, "error": str(error)}, ensure_ascii=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
