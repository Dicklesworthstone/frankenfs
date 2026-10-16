#!/usr/bin/env python3
"""Trusted pre-exec check, copied into the sandbox by the outer launcher.

Never use this as a general runner. The outer launcher supplies a sealed JSON
configuration and original read-only descriptors. Bind source /proc/self/fd/N
alone is insufficient: bubblewrap versions may canonicalize it to a pathname.
"""
from __future__ import annotations

import fcntl
import json
import os
import stat
import sys


def identity(s: os.stat_result) -> dict[str, int]:
    return {"device": s.st_dev, "inode": s.st_ino, "bytes": s.st_size,
            "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns}


def verify_binding(binding: dict, *, require_read_only: bool = True) -> None:
    """Compare mount, retained descriptor, and pre-hash identity before parsing."""
    fd, path, expected = binding["fd"], binding["path"], binding["identity"]
    if type(fd) is not int or fd < 3:
        raise ValueError("invalid inherited input descriptor")
    if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
        raise ValueError("inherited input has write authority")
    original = os.fstat(fd)
    if not stat.S_ISREG(original.st_mode) or identity(original) != expected:
        raise ValueError("retained input changed before sandbox execution")
    opened = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        mounted = os.fstat(opened)
        if not stat.S_ISREG(mounted.st_mode) or identity(mounted) != expected:
            raise ValueError("sandbox bind resolved a substituted input")
        if require_read_only and not os.fstatvfs(opened).f_flag & os.ST_RDONLY:
            raise ValueError("sandbox input mount is not read-only")
        if identity(os.fstat(fd)) != expected:
            raise ValueError("retained input changed during mount verification")
    finally:
        os.close(opened)


def verify_containment(outer_namespaces: dict[str, int]) -> None:
    for name in ("mnt", "user", "pid", "net", "ipc", "uts"):
        if os.stat(f"/proc/self/ns/{name}").st_ino == outer_namespaces[name]:
            raise ValueError(f"sandbox did not isolate the {name} namespace")
    with open("/proc/self/status", encoding="ascii") as source:
        status = dict(line.rstrip().split(":", 1) for line in source if ":" in line)
    if status.get("NoNewPrivs", "").strip() != "1":
        raise ValueError("no-new-privileges is not active")
    if any(int(status.get(name, "1"), 16) for name in ("CapEff", "CapPrm", "CapAmb", "CapBnd")):
        raise ValueError("sandbox retained capabilities")


def close_inherited(keep: int) -> None:
    # Keep only stdio and the verified ELF descriptor used for execveat/fexecve.
    # Inputs must be reopened through their verified, read-only sandbox mounts.
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd >= 3 and fd != keep:
            try:
                os.close(fd)
            except OSError:
                # proc enumeration itself may have already closed its fd.
                pass
    os.set_inheritable(keep, False)


def main() -> int:
    try:
        if len(sys.argv) != 2 or sys.argv[1] != "/app/config.json":
            raise ValueError("invalid sandbox bootstrap invocation")
        with open(sys.argv[1], "rb") as source:
            raw = source.read(65537)
        if len(raw) > 65536:
            raise ValueError("sandbox bootstrap configuration exceeds its limit")
        config = json.loads(raw)
        verify_containment(config["outer_namespaces"])
        for binding in config["bindings"]:
            verify_binding(binding)
        executable = config["binary_fd"]
        if os.pread(executable, 4, 0) != b"\x7fELF":
            raise ValueError("reader must be a native ELF executable")
        close_inherited(executable)
        os.execve(executable, ["/app/reader", *config["arguments"]],
                  {"PATH": "/app", "LANG": "C", "LC_ALL": "C", "HOME": "/tmp", "TMPDIR": "/tmp"})
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"bootstrap_refused": str(error)}, ensure_ascii=True), file=sys.stderr)
        return 125
    return 125


if __name__ == "__main__":
    raise SystemExit(main())
