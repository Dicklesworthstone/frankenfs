"""Executable supervisor tests; these are not a substitute for a real bwrap run.

Scratch directories are deliberately retained, including on failures.
"""
from __future__ import annotations

import contextlib
import dataclasses
import errno
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import resource
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "ffs_inspect_sandbox.py"
SPEC = importlib.util.spec_from_file_location("ffs_inspect_sandbox", SOURCE)
sandbox = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sandbox
SPEC.loader.exec_module(sandbox)
INNER_SPEC = importlib.util.spec_from_file_location("ffs_inspect_sandbox_inner", SOURCE.with_name("ffs_inspect_sandbox_inner.py"))
inner = importlib.util.module_from_spec(INNER_SPEC)
INNER_SPEC.loader.exec_module(inner)


class PolicyTests(unittest.TestCase):
    def test_commands_are_explicit_and_mutation_never_falls_back(self):
        for tool, commands in sandbox.TOOLS.items():
            for command in commands:
                self.assertEqual(sandbox.reader_arguments(tool, ["--", command, "@disk"], {"disk"}),
                                 [command, "/inputs/disk"])
            for command in ["mount", "format", "replace", "recover", "rename", "unlink", "sh"]:
                with self.assertRaises(sandbox.Refusal):
                    sandbox.reader_arguments(tool, [command, "@disk"], {"disk"})
            for option in ["--rw", "--rw=true", "--allow-repair", "--salvage-to=/tmp/out"]:
                with self.assertRaises(sandbox.Refusal):
                    sandbox.reader_arguments(tool, ["inspect", "@disk", option], {"disk"})
        with self.assertRaises(sandbox.Refusal):
            sandbox.reader_arguments("bash", ["inspect", "@disk"], {"disk"})

    def test_references_preserve_native_path_text_and_refuse_extra_authority(self):
        args = sandbox.reader_arguments("ffs-fat", ["cat", "@disk", "/a; echo BAD", "--sidecar=@parity"],
                                         {"disk", "parity"})
        self.assertEqual(args, ["cat", "/inputs/disk", "/a; echo BAD", "--sidecar=/inputs/parity"])
        for args, names in [(["inspect", "@unknown"], {"disk"}), (["inspect", "@disk"], {"disk", "secret"}),
                            (["inspect", "@disk"], set()), (["inspect", "@disk"], {str(x) for x in range(9)})]:
            with self.assertRaises(sandbox.Refusal):
                sandbox.reader_arguments("ffs-fat", args, names)

    def test_input_names_cannot_escape_the_input_mount(self):
        for name in ["..", ".", "../escape", "/abs", "é", "", "a" * 65]:
            with self.assertRaises(Exception):
                sandbox.input_spec(f"{name}=/tmp/source")
        name, path = sandbox.input_spec("disk-1.img=relative name.img")
        self.assertEqual(name, "disk-1.img")
        self.assertTrue(path.is_absolute())

    def test_namespace_policy_has_no_host_root_home_network_or_writable_input_bind(self):
        argv = sandbox.sandbox_argv(Path("/usr/bin/bwrap"), 8, [("disk", 9)],
                                    ["inspect", "/inputs/disk"], sandbox.Limits(), 10, 11, 12, 13, 14)
        self.assertEqual(argv[argv.index("--seccomp") + 1], "14")
        self.assertLess(argv.index("--seccomp"), argv.index("--"))
        for flag in ["--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
                     "--disable-userns", "--assert-userns-disabled", "--clearenv", "--new-session", "--die-with-parent"]:
            self.assertIn(flag, argv)
        for flag in ["--share-net", "--unshare-user-try", "--bind", "--not-a-security-boundary"]:
            self.assertNotIn(flag, argv)
        devices = [(argv[i + 1], argv[i + 2]) for i, arg in enumerate(argv) if arg == "--dev-bind"]
        self.assertEqual(devices, [("/dev/null", "/dev/null"), ("/dev/urandom", "/dev/urandom")])
        binds = [(argv[i + 1], argv[i + 2]) for i, arg in enumerate(argv) if arg == "--ro-bind"]
        self.assertIn(("/proc/self/fd/9", "/inputs/disk"), binds)
        self.assertIn(("/proc/self/fd/8", "/app/reader"), binds)
        self.assertFalse(any(source in ["/", "/home", "/etc", "/usr", "/dev", "/dev/fuse"] for source, _ in binds))
        remounts = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--remount-ro"]
        self.assertEqual(remounts, ["/dev/null", "/dev/urandom", "/"])
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertEqual(argv[-5:], ["/app/python", "-I", "-S", "/app/verify.py", "/app/config.json"])
        self.assertNotIn("inspect", argv, "native command belongs only in sealed configuration")

    def test_status_requires_execution_and_one_matching_integer_exit(self):
        good = '{"child-pid":123}\n{"exit-code":0}\n'
        self.assertTrue(sandbox.status_confirms_execution(good, 0))
        for text in ["", "not json", '[]', '{"exit-code":0}', '{"child-pid":true}\n{"exit-code":0}',
                     '{"child-pid":1}\n{"exit-code":true}', good + '{"exit-code":0}',
                     '{"child-pid":1}\n{"exit-code":7}']:
            self.assertFalse(sandbox.status_confirms_execution(text, 0))

    def test_invalid_limits_are_refused(self):
        for name in dataclasses.asdict(sandbox.Limits()):
            with self.assertRaises(sandbox.Refusal):
                dataclasses.replace(sandbox.Limits(), **{name: 0}).validate()

    def test_real_native_tool_subcommands_are_admitted_and_nonexistent_or_mutating_refused(self):
        for cmd in ("read", "listxattr", "getxattr", "scrub", "allocation", "properties",
                    "zil-inspect", "zil-read"):
            self.assertIn(cmd, sandbox.TOOLS["ffs-zfs"])
        for bad in ("cat", "xattr", "mount"):
            self.assertNotIn(bad, sandbox.TOOLS["ffs-zfs"])
        for cmd in ("check-security", "check-allocation", "read", "streams"):
            self.assertIn(cmd, sandbox.TOOLS["ffs-ntfs"])
        self.assertNotIn("mount", sandbox.TOOLS["ffs-ntfs"])
        for cmd in ("ls", "scrub", "partitions", "streams", "pool", "dataset"):
            self.assertIn(cmd, sandbox.TOOLS["ffs-cli"])
        for bad in ("mount", "format", "mkfs", "repair", "fsck", "check"):
            self.assertNotIn(bad, sandbox.TOOLS["ffs-cli"])

    def test_cgroup_limits_validation_and_systemd_wrapper_argv(self):
        disabled = sandbox.CgroupLimits()
        self.assertFalse(disabled.enabled)
        disabled.validate()
        with self.assertRaises(sandbox.Refusal):
            sandbox.cgroup_argv("ffs-test.scope", disabled, ["/usr/bin/bwrap"])
        for bad in [
            sandbox.CgroupLimits(memory_bytes=0),
            sandbox.CgroupLimits(memory_bytes=63 * sandbox.MIB),
            sandbox.CgroupLimits(memory_bytes=True),
            sandbox.CgroupLimits(pids_max=3),
            sandbox.CgroupLimits(pids_max=False),
            sandbox.CgroupLimits(cpu_quota_pct=0),
            sandbox.CgroupLimits(cpu_quota_pct=10_001),
            sandbox.CgroupLimits(cpu_quota_pct=True),
        ]:
            with self.assertRaises(sandbox.Refusal):
                bad.validate()
        active = sandbox.CgroupLimits(
            memory_bytes=128 * sandbox.MIB, pids_max=16, cpu_quota_pct=150
        )
        self.assertTrue(active.enabled)
        active.validate()
        wrapped = sandbox.cgroup_argv("ffs-inspect-unit.scope", active, ["/proc/self/fd/3", "--"])
        self.assertEqual(
            wrapped,
            [
                "systemd-run", "--user", "--scope", "--quiet", "--collect",
                "--unit=ffs-inspect-unit.scope",
                "-p", f"MemoryMax={128 * sandbox.MIB}",
                "-p", "MemorySwapMax=0",
                "-p", "TasksMax=16",
                "-p", "CPUQuota=150%",
                "--", "/proc/self/fd/3", "--",
            ],
        )
        for bad_unit in ("ffs-inspect-unit", "nested/ffs.scope"):
            with self.assertRaises(sandbox.Refusal):
                sandbox.cgroup_argv(bad_unit, active, ["/proc/self/fd/3"])


SECCOMP_DATA = struct.Struct("=iIQ6Q")  # struct seccomp_data
RET_KILL, RET_ALLOW, RET_EPERM = 0x80000000, 0x7FFF0000, 0x00050000 | errno.EPERM


def run_classic_bpf(program: bytes, nr: int, arch: int, args=(0, 0, 0, 0, 0, 0)) -> int:
    """Interpret the four opcodes the filter uses, exactly as the kernel would."""
    data = SECCOMP_DATA.pack(nr, arch, 0, *args)
    accumulator, pc = 0, 0
    instructions = [struct.unpack_from("=HBBI", program, at) for at in range(0, len(program), 8)]
    while True:
        code, jt, jf, k = instructions[pc]
        if code == 0x20:
            accumulator = struct.unpack_from("=I", data, k)[0]
            pc += 1
        elif code in (0x15, 0x35):
            taken = accumulator == k if code == 0x15 else accumulator >= k
            pc += 1 + (jt if taken else jf)
        elif code == 0x06:
            return k
        else:
            raise AssertionError(f"unexpected BPF opcode {code:#x}")


class SeccompTests(unittest.TestCase):
    HEADERS = {"x86_64": Path("/usr/include/x86_64-linux-gnu/asm/unistd_64.h"),
               "aarch64": Path("/usr/include/asm-generic/unistd.h")}

    def test_syscall_numbers_match_installed_kernel_uapi_headers(self):
        checked = 0
        for machine, header in self.HEADERS.items():
            if not header.exists():
                continue
            column = sandbox.SECCOMP_ARCHES[machine][0]
            defined = {m.group(1): int(m.group(2)) for m in
                       re.finditer(r"^#define __NR_(\w+)\s+(\d+)\s*$", header.read_text(), re.M)}
            for name, numbers in sandbox.DENIED_SYSCALLS.items():
                expected = numbers[column]
                if expected is None:
                    self.assertNotIn(name, defined, f"{machine} defines {name}")
                else:
                    self.assertEqual(defined.get(name), expected, f"{machine} {name}")
            self.assertEqual(defined["ioctl"], sandbox.SECCOMP_ARCHES[machine][2])
            checked += 1
        if checked == 0:
            self.skipTest("no kernel UAPI syscall headers installed")

    def test_filter_is_a_wellformed_forward_only_program(self):
        for machine in sandbox.SECCOMP_ARCHES:
            program = sandbox.seccomp_filter(machine)
            self.assertEqual(len(program) % 8, 0)
            count = len(program) // 8
            self.assertLessEqual(count, 4096)
            for index in range(count):
                code, jt, jf, _ = struct.unpack_from("=HBBI", program, index * 8)
                self.assertIn(code, (0x20, 0x15, 0x35, 0x06))
                if code in (0x15, 0x35):
                    self.assertLess(index + 1 + max(jt, jf), count)
            self.assertEqual(struct.unpack_from("=HBBI", program, len(program) - 8)[0], 0x06)

    def test_filter_kills_foreign_abis_denies_the_list_and_allows_the_rest(self):
        for machine, (column, arch, ioctl) in sandbox.SECCOMP_ARCHES.items():
            program = sandbox.seccomp_filter(machine)
            for name, numbers in sandbox.DENIED_SYSCALLS.items():
                if numbers[column] is not None:
                    self.assertEqual(run_classic_bpf(program, numbers[column], arch), RET_EPERM, name)
            denied = {numbers[column] for numbers in sandbox.DENIED_SYSCALLS.values()}
            for nr in range(0, 470):
                if nr not in denied and nr != ioctl:
                    self.assertEqual(run_classic_bpf(program, nr, arch), RET_ALLOW, f"{machine} {nr}")
            other = 0xC00000B7 if machine == "x86_64" else 0xC000003E
            self.assertEqual(run_classic_bpf(program, 0, other), RET_KILL)
            self.assertEqual(run_classic_bpf(program, 0, 0x40000003), RET_KILL)  # i386
            for request, verdict in [(0x5412, RET_EPERM), (0x541C, RET_EPERM), (0x5401, RET_ALLOW),
                                     ((0xFFFFFFFF << 32) | 0x5412, RET_EPERM)]:
                self.assertEqual(run_classic_bpf(program, ioctl, arch, (1, request, 0, 0, 0, 0)), verdict)
        x86 = sandbox.seccomp_filter("x86_64")
        self.assertEqual(run_classic_bpf(x86, 0x40000000 | 41, 0xC000003E), RET_KILL)  # x32 socket

    def test_unknown_architecture_is_refused_and_policy_is_recorded(self):
        with self.assertRaises(sandbox.Refusal):
            sandbox.seccomp_filter("mips")
        program = sandbox.seccomp_filter("x86_64")
        policy = sandbox.seccomp_policy("x86_64", program)
        self.assertEqual(policy["sha256"], hashlib.sha256(program).hexdigest())
        self.assertIn("socket", policy["denied_syscalls"])
        self.assertNotIn("uselib", sandbox.seccomp_policy("aarch64", sandbox.seccomp_filter("aarch64"))["denied_syscalls"])


class FileTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="ffs-inspect-test-"))
        self.input = self.directory / "input.img"
        self.input.write_bytes(b"retained native bytes")

    def test_real_descriptor_cannot_write_and_shared_inode_lock_excludes_writer(self):
        with contextlib.ExitStack() as stack:
            fd = sandbox.pin_file(stack, self.input)
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            with self.assertRaises(OSError) as error:
                os.write(fd, b"bad")
            self.assertEqual(error.exception.errno, errno.EBADF)
            second = sandbox.pin_file(stack, self.input)
            self.assertNotEqual(fd, second)
            writer = stack.enter_context(self.input.open("r+b"))
            with self.assertRaises(BlockingIOError):
                fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(self.input.read_bytes(), b"retained native bytes")

    def test_symlink_directory_and_fifo_are_refused_without_blocking(self):
        link = self.directory / "link"
        link.symlink_to(self.input)
        fifo = self.directory / "fifo"
        os.mkfifo(fifo)
        for path in [link, fifo, self.directory]:
            with contextlib.ExitStack() as stack, self.assertRaises(sandbox.Refusal):
                sandbox.pin_file(stack, path)

    def test_pinned_descriptor_survives_path_replacement_without_following_it(self):
        with contextlib.ExitStack() as stack:
            fd = sandbox.pin_file(stack, self.input)
            self.input.rename(self.directory / "original-retained.img")
            self.input.write_bytes(b"different named file")
            self.assertEqual(os.pread(fd, 64, 0), b"retained native bytes")
            self.assertEqual(sandbox.digest(fd, os.fstat(fd).st_size, time.monotonic() + 2),
                             hashlib.sha256(b"retained native bytes").hexdigest())

    def test_hash_deadline_and_early_eof_fail(self):
        with contextlib.ExitStack() as stack:
            fd = sandbox.pin_file(stack, self.input)
            for size, deadline in [(100, time.monotonic() + 2), (10, time.monotonic() - 1)]:
                with self.assertRaises(sandbox.Refusal):
                    sandbox.digest(fd, size, deadline)

    def test_artifacts_are_private_create_new_and_cannot_overwrite_evidence(self):
        output = self.directory / "result.json"
        sandbox.write_json(output, {"success": False})
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            sandbox.write_json(output, {"success": True})
        self.assertEqual(json.loads(output.read_text()), {"success": False})

    def test_missing_sandbox_is_a_preflight_refusal_with_no_output_directory(self):
        output = self.directory / "result"
        with mock.patch.object(sandbox.os, "geteuid", return_value=1000), \
             mock.patch.object(sandbox.os, "getuid", return_value=1000), self.assertRaises(sandbox.Refusal):
            sandbox.execute(Path(sys.executable), "ffs-fat", [("disk", self.input)],
                            ["inspect", "@disk"], output, sandbox.Limits(), self.directory / "absent-bwrap")
        self.assertFalse(output.exists())

    def test_root_is_refused_without_launching_any_process(self):
        with mock.patch.object(sandbox.os, "geteuid", return_value=0), \
             mock.patch.object(sandbox.subprocess, "Popen") as popen, self.assertRaises(sandbox.Refusal):
            sandbox.execute(Path(sys.executable), "ffs-fat", [("disk", self.input)],
                            ["inspect", "@disk"], self.directory / "output", sandbox.Limits(), Path("/usr/bin/bwrap"))
        popen.assert_not_called()

    def test_bootstrap_data_is_actually_sealed_against_write_and_resize(self):
        with contextlib.ExitStack() as stack:
            fd = sandbox.sealed_data(stack, b"known configuration")
            self.assertEqual(os.pread(fd, 100, 0), b"known configuration")
            for action in [lambda: os.pwrite(fd, b"bad", 0), lambda: os.ftruncate(fd, 0)]:
                with self.assertRaises(PermissionError):
                    action()
            with self.assertRaises(sandbox.Refusal):
                sandbox.sealed_data(stack, b"x" * 65537)

    def test_inner_checks_actual_bound_identity_not_only_a_retained_fd(self):
        with contextlib.ExitStack() as stack:
            fd = sandbox.pin_file(stack, self.input)
            binding = {"fd": fd, "path": str(self.input), "identity": sandbox.stamp(fd)}
            # Ordinary scratch storage is not a read-only mount. Check the
            # identity component here; the next test pins that separate refusal.
            inner.verify_binding(binding, require_read_only=False)
            self.input.rename(self.directory / "retained.img")
            self.input.write_bytes(b"substituted image")
            # Refresh the retained stamp because rename itself may change ctime;
            # a different bound inode must fail even when the fd still verifies.
            binding["identity"] = sandbox.stamp(fd)
            with self.assertRaisesRegex(ValueError, "substituted"):
                inner.verify_binding(binding, require_read_only=False)

    def test_inner_refuses_a_writable_mount_even_with_the_correct_readonly_fd(self):
        with contextlib.ExitStack() as stack:
            fd = sandbox.pin_file(stack, self.input)
            binding = {"fd": fd, "path": str(self.input), "identity": sandbox.stamp(fd)}
            self.assertFalse(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
            with self.assertRaisesRegex(ValueError, "mount is not read-only"):
                inner.verify_binding(binding)

    def test_inner_refuses_symlinks_and_descriptors_with_write_authority(self):
        with contextlib.ExitStack() as stack:
            fd = sandbox.pin_file(stack, self.input)
            link = self.directory / "untrusted-bind"
            link.symlink_to(self.input)
            with self.assertRaises(OSError):
                inner.verify_binding({"fd": fd, "path": str(link), "identity": sandbox.stamp(fd)}, require_read_only=False)
            writable = stack.enter_context(self.input.open("r+b"))
            with self.assertRaisesRegex(ValueError, "write authority"):
                inner.verify_binding({"fd": writable.fileno(), "path": str(self.input),
                                      "identity": sandbox.stamp(fd)}, require_read_only=False)

    def test_inner_refuses_unisolated_actual_namespace(self):
        namespaces = {name: os.stat(f"/proc/self/ns/{name}").st_ino for name in ("mnt", "user", "pid", "net", "ipc", "uts")}
        with self.assertRaisesRegex(ValueError, "did not isolate"):
            inner.verify_containment(namespaces)

    def test_inner_checks_capabilities_no_new_privileges_and_filter_after_namespace_checks(self):
        namespaces = {name: -1 for name in ("mnt", "user", "pid", "net", "ipc", "uts")}
        good = "NoNewPrivs:\t1\nCapEff:\t0\nCapPrm:\t0\nCapAmb:\t0\nCapBnd:\t0\nSeccomp:\t2\n"
        for status in [good.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
                       good.replace("CapEff:\t0", "CapEff:\t1"),
                       good.replace("Seccomp:\t2", "Seccomp:\t0"),
                       good.replace("Seccomp:\t2\n", "")]:
            with mock.patch("builtins.open", mock.mock_open(read_data=status)), self.assertRaises(ValueError):
                inner.verify_containment(namespaces)
        with mock.patch("builtins.open", mock.mock_open(read_data=good)):
            inner.verify_containment(namespaces)

    def test_inner_process_limit_rejects_invalid_values(self):
        for value in [None, "64", 3, 0, -1, True, 4.0]:
            with self.assertRaisesRegex(ValueError, "process limit"):
                inner.restrict_processes(value)

    def test_inner_verifies_cgroup_scope_membership_when_configured(self):
        namespaces = {name: -1 for name in ("mnt", "user", "pid", "net", "ipc", "uts")}
        good_status = "NoNewPrivs:\t1\nCapEff:\t0\nCapPrm:\t0\nCapAmb:\t0\nCapBnd:\t0\nSeccomp:\t2\n"

        def fake_open_for(cgroup_text: str):
            def _open(path, *args, **kwargs):
                if path == "/proc/self/status":
                    return io.StringIO(good_status)
                if path == "/proc/self/cgroup":
                    return io.StringIO(cgroup_text)
                raise AssertionError(f"unexpected path {path}")
            return _open

        with mock.patch("builtins.open", side_effect=fake_open_for("0::/user.slice/ffs-ok.scope\n")):
            inner.verify_containment(namespaces, "ffs-ok.scope")
        for bad_cgroup in ("0::/user.slice/other.scope\n", "1:name=systemd:/ffs-ok.scope\n", ""):
            with mock.patch("builtins.open", side_effect=fake_open_for(bad_cgroup)), \
                 self.assertRaisesRegex(ValueError, "cgroup v2 scope"):
                inner.verify_containment(namespaces, "ffs-ok.scope")
        for bad_unit in ("ffs-ok", "sub/ffs-ok.scope", 123):
            with mock.patch("builtins.open", side_effect=fake_open_for("0::/user.slice/ffs-ok.scope\n")), \
                 self.assertRaisesRegex(ValueError, "cgroup scope unit"):
                inner.verify_containment(namespaces, bad_unit)

    def test_cgroup_preflight_refuses_missing_hierarchy_controller_bus_or_systemd_run_without_creating_output(self):
        active = sandbox.CgroupLimits(memory_bytes=128 * sandbox.MIB, pids_max=16, cpu_quota_pct=100)
        fake_cg = self.directory / "fake-cgroup"
        fake_cg.mkdir()
        output = self.directory / "never-created"
        fake_bwrap = self.directory / "fake-bwrap"
        fake_bwrap.write_bytes(b"\x7fELF")
        fake_bwrap.chmod(0o755)
        fake_systemd_run = self.directory / "fake-systemd-run"
        fake_systemd_run.write_bytes(b"\x7fELF")
        fake_systemd_run.chmod(0o755)

        # 1. Missing cgroup.controllers -> fail closed before output.mkdir
        with mock.patch.object(sandbox.os, "geteuid", return_value=1000), \
             mock.patch.object(sandbox.os, "getuid", return_value=1000), \
             self.assertRaisesRegex(sandbox.Refusal, "cgroup v2 unified hierarchy"):
            sandbox.execute(Path(sys.executable), "ffs-fat", [("disk", self.input)],
                            ["inspect", "@disk"], output, sandbox.Limits(), fake_bwrap,
                            cgroup=active, systemd_run=fake_systemd_run, cgroup_root=fake_cg)
        self.assertFalse(output.exists())

        # 2. Missing required controller ("memory") -> fail closed
        (fake_cg / "cgroup.controllers").write_text("cpu pids\n", encoding="ascii")
        with mock.patch.object(sandbox.os, "geteuid", return_value=1000), \
             mock.patch.object(sandbox.os, "getuid", return_value=1000), \
             self.assertRaisesRegex(sandbox.Refusal, "memory"):
            sandbox.execute(Path(sys.executable), "ffs-fat", [("disk", self.input)],
                            ["inspect", "@disk"], output, sandbox.Limits(), fake_bwrap,
                            cgroup=active, systemd_run=fake_systemd_run, cgroup_root=fake_cg)
        self.assertFalse(output.exists())

        # 3. Missing user bus socket -> fail closed
        (fake_cg / "cgroup.controllers").write_text("cpu memory pids\n", encoding="ascii")
        empty_rt = self.directory / "empty-run-user"
        empty_rt.mkdir()
        with mock.patch.object(sandbox.os, "geteuid", return_value=1000), \
             mock.patch.object(sandbox.os, "getuid", return_value=1000), \
             mock.patch.object(sandbox, "_user_runtime_dir", return_value=empty_rt), \
             self.assertRaisesRegex(sandbox.Refusal, "user manager bus"):
            sandbox.execute(Path(sys.executable), "ffs-fat", [("disk", self.input)],
                            ["inspect", "@disk"], output, sandbox.Limits(), fake_bwrap,
                            cgroup=active, systemd_run=fake_systemd_run, cgroup_root=fake_cg)
        self.assertFalse(output.exists())

        # 4. Bus is a regular file instead of socket, or missing systemd-run -> fail closed
        (empty_rt / "bus").write_bytes(b"not a socket")
        with mock.patch.object(sandbox.os, "geteuid", return_value=1000), \
             mock.patch.object(sandbox.os, "getuid", return_value=1000), \
             mock.patch.object(sandbox, "_user_runtime_dir", return_value=empty_rt), \
             self.assertRaisesRegex(sandbox.Refusal, "not a user-owned socket"):
            sandbox.execute(Path(sys.executable), "ffs-fat", [("disk", self.input)],
                            ["inspect", "@disk"], output, sandbox.Limits(), fake_bwrap,
                            cgroup=active, systemd_run=fake_systemd_run, cgroup_root=fake_cg)
        self.assertFalse(output.exists())


class SupervisorTests(unittest.TestCase):
    def run_child(self, program, *, timeout=3, cap=8192):
        out, err = io.BytesIO(), io.BytesIO()
        result = sandbox._supervise([sys.executable, "-I", "-c", program], (),
                                      {"stdout": out, "stderr": err},
                                      sandbox.Limits(output_bytes=cap), time.monotonic() + timeout)
        return result, out.getvalue(), err.getvalue()

    def test_actual_binary_output_is_kept_private_and_hashed_without_terminal_decoding(self):
        result, out, err = self.run_child("import os; os.write(1, b'\\x00\\xff\\x1b[31m'); os.write(2, b'warning')")
        self.assertEqual(result["exit_code"], 0)
        self.assertIsNone(result["termination"])
        self.assertEqual(out, b"\x00\xff\x1b[31m")
        self.assertEqual(err, b"warning")
        self.assertEqual(result["output_sha256"]["stdout"], hashlib.sha256(out).hexdigest())

    def test_inherited_secrets_and_loader_environment_are_removed(self):
        with mock.patch.dict(os.environ, {"FFS_SECRET_TEST": "never expose", "RUST_LOG": "secret"}):
            result, out, _ = self.run_child("import os,json; print(json.dumps(dict(os.environ)))")
        self.assertEqual(result["exit_code"], 0)
        environment = json.loads(out)
        self.assertNotIn("FFS_SECRET_TEST", environment)
        self.assertNotIn("RUST_LOG", environment)
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")

    def test_real_child_observes_hard_descriptor_and_core_limits(self):
        result, out, _ = self.run_child("import resource,json; print(json.dumps([resource.getrlimit(resource.RLIMIT_NOFILE),resource.getrlimit(resource.RLIMIT_CORE)]))")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(json.loads(out), [[64, 64], [0, 0]])

    def test_outer_child_keeps_the_account_task_limit_so_namespaces_can_be_created(self):
        # A per-UID RLIMIT_NPROC on bubblewrap counts every task of the account
        # and makes namespace creation fail on a busy host. The cap is applied
        # inside the sandbox user namespace instead (see the live tests).
        result, out, _ = self.run_child("import resource,json; print(json.dumps(resource.getrlimit(resource.RLIMIT_NPROC)))")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(json.loads(out), list(resource.getrlimit(resource.RLIMIT_NPROC)))

    def test_combined_output_limit_kills_actual_flooding_child(self):
        result, out, err = self.run_child("import os\nwhile True:\n os.write(1,b'x'*4096)\n os.write(2,b'y'*4096)", cap=7000)
        self.assertEqual(result["termination"], "output_limit")
        self.assertEqual(len(out) + len(err), 7000)
        self.assertNotEqual(result["exit_code"], 0)

    def test_wall_clock_limit_kills_actual_sleeping_child(self):
        start = time.monotonic()
        result, _, _ = self.run_child("import time; time.sleep(30)", timeout=0.15)
        self.assertEqual(result["termination"], "wall_time_limit")
        self.assertLess(time.monotonic() - start, 3)
        self.assertNotEqual(result["exit_code"], 0)

    def test_exited_leader_with_inherited_pipe_does_not_hang_supervisor(self):
        start = time.monotonic()
        result, _, _ = self.run_child("import os,time\npid=os.fork()\nif pid: os._exit(0)\ntime.sleep(30)", timeout=0.2)
        self.assertEqual(result["termination"], "wall_time_limit")
        self.assertLess(time.monotonic() - start, 3)

    def test_nonzero_exit_is_preserved_not_interpreted_as_a_successful_read(self):
        result, out, _ = self.run_child("import os; os.write(1,b'partial'); raise SystemExit(7)")
        self.assertEqual(out, b"partial")
        self.assertEqual(result["exit_code"], 7)
        self.assertIsNone(result["termination"])

    def test_inner_closes_original_fds_before_exec_in_a_real_child(self):
        program = ("import os,importlib.util,json\n"
                   f"s=importlib.util.spec_from_file_location('inner',{str(SOURCE.with_name('ffs_inspect_sandbox_inner.py'))!r})\n"
                   "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n"
                   "keep=os.open('/dev/null',os.O_RDONLY);other=os.open('/dev/null',os.O_RDONLY)\n"
                   "m.close_inherited(keep)\n"
                   "try: os.fstat(other);closed=False\n"
                   "except OSError: closed=True\n"
                   "print(json.dumps([closed,os.get_inheritable(keep)]))\n")
        result, out, _ = self.run_child(program)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(json.loads(out), [True, False])


LIVE_PROBE = r"""
import ctypes, errno, importlib.util, json, os, socket, threading
out = {}
status = dict(line.rstrip().split(":", 1) for line in open("/proc/self/status") if ":" in line)
for key in ("Seccomp", "NoNewPrivs", "CapEff", "CapBnd"):
    out[key] = status[key].strip()
def errno_of(action):
    try:
        action()
        return 0
    except OSError as error:
        return error.errno
out["socket_unix"] = errno_of(lambda: socket.socket(socket.AF_UNIX).close())
out["socket_inet"] = errno_of(lambda: socket.socket(socket.AF_INET).close())
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
def raw(number, *args):
    result = libc.syscall(ctypes.c_long(number), *(ctypes.c_long(a) for a in args))
    return 0 if result != -1 else ctypes.get_errno()
numbers = {"x86_64": {"personality": 135, "keyctl": 250, "unshare": 272, "getpid": 39},
           "aarch64": {"personality": 92, "keyctl": 219, "unshare": 97, "getpid": 172}}[os.uname().machine]
out["personality"] = raw(numbers["personality"], 0xFFFFFFFF)
out["keyctl"] = raw(numbers["keyctl"], 0, -3, 0)
out["unshare"] = raw(numbers["unshare"], 0x00020000)
out["getpid"] = raw(numbers["getpid"])
out["root"] = sorted(os.listdir("/"))
out["visible"] = {path: os.path.exists(path) for path in ("/home", "/etc", "/root", "/dev/fuse", "/run")}
out["input_write"] = errno_of(lambda: open("/inputs/disk", "r+b").close())
out["input_bytes"] = open("/inputs/disk", "rb").read()
out["input_bytes"] = len(out["input_bytes"])
out["interfaces"] = sorted(line.split(":")[0].strip() for line in open("/proc/net/dev").readlines()[2:])
spec = importlib.util.spec_from_file_location("verify", "/app/verify.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)
verify.restrict_processes(8)
def spawn(count):
    stop, started = threading.Event(), []
    try:
        for _ in range(count):
            thread = threading.Thread(target=stop.wait)
            thread.start()
            started.append(thread)
    except RuntimeError:
        pass
    stop.set()
    for thread in started:
        thread.join()
    return len(started)
out["threads_4"], out["threads_20"] = spawn(4), spawn(20)
print(json.dumps(out))
"""


def live_sandbox_unavailable() -> str | None:
    """Why real bubblewrap cannot run here; FFS_REQUIRE_SANDBOX=1 makes it fatal."""
    bwrap = Path("/usr/bin/bwrap")
    if sys.platform != "linux" or os.geteuid() == 0:
        reason = "live sandbox tests need an ordinary non-root Linux user"
    elif not bwrap.exists():
        reason = "bubblewrap is not installed at /usr/bin/bwrap"
    else:
        probe = subprocess.run([str(bwrap), "--unshare-user", "--unshare-pid", "--unshare-net",
                                "--ro-bind", "/", "/", "--", "/usr/bin/python3", "-I", "-c", "pass"],
                               capture_output=True, check=False, timeout=30)
        reason = None if probe.returncode == 0 else f"bubblewrap cannot create namespaces: {probe.stderr[-200:]!r}"
    if reason and os.environ.get("FFS_REQUIRE_SANDBOX") == "1":
        raise AssertionError(f"FFS_REQUIRE_SANDBOX=1 but {reason}")
    return reason


def live_cgroup_unavailable() -> str | None:
    """Why live systemd-run --user --scope cgroup v2 tests cannot run; FFS_REQUIRE_CGROUP=1 makes it fatal."""
    reason = live_sandbox_unavailable()
    systemd_run = Path("/usr/bin/systemd-run")
    uid = os.getuid()
    bus = Path(f"/run/user/{uid}/bus")
    if reason is None:
        if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
            reason = "cgroup v2 unified hierarchy is not mounted at /sys/fs/cgroup"
        elif not systemd_run.is_file():
            reason = "systemd-run is not installed at /usr/bin/systemd-run"
        elif not bus.exists() or not stat.S_ISSOCK(bus.lstat().st_mode):
            reason = f"systemd user manager bus is unavailable at {bus}"
        else:
            probe = subprocess.run(
                [str(systemd_run), "--user", "--scope", "--quiet", "--collect",
                 "-p", "MemoryMax=67108864", "-p", "MemorySwapMax=0",
                 "-p", "TasksMax=16", "-p", "CPUQuota=100%", "--", "/usr/bin/true"],
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                     "XDG_RUNTIME_DIR": f"/run/user/{uid}"},
                capture_output=True, check=False, timeout=30,
            )
            if probe.returncode != 0:
                reason = f"systemd-run --user --scope failed: {probe.stderr[-200:]!r}"
    if reason and os.environ.get("FFS_REQUIRE_CGROUP") == "1":
        raise AssertionError(f"FFS_REQUIRE_CGROUP=1 but {reason}")
    return reason


def plain_true_executable() -> Path | None:
    # Multicall coreutils dispatch on argv[0], which the launcher sets to /app/reader.
    for candidate in (Path("/usr/bin/gnutrue"), Path("/usr/bin/true"), Path("/bin/true")):
        if candidate.exists():
            resolved = candidate.resolve()
            if resolved.name in {"true", "gnutrue"} and resolved.read_bytes()[:4] == b"\x7fELF":
                return resolved
    return None


class LiveSandboxTests(unittest.TestCase):
    """Kernel-enforced behavior through real bubblewrap, not mocks."""

    def setUp(self):
        reason = live_sandbox_unavailable()
        if reason:
            self.skipTest(reason)
        self.directory = Path(tempfile.mkdtemp(prefix="ffs-inspect-live-"))
        self.input = self.directory / "disk.img"
        self.content = os.urandom(12345)
        self.input.write_bytes(self.content)

    def test_live_policy_enforces_namespaces_filter_read_only_inputs_and_task_cap(self):
        python = Path("/usr/bin/python3").resolve()
        with contextlib.ExitStack() as stack:
            binary_fd = sandbox.pin_file(stack, python, executable=True)
            python_fd = sandbox.pin_file(stack, python, executable=True)
            disk_fd = sandbox.pin_file(stack, self.input)
            inner_fd = sandbox.sealed_data(stack, SOURCE.with_name("ffs_inspect_sandbox_inner.py").read_bytes())
            config_fd = sandbox.sealed_data(stack, b"{}")
            seccomp_fd = sandbox.sealed_data(stack, sandbox.seccomp_filter(os.uname().machine))
            status = os.pipe2(os.O_CLOEXEC)
            argv = sandbox.sandbox_argv(Path("/usr/bin/bwrap"), binary_fd, [("disk", disk_fd)],
                                        ["inspect", "/inputs/disk"], sandbox.Limits(), status[1],
                                        python_fd, inner_fd, config_fd, seccomp_fd)
            # Same policy; replace only the verifier invocation with the probe.
            argv = argv[:argv.index("--") + 1] + ["/app/python", "-I", "-S", "-c", LIVE_PROBE]
            out, err = io.BytesIO(), io.BytesIO()
            result = sandbox._supervise(argv, (binary_fd, python_fd, disk_fd, inner_fd, config_fd,
                                               seccomp_fd, status[1]),
                                        {"stdout": out, "stderr": err}, sandbox.Limits(),
                                        time.monotonic() + 60, status)
        self.assertEqual(result["exit_code"], 0, err.getvalue()[-2000:])
        self.assertTrue(sandbox.status_confirms_execution(result["sandbox_status"], 0))
        probe = json.loads(out.getvalue())
        self.assertEqual(probe["Seccomp"], "2")
        self.assertEqual(probe["NoNewPrivs"], "1")
        self.assertEqual(int(probe["CapEff"], 16), 0)
        self.assertEqual(int(probe["CapBnd"], 16), 0)
        # Both succeed without the filter, even in an empty network namespace.
        self.assertEqual(probe["socket_unix"], errno.EPERM)
        self.assertEqual(probe["personality"], errno.EPERM)
        for name in ("socket_inet", "keyctl", "unshare"):
            self.assertEqual(probe[name], errno.EPERM, name)
        self.assertEqual(probe["getpid"], 0)
        self.assertFalse(any(probe["visible"].values()), probe["visible"])
        self.assertTrue(set(probe["root"]) <= {"app", "inputs", "usr", "dev", "proc", "tmp", "lib", "lib64"},
                        probe["root"])
        self.assertEqual(probe["input_write"], errno.EROFS)
        self.assertEqual(probe["input_bytes"], len(self.content))
        self.assertEqual(probe["interfaces"], ["lo"])
        # The cap counts this sandbox only, not the host account's other tasks.
        self.assertEqual(probe["threads_4"], 4)
        self.assertLess(probe["threads_20"], 8)
        self.assertEqual(self.input.read_bytes(), self.content)

    def test_live_end_to_end_execution_succeeds_and_records_the_enforced_policy(self):
        reader = plain_true_executable()
        if reader is None:
            if os.environ.get("FFS_REQUIRE_SANDBOX") == "1":
                self.fail("FFS_REQUIRE_SANDBOX=1 but no single-purpose ELF true is installed")
            self.skipTest("no single-purpose ELF true to stand in for a reader")
        output = self.directory / "evidence"
        code = sandbox.execute(reader, "ffs-cli", [("disk", self.input)], ["inspect", "@disk"],
                               output, sandbox.Limits(), Path("/usr/bin/bwrap"))
        result = json.loads((output / "result.json").read_text())
        request = json.loads((output / "request.json").read_text())
        self.assertEqual(code, 0, result)
        self.assertTrue(result["success"])
        self.assertTrue(result["execution_confirmed"])
        self.assertTrue(result["reader_and_inputs_unchanged"])
        self.assertEqual(result["inputs"][0]["sha256_after"], hashlib.sha256(self.content).hexdigest())
        self.assertEqual(request["policy"], sandbox.POLICY)
        self.assertFalse(request["cgroup"]["enabled"])
        program = sandbox.seccomp_filter(os.uname().machine)
        self.assertEqual(request["seccomp"]["sha256"], hashlib.sha256(program).hexdigest())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)

    def test_live_cgroup_scope_enforces_kernel_memory_swap_pids_and_cpu_quotas(self):
        reason = live_cgroup_unavailable()
        if reason:
            self.skipTest(reason)
        reader = plain_true_executable()
        if reader is None:
            if os.environ.get("FFS_REQUIRE_SANDBOX") == "1" or os.environ.get("FFS_REQUIRE_CGROUP") == "1":
                self.fail("no single-purpose ELF true is installed")
            self.skipTest("no single-purpose ELF true to stand in for a reader")

        # 1. Inspect actual kernel cgroup v2 files while a live systemd-run + bwrap scope is active.
        python = Path("/usr/bin/python3").resolve()
        systemd_run = Path("/usr/bin/systemd-run").resolve()
        cg = sandbox.CgroupLimits(memory_bytes=96 * sandbox.MIB, pids_max=16, cpu_quota_pct=150)
        scope_unit = f"ffs-inspect-live-{os.getpid()}-{time.monotonic_ns():x}.scope"
        hold_r, hold_w = os.pipe()
        try:
            with contextlib.ExitStack() as stack:
                systemd_fd = sandbox.pin_file(stack, systemd_run, executable=True)
                bwrap_fd = sandbox.pin_file(stack, Path("/usr/bin/bwrap").resolve(), executable=True)
                binary_fd = sandbox.pin_file(stack, python, executable=True)
                python_fd = sandbox.pin_file(stack, python, executable=True)
                disk_fd = sandbox.pin_file(stack, self.input)
                inner_fd = sandbox.sealed_data(stack, SOURCE.with_name("ffs_inspect_sandbox_inner.py").read_bytes())
                config_fd = sandbox.sealed_data(stack, b"{}")
                seccomp_fd = sandbox.sealed_data(stack, sandbox.seccomp_filter(os.uname().machine))
                status = os.pipe2(os.O_CLOEXEC)
                stack.callback(lambda: [contextlib.suppress(OSError).__enter__() or os.close(fd) for fd in status])
                bwrap_argv = sandbox.sandbox_argv(
                    Path(f"/proc/self/fd/{bwrap_fd}"), binary_fd, [("disk", disk_fd)],
                    ["inspect", "/inputs/disk"], sandbox.Limits(), status[1],
                    python_fd, inner_fd, config_fd, seccomp_fd,
                )
                probe_code = (
                    f"import os, sys; sys.stdout.write(open('/proc/self/cgroup').read()); "
                    f"sys.stdout.flush(); os.read({hold_r}, 1)"
                )
                bwrap_argv = bwrap_argv[:bwrap_argv.index("--") + 1] + [
                    "/app/python", "-I", "-S", "-c", probe_code
                ]
                argv = sandbox.cgroup_argv(scope_unit, cg, bwrap_argv)
                proc = subprocess.Popen(
                    argv,
                    executable=f"/proc/self/fd/{systemd_fd}",
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    pass_fds=(systemd_fd, bwrap_fd, binary_fd, python_fd, disk_fd,
                              inner_fd, config_fd, seccomp_fd, status[1], hold_r),
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                         "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}"},
                )
                os.close(hold_r)
                hold_r = -1
                cg_line = proc.stdout.readline().decode("ascii").strip()
                self.assertTrue(cg_line.startswith("0::/"), cg_line)
                self.assertTrue(cg_line.endswith(f"/{scope_unit}"), cg_line)
                cg_dir = Path("/sys/fs/cgroup") / cg_line[4:]
                self.assertEqual((cg_dir / "memory.max").read_text().strip(), str(96 * sandbox.MIB))
                self.assertEqual((cg_dir / "memory.swap.max").read_text().strip(), "0")
                self.assertEqual((cg_dir / "pids.max").read_text().strip(), "16")
                self.assertEqual((cg_dir / "cpu.max").read_text().strip(), "150000 100000")
                os.close(hold_w)
                hold_w = -1
                _, stderr_bytes = proc.communicate(timeout=30)
                proc.stdout.close()
                self.assertEqual(proc.returncode, 0, stderr_bytes[-1000:])
        finally:
            for fd in (hold_r, hold_w):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)

        # 2. Hostile memory-hog child inside a 64 MiB MemoryMax (SwapMax=0) cgroup is killed by kernel OOM.
        with contextlib.ExitStack() as stack:
            systemd_fd = sandbox.pin_file(stack, systemd_run, executable=True)
            bwrap_fd = sandbox.pin_file(stack, Path("/usr/bin/bwrap").resolve(), executable=True)
            binary_fd = sandbox.pin_file(stack, python, executable=True)
            python_fd = sandbox.pin_file(stack, python, executable=True)
            disk_fd = sandbox.pin_file(stack, self.input)
            inner_fd = sandbox.sealed_data(stack, SOURCE.with_name("ffs_inspect_sandbox_inner.py").read_bytes())
            config_fd = sandbox.sealed_data(stack, b"{}")
            seccomp_fd = sandbox.sealed_data(stack, sandbox.seccomp_filter(os.uname().machine))
            status = os.pipe2(os.O_CLOEXEC)
            oom_cg = sandbox.CgroupLimits(memory_bytes=64 * sandbox.MIB, pids_max=16)
            oom_unit = f"ffs-inspect-oom-{os.getpid()}-{time.monotonic_ns():x}.scope"
            bwrap_argv = sandbox.sandbox_argv(
                Path(f"/proc/self/fd/{bwrap_fd}"), binary_fd, [("disk", disk_fd)],
                ["inspect", "/inputs/disk"], sandbox.Limits(), status[1],
                python_fd, inner_fd, config_fd, seccomp_fd,
            )
            hog = "buf = bytearray(160 * 1024 * 1024)\nfor i in range(0, len(buf), 4096): buf[i] = 1\n"
            bwrap_argv = bwrap_argv[:bwrap_argv.index("--") + 1] + [
                "/app/python", "-I", "-S", "-c", hog
            ]
            argv = sandbox.cgroup_argv(oom_unit, oom_cg, bwrap_argv)
            out, err = io.BytesIO(), io.BytesIO()
            oom_res = sandbox._supervise(
                argv,
                (systemd_fd, bwrap_fd, binary_fd, python_fd, disk_fd,
                 inner_fd, config_fd, seccomp_fd, status[1]),
                {"stdout": out, "stderr": err},
                sandbox.Limits(),
                time.monotonic() + 30,
                status,
                executable=f"/proc/self/fd/{systemd_fd}",
                extra_env={"XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}"},
            )
        self.assertNotEqual(oom_res["exit_code"], 0)
        self.assertEqual(self.input.read_bytes(), self.content)

        # 3. End-to-end sandbox.execute with CgroupLimits verifies inner scope check + manifest fields.
        output = self.directory / "evidence-cgroup"
        code = sandbox.execute(
            reader, "ffs-cli", [("disk", self.input)], ["inspect", "@disk"],
            output, sandbox.Limits(), Path("/usr/bin/bwrap"),
            cgroup=cg, systemd_run=systemd_run,
        )
        result = json.loads((output / "result.json").read_text())
        request = json.loads((output / "request.json").read_text())
        self.assertEqual(code, 0, result)
        self.assertTrue(result["success"])
        self.assertTrue(result["execution_confirmed"])
        self.assertTrue(result["reader_and_inputs_unchanged"])
        self.assertTrue(request["cgroup"]["enabled"])
        self.assertEqual(request["cgroup"]["memory_bytes"], 96 * sandbox.MIB)
        self.assertEqual(request["cgroup"]["swap_max"], 0)
        self.assertEqual(request["cgroup"]["pids_max"], 16)
        self.assertEqual(request["cgroup"]["cpu_quota_pct"], 150)
        self.assertTrue(request["cgroup"]["scope_unit"].endswith(".scope"))
        self.assertEqual(len(request["cgroup"]["systemd_run_sha256"]), 64)
        self.assertTrue(result["cgroup"]["enabled"])
        self.assertEqual(result["cgroup"]["scope_unit"], request["cgroup"]["scope_unit"])


if __name__ == "__main__":
    unittest.main()
