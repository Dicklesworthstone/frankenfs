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
import stat
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
                                    ["inspect", "/inputs/disk"], sandbox.Limits(), 10, 11, 12, 13)
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

    def test_inner_checks_capabilities_and_no_new_privileges_after_namespace_checks(self):
        namespaces = {name: -1 for name in ("mnt", "user", "pid", "net", "ipc", "uts")}
        for status in ["NoNewPrivs:\t0\nCapEff:\t0\nCapPrm:\t0\nCapAmb:\t0\nCapBnd:\t0\n",
                       "NoNewPrivs:\t1\nCapEff:\t1\nCapPrm:\t0\nCapAmb:\t0\nCapBnd:\t0\n"]:
            with mock.patch("builtins.open", mock.mock_open(read_data=status)), self.assertRaises(ValueError):
                inner.verify_containment(namespaces)
        with mock.patch("builtins.open", mock.mock_open(read_data="NoNewPrivs:\t1\nCapEff:\t0\nCapPrm:\t0\nCapAmb:\t0\nCapBnd:\t0\n")):
            inner.verify_containment(namespaces)


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


if __name__ == "__main__":
    unittest.main()
