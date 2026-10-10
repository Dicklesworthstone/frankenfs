#!/usr/bin/env python3
"""Exercise a built ffs-ntfs through a real read-only Linux FUSE mount.

Creates only fresh, retained scratch images using mkntfs/ntfscp. Requires real
FUSE, over 256 native directory entries, independent ntfscat comparisons,
mounted reads/statfs/EROFS, and unchanged whole-image hashes. Missing tools and
failed operations are failures, never successful skips. Does not build Rust.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for data in iter(lambda: source.read(1024 * 1024), b""):
            result.update(data)
    return result.hexdigest()


def mounted_here(path: Path) -> bool:
    # Reading mountinfo never issues a request to a possibly stuck FUSE daemon.
    def unescape(value: str) -> str:
        return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)

    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 5 and unescape(fields[4]) == str(path):
            return True
    return False


def probe(mountpoint: Path, manifest_path: Path) -> None:
    """Runs in a timed child: no unbounded mounted filesystem call in parent."""
    manifest = json.loads(manifest_path.read_text())
    names = set(manifest)
    for _ in range(3):
        listing = os.listdir(mountpoint)
        require(len(listing) == len(set(listing)), "duplicate names in mounted readdir")
        require(names <= set(listing), "native files lost across readdir pages")
        for name, expected in manifest.items():
            path = mountpoint / name
            metadata = path.stat()
            require(metadata.st_size == expected["size"], f"wrong mounted size: {name}")
            require(metadata.st_mode & 0o222 == 0, f"writable projected mode: {name}")
            require(metadata.st_uid == os.getuid() and metadata.st_gid == os.getgid(),
                    f"wrong configured mount ownership: {name}")
    for name, expected in manifest.items():
        path = mountpoint / name
        require(digest(path) == expected["sha256"], f"mounted content differs: {name}")
        with path.open("rb") as stream:
            stream.seek(507)
            require(stream.read(1031).hex() == expected["range_hex"],
                    f"unaligned mounted range differs: {name}")
            stream.seek(expected["size"])
            require(stream.read(1) == b"", f"mounted EOF exposes allocation slack: {name}")
    victim = mountpoint / next(iter(manifest))
    for flags in (os.O_WRONLY, os.O_RDWR, os.O_RDONLY | os.O_TRUNC):
        try:
            descriptor = os.open(victim, flags)
        except OSError as error:
            require(error.errno == errno.EROFS, f"write-open returned errno {error.errno}, not EROFS")
        else:
            os.close(descriptor)
            raise RuntimeError("read-only mount admitted a write-capable open")
    stats = os.statvfs(mountpoint)
    require(stats.f_blocks > 0 and 0 <= stats.f_bfree <= stats.f_blocks,
            "invalid mounted allocation statistics")
    require(stats.f_files > 0 and 0 <= stats.f_ffree <= stats.f_files,
            "invalid mounted MFT statistics")
    require(stats.f_flag & os.ST_RDONLY != 0, "kernel did not mark the mount read-only")
    print(json.dumps({"files_checked": len(manifest), "directory_passes": 3,
                      "content_and_ranges": True, "write_open_errno": errno.EROFS}))


class Run:
    def __init__(self, root: Path, binary: Path) -> None:
        self.root = root
        self.binary = binary
        self.sequence = 0

    def command(self, *args: str | Path, timeout: int = 120) -> bytes:
        self.sequence += 1
        prefix = self.root / f"command-{self.sequence:04d}"
        argv = [str(arg) for arg in args]
        prefix.with_suffix(".argv.json").write_text(json.dumps(argv) + "\n")
        try:
            result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False,
                                    env={**os.environ, "LC_ALL": "C"})
        except subprocess.TimeoutExpired as error:
            prefix.with_suffix(".stdout").write_bytes(error.stdout or b"")
            prefix.with_suffix(".stderr").write_bytes(error.stderr or b"")
            prefix.with_suffix(".status").write_text("timeout\n")
            raise
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        prefix.with_suffix(".status").write_text(str(result.returncode) + "\n")
        require(result.returncode == 0, f"command failed: {argv!r}; see {prefix}.stderr")
        return result.stdout

    def mount_probe(self, image: Path, manifest: Path, offset: int, length: int) -> dict:
        mountpoint = self.root / (image.stem + "-mount")
        mountpoint.mkdir()
        log_path = self.root / (image.stem + "-mount.log")
        argv = [str(self.binary), "mount", str(image), str(mountpoint), "--offline-image",
                "--offset", str(offset), "--length", str(length), "--uid", str(os.getuid()),
                "--gid", str(os.getgid())]
        (self.root / (image.stem + "-mount.argv.json")).write_text(json.dumps(argv) + "\n")
        with log_path.open("wb") as log:
            process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while not mounted_here(mountpoint):
                    require(process.poll() is None, f"mount exited; see {log_path}")
                    require(time.monotonic() < deadline, f"mount did not appear; see {log_path}")
                    time.sleep(0.05)
                output = self.command(sys.executable, Path(__file__).resolve(), "--probe",
                                      mountpoint, "--manifest", manifest, timeout=180)
                report = json.loads(output)
                self.command("fusermount3", "-u", mountpoint, timeout=30)
                require(process.wait(timeout=30) == 0, f"mount did not exit cleanly; see {log_path}")
                require(not mounted_here(mountpoint), "successful unmount left a mounted filesystem")
                return report
            finally:
                # Never recursively delete a tree and never touch another mount.
                # Failures retain the image, mountpoint, logs and failed result.
                try:
                    if mounted_here(mountpoint):
                        self.command("fusermount3", "-u", mountpoint, timeout=30)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=10)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="already-built ffs-ntfs executable")
    parser.add_argument("--probe", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--manifest", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.probe is not None:
        require(args.manifest is not None, "mounted probe requires its manifest")
        probe(args.probe, args.manifest)
        return
    require(args.binary is not None, "--binary is required")
    binary = args.binary.resolve(strict=True)
    require(os.access(binary, os.X_OK), "candidate is not executable")
    require(Path("/dev/fuse").exists() and Path("/proc/self/mountinfo").exists(),
            "a real Linux FUSE environment is required; no skip credit")
    tools = ["mkntfs", "ntfscp", "ntfscat", "fusermount3"]
    for tool in tools:
        require(shutil.which(tool) is not None, f"missing required tool: {tool}")
    root = Path(tempfile.mkdtemp(prefix="ffs-ntfs-mounted-"))
    print(f"Retaining native images and logs in {root}", flush=True)
    run = Run(root, binary)
    report = {"status": "running", "candidate_sha256": digest(binary),
              "tools": {tool: shutil.which(tool) for tool in tools}, "mounts": []}
    try:
        image = root / "native.img"
        with image.open("xb") as target:
            target.truncate(64 * 1024 * 1024)
        # Only this newly created scratch regular file is passed to the formatter.
        run.command("mkntfs", "-F", "-Q", "-s", "512", "-c", "4096", image)
        manifest = {}
        for index in range(320):
            name = f"entry-{index:04d}.bin"
            payload = (f"native entry {index}\n".encode() * 100)[:1037]
            if index == 0:
                payload = b""
            elif index == 319:
                payload = (bytes(range(251)) * 9000)[:2 * 1024 * 1024 + 37]
            source = root / name
            source.write_bytes(payload)
            run.command("ntfscp", image, source, "/" + name)
            manifest[name] = {"size": len(payload), "sha256": digest(source),
                              "range_hex": payload[507:1538].hex()}
        # Independent byte oracle for every seeded file, not just candidates
        # agreeing with their own parser or with a claimed directory count.
        before = digest(image)
        for name, expected in manifest.items():
            native = run.command("ntfscat", image, "/" + name)
            require(hashlib.sha256(native).hexdigest() == expected["sha256"],
                    f"native reference differs from source: {name}")
        manifest_path = root / "expected.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        report["mounts"].append(run.mount_probe(image, manifest_path, 0, image.stat().st_size))
        require(digest(image) == before, "mounted reads changed the native image")
        disk = root / "partitioned.img"
        with disk.open("xb") as target, image.open("rb") as source:
            target.write(b"P" * 1048576)
            shutil.copyfileobj(source, target)
            target.write(b"Q" * 4096)
        disk_before = digest(disk)
        report["mounts"].append(run.mount_probe(disk, manifest_path, 1048576, image.stat().st_size))
        require(digest(disk) == disk_before, "mounted reads changed the selected or adjacent volumes")
        report.update(status="passed", native_sha256=before, partitioned_sha256=disk_before)
        print(json.dumps(report, indent=2))
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
