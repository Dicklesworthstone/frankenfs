#!/usr/bin/env python3
"""Exercise a built ffs-fat against dosfstools/mtools-created FAT16 and FAT32.

No Cargo subprocess, privileged kernel mount, or existing image mutation. Every
image is newly created in a retained scratch directory. Missing tools, missing
FUSE in --mounted mode, failed commands, byte changes and mismatched payloads
are failures, never skipped successes. Build the candidate before running this.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


class Run:
    def __init__(self, binary: Path, root: Path) -> None:
        self.binary = binary
        self.root = root
        self.sequence = 0

    def command(self, *args: str | Path, timeout: int = 120) -> bytes:
        self.sequence += 1
        command = [str(arg) for arg in args]
        result = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
        prefix = self.root / f"command-{self.sequence:03d}"
        prefix.with_suffix(".json").write_text(
            json.dumps({"argv": command, "returncode": result.returncode}, indent=2) + "\n"
        )
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        check(result.returncode == 0, f"command failed: {command!r}; see {prefix}.stderr")
        return result.stdout

    def mounted(self, image: Path, payloads: dict[str, bytes]) -> None:
        mountpoint = self.root / f"{image.stem}-mount"
        mountpoint.mkdir()
        log = (self.root / f"{image.stem}-mount.stderr").open("wb")
        process = subprocess.Popen(
            [str(self.binary), "mount", str(image), str(mountpoint), "--offline-image",
             "--uid", str(os.getuid()), "--gid", str(os.getgid())],
            stdout=subprocess.DEVNULL,
            stderr=log,
        )
        try:
            deadline = time.monotonic() + 30
            while not os.path.ismount(mountpoint):
                check(process.poll() is None, f"FAT mount exited; see {log.name}")
                check(time.monotonic() < deadline, f"FAT mount timed out; see {log.name}")
                time.sleep(0.05)
            for name, expected in payloads.items():
                path = mountpoint / name
                check(path.read_bytes() == expected, f"mounted FAT bytes differ: {name}")
                check(path.stat().st_size == len(expected), f"mounted FAT size differs: {name}")
                with path.open("rb") as stream:
                    stream.seek(507)
                    check(stream.read(1031) == expected[507:1538], f"mounted unaligned read differs: {name}")
            first = mountpoint / next(iter(payloads))
            try:
                descriptor = os.open(first, os.O_WRONLY)
            except OSError as error:
                check(error.errno == errno.EROFS, f"write-open returned {error.errno}, expected EROFS")
            else:
                os.close(descriptor)
                raise RuntimeError("FAT read-only mount admitted a writable descriptor")
            check(os.statvfs(mountpoint).f_bsize > 0, "mounted statfs returned no block size")
            self.command("fusermount3", "-u", mountpoint)
            check(process.wait(timeout=30) == 0, f"FAT mount did not exit cleanly; see {log.name}")
        finally:
            # Only our own mountpoint/process is touched. Failed evidence stays
            # on disk; in particular, never recursively delete a mounted tree.
            try:
                if os.path.ismount(mountpoint):
                    self.command("fusermount3", "-u", mountpoint)
            finally:
                try:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=10)
                finally:
                    log.close()

    def dialect(self, bits: int, mounted: bool) -> dict[str, object]:
        image = self.root / f"fat{bits}.img"
        with image.open("xb") as stream:
            stream.truncate((64 if bits == 16 else 128) * 1024 * 1024)
        self.command("mkfs.fat", "-F", str(bits), image)
        self.command("mmd", "-i", image, "::/nested")
        payload = (bytes(range(251)) * 9000)[:2 * 1024 * 1024 + 37]
        payloads = {
            "Long native filename.txt": payload,
            "nested/Native café.bin": bytes(reversed(range(256))) * 33 + b"tail",
            "empty.txt": b"",
        }
        for index, (name, expected) in enumerate(payloads.items()):
            source = self.root / f"fat{bits}-source-{index}.bin"
            source.write_bytes(expected)
            self.command("mcopy", "-i", image, source, f"::/{name}")
            reference = self.root / f"fat{bits}-reference-{index}.bin"
            self.command("mcopy", "-i", image, f"::/{name}", reference)
            check(reference.read_bytes() == expected, "mtools reference bytes differ from source")
        self.command("fsck.fat", "-n", image)
        before = digest(image)
        info = json.loads(self.command(self.binary, "inspect", image))
        check(info["format"] == f"Fat{bits}", "wrong count-derived FAT dialect")
        check(info["read_only"] is True, "candidate did not declare read-only mode")
        root = json.loads(self.command(self.binary, "ls", image, "/"))
        names = {entry["name"].lower() for entry in root}
        check({"long native filename.txt", "nested", "empty.txt"} <= names, "native root names missing")
        for name, expected in payloads.items():
            actual = self.command(self.binary, "cat", image, f"/{name}")
            check(actual == expected, f"native-image CLI bytes differ: FAT{bits} {name}")
        if mounted:
            self.mounted(image, payloads)
        check(digest(image) == before, f"candidate changed FAT{bits} image bytes")
        self.command("fsck.fat", "-n", image)
        check(digest(image) == before, "read-only native checker changed the image")
        return {"format": f"FAT{bits}", "image_sha256": before,
                "files_checked": len(payloads), "mounted": mounted, "result": "passed"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="already-built ffs-fat executable")
    parser.add_argument("--mounted", action="store_true", help="require actual FUSE reads and EROFS refusal")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    check(os.access(binary, os.X_OK), "candidate is not executable")
    tools = ["mkfs.fat", "fsck.fat", "mcopy", "mmd"]
    if args.mounted:
        tools.append("fusermount3")
        check(Path("/dev/fuse").exists(), "--mounted requires /dev/fuse; no skip credit")
    for tool in tools:
        check(shutil.which(tool) is not None, f"required native oracle tool is missing: {tool}")
    root = Path(tempfile.mkdtemp(prefix="ffs-fat-native-"))
    print(f"Retaining native images and command logs in {root}", flush=True)
    run = Run(binary, root)
    report = {"candidate_sha256": digest(binary), "tool_paths": {tool: shutil.which(tool) for tool in tools},
              "scenarios": []}
    try:
        for bits in (16, 32):
            scenario = run.dialect(bits, args.mounted)
            report["scenarios"].append(scenario)
            print(json.dumps(scenario), flush=True)
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
