#!/usr/bin/env python3
"""Exercise FAT16/FAT32 images created by ffs-fat and native dosfstools.

No Cargo subprocess or privileged kernel mount. Every image that is mutated is
newly created in a retained scratch directory. Missing tools, missing
FUSE in --mounted mode, failed commands, byte changes and mismatched payloads
are failures, never skipped successes. Build the candidate before running this.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import locale
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



def native_allocation(image: Path) -> dict[str, int | str]:
    """Independent BPB/FAT byte scan for the images owned by this runner."""
    with image.open("rb") as stream:
        boot = stream.read(512)
        check(len(boot) == 512 and boot[510:512] == b"\x55\xaa", "native BPB signature differs")
        u16 = lambda offset: int.from_bytes(boot[offset:offset + 2], "little")
        u32 = lambda offset: int.from_bytes(boot[offset:offset + 4], "little")
        check(u16(11) == 512, "formatter did not use the declared sector size")
        sectors_per_cluster = boot[13]
        check(sectors_per_cluster in (1, 2, 4, 8, 16, 32, 64, 128), "invalid format cluster size")
        total = u16(19) or u32(32)
        fat_sectors = u16(22) or u32(36)
        reserved = u16(14)
        check(boot[16] == 2, "formatter did not create both FAT copies")
        root_sectors = (u16(17) * 32 + 511) // 512
        first_data = reserved + 2 * fat_sectors + root_sectors
        check(total * 512 == image.stat().st_size, "native BPB/image length differs")
        check(0 < reserved < first_data < total, "native metadata exceeds image")
        clusters = (total - first_data) // sectors_per_cluster
        check(4085 <= clusters <= 8_388_608, "native cluster count outside the declared profile")
        bits = 16 if clusters < 65525 else 32
        width = bits // 8
        check((clusters + 2) * width <= fat_sectors * 512, "native FAT capacity is short")
        stream.seek(reserved * 512)
        first = stream.read(fat_sectors * 512)
        second = stream.read(fat_sectors * 512)
        check(len(first) == fat_sectors * 512 and first == second, "native FAT copies differ")
        mask = (1 << (16 if bits == 16 else 28)) - 1
        free = sum(
            (int.from_bytes(first[cluster * width:(cluster + 1) * width], "little") & mask) == 0
            for cluster in range(2, clusters + 2)
        )
    return {"format": f"Fat{bits}", "data_clusters": clusters, "free_clusters": free}


class Run:
    def __init__(self, binary: Path, root: Path) -> None:
        self.binary = binary
        self.root = root
        self.sequence = 0

    def command(self, *args: str | Path, timeout: int = 120,
                expected_returncode: int = 0) -> bytes:
        self.sequence += 1
        command = [str(arg) for arg in args]
        result = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
        prefix = self.root / f"command-{self.sequence:03d}"
        prefix.with_suffix(".json").write_text(
            json.dumps({"argv": command, "returncode": result.returncode,
                        "expected_returncode": expected_returncode}, indent=2) + "\n"
        )
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        check(result.returncode == expected_returncode,
              f"unexpected command status: {command!r}; see {prefix}.stderr")
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


    def formatted(self, bits: int, mounted: bool) -> dict[str, object]:
        image = self.root / f"formatted-fat{bits}.img"
        label = f"FFS{bits}"
        arguments = [
            self.binary, "format", image, "--kind", f"fat{bits}", "--size-mib", "64",
            "--label", label, "--serial", "0x1234ABCD",
        ]
        created = json.loads(self.command(*arguments))
        check(created["operation"] == "create_new_image" and created["created_new_image"] is True,
              "formatter did not identify its fresh-image operation")
        check(created["format"] == f"Fat{bits}", "formatter created the wrong native dialect")
        check(created["volume_bytes"] == 64 * 1024 * 1024, "formatted image length differs")
        check(created["label"] == label and created["serial"] == 0x1234ABCD,
              "formatter label/serial differs")
        check(created["durability"] == "file_and_parent_synced", "format did not finish its syncs")
        native = native_allocation(image)
        check(native["data_clusters"] == (65264 if bits == 16 else 129022),
              "fresh geometry differs from independent 64 MiB layout")
        check(native["free_clusters"] == (65264 if bits == 16 else 129021),
              "fresh native free count differs")
        verification = created["verification"]
        check(created["data_clusters"] == native["data_clusters"] and
              verification["free_clusters"] == native["free_clusters"],
              "format report differs from bytes")
        check(verification["clean"] is True and verification["complete"] is True and
              verification["namespace_complete"] is True and verification["lost_clusters"] == 0 and
              verification["files"] == 0 and verification["directories"] == 1 and
              verification["issues"] == [] and verification["omitted_issues"] == 0,
              "formatter did not finish complete empty-image verification")
        if bits == 32:
            # The three-sector boot record must have a complete native copy.
            # Check this before mtools legitimately changes the live FSInfo hint.
            with image.open("rb") as stream:
                for relative in range(3):
                    stream.seek(relative * 512)
                    primary = stream.read(512)
                    stream.seek((6 + relative) * 512)
                    backup = stream.read(512)
                    check(primary == backup and primary[510:512] == b"\x55\xaa",
                          f"native FAT32 boot sector {relative} or its backup differs")
        self.command("fsck.fat", "-n", image)
        check(json.loads(self.command(self.binary, "ls", image, "/")) == [],
              "fresh root unexpectedly contains a file")
        checked = json.loads(self.command(self.binary, "check", image))
        check(checked["clean"] is True and checked["complete"] is True and
              checked["namespace_complete"] is True and checked["status"] == "clean",
              "fresh formatted allocation was not completely clean")
        check(checked["files"] == 0 and checked["directories"] == 1 and
              checked["lost_clusters"] == 0 and checked["issues"] == [] and
              checked["omitted_issues"] == 0, "fresh format contains allocation or namespace findings")
        check(checked["free_clusters"] == native["free_clusters"], "fresh checker free count differs")

        empty_hash = digest(image)
        self.command(*arguments, expected_returncode=1)
        check(digest(image) == empty_hash, "refused format changed an existing image")
        refused = self.root / f"forbidden-range-fat{bits}.img"
        self.command(self.binary, "format", refused, "--kind", f"fat{bits}",
                     "--size-mib", "64", "--offset", "512", expected_returncode=2)
        check(not refused.exists(), "rejected partition range left a destination")

        # Native tools now allocate directories, LFNs, payload chains and an
        # empty file in our formatter's image. They remain independent oracles.
        self.command("mmd", "-i", image, "::/nested")
        payloads = {
            "From native tools.txt": bytes(range(256)) * 4097 + b"native tail",
            "nested/PAYLOAD.BIN": bytes(reversed(range(256))) * 513,
            "empty.txt": b"",
        }
        for index, (name, expected) in enumerate(payloads.items()):
            source = self.root / f"formatted-fat{bits}-source-{index}.bin"
            reference = self.root / f"formatted-fat{bits}-reference-{index}.bin"
            source.write_bytes(expected)
            self.command("mcopy", "-i", image, source, f"::/{name}")
            self.command("mcopy", "-i", image, f"::/{name}", reference)
            check(reference.read_bytes() == expected, "mtools cannot round-trip formatter-created image")
        self.command("fsck.fat", "-n", image)
        native = native_allocation(image)
        before = digest(image)
        checked = json.loads(self.command(self.binary, "check", image))
        check(checked["format"] == f"Fat{bits}" and checked["read_only"] is True,
              "native-written formatter image has the wrong checker profile")
        check(checked["clean"] is True and checked["complete"] is True and
              checked["namespace_complete"] is True and checked["status"] == "clean",
              "native-written formatter allocation was not completely clean")
        check(checked["files"] == len(payloads) and checked["directories"] == 2 and
              checked["lost_clusters"] == 0, "native-written formatter reachability differs")
        check(checked["free_clusters"] == native["free_clusters"] and
              checked["issues"] == [] and checked["omitted_issues"] == 0,
              "native-written formatter allocation findings differ from raw FAT evidence")
        for name, expected in payloads.items():
            actual = self.command(self.binary, "cat", image, f"/{name}")
            check(actual == expected, f"formatter/native-write CLI bytes differ: FAT{bits} {name}")
        if mounted:
            self.mounted(image, payloads)
        check(digest(image) == before, "readback changed formatter/native-written image")
        self.command("fsck.fat", "-n", image)
        check(digest(image) == before, "native read-only check changed formatter image")
        return {"format": f"FAT{bits}", "creator": "ffs-fat format",
                "fresh_image_sha256": empty_hash, "native_written_sha256": before,
                "files_checked": len(payloads), "mounted": mounted, "result": "passed"}


    def populated(self, bits: int, mounted: bool) -> dict[str, object]:
        source = self.root / f"populated-fat{bits}-source"
        source.mkdir()
        directories = ["nested", "nested/deep", "nested/Empty directory", "many"]
        for name in directories:
            (source / name).mkdir()
        payloads = {
            "LONGNA~1.TXT": b"reserve the native alias before generating long names",
            "Long native filename.txt": (bytes(range(251)) * 9000)[:2 * 1024 * 1024 + 37],
            "Long native filename two.txt": bytes(range(256)) * 5 + b"unaligned tail",
            "empty.txt": b"",
            "nested/Native café.bin": bytes(reversed(range(256))) * 33 + b"tail",
            "nested/deep/last segment.txt": b"deep native payload\n",
        }
        # Enough long-name slots to force a multi-cluster directory in both
        # dialects. None of these expected names or bytes come from the image.
        for number in range(40):
            payloads[f"many/Directory expansion payload {number:02d}.bin"] = (
                number.to_bytes(2, "little") * (number + 1)
            )
        for name, expected in payloads.items():
            (source / name).write_bytes(expected)
        image = self.root / f"populated-fat{bits}.img"
        arguments = [self.binary, "format", image, "--kind", f"fat{bits}",
                     "--size-mib", "64", "--source-dir", source]
        created = json.loads(self.command(*arguments))
        check(created["created_new_image"] is True and created["format"] == f"Fat{bits}",
              "populated formatter did not create the requested dialect")
        check(created["source_directory"] == str(source.resolve()) and
              created["copied_files"] == len(payloads) and
              created["copied_directories"] == len(directories) + 1 and
              created["copied_bytes"] == sum(map(len, payloads.values())),
              "populated formatter report differs from the independent source tree")
        check(created["payload_verification"] == "sha256_via_native_reader" and
              created["durability"] == "file_and_parent_synced",
              "populated formatter omitted payload verification or durability")
        native = native_allocation(image)
        verification = created["verification"]
        check(verification["files"] == len(payloads) and
              verification["directories"] == len(directories) + 1 and
              verification["free_clusters"] == native["free_clusters"] and
              verification["clean"] is True and verification["complete"] is True and
              verification["namespace_complete"] is True and
              verification["lost_clusters"] == 0 and verification["issues"] == [] and
              verification["omitted_issues"] == 0,
              "populated formatter verification differs from source/native allocation")
        if bits == 32:
            with image.open("rb") as stream:
                for relative in range(3):
                    stream.seek(relative * 512)
                    primary = stream.read(512)
                    stream.seek((6 + relative) * 512)
                    backup = stream.read(512)
                    check(primary == backup and primary[510:512] == b"\x55\xaa",
                          "populated FAT32 boot record/backup differs")
                    if relative == 1:
                        check(int.from_bytes(primary[488:492], "little") == native["free_clusters"],
                              "populated FSInfo free count differs from native FAT bytes")
        before = digest(image)
        self.command("fsck.fat", "-n", image)
        for parent in [""] + directories:
            expected_names = {
                Path(name).name for name in list(payloads) + directories
                if str(Path(name).parent) == (parent or ".")
            }
            listed = json.loads(self.command(self.binary, "ls", image, "/" + parent))
            check({entry["name"] for entry in listed} == expected_names,
                  f"populated directory names differ: {parent!r}")
            aliases = [entry["short_alias"].upper() for entry in listed]
            check(len(aliases) == len(set(aliases)), "populated short aliases collide")
        for index, (name, expected) in enumerate(payloads.items()):
            reference = self.root / f"populated-fat{bits}-native-{index}.bin"
            self.command("mcopy", "-i", image, f"::/{name}", reference)
            check(reference.read_bytes() == expected, f"native populated-image bytes differ: {name}")
            check(self.command(self.binary, "cat", image, "/" + name) == expected,
                  f"FrankenFS populated-image bytes differ: {name}")
            check((source / name).read_bytes() == expected, f"formatter changed source bytes: {name}")
        checked = json.loads(self.command(self.binary, "check", image))
        check(checked["status"] == "clean" and checked["clean"] is True and
              checked["complete"] is True and checked["namespace_complete"] is True and
              checked["files"] == len(payloads) and checked["directories"] == len(directories) + 1 and
              checked["free_clusters"] == native["free_clusters"] and
              checked["lost_clusters"] == 0 and checked["issues"] == [] and checked["omitted_issues"] == 0,
              "populated native allocation/namespace check differs")
        if mounted:
            self.mounted(image, payloads)
        self.command(*arguments, expected_returncode=1)
        check(digest(image) == before, "readback or refused reformat changed populated image")

        # Verify that another FAT implementation can extend our allocation and
        # namespace after population, then verify its bytes through our reader.
        self.command("mmd", "-i", image, "::/Native added directory")
        added = self.root / f"populated-fat{bits}-native-addition.bin"
        added.write_bytes(bytes(range(256)) * 257 + b"native allocation after population")
        self.command("mcopy", "-i", image, added, "::/Native added directory/Added payload.bin")
        self.command("fsck.fat", "-n", image)
        after_native = digest(image)
        check(self.command(self.binary, "cat", image, "/Native added directory/Added payload.bin")
              == added.read_bytes(), "native append to populated image could not be read")
        for name, expected in payloads.items():
            check(self.command(self.binary, "cat", image, "/" + name) == expected,
                  f"native extension damaged an existing populated file: {name}")
        checked = json.loads(self.command(self.binary, "check", image))
        check(checked["status"] == "clean" and checked["clean"] is True and
              checked["complete"] is True and checked["namespace_complete"] is True and
              checked["files"] == len(payloads) + 1 and checked["directories"] == len(directories) + 2 and
              checked["free_clusters"] == native_allocation(image)["free_clusters"] and
              checked["lost_clusters"] == 0 and checked["issues"] == [] and checked["omitted_issues"] == 0,
              "native extension of populated image failed allocation verification")
        check(digest(image) == after_native, "native-extension readback changed the image")

        for case in ("symlink", "case-collision", "invalid-name"):
            bad_source = self.root / f"refused-{case}-fat{bits}-source"
            bad_source.mkdir()
            if case == "symlink":
                (bad_source / "link.txt").symlink_to(source / "empty.txt")
            elif case == "case-collision":
                (bad_source / "case.txt").write_bytes(b"first")
                (bad_source / "CASE.TXT").write_bytes(b"second")
            else:
                (bad_source / "invalid?.txt").write_bytes(b"invalid native name")
            refused = self.root / f"refused-{case}-fat{bits}.img"
            self.command(self.binary, "format", refused, "--kind", f"fat{bits}",
                         "--size-mib", "64", "--source-dir", bad_source, expected_returncode=1)
            check(not refused.exists(), f"{case} preflight created a destination")
        return {"format": f"FAT{bits}", "creator": "ffs-fat format --source-dir",
                "populated_image_sha256": before, "native_extended_sha256": after_native,
                "files_checked": len(payloads) + 1, "directories_checked": len(directories) + 2,
                "mounted": mounted, "result": "passed"}


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
        native = native_allocation(image)
        check(native["format"] == f"Fat{bits}" and
              native["free_clusters"] == info["free_clusters"],
              "candidate free count differs from independent native FAT scan")
        allocation = json.loads(self.command(self.binary, "check", image))
        check(allocation["format"] == f"Fat{bits}", "checker selected the wrong FAT dialect")
        check(allocation["read_only"] is True, "checker did not declare read-only mode")
        check(allocation["status"] == "clean", "native-created FAT allocation was not clean")
        checked = allocation
        check(checked["complete"] is True, "candidate allocation scan was incomplete")
        check(checked["lost_clusters"] == 0, "candidate reported lost native allocation")
        check(checked["files"] == len(payloads), "candidate did not examine every native file")
        check(checked["directories"] == 2, "candidate did not examine root and nested directory")
        check(checked["free_clusters"] == info["free_clusters"], "allocation/free scans disagree")
        check(checked["issues"] == [] and checked["omitted_issues"] == 0,
              "clean status concealed allocation findings")
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
    # mtools interprets argv using the native locale. Under C it writes the
    # UTF-8 bytes of cafe-with-accent as two different Unicode characters.
    # Select an available UTF-8 locale for this fixture process and its children;
    # retain every Unicode-name assertion rather than changing expected names.
    for native_locale in ("C.UTF-8", "en_US.UTF-8", "UTF-8"):
        try:
            locale.setlocale(locale.LC_ALL, native_locale)
        except locale.Error:
            continue
        break
    else:
        raise RuntimeError("native Unicode fixtures require an installed UTF-8 locale")
    check(locale.nl_langinfo(locale.CODESET).replace("-", "").lower() == "utf8",
          "selected native tool locale is not UTF-8")
    check(os.fsencode("café") == b"caf\xc3\xa9",
          "Python argv encoding is not UTF-8; start the fixture with a UTF-8 locale")
    os.environ["LC_ALL"] = native_locale
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
    report = {"candidate_sha256": digest(binary), "native_tool_locale": native_locale,
              "tool_paths": {tool: shutil.which(tool) for tool in tools},
              "scenarios": []}
    try:
        for bits in (16, 32):
            scenario = run.dialect(bits, args.mounted)
            report["scenarios"].append(scenario)
            print(json.dumps(scenario), flush=True)
            formatted = run.formatted(bits, args.mounted)
            report["scenarios"].append(formatted)
            print(json.dumps(formatted), flush=True)
            populated = run.populated(bits, args.mounted)
            report["scenarios"].append(populated)
            print(json.dumps(populated), flush=True)
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
