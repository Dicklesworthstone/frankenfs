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
import hmac
import json
import locale
import os
import shutil
import signal
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def masked_digest(path: Path, ranges: dict[int, int]) -> str:
    """Hash all bytes, normalizing only independently checked native hint words."""
    result = hashlib.sha256()
    at = 0
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            data = bytearray(data)
            for start, length in ranges.items():
                left, right = max(at, start), min(at + len(data), start + length)
                if left < right:
                    data[left - at:right - at] = bytes(right - left)
            result.update(data)
            at += len(data)
    return result.hexdigest()


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def complete_report(report: dict[str, object], required_scenarios: int) -> None:
    scenarios = report["scenarios"]
    check(required_scenarios > 0 and isinstance(scenarios, list)
          and len(scenarios) == required_scenarios,
          "native qualification selected no scenarios or did not finish its required set")
    check(all(isinstance(scenario, dict) and scenario.get("result") == "passed"
              for scenario in scenarios), "native qualification has an incomplete or failed scenario")
    report["status"] = "passed"



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
        next_free = next((cluster for cluster in range(2, clusters + 2)
                          if (int.from_bytes(first[cluster * width:(cluster + 1) * width], "little")
                              & mask) == 0), 0xFFFFFFFF)
    return {"format": f"Fat{bits}", "data_clusters": clusters, "free_clusters": free,
            "next_free_cluster": next_free}


def native_root_file(image: Path, short_name: bytes) -> dict[str, object]:
    """Byte-level footprint of a file in the initial root sector/cluster.

    Used only for this runner's own dosfstools images. Pin the complete native
    entry and allocated data (including slack), independently of ffs-fat output.
    """
    with image.open("rb") as stream:
        boot = stream.read(512)
        u16 = lambda at: int.from_bytes(boot[at:at + 2], "little")
        u32 = lambda at: int.from_bytes(boot[at:at + 4], "little")
        sector, spc, reserved = u16(11), boot[13], u16(14)
        fat_sectors = u16(22) or u32(36)
        root_sectors = (u16(17) * 32 + sector - 1) // sector
        first_data = reserved + boot[16] * fat_sectors + root_sectors
        width = 2 if u16(17) else 4
        root_sector = reserved + boot[16] * fat_sectors if width == 2 else \
            first_data + (u32(44) - 2) * spc
        stream.seek(root_sector * sector)
        root = stream.read(root_sectors * sector if width == 2 else spc * sector)
        entries = [root[at:at + 32] for at in range(0, len(root), 32)
                   if root[at:at + 11] == short_name and root[at + 11] != 0x0F]
        check(len(entries) == 1, f"native root file is missing or ambiguous: {short_name!r}")
        entry = entries[0]
        cluster = int.from_bytes(entry[26:28], "little")
        if width == 4:
            cluster |= int.from_bytes(entry[20:22], "little") << 16
        chain: list[int] = []
        seen: set[int] = set()
        result = hashlib.sha256()
        while cluster >= 2 and cluster < (0xFFF8 if width == 2 else 0x0FFFFFF8):
            check(cluster not in seen and len(chain) < 1_048_576, "native footprint chain cycle/budget")
            seen.add(cluster)
            chain.append(cluster)
            stream.seek((first_data + (cluster - 2) * spc) * sector)
            data = stream.read(spc * sector)
            check(len(data) == spc * sector, "native footprint exceeds image")
            result.update(data)
            stream.seek(reserved * sector + cluster * width)
            cluster = int.from_bytes(stream.read(width), "little") & (0xFFFF if width == 2 else 0x0FFFFFFF)
        return {"entry_hex": entry.hex(), "clusters": chain, "allocated_sha256": result.hexdigest()}


def native_inventory(image: Path) -> dict[str, object]:
    """Independent native records/chains for this runner's retained mkfs images."""
    with image.open("rb") as stream:
        header = stream.read(512)
        sector = int.from_bytes(header[11:13], "little")
        spc = header[13]
        reserved = int.from_bytes(header[14:16], "little")
        roots = int.from_bytes(header[17:19], "little")
        bits = 16 if roots else 32
        width, mask = bits // 8, 0xFFFF if bits == 16 else 0x0FFFFFFF
        fat_sectors = int.from_bytes(header[22:24] if bits == 16 else header[36:40], "little")
        total = int.from_bytes(header[19:21], "little") or int.from_bytes(header[32:36], "little")
        root_sectors = (roots * 32 + sector - 1) // sector
        first_data = reserved + header[16] * fat_sectors + root_sectors
        count = (total - first_data) // spc
        check(sector in (512, 4096) and spc > 0 and header[16] == 2
              and 4085 <= count <= 8_388_608 and total * sector == image.stat().st_size,
              "native inventory geometry differs from its producer contract")
        stream.seek(0)
        boot = bytearray(stream.read(sector))
        for start, end in ((19, 21), (28, 36), (17, 19) if bits == 16 else (44, 48),
                           (22, 24) if bits == 16 else (36, 40)):
            boot[start:end] = bytes(end - start)
        stream.seek(reserved * sector)
        fats = [stream.read(fat_sectors * sector) for _ in range(2)]
        check(all(len(fat) == fat_sectors * sector for fat in fats), "native FAT is truncated")
        flags = int.from_bytes(header[40:42], "little") if bits == 32 else 0
        active = flags & 15 if flags & 128 else 0
        check(active < 2, "invalid active native FAT")

        def pointer(record: bytes) -> int:
            first = int.from_bytes(record[26:28], "little")
            if bits == 32:
                first |= (int.from_bytes(record[20:22], "little") & 0x0FFF) << 16
            return first

        def chain(first: int) -> list[int]:
            result, seen = [], set()
            while first:
                check(2 <= first < count + 2 and first not in seen, "native chain is invalid or cyclic")
                seen.add(first)
                result.append(first)
                value = int.from_bytes(fats[active][first * width:(first + 1) * width], "little") & mask
                if value >= (0xFFF8 if bits == 16 else 0x0FFFFFF8):
                    break
                check(value >= 2 and value < count + 2, "native live chain has no valid successor")
                first = value
            return result

        def contents(clusters: list[int]) -> bytes:
            chunks = []
            for cluster in clusters:
                stream.seek((first_data + (cluster - 2) * spc) * sector)
                data = stream.read(spc * sector)
                check(len(data) == spc * sector, "native allocation exceeds the image")
                chunks.append(data)
            return b"".join(chunks)

        root_chain = chain(int.from_bytes(header[44:48], "little")) if bits == 32 else []
        if bits == 16:
            stream.seek((reserved + 2 * fat_sectors) * sector)
            root_data = stream.read(root_sectors * sector)
        else:
            root_data = contents(root_chain)
        entries = {"/": {"chain": root_chain, "record": "", "lfn": [], "directory": True}}
        pending = [("/", root_data, 0, 0)]
        while pending:
            parent, data, first, expected_parent = pending.pop()
            normalized = bytearray(data)
            long_names = []
            for at in range(0, len(data), 32):
                record = data[at:at + 32]
                check(len(record) == 32, "partial native directory record")
                if record[0] == 0:
                    break
                if record[0] == 0xE5:
                    long_names = []
                    continue
                if record[11] == 0x0F:
                    long_names.append(record.hex())
                    continue
                start = pointer(record)
                normalized[at + 26:at + 28] = bytes(2)
                if bits == 32:
                    high = int.from_bytes(record[20:22], "little") & 0xF000
                    normalized[at + 20:at + 22] = high.to_bytes(2, "little")
                if record[:11] in (b".          ", b"..         "):
                    check(parent != "/" and start == (first if record[1] == 32 else expected_parent),
                          "native dot/parent binding differs")
                    continue
                path = parent.rstrip("/") + "/" + record[:11].hex()
                check(path not in entries and len(entries) < 1024, "duplicate/budgeted native namespace")
                clusters = chain(start)
                body = contents(clusters)
                directory = bool(record[11] & 0x10)
                entries[path] = {"record": bytes(normalized[at:at + 32]).hex(),
                                 "lfn": long_names, "directory": directory, "chain": clusters,
                                 "allocated_digest": hashlib.sha256(body).hexdigest()}
                long_names = []
                if directory:
                    pending.append((path, body, start, first))
            entries[parent]["normalized_directory"] = normalized.hex()
        return {"bits": bits, "sector": sector, "cluster_bytes": spc * sector,
                "root_entries": roots, "clusters": count, "active": active,
                "flags": flags, "boot": bytes(boot).hex(), "fats": fats, "entries": entries}


def native_preserved(before: dict[str, object], after: dict[str, object], *, relocating: bool) -> dict[int, int]:
    for field in ("bits", "sector", "cluster_bytes", "active", "flags", "boot"):
        check(before[field] == after[field], f"resize changed native {field}")
    old, new = before["entries"], after["entries"]
    check(old.keys() == new.keys(), "resize changed the raw native namespace")
    moves = {}
    for path, record in old.items():
        other = new[path]
        check(record["record"] == other["record"] and record["lfn"] == other["lfn"]
              and record["directory"] == other["directory"], "resize changed native entry metadata")
        check(len(record["chain"]) == len(other["chain"]), "resize changed native chain length")
        for previous, current in zip(record["chain"], other["chain"], strict=True):
            check(previous not in moves or moves[previous] == current, "inconsistent relocation mapping")
            moves[previous] = current
            if not relocating or previous < after["clusters"] + 2:
                check(previous == current, "resize moved a retained native cluster")
        if record["directory"]:
            left, right = record["normalized_directory"], other["normalized_directory"]
            check(right.startswith(left) and not any(bytes.fromhex(right[len(left):])),
                  "resize changed allocated directory bytes outside pointer translations/zero root growth")
        else:
            check(hmac.compare_digest(record["allocated_digest"], other["allocated_digest"]),
                  "resize changed native allocated payload or slack")
    check(len(set(moves.values())) == len(moves), "relocation assigned one cluster to distinct source objects")
    inverse = {new: old for old, new in moves.items()}
    width, mask = before["bits"] // 8, 0xFFFF if before["bits"] == 16 else 0x0FFFFFFF
    for copy in range(2):
        original, output = before["fats"][copy], after["fats"][copy]
        for cluster in range(after["clusters"] + 2):
            previous = int.from_bytes(original[cluster * width:(cluster + 1) * width], "little") \
                if cluster < before["clusters"] + 2 else 0
            current = int.from_bytes(output[cluster * width:(cluster + 1) * width], "little")
            if cluster < 2:
                check(previous == current, "resize changed native reserved allocation words")
                continue
            if not relocating or (before["flags"] & 128 and copy != before["active"]):
                check(previous == current, "resize changed preserved FAT words")
                continue
            origin = inverse.get(cluster, cluster)
            value = int.from_bytes(original[origin * width:(origin + 1) * width], "little") & mask
            value = moves.get(value, value)
            if cluster in moves and moves[cluster] != cluster and origin == cluster:
                value = 0
            check(current & mask == value and current & ~mask == previous & ~mask,
                  "resize changed FAT topology or destination high bits")
    return {old: new for old, new in moves.items() if old != new}


class Run:
    def __init__(self, binary: Path, root: Path, facade: Path | None = None) -> None:
        self.binary = binary
        self.root = root
        self.facade = facade
        self.sequence = 0

    def command(self, *args: str | Path, timeout: int = 120,
                expected_returncode: int = 0) -> bytes:
        self.sequence += 1
        command = [str(arg) for arg in args]
        prefix = self.root / f"command-{self.sequence:03d}"
        record = {"argv": command, "returncode": None,
                  "expected_returncode": expected_returncode,
                  "timeout_seconds": timeout, "status": "running"}
        with prefix.with_suffix(".json").open("x") as metadata:
            metadata.write(json.dumps(record, indent=2) + "\n")
        try:
            # Direct file capture retains partial bytes even when run() raises.
            # Exclusive creation also prevents a reused root from erasing logs.
            with prefix.with_suffix(".stdout").open("xb") as stdout, \
                    prefix.with_suffix(".stderr").open("xb") as stderr:
                result = subprocess.run(command, stdout=stdout, stderr=stderr,
                                        timeout=timeout, check=False)
            record.update(status="completed", returncode=result.returncode)
        except BaseException as error:
            status = "timeout" if isinstance(error, subprocess.TimeoutExpired) else "failed"
            record.update(status=status, error=f"{type(error).__name__}: {error}")
            raise
        finally:
            prefix.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n")
        check(result.returncode == expected_returncode,
              f"unexpected command status: {command!r}; see {prefix}.stderr")
        return prefix.with_suffix(".stdout").read_bytes()

    @contextmanager
    def mount_image(self, image: Path, *, writable: bool = False,
                    image_options: tuple[str, ...] = ()):
        mountpoint = self.root / f"{image.stem}-mount"
        mountpoint.mkdir(exist_ok=True)
        check(not os.path.ismount(mountpoint) and not any(mountpoint.iterdir()),
              "candidate mountpoint is not empty and unmounted")
        self.sequence += 1
        log = (self.root / f"{image.stem}-mount-{self.sequence:03d}.stderr").open("xb")
        command = [str(self.binary), "mount", str(image), str(mountpoint), "--offline-image",
                   "--uid", str(os.getuid()), "--gid", str(os.getgid()), *image_options]
        if writable:
            command.append("--rw")
        metadata = self.root / f"{image.stem}-mount-{self.sequence:03d}.json"
        record = {"argv": command, "status": "starting", "returncode": None}
        with metadata.open("x") as stream:
            stream.write(json.dumps(record, indent=2) + "\n")
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=log,
        )
        try:
            deadline = time.monotonic() + 30
            while not os.path.ismount(mountpoint):
                check(process.poll() is None, f"FAT mount exited; see {log.name}")
                check(time.monotonic() < deadline, f"FAT mount timed out; see {log.name}")
                time.sleep(0.05)
            record["status"] = "mounted"
            yield mountpoint
            self.command("fusermount3", "-u", mountpoint)
            check(process.wait(timeout=30) == 0, f"FAT mount did not exit cleanly; see {log.name}")
            record["status"] = "passed"
        except BaseException as error:
            record.update(status="failed", error=f"{type(error).__name__}: {error}")
            raise
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
                    record["returncode"] = process.poll()
                    metadata.write_text(json.dumps(record, indent=2) + "\n")

    def mounted(self, image: Path, payloads: dict[str, bytes]) -> None:
        with self.mount_image(image) as mountpoint:
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

    def maintenance(self, bits: int, sector: int, bounded: bool) -> dict[str, object]:
        """Native allocation forces real relocation; every source stays frozen."""
        tag = f"maintenance-fat{bits}-s{sector}"
        size = 512 if bits == 32 and sector == 4096 else 64
        if bits == 16 and sector == 512:
            size = 16
        smaller = size * 3 // 4
        larger = size * 3 // 2 if bits == 16 else size * 5 // 4
        native = self.root / f"{tag}.img"
        with native.open("xb") as stream:
            stream.truncate(size * 1024 * 1024)
        roots = ("-r", "32") if bits == 16 else ()
        self.command("mkfs.fat", "-F", str(bits), "-S", str(sector), "-s", "1", *roots, native)
        source = self.root / f"{tag}-sentinel.bin"
        sentinel = bytes(range(251)) * 41 + b"native maintenance sentinel"
        source.write_bytes(sentinel)
        self.command("mcopy", "-i", native, source, "::/KEEP.BIN")
        padding = self.root / f"{tag}-padding.bin"
        with padding.open("xb") as stream:
            stream.truncate(smaller * 1024 * 1024)
        self.command("mcopy", "-i", native, padding, "::/PAD.BIN")
        self.command("mmd", "-i", native, "::/Native directory café")
        self.command("mmd", "-i", native, "::/Native directory café/Nested child")
        payloads = {"KEEP.BIN": sentinel}
        for index, name in enumerate(("Native directory café/Payload café.txt",
                                      "Native directory café/Nested child/Child.bin")):
            data = bytes(range(256)) * (19 + index) + bytes([index])
            source = self.root / f"{tag}-payload-{index}.bin"
            source.write_bytes(data)
            self.command("mcopy", "-i", native, source, f"::/{name}")
            payloads[name] = data
        if bits == 32:
            # Root fragments are forced beyond the future shrink boundary.
            empty = self.root / f"{tag}-empty.bin"
            empty.write_bytes(b"")
            for index in range(40):
                name = f"Root growth native café {index:03d}.txt"
                self.command("mcopy", "-i", native, empty, f"::/{name}")
                payloads[name] = b""
        self.command("mdel", "-i", native, "::/PAD.BIN")
        self.command("fsck.fat", "-n", native)
        before = native_inventory(native)
        (self.root / f"{tag}-native-before.json").write_text(json.dumps(
            {key: value for key, value in before.items() if key != "fats"}, indent=2) + "\n")
        image, selection = native, ()
        if bounded:
            image = self.root / f"{tag}-bounded.img"
            with image.open("xb") as stream, native.open("rb") as plain:
                stream.write(b"P" * 4096)
                shutil.copyfileobj(plain, stream, 1024 * 1024)
                stream.write(b"S" * 4096)
            selection = ("--offset", "4096", "--length", str(native.stat().st_size))
        frozen, native_frozen = digest(image), digest(native)
        outputs = []
        operations = [("grow", larger, ()), ("relocate", smaller, ("--relocate",))]
        if bits == 16:
            operations.append(("root-expand", larger, ("--root-entries", str(before["root_entries"] * 2))))
        for operation, target, extra in operations:
            output = self.root / f"{tag}-{operation}.img"
            command = (self.binary, "resize", image, *selection, "--output", output,
                       "--size-mib", str(target), "--offline-image", *extra)
            if operation == "relocate":
                refusal = self.root / f"{tag}-tail-refused.img"
                self.command(self.binary, "resize", image, *selection, "--output", refusal,
                             "--size-mib", str(target), "--offline-image", expected_returncode=1)
                check(not refusal.exists(), "allocated-tail refusal created an output")
            preview = json.loads(self.command(*command, "--dry-run"))
            check(preview["dry_run"] is True and not output.exists()
                  and hmac.compare_digest(digest(image), frozen), "resize dry run changed an input")
            report = json.loads(self.command(*command))
            check(report["source_modified"] is False and report["output_volume_bytes"] == target * 1024 * 1024
                  and hmac.compare_digest(report["sha256"], digest(output)), "resize publication report differs")
            after = native_inventory(output)
            moves = native_preserved(before, after, relocating=operation == "relocate")
            check(report["relocated_clusters"] == len(moves), "reported relocation count differs from native chains")
            (self.root / f"{tag}-{operation}-native-after.json").write_text(json.dumps(
                {key: value for key, value in after.items() if key != "fats"}
                | {"relocation_mapping": moves}, indent=2) + "\n")
            if operation == "relocate":
                check(report["relocated_clusters"] > 0 and not report["cluster_numbers_preserved"],
                      "relocation did not move the independently forced live tail")
                if bits == 32:
                    check(len(before["entries"]["/"]["chain"]) > 1,
                          "native FAT32 root did not grow across clusters")
            self.command("fsck.fat", "-n", output)
            for name, data in payloads.items():
                check(self.command("mcopy", "-i", output, f"::/{name}", "-") == data,
                      f"native resize payload differs: {operation}/{name}")
                check(self.command(self.binary, "cat", output, f"/{name}") == data,
                      f"fresh engine resize payload differs: {operation}/{name}")
            self.mounted(output, payloads)
            interchange = self.root / f"{tag}-{operation}-interchange.bin"
            interchange.write_bytes(b"native -> FrankenFS -> native after resize")
            self.command("mcopy", "-i", output, interchange, "::/NATIVE.BIN")
            check(self.command(self.binary, "cat", output, "/NATIVE.BIN") == interchange.read_bytes(),
                  "FrankenFS cannot consume native writes after resize")
            self.command(self.binary, "replace", output, "/FRANKEN.BIN", "--create",
                         "--source", interchange, "--offline-image")
            check(self.command("mcopy", "-i", output, "::/FRANKEN.BIN", "-") == interchange.read_bytes(),
                  "native reader cannot consume FrankenFS writes after resize")
            self.command("fsck.fat", "-n", output)
            check(hmac.compare_digest(digest(image), frozen)
                  and hmac.compare_digest(digest(native), native_frozen), "resize changed its frozen source")
            outputs.append({"operation": operation, "relocated_clusters": report["relocated_clusters"],
                            "output_sha256": digest(output), "result": "passed"})
        # A second native fixture has no tail allocation, so no relocation is allowed.
        free = self.root / f"{tag}-free-tail.img"
        with free.open("xb") as stream:
            stream.truncate(size * 1024 * 1024)
        self.command("mkfs.fat", "-F", str(bits), "-S", str(sector), "-s", "1", *roots, free)
        self.command("mcopy", "-i", free, interchange, "::/KEEP.BIN")
        free_before, free_hash = native_inventory(free), digest(free)
        shrunk = self.root / f"{tag}-free-tail-shrunk.img"
        report = json.loads(self.command(self.binary, "resize", free, "--output", shrunk,
                                         "--size-mib", str(smaller), "--offline-image"))
        check(report["relocated_clusters"] == 0 and report["cluster_numbers_preserved"],
              "free-tail shrink unexpectedly relocated allocation")
        native_preserved(free_before, native_inventory(shrunk), relocating=False)
        self.command("fsck.fat", "-n", shrunk)
        check(self.command("mcopy", "-i", shrunk, "::/KEEP.BIN", "-") == interchange.read_bytes(),
              "free-tail shrink lost native data")
        self.mounted(shrunk, {"KEEP.BIN": interchange.read_bytes()})
        check(hmac.compare_digest(digest(free), free_hash), "free-tail shrink changed its source")
        recovery = self.maintenance_recovery(native, before, payloads, sector, bits)
        interruptions = []
        if bits == 32 and sector == 4096:
            interruptions = self.resize_interruptions(image, selection, larger, frozen)
        return {"scenario": "native_maintenance", "format": f"FAT{bits}", "sector_bytes": sector,
                "bounded": bounded, "source_sha256": frozen, "outputs": outputs,
                "free_tail_output_sha256": digest(shrunk), "recovery": recovery,
                "interruptions": interruptions, "result": "passed"}

    def resize_interruptions(self, image: Path, selection: tuple[str, ...], target: int,
                             frozen: str) -> list[dict[str, object]]:
        results = []
        for event in ("cancel", "source-race"):
            source = image
            if event == "source-race":
                source = self.root / "resize-raced-private-source.img"
                with source.open("xb") as output, image.open("rb") as original:
                    shutil.copyfileobj(original, output, 1024 * 1024)
            output = self.root / f"resize-{event}-partial.img"
            command = [str(arg) for arg in (self.binary, "resize", source, *selection,
                       "--output", output, "--size-mib", str(target), "--offline-image")]
            self.sequence += 1
            prefix = self.root / f"command-{self.sequence:03d}"
            record = {"argv": command, "returncode": None, "expected_returncode": 1,
                      "timeout_seconds": 120, "status": "running", "controlled_event": event}
            prefix.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n")
            process, stopped = None, False
            try:
                with prefix.with_suffix(".stdout").open("xb") as stdout, \
                        prefix.with_suffix(".stderr").open("xb") as stderr:
                    process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
                    deadline = time.monotonic() + 120
                    while not output.exists() or output.stat().st_blocks == 0:
                        check(process.poll() is None, "resize finished before the interruption window")
                        check(time.monotonic() < deadline, "resize did not reach output publication")
                        time.sleep(0.002)
                    # Stop only the exact child started above. No other agent,
                    # mount daemon, service or process group receives a signal.
                    process.send_signal(signal.SIGSTOP)
                    stopped = True
                    while True:
                        status = Path(f"/proc/{process.pid}/status").read_text()
                        if any(line.startswith("State:") and line.split()[1] == "T"
                               for line in status.splitlines()):
                            break
                        check(time.monotonic() < deadline, "owned resize child did not stop")
                        time.sleep(0.002)
                    with output.open("rb") as stream:
                        check(stream.read(4096) == bytes(4096), "interruption missed the withheld-primary window")
                    record["partial_allocated_bytes_before_event"] = output.stat().st_blocks * 512
                    if event == "cancel":
                        process.send_signal(signal.SIGINT)
                    else:
                        # An uncooperative writer bypasses advisory locking on
                        # this private copy only. Original image stays immutable.
                        base = int(selection[1]) if selection else 0
                        with source.open("r+b") as stream:
                            stream.seek(base + 3)
                            previous = stream.read(1)
                            stream.seek(base + 3)
                            stream.write(bytes([previous[0] ^ 1]))
                            stream.flush()
                            os.fsync(stream.fileno())
                    process.send_signal(signal.SIGCONT)
                    stopped = False
                    code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
                record.update(status="completed", returncode=code)
                check(code == 1, f"resize {event} was acknowledged instead of refused")
                error = prefix.with_suffix(".stderr").read_text()
                check(("cancel" in error.lower() if event == "cancel" else "source changed" in error)
                      and "retained" in error and "no rollback" in error,
                      f"resize {event} failed for an unrelated reason")
                with output.open("rb") as stream:
                    check(stream.read(4096) == bytes(4096), "failed resize published primary boot bytes")
                check(hmac.compare_digest(digest(image), frozen), "interrupted resize changed its original")
                self.command(self.binary, "check", output, expected_returncode=1)
                results.append({"event": event, "partial_output_sha256": digest(output), "result": "passed"})
            except BaseException as error:
                record.update(status="failed", error=f"{type(error).__name__}: {error}")
                raise
            finally:
                if process is not None and process.poll() is None:
                    if stopped:
                        process.send_signal(signal.SIGCONT)
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
                if process is not None:
                    record["returncode"] = process.returncode
                prefix.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n")
        # A real FAT-backed host output has insufficient capacity. This tests
        # actual ENOSPC without filling or deleting shared worker storage.
        backend = self.root / "resize-small-output-filesystem.img"
        with backend.open("xb") as stream:
            stream.truncate(4 * 1024 * 1024)
        self.command("mkfs.fat", "-F", "16", "-s", "1", backend)
        with self.mount_image(backend, writable=True) as mounted:
            output = mounted / "PARTIAL.IMG"
            self.command(self.binary, "resize", image, *selection, "--output", output,
                         "--size-mib", str(target), "--offline-image", expected_returncode=1)
            error = (self.root / f"command-{self.sequence:03d}.stderr").read_text()
            check("No space left on device" in error and "retained" in error,
                  "small-output resize failed for a reason other than ENOSPC")
            check(output.exists() and output.stat().st_size == 0, "ENOSPC output was deleted or published")
        self.command("fsck.fat", "-n", backend)
        check(hmac.compare_digest(digest(image), frozen), "ENOSPC resize changed its source")
        results.append({"event": "ENOSPC", "backing_image_sha256": digest(backend), "result": "passed"})
        return results

    def maintenance_recovery(self, native: Path, inventory: dict[str, object],
                             payloads: dict[str, bytes], sector: int, bits: int) -> list[dict[str, object]]:
        """Damage private native copies; each repair has explicit separate authority."""
        frozen = digest(native)
        with native.open("rb") as stream:
            boot = stream.read(sector)
        width, mask = bits // 8, 0xFFFF if bits == 16 else 0x0FFFFFFF
        reserved = int.from_bytes(boot[14:16], "little")
        fat_bytes = len(inventory["fats"][0])
        dirty_mask = 0x8000 if bits == 16 else 0x08000000
        kinds = ["mirror", "dirty", "parents"] + (["fsinfo", "boot"] if bits == 32 else [])
        results = []
        for damage in kinds:
            image = self.root / f"recovery-fat{bits}-s{sector}-{damage}.img"
            base = 4096 if sector == 4096 else 0
            selection = ("--offset", str(base), "--length", str(native.stat().st_size)) if base else ()
            with image.open("xb") as output, native.open("rb") as source:
                if base:
                    output.write(b"P" * base)
                shutil.copyfileobj(source, output, 1024 * 1024)
                if base:
                    output.write(b"S" * base)
            hint_ranges = {}
            if bits == 32:
                info = int.from_bytes(boot[48:50], "little")
                backup = int.from_bytes(boot[50:52], "little")
                hint_ranges[base + info * sector + 488] = 8
                if damage == "fsinfo":
                    hint_ranges[base + (backup + info) * sector + 488] = 8
            unaffected = masked_digest(image, hint_ranges)
            patches = {}
            if damage == "mirror":
                free = next(cluster for cluster in range(2, inventory["clusters"] + 2)
                            if int.from_bytes(inventory["fats"][0][cluster * width:(cluster + 1) * width],
                                              "little") & mask == 0)
                at = reserved * sector + fat_bytes + free * width
                previous = int.from_bytes(inventory["fats"][1][free * width:(free + 1) * width], "little")
                patches[at] = ((previous & ~mask) | mask).to_bytes(width, "little")
                command = (self.binary, "recover", image, *selection, "--offline-image", "--repair-mirrors-from", "0")
            elif damage == "dirty":
                for copy in range(2):
                    value = int.from_bytes(inventory["fats"][copy][width:2 * width], "little")
                    patches[reserved * sector + copy * fat_bytes + width] = (value & ~dirty_mask).to_bytes(width, "little")
                command = (self.binary, "recover", image, *selection, "--offline-image")
            elif damage == "parents":
                root_sectors = (inventory["root_entries"] * 32 + sector - 1) // sector
                data_start = (reserved * sector + 2 * fat_bytes + root_sectors * sector)
                directory = next(entry for path, entry in inventory["entries"].items()
                                 if path != "/" and entry["directory"])
                # Native root-parent convention is zero; an unrelated free
                # cluster is not a guessed replacement parent.
                at = data_start + (directory["chain"][0] - 2) * inventory["cluster_bytes"] + 32
                patches[at + 26] = (1).to_bytes(2, "little")
                if bits == 32:
                    patches[at + 20] = bytes(2)
                command = (self.binary, "repair-parents", image, *selection, "--offline-image")
            elif damage == "fsinfo":
                info = int.from_bytes(boot[48:50], "little")
                patches[info * sector] = b"BAD!"
                patches[info * sector + 488] = bytes(4)
                patches[info * sector + 492] = (2).to_bytes(4, "little")
                command = (self.binary, "repair-fsinfo", image, *selection, "--offline-image")
            else:
                backup = int.from_bytes(boot[50:52], "little")
                check(backup > 0, "native FAT32 fixture has no declared backup boot")
                patches[11] = bytes(2)
                patches[510] = bytes(2)
                command = (self.binary, "recover", image, *selection, "--offline-image",
                           "--repair-boot-from", str(backup * sector))
            with image.open("r+b") as stream:
                for at, value in patches.items():
                    stream.seek(base + at)
                    stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            damaged = digest(image)
            self.command(self.binary, "check", image, *selection, expected_returncode=1)
            check(hmac.compare_digest(digest(image), damaged), "read-only native diagnosis changed bytes")
            preview = json.loads(self.command(*command, "--dry-run"))
            check(preview["dry_run"] is True and hmac.compare_digest(digest(image), damaged),
                  "native recovery dry run changed bytes")
            report = json.loads(self.command(*command))
            repair_output = f"command-{self.sequence:03d}.stdout"
            if damage in ("parents", "fsinfo", "boot"):
                # These authorities deliberately retain dirty state; ordinary
                # recovery is an explicit subsequent operation, not an implicit
                # enlargement of the selected repair's write authority.
                self.command(self.binary, "check", image, *selection, expected_returncode=1)
                self.command(self.binary, "recover", image, *selection, "--offline-image")
            checked = json.loads(self.command(self.binary, "check", image, *selection))
            check(checked["clean"] is True and checked["complete"] is True
                  and checked["namespace_complete"] is True and checked["issues"] == [],
                  "explicit native recovery did not restore complete clean ownership")
            check(hmac.compare_digest(masked_digest(image, hint_ranges), unaffected),
                  "recovery changed bytes outside repaired fields and declared hint updates")
            if bits == 32:
                free = [cluster for cluster in range(2, inventory["clusters"] + 2)
                        if int.from_bytes(inventory["fats"][0][cluster * width:(cluster + 1) * width],
                                          "little") & mask == 0]
                with image.open("rb") as stream:
                    stream.seek(base + info * sector + 488)
                    hints = stream.read(8)
                    check(int.from_bytes(hints[:4], "little") == len(free)
                          and hints[4:] == bytes([255]) * 4, "recovery primary hints differ from native allocation")
                    if damage == "fsinfo":
                        stream.seek(base + (backup + info) * sector + 488)
                        hints = stream.read(8)
                        check(int.from_bytes(hints[:4], "little") == len(free)
                              and int.from_bytes(hints[4:], "little") == (free[0] if free else 0xFFFFFFFF),
                              "FSInfo backup hints differ from native allocation")
            selected = image
            if base:
                selected = self.root / f"recovery-fat{bits}-s{sector}-{damage}-selected.img"
                with selected.open("xb") as output, image.open("rb") as source:
                    source.seek(base)
                    remaining = native.stat().st_size
                    while remaining:
                        data = source.read(min(1024 * 1024, remaining))
                        check(bool(data), "bounded recovery result is truncated")
                        output.write(data)
                        remaining -= len(data)
            after = native_inventory(selected)
            for path, entry in inventory["entries"].items():
                actual = after["entries"][path]
                check(entry["record"] == actual["record"] and entry["lfn"] == actual["lfn"]
                      and entry["chain"] == actual["chain"], "recovery changed native names/metadata/allocation")
                if not entry["directory"]:
                    check(hmac.compare_digest(entry["allocated_digest"], actual["allocated_digest"]),
                          "recovery changed payload or slack")
            self.command("fsck.fat", "-n", selected)
            for name, data in payloads.items():
                check(self.command("mcopy", "-i", selected, f"::/{name}", "-") == data,
                      f"native payload differs after {damage} recovery: {name}")
            self.mounted(selected, payloads)
            check(hmac.compare_digest(digest(native), frozen), "recovery changed the retained original")
            results.append({"damage": damage, "damaged_sha256": damaged,
                            "recovered_sha256": digest(image), "operation": report["operation"],
                            "repair_report": repair_output, "result": "passed"})
        return results

    def protected(self, bits: int) -> dict[str, object]:
        """Exercise the existing sidecar-backed writer, then a fresh reader.

        This qualifies live FAT transport wiring, not independent-device crash
        atomicity or recovery from damaged sidecar generations.
        """
        tag = f"protected-fat{bits}"
        image = self.root / f"{tag}.img"
        sidecar = self.root / f"{tag}.ffs-rq"
        source = self.root / f"{tag}-source"
        source.mkdir()
        sentinel = bytes(range(251)) * 19 + b"protected native sentinel"
        (source / "KEEP.BIN").write_bytes(sentinel)
        formatted = json.loads(self.command(
            self.binary, "format", image, "--kind", f"fat{bits}",
            "--size-mib", "64", "--source-dir", source, "--sidecar", sidecar))
        check(formatted["sidecar_refreshed"] is True and sidecar.is_file(),
              "protected formatter did not publish its sidecar")
        self.command("fsck.fat", "-n", image)
        initial_hash, initial_sidecar = digest(image), digest(sidecar)
        keep_before = native_root_file(image, b"KEEP    BIN")
        events = self.root / f"{tag}-syscalls.jsonl"

        def acknowledged(operation: str, **details: object) -> None:
            with events.open("a") as stream:
                stream.write(json.dumps({"operation": operation, "acknowledged": True,
                                         **details}) + "\n")

        options = ("--sidecar", str(sidecar))
        payload = bytes(range(256)) * 17 + b"protected tail"
        with self.mount_image(image, writable=True, image_options=options) as mounted:
            check((mounted / "KEEP.BIN").read_bytes() == sentinel, "protected sentinel differs")
            directory = mounted / "native"
            directory.mkdir()
            path = directory / "Protected café.txt"
            with path.open("xb", buffering=0) as stream:
                check(stream.write(payload) == len(payload), "short protected write")
                stream.truncate(1031)
                stream.truncate(8197)
                payload = payload[:1031] + bytes(8197 - 1031)
                os.fsync(stream.fileno())
            acknowledged("create, write, truncate and fsync", path=str(path.name), bytes=len(payload))
            renamed = directory / "renamed.txt"
            path.rename(renamed)
            acknowledged("rename", old=path.name, new=renamed.name)
            orphan = directory / "orphan.txt"
            with orphan.open("x+b", buffering=0) as stream:
                check(stream.write(b"open-unlinked") == 13, "short protected orphan write")
                orphan.unlink()
                stream.seek(0)
                check(stream.read() == b"open-unlinked", "protected open-unlink lost bytes")
                os.fsync(stream.fileno())
            acknowledged("open-unlink, read, fsync and release")
            check(renamed.read_bytes() == payload, "protected truncate or rename lost data")
        self.command("fsck.fat", "-n", image)
        expected = {"KEEP.BIN": sentinel, "native/renamed.txt": payload}
        for name, data in expected.items():
            check(self.command("mcopy", "-i", image, f"::/{name}", "-") == data,
                  f"native consumer differs after protected mount: {name}")
            check(self.command(self.binary, "cat", image, f"/{name}", *options) == data,
                  f"fresh protected reader differs: {name}")
        names = self.command("mdir", "-i", image, "-b", "-s", "::/").decode("utf-8").splitlines()
        check({name.removeprefix("::/").rstrip("/") for name in names}
              == {"KEEP.BIN", "native", "native/renamed.txt"},
              "protected namespace contains missing or leaked entries")
        check(native_root_file(image, b"KEEP    BIN") == keep_before,
              "protected writes changed the acknowledged native sentinel")
        # Offline diagnosis deliberately reads original native bytes without
        # repair authority. Protected data reads above use separate fresh opens.
        checked = json.loads(self.command(self.binary, "check", image))
        check(checked["clean"] is True and checked["complete"] is True
              and checked["namespace_complete"] is True and checked["issues"] == [],
              "native checker does not admit the protected writer's committed image")
        final_hash, final_sidecar = digest(image), digest(sidecar)
        check(not hmac.compare_digest(final_hash, initial_hash)
              and not hmac.compare_digest(final_sidecar, initial_sidecar),
              "protected mounted writes did not update both image and sidecar")
        with self.mount_image(image, image_options=options) as mounted:
            for name, data in expected.items():
                check((mounted / name).read_bytes() == data,
                      f"fresh protected mount differs: {name}")
            check(not (mounted / "native/orphan.txt").exists(), "protected orphan reappeared")
        check(hmac.compare_digest(digest(image), final_hash)
              and hmac.compare_digest(digest(sidecar), final_sidecar),
              "read-only protected verification changed image or sidecar")
        return {"scenario": "protected_writable_mount", "format": f"FAT{bits}",
                "initial_sha256": initial_hash, "final_sha256": final_hash,
                "initial_sidecar_sha256": initial_sidecar, "final_sidecar_sha256": final_sidecar,
                "files_checked": len(expected), "result": "passed"}

    def writable(self, bits: int, sector: int, bounded: bool) -> dict[str, object]:
        """Native -> real FUSE syscalls -> independent fsck/mtools -> fresh FUSE.

        These are newly created, retained regular images, never host devices.
        Unlink/overwrite below are the operations under test, not scratch cleanup.
        FAT timestamps use the adapter's documented UTC/two-second projection.
        """
        tag = f"rw-fat{bits}-s{sector}-{'bounded' if bounded else 'plain'}"
        native = self.root / f"{tag}-native.img"
        size_mib = 512 if bits == 32 and sector == 4096 else 64
        if bits == 16 and sector == 512:
            size_mib = 16
        size = size_mib * 1024 * 1024
        with native.open("xb") as stream:
            stream.truncate(size)
        root_options = ("-r", "32") if bits == 16 else ()
        self.command("mkfs.fat", "-F", str(bits), "-S", str(sector), "-s", "1",
                     *root_options, native)
        sentinel = bytes(range(251)) * 37 + b"native file must survive unrelated writes"
        source = self.root / f"{tag}-sentinel.bin"
        source.write_bytes(sentinel)
        self.command("mcopy", "-i", native, source, "::/KEEP.BIN")
        self.command("fsck.fat", "-n", native)
        keep_before = native_root_file(native, b"KEEP    BIN")
        image = native
        options: tuple[str, ...] = ()
        if bounded:
            image = self.root / f"{tag}-wrapped.img"
            with image.open("xb") as stream, native.open("rb") as plain:
                stream.write(b"P" * 4096)
                shutil.copyfileobj(plain, stream)
                stream.write(b"S" * 4096)
            options = ("--offset", "4096", "--length", str(size))
        initial_hash = digest(image)
        expected = {"KEEP.BIN": sentinel}
        events = self.root / f"{tag}-syscalls.jsonl"

        def acknowledged(operation: str, **details: object) -> None:
            with events.open("a") as stream:
                stream.write(json.dumps({"operation": operation, "acknowledged": True,
                                         **details}) + "\n")

        def expect_errno(operation: str, wanted: int, action) -> None:
            try:
                action()
            except OSError as error:
                check(error.errno == wanted,
                      f"{operation}: errno {error.errno}, expected {wanted}")
                acknowledged(operation, errno=error.errno)
            else:
                raise RuntimeError(f"{operation}: unexpectedly succeeded, expected errno {wanted}")

        with self.mount_image(image, writable=True, image_options=options) as mounted:
            check((mounted / "KEEP.BIN").read_bytes() == sentinel, "initial native bytes differ")
            (mounted / "left").mkdir()
            (mounted / "right").mkdir()
            name = "left/Native café and collision.txt"
            path = mounted / name
            payload = bytes(range(256)) * 17 + b"tail"
            with path.open("xb", buffering=0) as stream:
                check(stream.write(payload) == len(payload), "short mounted write")
                stream.seek(8197)
                check(stream.write(b"gap tail") == 8, "short positioned mounted write")
                payload += b"\0" * (8197 - len(payload)) + b"gap tail"
                os.fsync(stream.fileno())
            check(path.read_bytes() == payload, "gap exposed unrelated data")
            expect_errno("case collision", errno.EEXIST,
                         lambda: (mounted / name.upper()).open("xb"))
            with path.open("r+b", buffering=0) as stream:
                stream.truncate(1031)
                payload = payload[:1031]
                stream.truncate(12291)
                payload += b"\0" * (12291 - len(payload))
                os.posix_fallocate(stream.fileno(), 0, 16391)
                payload += b"\0" * (16391 - len(payload))
                os.fsync(stream.fileno())
            check(path.read_bytes() == payload, "truncate/preallocation exposed unrelated data")
            acknowledged("range write, gap, shrink, grow and preallocation", bytes=len(payload))

            # Overwrite a pinned destination: its old descriptor keeps old data.
            destination = mounted / "right/Replaced café.txt"
            destination.write_bytes(b"old destination")
            with destination.open("rb", buffering=0) as old:
                old_ino = os.fstat(old.fileno()).st_ino
                path.rename(destination)
                check(old.read() == b"old destination", "overwrite changed pinned destination")
                check(destination.read_bytes() == payload, "cross-parent rename lost source")
                check(destination.stat().st_ino != old_ino, "overwrite reused pinned inode")
            expected["right/Replaced café.txt"] = payload
            os.utime(destination, (1_700_000_000, 1_700_000_002))
            check(int(destination.stat().st_mtime) == 1_700_000_002,
                  "mounted FAT UTC/two-second timestamp projection differs")
            (mounted / "left/subdir").mkdir()
            expect_errno("directory cycle", errno.EINVAL,
                         lambda: (mounted / "left").rename(mounted / "left/subdir/cycle"))
            acknowledged("cross-parent overwrite with pinned destination")

            orphan = mounted / "open-unlink.bin"
            orphan.write_bytes(b"old handle data")
            with orphan.open("r+b", buffering=0) as old:
                old_ino = os.fstat(old.fileno()).st_ino
                orphan.unlink()
                check(not orphan.exists(), "unlinked name remains visible")
                orphan.write_bytes(b"new namespace data")
                check(old.read() == b"old handle data", "unlink/reuse changed pinned bytes")
                old.seek(4)
                old.write(b"HANDLE")
                os.fsync(old.fileno())
                old.seek(0)
                check(old.read() == b"old HANDLE data", "unlinked positioned write differs")
                check(orphan.read_bytes() == b"new namespace data", "old handle overwrote new file")
                check(orphan.stat().st_ino != old_ino, "unlink reused pinned inode")
            expected["open-unlink.bin"] = b"new namespace data"
            acknowledged("open-unlink, new namespace allocation and old-handle fsync")

            # Long entries force the subdirectory past its initial cluster.
            for index in range(40):
                relative = f"left/subdir/Long directory growth café {index:03d}.txt"
                data = f"entry {index:03d}".encode()
                (mounted / relative).write_bytes(data)
                expected[relative] = data
            names = [entry.name for entry in (mounted / "left/subdir").iterdir()]
            check(len(names) == 40 and len(set(names)) == 40, "grown readdir lost/duplicated names")
            check((mounted / "KEEP.BIN").read_bytes() == sentinel, "unrelated native file changed")
            acknowledged("directory growth and readdir", entries=40)

            cluster = os.statvfs(mounted).f_frsize
            # Alternate growth so both files have noncontiguous native chains.
            with (mounted / "FRAG_A.BIN").open("x+b", buffering=0) as first, \
                    (mounted / "FRAG_B.BIN").open("x+b", buffering=0) as second:
                for count in range(1, 5):
                    os.posix_fallocate(first.fileno(), 0, count * cluster)
                    os.posix_fallocate(second.fileno(), 0, count * cluster)
                for stream, byte, name in ((first, b"A", "FRAG_A.BIN"),
                                            (second, b"B", "FRAG_B.BIN")):
                    data = byte * (4 * cluster)
                    check(stream.write(data) == len(data), "short fragmented write")
                    os.fsync(stream.fileno())
                    expected[name] = data
            acknowledged("interleaved fragmented native chains", cluster_bytes=cluster)

            # Fill the actual remaining allocation, overwrite without allocating,
            # then shrink/regrow into the freed storage. The old tail must not
            # reappear after its bytes have passed beyond the shortened EOF.
            capacity_file = mounted / "CAPACITY.BIN"
            with capacity_file.open("x+b", buffering=0) as stream:
                free_before = os.statvfs(mounted).f_bavail
                length = free_before * cluster
                check(length > 4 * cluster, "full-volume case has no useful free allocation")
                os.posix_fallocate(stream.fileno(), 0, length)
                check(os.statvfs(mounted).f_bavail == 0, "fallocate did not fill the volume")
                check(os.pwrite(stream.fileno(), b"old private tail", length - 16) == 16,
                      "overwrite on a full volume failed")
                expect_errno("growth on full volume", errno.ENOSPC,
                             lambda: os.pwrite(stream.fileno(), b"X", length))
                stream.truncate(length - 3 * cluster)
                check(os.statvfs(mounted).f_bavail == 3, "shrink did not release exactly three clusters")
                stream.truncate(length)
                check(os.statvfs(mounted).f_bavail == 0, "regrowth did not reuse freed allocation")
                check(os.pread(stream.fileno(), 3 * cluster, length - 3 * cluster) == b"\0" * (3 * cluster),
                      "regrowth exposed old private tail bytes")
                stream.truncate(0)
                os.fsync(stream.fileno())
                check(os.statvfs(mounted).f_bavail == free_before, "truncate leaked allocation")
            expected["CAPACITY.BIN"] = b""
            acknowledged("full-volume overwrite, ENOSPC, shrink and zeroed reuse", free_clusters=free_before)

            if bits == 16:
                # dosfstools rounds the requested fixed root to sector size.
                with native.open("rb") as stream:
                    boot = stream.read(512)
                capacity = int.from_bytes(boot[17:19], "little")
                filled = 0
                for index in range(capacity + 1):
                    relative = f"F{index:07d}.BIN"
                    try:
                        with (mounted / relative).open("xb"):
                            pass
                    except OSError as error:
                        check(error.errno == errno.ENOSPC,
                              f"fixed-root exhaustion returned {error.errno}, expected ENOSPC")
                        break
                    expected[relative] = b""
                    filled += 1
                else:
                    raise RuntimeError("FAT16 fixed root grew beyond its native capacity")
                check(filled > 0, "fixed-root exhaustion did not exercise any available slots")
                expect_errno("mkdir in full fixed root", errno.ENOSPC,
                             lambda: (mounted / "FULLROOT").mkdir())
                check((mounted / "KEEP.BIN").read_bytes() == sentinel,
                      "fixed-root exhaustion changed an unrelated file")
                acknowledged("fixed-root exhaustion", empty_files=filled, root_slots=capacity)

        # fsck has no bounded-image selector: extract only our selected range.
        checked_image = image
        if bounded:
            checked_image = self.root / f"{tag}-after.img"
            with image.open("rb") as stream, checked_image.open("xb") as output:
                check(stream.read(4096) == b"P" * 4096, "prefix changed outside volume")
                remaining = size
                while remaining:
                    chunk = stream.read(min(remaining, 1024 * 1024))
                    check(bool(chunk), "bounded image was truncated")
                    output.write(chunk)
                    remaining -= len(chunk)
                check(stream.read() == b"S" * 4096, "suffix changed outside volume")
        self.command("fsck.fat", "-n", checked_image)
        native_names = self.command("mdir", "-b", "-s", "-i", checked_image, "::/").decode("utf-8").splitlines()
        expected_names = {f"::/{name}" for name in expected}
        expected_names.update({"::/left/", "::/right/", "::/left/subdir/"})
        check(len(native_names) == len(expected_names) and set(native_names) == expected_names,
              "native namespace names differ, or an unlinked recovery record survived clean unmount")
        check(native_root_file(checked_image, b"KEEP    BIN") == keep_before,
              "unrelated native entry, chain, payload or slack changed")
        for short_name in (b"FRAG_A  BIN", b"FRAG_B  BIN"):
            chain = native_root_file(checked_image, short_name)["clusters"]
            check(len(chain) == 4 and any(right != left + 1 for left, right in zip(chain, chain[1:])),
                  "interleaved allocation did not create an independently verified fragmented chain")
        for index, (name, data) in enumerate(expected.items()):
            output = self.root / f"{tag}-native-read-{index:03d}.bin"
            self.command("mcopy", "-i", checked_image, f"::/{name}", output)
            check(output.read_bytes() == data, f"native reopen bytes differ: {name}")
        checked = json.loads(self.command(self.binary, "check", image, *options))
        check(checked["clean"] and checked["complete"] and checked["namespace_complete"],
              "mounted writes did not leave a completely checked clean volume")
        check(checked["files"] == len(expected) and checked["directories"] == 4,
              "mounted namespace contains missing or unexpected files/directories")
        before_readonly = digest(image)
        with self.mount_image(image, image_options=options) as mounted:
            for name, data in expected.items():
                check((mounted / name).read_bytes() == data, f"fresh FUSE bytes differ: {name}")
            check(int((mounted / "right/Replaced café.txt").stat().st_mtime) == 1_700_000_002,
                  "native timestamp was not preserved on a fresh mount")
        check(hmac.compare_digest(digest(image), before_readonly), "fresh read-only mount changed bytes")
        acknowledged("native fsck/mtools and fresh read-only mount", files=len(expected))
        return {"scenario": "writable_mount", "format": f"FAT{bits}", "sector_bytes": sector,
                "bounded": bounded, "initial_sha256": initial_hash,
                "final_sha256": before_readonly, "files_checked": len(expected), "result": "passed"}


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
        check(hmac.compare_digest(digest(image), empty_hash), "refused format changed an existing image")
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
        check(hmac.compare_digest(digest(image), before), "readback changed formatter/native-written image")
        self.command("fsck.fat", "-n", image)
        check(hmac.compare_digest(digest(image), before), "native read-only check changed formatter image")
        facade_reads = self.public_reads(self.facade, image, payloads) if self.facade else None
        return {"format": f"FAT{bits}", "creator": "ffs-fat format",
                "fresh_image_sha256": empty_hash, "native_written_sha256": before,
                "facade_reads": facade_reads,
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
        check(hmac.compare_digest(digest(image), before), "readback or refused reformat changed populated image")

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
        check(hmac.compare_digest(digest(image), after_native), "native-extension readback changed the image")

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
        facade_payloads = {**payloads, "Native added directory/Added payload.bin": added.read_bytes()}
        facade_reads = self.public_reads(self.facade, image, facade_payloads) if self.facade else None
        return {"format": f"FAT{bits}", "creator": "ffs-fat format --source-dir",
                "populated_image_sha256": before, "native_extended_sha256": after_native,
                "facade_reads": facade_reads,
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
        check(hmac.compare_digest(digest(image), before), f"candidate changed FAT{bits} image bytes")
        self.command("fsck.fat", "-n", image)
        check(hmac.compare_digest(digest(image), before), "read-only native checker changed the image")
        root_growth = self.root_growth(image, payloads) if bits == 16 else None
        fsinfo_recovery = self.fsinfo_recovery(image, payloads) if bits == 32 else None
        streaming_reads = self.streaming_reads(image, payloads)
        facade_reads = self.public_reads(self.facade, image, payloads) if self.facade else None
        return {"format": f"FAT{bits}", "image_sha256": before,
                "files_checked": len(payloads), "mounted": mounted,
                "root_growth": root_growth, "fsinfo_recovery": fsinfo_recovery,
                "streaming_reads": streaming_reads, "facade_reads": facade_reads, "result": "passed"}

    def public_reads(self, facade: Path, original: Path,
                     payloads: dict[str, bytes]) -> dict[str, object]:
        """Exercise the public FsOps consumer against independent native bytes."""
        check(bool(payloads), "public FAT profile requires native files")
        original_hash = digest(original)
        facade_hash = digest(facade)
        volume_bytes = original.stat().st_size
        native = native_allocation(original)
        self.command("fsck.fat", "-n", original)
        parents = {""}
        for name, expected in payloads.items():
            parts = name.split("/")
            check(all(part and part not in (".", "..") for part in parts),
                  "public FAT fixture path is not image-relative")
            parents.update("/".join(parts[:index]) for index in range(1, len(parts)))
            check(self.command("mcopy", "-i", original, f"::/{name}", "-") == expected,
                  f"native public-API reference differs: {name}")
        native_names = {}
        for parent in sorted(parents):
            prefix = ("::/" + (parent + "/" if parent else "")).encode("utf-8")
            lines = self.command("mdir", "-b", "-a", "-i", original,
                                 prefix.decode("utf-8") + "*").splitlines()
            names = []
            for line in lines:
                check(line.startswith(prefix), "native listing escaped its selected directory")
                name = line[len(prefix):].removesuffix(b"/")
                check(bool(name) and b"/" not in name, "native listing has an invalid component")
                if name not in (b".", b".."):
                    names.append(name)
            check(len(names) == len(set(names)), "native listing has duplicate names")
            native_names[parent] = set(names)
        absent = "__ffs_public_missing_72851__.bin"
        check(absent.encode("ascii") not in native_names[""], "negative fixture name already exists")

        bounded = self.root / f"public-read-{original.stem}-bounded.img"
        with bounded.open("xb") as wrapped, original.open("rb") as source:
            wrapped.write(b"P" * 8192)
            shutil.copyfileobj(source, wrapped, 1024 * 1024)
            wrapped.write(b"S" * 4096)
        check(bounded.stat().st_size == 8192 + volume_bytes + 4096,
              "public FAT wrapper length differs")
        bounded_hash = digest(bounded)
        profiles = []
        for backing, offset, flags, before in (
            (original, 0, [], original_hash),
            (bounded, 8192, ["--offset", "8192", "--length", str(volume_bytes)], bounded_hash),
        ):
            public = [facade, backing, *flags]
            for parent in sorted(parents):
                listed = self.command(*public, "list", "/" + parent)
                check(listed.endswith(b"\0"), "public listing lacks its final NUL delimiter")
                names = listed[:-1].split(b"\0")
                check(len(names) == len(set(names)) and set(names) == native_names[parent] | {b".", b".."},
                      f"public listing differs from native names: {parent!r}")
            comparisons = 0
            for name, expected in payloads.items():
                path = "/" + name
                check(self.command(*public, "stat", path) ==
                      f"{native['format'].lower()}\tRegularFile\t{len(expected)}\n".encode("ascii"),
                      f"public FAT metadata differs: {name}")
                check(self.command(*public, "read", path) == expected,
                      f"public FAT complete bytes differ: {name}")
                for start, count in ((507, 1031), (max(0, len(expected) - 3), 17),
                                     (len(expected), 9), (len(expected) + 13, 9), (0, 0)):
                    check(self.command(*public, "read", path, "--start", str(start),
                                       "--bytes", str(count)) == expected[start:start + count],
                          f"public FAT range/EOF differs: {name} {start}+{count}")
                comparisons += 6
            first = "/" + next(iter(payloads))
            check(self.command(*public, "refuse-write", first) == b"",
                  "public FAT write-refusal emitted unexpected bytes")
            for operation, path, reason in (("stat", "/" + absent, b"NotFound"),
                                            ("read", "/", b"read requires a regular file")):
                output = self.command(*public, operation, path, expected_returncode=1)
                stderr = (self.root / f"command-{self.sequence:03d}.stderr").read_bytes()
                check(output == b"" and reason in stderr,
                      "public FAT negative emitted bytes or failed for another reason")
            check(comparisons == len(payloads) * 6 and hmac.compare_digest(digest(backing), before),
                  "public FAT profile omitted a read or changed backing/sentinels")
            profiles.append({"volume_offset": offset, "sha256": before,
                             "file_stats": len(payloads), "directory_listings": len(parents),
                             "byte_comparisons": comparisons, "write_refusals": 1,
                             "expected_failures": 2})
        self.command("fsck.fat", "-n", original)
        check(hmac.compare_digest(digest(original), original_hash)
              and hmac.compare_digest(digest(bounded), bounded_hash)
              and hmac.compare_digest(digest(facade), facade_hash), "public FAT check changed an input or executable")
        return {"format": native["format"], "facade_sha256": facade_hash,
                "files_checked": len(payloads), "native_reference_reads": len(payloads),
                "native_directory_listings": len(parents), "profiles": profiles, "result": "passed"}

    def streaming_reads(self, original: Path, payloads: dict[str, bytes]) -> dict[str, object]:
        """Read native files through both streaming selectors and volume bounds."""
        check(bool(payloads), "streaming profile must exercise actual native files")
        original_hash = digest(original)
        volume_bytes = original.stat().st_size
        native = native_allocation(original)
        self.command("fsck.fat", "-n", original)
        for name, expected in payloads.items():
            check(self.command("mcopy", "-i", original, f"::/{name}", "-") == expected,
                  f"native streaming reference differs: {name}")

        bounded = self.root / f"stream-read-{original.stem}-bounded.img"
        with bounded.open("xb") as wrapped, original.open("rb") as plain:
            wrapped.write(b"P" * 8192)
            shutil.copyfileobj(plain, wrapped, 1024 * 1024)
            wrapped.write(b"S" * 4096)
        check(bounded.stat().st_size == 8192 + volume_bytes + 4096,
              "streaming wrapper length differs")
        bounded_hash = digest(bounded)
        profiles = []
        cycle_target = None
        for backing, offset, flags, before in (
            (original, 0, [], original_hash),
            (bounded, 8192, ["--offset", "8192", "--length", str(volume_bytes)], bounded_hash),
        ):
            catalogs: dict[str, dict[str, object]] = {}
            nested_selector = None
            comparisons = 0
            for name, expected in payloads.items():
                components = name.split("/")
                parent = ""
                for index, component in enumerate(components):
                    if parent not in catalogs:
                        selected = ["--entry-slots", parent] if parent else []
                        catalog = json.loads(self.command(
                            self.binary, "catalog", backing, *selected, *flags))
                        check(catalog["format"] == native["format"] and catalog["read_only"] is True
                              and catalog["volume_offset"] == offset
                              and catalog["volume_bytes"] == volume_bytes
                              and catalog["entry_offset_origin"] == "selected_volume"
                              and catalog["directory_entry_slots"] == (parent or None),
                              "catalog changed the native volume or selector origin")
                        catalogs[parent] = catalog
                    matches = [entry for entry in catalogs[parent]["entries"]
                               if entry["name"] == component]
                    check(len(matches) == 1, f"native catalog component is missing or ambiguous: {name}")
                    entry = matches[0]
                    selector = entry["entry_slots"]
                    slots = selector.split(",")
                    check(len(slots) == index + 1 and all(slot.isdecimal() for slot in slots)
                          and all(int(slot) % 32 == 0 for slot in slots)
                          and int(slots[-1]) == entry["entry_offset"]
                          and ",".join(slots[:-1]) == parent
                          and entry["display_error"] is None,
                          "catalog selector does not preserve native slot ancestry")
                    final = index + 1 == len(components)
                    check(entry["directory"] is (not final), "catalog component has the wrong native type")
                    if final:
                        check(entry["size"] == len(expected), f"native catalog file size differs: {name}")
                        if len(slots) > 1:
                            nested_selector = slots[-1]
                        if offset == 0 and len(expected) > 1024 * 1024:
                            cycle_target = (name, selector, entry["first_cluster"])
                    parent = selector
                check(self.command(self.binary, "cat", backing, f"/{name}", *flags) == expected,
                      f"streamed path bytes differ: {name}")
                check(self.command(self.binary, "extract", backing, "--entry-slots", parent,
                                   *flags) == expected, f"streamed native-slot bytes differ: {name}")
                comparisons += 2

            check(nested_selector is not None, "streaming profile requires a nested native file")
            for invalid in ("0", nested_selector):
                refused = self.command(self.binary, "extract", backing, "--entry-slots", invalid,
                                       *flags, expected_returncode=1)
                stderr = (self.root / f"command-{self.sequence:03d}.stderr").read_bytes()
                check(refused == b"" and b"not in its selected parent" in stderr,
                      "invalid native selector emitted bytes or failed for another reason")
            check(comparisons == len(payloads) * 2 and hmac.compare_digest(digest(backing), before),
                  "streaming omitted a selector or changed its image/sentinels")
            profiles.append({"volume_offset": offset, "sha256": before,
                             "byte_comparisons": comparisons, "expected_refusals": 2})

        # A native multi-chunk file with only its final allocation link damaged
        # must fail during complete-chain admission, before even its first byte.
        check(cycle_target is not None, "streaming profile requires a multi-chunk native file")
        name, selector, cluster = cycle_target
        damaged_bytes = bytearray(original.read_bytes())
        boot = bytes(damaged_bytes[:512])
        u16 = lambda at: int.from_bytes(boot[at:at + 2], "little")
        u32 = lambda at: int.from_bytes(boot[at:at + 4], "little")
        sector = u16(11)
        table_start = u16(14) * sector
        table_bytes = (u16(22) or u32(36)) * sector
        width = 2 if native["format"] == "Fat16" else 4
        mask = 0xFFFF if width == 2 else 0x0FFFFFFF
        eof = 0xFFF8 if width == 2 else 0x0FFFFFF8
        visited = set()
        while True:
            check(2 <= cluster < native["data_clusters"] + 2 and cluster not in visited,
                  "independent native chain walk found invalid allocation")
            visited.add(cluster)
            at = table_start + cluster * width
            value = int.from_bytes(damaged_bytes[at:at + width], "little") & mask
            if value >= eof:
                break
            cluster = value
        for copy in range(2):
            at = table_start + copy * table_bytes + cluster * width
            old = int.from_bytes(damaged_bytes[at:at + width], "little")
            damaged_bytes[at:at + width] = ((old & ~mask) | cluster).to_bytes(width, "little")
        damaged = self.root / f"stream-read-{original.stem}-cyclic-tail.img"
        with damaged.open("xb") as stream:
            stream.write(damaged_bytes)
        damaged_hash = hashlib.sha256(damaged_bytes).hexdigest()
        del damaged_bytes
        for operation, selected in (("cat", [f"/{name}"]), ("extract", ["--entry-slots", selector])):
            refused = self.command(self.binary, operation, damaged, *selected, expected_returncode=1)
            stderr = (self.root / f"command-{self.sequence:03d}.stderr").read_bytes()
            check(refused == b"" and b"cyclic FAT file chain" in stderr,
                  "cyclic native tail emitted bytes or failed for another reason")
        check(hmac.compare_digest(digest(damaged), damaged_hash), "cycle refusal changed the damaged private copy")
        self.command("fsck.fat", "-n", original)
        check(hmac.compare_digest(digest(original), original_hash)
              and hmac.compare_digest(digest(bounded), bounded_hash),
              "streaming or native read-only checking changed an input")
        return {"format": native["format"], "files_checked": len(payloads),
                "source_sha256": original_hash, "bounded_sha256": bounded_hash,
                "native_reference_reads": len(payloads), "profiles": profiles,
                "cyclic_tail_sha256": damaged_hash, "cyclic_tail_refusals": 2, "result": "passed"}

    def fsinfo_recovery(self, original: Path, payloads: dict[str, bytes]) -> dict[str, object]:
        """Damage private native FSInfo, repair hints, then separately recover."""
        original_hash = digest(original)
        native = native_allocation(original)
        check(native["format"] == "Fat32", "FSInfo profile requires native FAT32")
        self.command("fsck.fat", "-n", original)
        with original.open("rb") as stream:
            boot = stream.read(512)
            u16 = lambda at: int.from_bytes(boot[at:at + 2], "little")
            sector = u16(11)
            reserved = u16(14)
            info = u16(48)
            backup_boot = u16(50)
            backup_info = backup_boot + info
            fat_sectors = int.from_bytes(boot[36:40], "little")
            check(sector == 512 and boot[16] == 2 and u16(40) & 0x80 == 0
                  and 0 < info < reserved and 0 < backup_boot < reserved
                  and backup_info < reserved and len({0, info, backup_boot, backup_info}) == 4,
                  "native FSInfo profile has an unexpected reserved layout")
            dirty = {}
            for number in (0, backup_boot):
                stream.seek(number * sector + 65)
                state = stream.read(1)
                check(state == b"\0", "native boot state is not clean")
                dirty[number * sector + 65] = b"\1"
            for copy in range(2):
                at = (reserved + copy * fat_sectors) * sector + 7
                stream.seek(at)
                state = stream.read(1)
                check(len(state) == 1 and state[0] & 8 != 0, "native FAT clean bit is absent")
                dirty[at] = bytes([state[0] & ~8])
            for number in (info, backup_info):
                stream.seek(number * sector)
                data = stream.read(sector)
                check(all(int.from_bytes(data[at:at + 4], "little") == value
                          for at, value in ((0, 0x41615252), (484, 0x61417272), (508, 0xAA550000))),
                      "native primary/backup FSInfo signatures differ")

        # Expected whole-file digests come from the immutable native source,
        # with only independently specified native fields replaced. Every other
        # byte, including both neighboring sentinel regions, must survive.
        def expected_digest(patches: dict[int, bytes]) -> str:
            result = hashlib.sha256(b"P" * 4096)
            with original.open("rb") as stream:
                position = 0
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    data = bytearray(chunk)
                    for at, replacement in patches.items():
                        start = max(at, position)
                        end = min(at + len(replacement), position + len(data))
                        if start < end:
                            data[start - position:end - position] = replacement[start - at:end - at]
                    result.update(data)
                    position += len(data)
            result.update(b"S" * 4096)
            return result.hexdigest()

        image = self.root / "fsinfo-bounded.img"
        with image.open("xb") as wrapped, original.open("rb") as plain:
            wrapped.write(b"P" * 4096)
            shutil.copyfileobj(plain, wrapped, 1024 * 1024)
            wrapped.write(b"S" * 4096)
        check(hmac.compare_digest(digest(image), expected_digest({})), "private FSInfo copy differs before damage")
        damaged = {info * sector + at: bytes(4) for at in (0, 484, 488, 492, 508)}
        damaged.update({backup_info * sector + at: bytes(4) for at in (488, 492)})
        with image.open("r+b") as stream:
            for at, replacement in damaged.items():
                stream.seek(4096 + at)
                stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        damaged_hash = expected_digest(damaged)
        check(hmac.compare_digest(digest(image), damaged_hash), "FSInfo damage escaped its private declared fields")
        selection = ["--offset", "4096", "--length", str(original.stat().st_size)]
        self.command(self.binary, "repair-fsinfo", image, *selection, expected_returncode=2)
        check(b"--offline-image" in (self.root / f"command-{self.sequence:03d}.stderr").read_bytes(),
              "FSInfo authority refusal has the wrong cause")
        self.command(self.binary, "recover", image, *selection, "--offline-image", expected_returncode=1)
        check(b"fs_info_signature" in (self.root / f"command-{self.sequence:03d}.stderr").read_bytes(),
              "ordinary recovery refused for a reason other than invalid FSInfo")
        repair = [self.binary, "repair-fsinfo", image, *selection, "--offline-image"]
        preview = json.loads(self.command(*repair, "--dry-run"))
        check(preview["dry_run"] is True and preview["changed"] is False
              and preview["free_clusters"] == native["free_clusters"]
              and preview["next_free_cluster"] == native["next_free_cluster"]
              and preview["backup_policy"] == "recognized_hint_copy"
              and {item["offset"] for item in preview["sectors"]} == {info * sector, backup_info * sector},
              "FSInfo plan differs from native allocation/reserved evidence")
        check(hmac.compare_digest(digest(image), damaged_hash), "refusal or FSInfo dry run changed the source")
        rebuilt = {}
        for number in (info, backup_info):
            for at, value in ((0, 0x41615252), (484, 0x61417272), (508, 0xAA550000),
                              (488, native["free_clusters"]), (492, native["next_free_cluster"])):
                rebuilt[number * sector + at] = int(value).to_bytes(4, "little")
        repaired = json.loads(self.command(*repair))
        dirty_hash = expected_digest(rebuilt | dirty)
        check(repaired["changed"] is True and repaired["native_recovery_required"] is True
              and repaired["allocation_links_written"] is False and repaired["reclaimed_clusters"] == 0
              and repaired["durability"] == "fsinfo_sectors_synced_and_verified_image_left_dirty"
              and hmac.compare_digest(digest(image), dirty_hash), "FSInfo repair changed bytes beyond five words and dirty markers")
        checked = json.loads(self.command(self.binary, "check", image, *selection, expected_returncode=1))
        check(b"no changes were made" in (self.root / f"command-{self.sequence:03d}.stderr").read_bytes(),
              "dirty-state checker refusal has the wrong cause")
        check(checked["clean"] is False and checked["complete"] is True
              and checked["namespace_complete"] is True and checked["lost_clusters"] == 0
              and len(checked["issues"]) == 4
              and {issue["kind"] for issue in checked["issues"]} == {"native_boot_dirty", "native_fat_dirty"},
              "reconstructed FSInfo did not leave only all four native dirty markers")
        repeated = json.loads(self.command(*repair))
        check(repeated["changed"] is False and hmac.compare_digest(digest(image), dirty_hash),
              "repeated FSInfo repair changed already-correct bytes")

        def native_payloads(label: str) -> Path:
            selected = self.root / f"fsinfo-{label}.img"
            with image.open("rb") as wrapped, selected.open("xb") as plain:
                wrapped.seek(4096)
                remaining = original.stat().st_size
                while remaining:
                    chunk = wrapped.read(min(1024 * 1024, remaining))
                    check(bool(chunk), "bounded FSInfo image is truncated")
                    plain.write(chunk)
                    remaining -= len(chunk)
            before = digest(selected)
            for name, expected in payloads.items():
                check(self.command("mcopy", "-i", selected, f"::/{name}", "-") == expected,
                      f"native payload differs after FSInfo {label}: {name}")
            check(hmac.compare_digest(digest(selected), before), "native FSInfo readback changed its image")
            return selected

        native_payloads("repaired-dirty")
        recover = [self.binary, "recover", image, *selection, "--offline-image"]
        self.command(*recover, "--dry-run")
        check(hmac.compare_digest(digest(image), dirty_hash), "ordinary recovery dry run changed the image")
        recovered = json.loads(self.command(*recover))
        # Ordinary recovery deliberately resets the primary next-free hint to
        # unknown; the already-verified backup FSInfo is outside its write set.
        final = rebuilt | {info * sector + 492: bytes([255]) * 4}
        final_hash = expected_digest(final)
        check(recovered["changed"] is True and recovered["reclaimed_clusters"] == 0
              and recovered["retired_lfn_records"] == 0 and hmac.compare_digest(digest(image), final_hash),
              "ordinary recovery changed bytes outside its native state/hint contract")
        checked = json.loads(self.command(self.binary, "check", image, *selection))
        check(checked["clean"] is True and checked["complete"] is True
              and checked["namespace_complete"] is True and checked["issues"] == []
              and checked["files"] == len(payloads) and checked["free_clusters"] == native["free_clusters"],
              "separate ordinary recovery did not restore clean complete ownership")
        for name, expected in payloads.items():
            check(self.command(self.binary, "cat", image, f"/{name}", *selection) == expected,
                  f"FrankenFS payload differs after FSInfo recovery: {name}")
        selected = native_payloads("recovered-clean")
        self.command("fsck.fat", "-n", selected)
        check(native_allocation(selected) == native, "FSInfo recovery changed native allocation")
        check(hmac.compare_digest(digest(image), final_hash)
              and hmac.compare_digest(digest(original), original_hash),
              "FSInfo verification changed the bounded image or retained native source")
        facade_reads = self.public_reads(self.facade, selected, payloads) if self.facade else None
        return {"source_sha256": original_hash, "damaged_bounded_sha256": damaged_hash,
                "repaired_dirty_bounded_sha256": dirty_hash, "recovered_bounded_sha256": final_hash,
                "facade_reads": facade_reads,
                "free_clusters": native["free_clusters"], "next_free_cluster": native["next_free_cluster"],
                "preserved_files": len(payloads), "result": "passed"}

    def root_growth(self, original: Path, payloads: dict[str, bytes]) -> dict[str, object]:
        """Fill a native FAT16 root, grow it, and interchange both writers."""
        original_hash = digest(original)
        source = self.root / "root-growth-source.img"
        with original.open("rb") as old, source.open("xb") as new:
            shutil.copyfileobj(old, new, 1024 * 1024)

        def records(image: Path) -> tuple[int, bytes]:
            with image.open("rb") as stream:
                boot = stream.read(512)
                sector = int.from_bytes(boot[11:13], "little")
                slots = int.from_bytes(boot[17:19], "little")
                start = (int.from_bytes(boot[14:16], "little")
                         + boot[16] * int.from_bytes(boot[22:24], "little")) * sector
                check(sector == 512 and slots in (512, 1024),
                      "root-growth fixture has an unexpected native layout")
                stream.seek(start)
                data = stream.read(slots * 32)
            check(len(data) == slots * 32, "native root records are truncated")
            return slots, data

        slots, data = records(source)
        check(slots == 512, "native producer did not create the declared fixed root")
        empty = self.root / "root-growth-empty.bin"
        with empty.open("xb"):
            pass
        ended = False
        free = 0
        for at in range(0, len(data), 32):
            ended |= data[at] == 0
            free += ended or data[at] == 0xE5
        check(0 < free <= slots, "native fixture has no root slots to fill")
        for index in range(free):
            self.command("mcopy", "-i", source, empty, f"::/F{index:07d}.BIN")
        _, full = records(source)
        check(all(full[at] not in (0, 0xE5) for at in range(0, len(full), 32)),
              "native tools did not fill every root slot")
        payload = self.root / "root-growth-payload.bin"
        expected_payload = bytes(range(251)) * 19 + b"native root growth\n"
        with payload.open("xb") as stream:
            stream.write(expected_payload)
        self.command("mcopy", "-i", source, payload, "::/MORE.BIN", expected_returncode=1)
        refusal = self.root / f"command-{self.sequence:03d}.stderr"
        check(b"no directory slots" in refusal.read_bytes().lower(),
              "native create failed for a reason other than exhausted root capacity")
        self.command("fsck.fat", "-n", source)
        source_hash = digest(source)
        checked = json.loads(self.command(self.binary, "check", source))
        check(checked["clean"] is True and checked["complete"] is True and
              checked["namespace_complete"] is True, "full native root failed admission")
        output = self.root / "root-growth-expanded.img"
        resize = [self.binary, "resize", source, "--output", output, "--size-mib", "64",
                  "--root-entries", "1024", "--offline-image"]
        preview = json.loads(self.command(*resize, "--dry-run"))
        check(not output.exists() and hmac.compare_digest(digest(source), source_hash),
              "root-growth dry run created output or changed source")
        check(preview["source_root_entries"] == 512 and preview["output_root_entries"] == 1024,
              "root-growth plan reports the wrong native capacities")
        grown = json.loads(self.command(*resize))
        check(grown["source_modified"] is False and grown["root_directory_expanded"] is True
              and grown["source_volume_bytes"] == source.stat().st_size
              and grown["relocated_clusters"] == 0 and grown["cluster_numbers_preserved"] is True,
              "root growth changed its source or native cluster identity")
        check(output.stat().st_size == 64 * 1024 * 1024,
              "root growth did not preserve the requested output length")
        slots, expanded = records(output)
        check(slots == 1024 and expanded[:len(full)] == full
              and expanded[len(full):] == bytes(len(full)),
              "root growth changed old native records or failed to add zeroed storage")
        self.command("fsck.fat", "-n", output)
        for name, expected in payloads.items():
            check(self.command("mcopy", "-i", output, f"::/{name}", "-") == expected,
                  f"native read after root growth differs: {name}")
            check(self.command(self.binary, "cat", output, f"/{name}") == expected,
                  f"FrankenFS read after root growth differs: {name}")
        bounded = self.root / "root-growth-bounded.img"
        with bounded.open("xb") as wrapped, source.open("rb") as plain:
            wrapped.write(b"P" * 4096)
            shutil.copyfileobj(plain, wrapped, 1024 * 1024)
            wrapped.write(b"S" * 4096)
        bounded_hash = digest(bounded)
        bounded_output = self.root / "root-growth-bounded-expanded.img"
        selected = json.loads(self.command(
            self.binary, "resize", bounded, "--offset", "4096", "--length", str(source.stat().st_size),
            "--output", bounded_output, "--size-mib", "64", "--root-entries", "1024", "--offline-image"))
        check(selected["source_volume_offset"] == 4096 and selected["source_modified"] is False
              and hmac.compare_digest(digest(bounded), bounded_hash)
              and hmac.compare_digest(digest(bounded_output), digest(output)),
              "bounded root growth changed sentinels or included neighboring storage")
        self.command("fsck.fat", "-n", bounded_output)
        self.command("mcopy", "-i", output, payload, "::/MORE.BIN")
        check(self.command(self.binary, "cat", output, "/MORE.BIN") == expected_payload,
              "native creation did not use the expanded root correctly")
        self.command("fsck.fat", "-n", output)
        created = json.loads(self.command(self.binary, "replace", output, "/FFSNEW.BIN",
                                         "--source", payload, "--create", "--offline-image"))
        check(created["created_new_file"] is True, "FrankenFS did not create in the expanded root")
        check(self.command("mcopy", "-i", output, "::/FFSNEW.BIN", "-") == expected_payload,
              "native tools cannot read FrankenFS creation in the expanded root")
        self.command("fsck.fat", "-n", output)
        before_refusal = digest(output)
        self.command(*resize, expected_returncode=1)
        refusal = self.root / f"command-{self.sequence:03d}.stderr"
        check(b"output already exists" in refusal.read_bytes().lower(),
              "repeated root growth failed for a reason other than existing output")
        check(hmac.compare_digest(digest(output), before_refusal)
              and hmac.compare_digest(digest(source), source_hash)
              and hmac.compare_digest(digest(original), original_hash),
              "root growth or refusal changed an existing source/output")
        for name, expected in payloads.items():
            check(self.command("mcopy", "-i", output, f"::/{name}", "-") == expected,
                  f"new writes damaged a preserved file after root growth: {name}")
        checked = json.loads(self.command(self.binary, "check", output))
        check(checked["clean"] is True and checked["complete"] is True and
              checked["namespace_complete"] is True, "expanded native root failed final verification")
        facade_payloads = {**payloads, "MORE.BIN": expected_payload, "FFSNEW.BIN": expected_payload}
        facade_reads = self.public_reads(self.facade, output, facade_payloads) if self.facade else None
        return {"filled_native_slots": free, "source_root_entries": 512, "output_root_entries": 1024,
                "source_sha256": source_hash, "bounded_sha256": bounded_hash,
                "facade_reads": facade_reads,
                "output_sha256": before_refusal, "preserved_files": len(payloads), "result": "passed"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="already-built ffs-fat executable")
    parser.add_argument("--facade-binary", type=Path,
                        help="also execute the public ffs native_reader on plain/bounded images")
    parser.add_argument("--mounted", action="store_true", help="require actual FUSE reads and EROFS refusal")
    parser.add_argument("--writable-mounted", action="store_true",
                        help="also require native/FUSE writable round trips for both dialects and sector sizes")
    parser.add_argument("--protected-mounted", action="store_true",
                        help="also require sidecar-backed writable and fresh read-only mounts for both dialects")
    parser.add_argument("--maintenance-mounted", action="store_true",
                        help="also require native grow/shrink/relocation/root-growth output mounts")
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
    facade = args.facade_binary.resolve(strict=True) if args.facade_binary else None
    if facade:
        check(os.access(facade, os.X_OK), "public facade consumer is not executable")
    tools = ["mkfs.fat", "fsck.fat", "mcopy", "mmd"]
    if facade or args.writable_mounted or args.protected_mounted or args.maintenance_mounted:
        tools.append("mdir")
    if args.maintenance_mounted:
        tools.append("mdel")
    if args.mounted or args.writable_mounted or args.protected_mounted or args.maintenance_mounted:
        tools.append("fusermount3")
        check(Path("/dev/fuse").exists(), "--mounted requires /dev/fuse; no skip credit")
    for tool in tools:
        check(shutil.which(tool) is not None, f"required native oracle tool is missing: {tool}")
    root = Path(tempfile.mkdtemp(prefix="ffs-fat-native-"))
    print(f"Retaining native images and command logs in {root}", flush=True)
    run = Run(binary, root, facade)
    report = {"status": "running", "candidate_sha256": digest(binary), "native_tool_locale": native_locale,
              "tool_paths": {tool: shutil.which(tool) for tool in tools},
              "scenarios": []}
    if facade:
        report["facade_sha256"] = digest(facade)
    try:
        if args.maintenance_mounted:
            for bits in (16, 32):
                for sector, bounded in ((512, False), (4096, True)):
                    scenario = run.maintenance(bits, sector, bounded)
                    report["scenarios"].append(scenario)
                    print(json.dumps(scenario), flush=True)
        if args.protected_mounted:
            for bits in (16, 32):
                scenario = run.protected(bits)
                report["scenarios"].append(scenario)
                print(json.dumps(scenario), flush=True)
        if args.writable_mounted:
            for bits in (16, 32):
                for sector, bounded in ((512, False), (4096, True)):
                    scenario = run.writable(bits, sector, bounded)
                    report["scenarios"].append(scenario)
                    print(json.dumps(scenario), flush=True)
        for bits in (16, 32):
            scenario = run.dialect(bits, args.mounted or args.writable_mounted or args.protected_mounted or args.maintenance_mounted)
            report["scenarios"].append(scenario)
            print(json.dumps(scenario), flush=True)
            formatted = run.formatted(bits, args.mounted or args.writable_mounted or args.protected_mounted or args.maintenance_mounted)
            report["scenarios"].append(formatted)
            print(json.dumps(formatted), flush=True)
            populated = run.populated(bits, args.mounted or args.writable_mounted or args.protected_mounted or args.maintenance_mounted)
            report["scenarios"].append(populated)
            print(json.dumps(populated), flush=True)
        complete_report(report, 6 + 4 * args.writable_mounted + 2 * args.protected_mounted
                        + 4 * args.maintenance_mounted)
    except BaseException as error:
        report.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
