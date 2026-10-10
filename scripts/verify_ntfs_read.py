#!/usr/bin/env python3
"""Compare a built ffs-ntfs with ntfs-3g tools on a NEW retained scratch image.

This does not build Rust, mount a filesystem, or modify any existing image.
Missing tools and unsupported native layouts are failures, never skip credit.
Native tools must actually create ATTRIBUTE_LIST-backed named streams; a
single-record substitute is not accepted as extension-record coverage.
Additional fresh images require native compressed DATA at 512- and 4096-byte
cluster sizes, with storage reduction observed in independently read MFT bytes.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise RuntimeError(detail)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def native_extension_records(value: bytes, base_record: int, names: set[str]) -> list[int]:
    """Inspect the list returned by ntfscat, not candidate-generated metadata."""
    require(bool(value), "native oracle returned an empty ATTRIBUTE_LIST")
    offset = 0
    named_records: dict[str, int] = {}
    while offset < len(value):
        require(len(value) - offset >= 26, "truncated native attribute-list header")
        kind, length, count, start, vcn, reference, _ = struct.unpack_from("<IHBBQQH", value, offset)
        require(length >= 32 and length % 8 == 0 and offset + length <= len(value),
                "invalid native attribute-list boundary")
        require(count == 0 or (start >= 26 and start + count * 2 <= length),
                "native attribute-list name crosses its entry")
        raw_name = value[offset + start:offset + start + count * 2] if count else b""
        name = raw_name.decode("utf-16-le", errors="strict")
        if kind == 0x80 and vcn == 0 and name in names:
            require(name not in named_records, "native list has duplicate starting DATA entries")
            named_records[name] = reference & 0x0000FFFFFFFFFFFF
        offset += length
    require(names <= named_records.keys(), "native list omitted seeded named streams")
    records = sorted({record for record in named_records.values() if record != base_record})
    require(bool(records), "native fixture did not put named streams in extension records")
    return records


def native_compressed_allocation(mft: bytes, boot: bytes, number: int, expected_size: int) -> int:
    """Check a fresh fixture's unnamed DATA using ntfscat's raw MFT stream."""
    sector = struct.unpack_from("<H", boot, 11)[0]
    cluster = sector * boot[13]
    encoded = struct.unpack_from("<b", boot, 64)[0]
    require(-16 <= encoded <= 127 and encoded != 0, "invalid native FILE record size")
    size = 1 << -encoded if encoded < 0 else encoded * cluster
    require(512 <= size <= 65536 and size % 512 == 0, "unsupported native FILE record size")
    raw = bytearray(mft[number * size:(number + 1) * size])
    require(len(raw) == size and raw[:4] == b"FILE", "native MFT did not return the seeded record")
    usa, count = struct.unpack_from("<HH", raw, 4)
    require(count == size // 512 + 1 and 48 <= usa and usa + count * 2 <= 510,
            "invalid native update-sequence array")
    saved = bytes(raw[usa:usa + count * 2])
    for index in range(1, count):
        end = index * 512
        require(raw[end - 2:end] == saved[:2], "torn record in native compression fixture")
        raw[end - 2:end] = saved[index * 2:index * 2 + 2]
    used = struct.unpack_from("<I", raw, 24)[0]
    position = struct.unpack_from("<H", raw, 20)[0]
    require(usa + count * 2 <= position <= used <= size, "invalid native record bounds")
    while position + 4 <= used:
        kind = struct.unpack_from("<I", raw, position)[0]
        if kind == 0xFFFFFFFF:
            break
        require(position + 24 <= used, "truncated native attribute header")
        length = struct.unpack_from("<I", raw, position + 4)[0]
        require(length >= 24 and length % 8 == 0 and position + length <= used,
                "invalid native attribute boundary")
        if kind == 0x80 and raw[position + 9] == 0:
            require(raw[position + 8] == 1 and length >= 72, "compression fixture DATA is resident")
            flags = struct.unpack_from("<H", raw, position + 12)[0]
            unit = struct.unpack_from("<H", raw, position + 34)[0]
            require(flags & 0xFF == 1 and flags & 0x4000 == 0 and unit == 4,
                    "native tools did not create an ordinary LZNT1 DATA stream")
            require(struct.unpack_from("<Q", raw, position + 16)[0] == 0,
                    "seeded DATA initial extent is not in its base record")
            logical = struct.unpack_from("<Q", raw, position + 48)[0]
            physical = struct.unpack_from("<Q", raw, position + 64)[0]
            require(logical == expected_size and 0 < physical < logical,
                    "native nonzero fixture has no actual compression savings")
            return physical
        position += length
    raise RuntimeError("native MFT fixture has no unnamed compressed DATA")


def compressed_cases(command: Callable[..., bytes], binary: Path, root: Path) -> list[dict[str, object]]:
    results = []
    for cluster in (512, 4096):
        unit = 16 * cluster
        image = root / f"compressed-{cluster}.img"
        with image.open("xb") as target:
            target.truncate(64 * 1024 * 1024)
        command("mkntfs", "-F", "-Q", "-C", "-s", "512", "-c", str(cluster), image)
        payloads = {
            "dense.bin": b"ABCD" * (unit * 3 // 4) + b"Z" * 37,
            "mixed.bin": hashlib.shake_256(b"native NTFS raw unit").digest(unit)
                         + bytes(unit) + b"K" * unit + b"tail" * 253,
        }
        for name, expected in payloads.items():
            source = root / f"compressed-{cluster}-{name}"
            source.write_bytes(expected)
            command("ntfscp", image, source, "/" + name)
        before = digest(image)
        listing = command("ntfsls", "-a", "-i", image).decode("utf-8", errors="strict")
        records = {}
        for line in listing.splitlines():
            match = re.fullmatch(r"\s*(\d+)\s+(.+?)\s*", line)
            if match:
                records[match[2]] = int(match[1])
        require(set(payloads) <= records.keys(), "native compressed fixture names are missing")
        with image.open("rb") as source:
            boot = source.read(512)
        native_mft = command("ntfscat", "-i", "0", image)
        allocated = native_compressed_allocation(native_mft, boot, records["dense.bin"], len(payloads["dense.bin"]))
        for name, expected in payloads.items():
            record = str(records[name])
            require(command("ntfscat", "-i", record, image) == expected,
                    f"native compressed oracle differs: {cluster} {name}")
            require(command(binary, "cat", image, record, "--offline-image") == expected,
                    f"candidate compressed numeric read differs: {cluster} {name}")
            require(command(binary, "read", image, "/" + name, "--offline-image") == expected,
                    f"candidate compressed path read differs: {cluster} {name}")
            for start in (507, 4090, unit - 3, unit * 2 - 3, len(expected) - 3, len(expected)):
                require(command(binary, "read", image, "/" + name, "--offline-image",
                                "--start", str(start), "--bytes", "1031") == expected[start:start + 1031],
                        f"candidate compressed range differs: {cluster} {name} at {start}")
        require(digest(image) == before, "compressed reads changed the native image")
        results.append({"cluster_bytes": cluster, "image_sha256": before,
                        "dense_physical_bytes": allocated, "files_checked": len(payloads),
                        "native_mft_sha256": hashlib.sha256(native_mft).hexdigest()})
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="already-built ffs-ntfs executable")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    require(os.access(binary, os.X_OK), "candidate is not executable")
    tools = ["mkntfs", "ntfscp", "ntfsls", "ntfscat"]
    for tool in tools:
        require(shutil.which(tool) is not None, f"missing required native oracle: {tool}")
    root = Path(tempfile.mkdtemp(prefix="ffs-ntfs-native-"))
    print(f"Retaining images and command evidence in {root}", flush=True)
    sequence = 0
    report = {"status": "running", "candidate_sha256": digest(binary),
              "tools": {tool: shutil.which(tool) for tool in tools}, "streams_checked": []}

    def command(*args: str | Path) -> bytes:
        nonlocal sequence
        sequence += 1
        argv = [str(arg) for arg in args]
        prefix = root / f"command-{sequence:03d}"
        prefix.with_suffix(".argv.json").write_text(json.dumps(argv) + "\n")
        result = subprocess.run(argv, capture_output=True, timeout=120, check=False,
                                env={**os.environ, "LC_ALL": "C"})
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        prefix.with_suffix(".status").write_text(str(result.returncode) + "\n")
        require(result.returncode == 0, f"command failed: {argv!r}; see {prefix}.stderr")
        return result.stdout

    try:
        image = root / "native.img"
        with image.open("xb") as target:
            target.truncate(64 * 1024 * 1024)
        # Force is confined to this newly created regular scratch file, never a user image.
        command("mkntfs", "-F", "-Q", "-s", "512", "-c", "4096", image)
        payloads = {"tiny.txt": b"resident!", "empty.bin": b"",
                    "large.bin": (bytes(range(251)) * 9000)[:2 * 1024 * 1024 + 37]}
        for name, payload in payloads.items():
            source = root / name
            source.write_bytes(payload)
            command("ntfscp", image, source, "/" + name)
        named = b"native alternate stream\x00\xff"
        source = root / "named.bin"
        source.write_bytes(named)
        command("ntfscp", "-N", "note", image, source, "/tiny.txt")
        # Even nonresident attribute headers for these names cannot all fit in
        # one ordinary FILE record. The independent native list below must
        # confirm actual extension references, not merely many stream names.
        extension_streams = {
            f"extension-{index:02d}": bytes((byte + index) % 256 for byte in range(256)) * (index + 1)
            for index in range(32)
        }
        for name, payload in extension_streams.items():
            source = root / f"{name}.bin"
            source.write_bytes(payload)
            command("ntfscp", "-N", name, image, source, "/tiny.txt")
        before = digest(image)
        listing = command("ntfsls", "-a", "-i", image).decode("utf-8", errors="strict")
        records = {}
        for line in listing.splitlines():
            match = re.fullmatch(r"\s*(\d+)\s+(.+?)\s*", line)
            if match:
                records[match[2]] = int(match[1])
        require(set(payloads) <= records.keys(), "native inode listing did not identify seeded files")
        raw_list = command("ntfscat", "-i", str(records["tiny.txt"]), "-a", "0x20", image)
        extension_records = native_extension_records(raw_list, records["tiny.txt"], set(extension_streams))
        info = json.loads(command(binary, "inspect", image, "--offline-image"))
        require(info["format"] == "NTFS" and info["version"] == "3.1", "wrong format/version")
        require(info["read_only"] is True and info["mft_mirror_record_zero_matches"] is True,
                "candidate did not confirm the admitted read profile")
        directory = json.loads(command(binary, "ls", image, "/", "--offline-image"))
        require(set(payloads) <= {entry["name"] for entry in directory},
                "candidate native directory index omitted seeded names")
        for name, expected in payloads.items():
            record = str(records[name])
            require(command("ntfscat", "-i", record, image) == expected, f"native oracle mismatch: {name}")
            require(command(binary, "cat", image, record, "--offline-image") == expected,
                    f"candidate bytes differ: {name}")
            require(command(binary, "cat", image, record, "--offline-image", "--start", "507", "--bytes", "1031")
                    == expected[507:1538], f"candidate range differs: {name}")
            # ntfscp may create POSIX namespace entries, which this profile
            # intentionally resolves exactly rather than case-insensitively.
            folded = any(entry["name"] == name and entry["namespace"] != 0 for entry in directory)
            lookup_name = name.upper() if folded else name
            require(command(binary, "read", image, "/" + lookup_name, "--offline-image") == expected,
                    f"candidate namespace-aware path read differs: {name}")
            metadata = json.loads(command(binary, "record", image, record, "--offline-image"))
            require(metadata["record"] == int(record), "candidate returned a different MFT identity")
            report["streams_checked"].append({"record": int(record), "name": name, "size": len(expected)})
        record = str(records["tiny.txt"])
        require(command("ntfscat", "-i", record, "-n", "note", image) == named, "native named stream differs")
        require(command(binary, "cat", image, record, "--offline-image", "--stream", "note") == named,
                "candidate named stream differs")
        require(command(binary, "read", image, "/tiny.txt", "--offline-image", "--stream", "note") == named,
                "candidate path-selected named stream differs")
        for name, expected in extension_streams.items():
            require(command("ntfscat", "-i", record, "-n", name, image) == expected,
                    f"native extension-stream oracle differs: {name}")
            require(command(binary, "cat", image, record, "--offline-image", "--stream", name) == expected,
                    f"candidate extension stream differs: {name}")
            require(command(binary, "read", image, "/tiny.txt", "--offline-image", "--stream", name,
                            "--start", "507", "--bytes", "1031") == expected[507:1538],
                    f"candidate extension path/range differs: {name}")
            report["streams_checked"].append({"record": int(record), "stream": name, "size": len(expected)})
        require(digest(image) == before, "read operations changed the original image")
        disk = root / "partitioned.img"
        with disk.open("xb") as target, image.open("rb") as source:
            target.write(b"P" * 1048576)
            shutil.copyfileobj(source, target)
            target.write(b"Q" * 512)
        disk_before = digest(disk)
        require(command(binary, "cat", disk, str(records["large.bin"]), "--offline-image",
                        "--offset", "1048576", "--length", str(image.stat().st_size)) == payloads["large.bin"],
                "selected-partition data differs")
        require(command(binary, "read", disk, "/tiny.txt", "--offline-image", "--stream", "extension-31",
                        "--offset", "1048576", "--length", str(image.stat().st_size)) == extension_streams["extension-31"],
                "selected-partition extension stream differs")
        require(digest(disk) == disk_before, "candidate modified image or adjacent partition bytes")
        compression = compressed_cases(command, binary, root)
        report.update(status="passed", image_sha256=before, partitioned_sha256=disk_before,
                      named_stream_checked=True, directory_and_path_reads_checked=True,
                      attribute_list_sha256=hashlib.sha256(raw_list).hexdigest(),
                      native_extension_records=extension_records, extension_streams_checked=len(extension_streams),
                      compression=compression)
        print(json.dumps(report, indent=2))
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
