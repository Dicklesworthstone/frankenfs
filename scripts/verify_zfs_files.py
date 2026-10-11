#!/usr/bin/env python3
"""Compare offline ZPL path reads against newly created native filesystems.

Requires explicit creation AND native mounting of random scratch file pools.
Never accepts existing pools/images, forces import/export, destroys a pool, or
removes evidence. The candidate only sees exported images. Missing prerequisites
or unsupported layouts are failures, not skipped successes. Build ffs-zfs first.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def listing_names(report: dict) -> set[bytes]:
    result = set()
    for entry in report["entries"]:
        name = bytes(entry["name_bytes"])
        require(bool(name) and name not in result, "empty or duplicate native directory name")
        require(b"/" not in name and b"\0" not in name, "invalid native name bytes")
        result.add(name)
    return result


def compare_stat(report: dict, expected: dict, guid: str, version: int) -> None:
    require(report["dataset_guid"] == guid and report["zpl_version"] == version,
            "candidate selected another dataset or ZPL version")
    metadata = report["metadata"]
    for key in ("object", "size", "mode", "links", "native_uid", "native_gid"):
        require(metadata[key] == expected[key], f"native stat mismatch: {key}")
    time = metadata["times_access_modify_change_create"][1]
    require(time["seconds"] * 1_000_000_000 + time["nanoseconds"] == expected["mtime_ns"],
            "native modification timestamp mismatch")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--create-and-mount-scratch-pool", action="store_true", required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    require(os.access(binary, os.X_OK), "candidate is not executable")
    for tool in ("zpool", "zfs"):
        require(shutil.which(tool) is not None, f"required native tool missing: {tool}")
    root = Path(tempfile.mkdtemp(prefix="ffs-zpl-native-"))
    print(f"Retaining all images, file oracles and logs in {root}", flush=True)
    sequence = 0
    report = {"status": "running", "candidate_sha256": digest(binary), "scenarios": []}

    def command(*argv: str | Path, fails: bool = False) -> bytes:
        nonlocal sequence
        sequence += 1
        prefix = root / f"command-{sequence:03d}"
        argv = [str(arg) for arg in argv]
        prefix.with_suffix(".argv.json").write_text(json.dumps(argv) + "\n")
        completed = subprocess.run(argv, capture_output=True, timeout=120, check=False,
                                   env={**os.environ, "LC_ALL": "C"})
        prefix.with_suffix(".stdout").write_bytes(completed.stdout)
        prefix.with_suffix(".stderr").write_bytes(completed.stderr)
        prefix.with_suffix(".status").write_text(str(completed.returncode) + "\n")
        require((completed.returncode != 0) if fails else (completed.returncode == 0),
                f"unexpected command result; see {prefix}")
        return completed.stdout

    try:
        command("zpool", "version")
        for version in (4, 5):
            directory = root / f"zpl-{version}"
            directory.mkdir()
            image = directory / "leaf.img"
            with image.open("xb") as stream:
                stream.truncate(256 * 1024 * 1024)
            mountpoint = directory / "native"
            mountpoint.mkdir()
            pool = "ffs_zpl_" + secrets.token_hex(8)
            active = False
            try:
                command("zpool", "create", "-d", "-m", "none", "-o", "cachefile=none",
                        "-o", "ashift=12", pool, image)
                active = True
                command("zfs", "create", "-o", f"version={version}", "-o", "atime=off",
                        "-o", "compression=lzjb", "-o", f"mountpoint={mountpoint}", pool + "/data")
                require(os.path.ismount(mountpoint), "native fixture was not mounted")
                pool_guid = command("zpool", "get", "-H", "-p", "-o", "value", "guid", pool).decode().strip()
                dataset_guid = command("zfs", "get", "-H", "-p", "-o", "value", "guid", pool + "/data").decode().strip()
                require(pool_guid.isdecimal() and dataset_guid.isdecimal(), "invalid native GUIDs")
                native_version = command("zfs", "get", "-H", "-p", "-o", "value", "version", pool + "/data").decode().strip()
                require(native_version == str(version), "native ZPL version differs from requested fixture")
                long_name = "long-" + "n" * 60 + ".bin"
                payload = (bytes(range(251)) * 9000)[:2 * 1024 * 1024 + 23]
                path = mountpoint / long_name
                with path.open("xb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                path.chmod(0o640)
                (mountpoint / "sub").mkdir()
                os.link(path, mountpoint / "alias.bin")
                os.link(path, mountpoint / "sub" / "nested.bin")
                os.symlink("../../outside-not-followed", mountpoint / "external-link")
                (mountpoint / "empty").touch(exist_ok=False)
                sparse_size = (1 << 32) + 17
                with (mountpoint / "sparse").open("xb") as stream:
                    stream.write(b"prefix")
                    stream.truncate(sparse_size)
                    stream.flush()
                    os.fsync(stream.fileno())
                require(path.read_bytes() == payload, "native file differs from seeded bytes")
                (directory / "payload.bin").write_bytes(payload)
                native = path.stat()
                expected = {"object": native.st_ino, "size": native.st_size, "mode": native.st_mode,
                            "links": native.st_nlink, "native_uid": native.st_uid,
                            "native_gid": native.st_gid, "mtime_ns": native.st_mtime_ns}
                names = {os.fsencode(entry.name) for entry in mountpoint.iterdir()}
                (directory / "native-stat.json").write_text(json.dumps(expected, indent=2) + "\n")
                command("zpool", "export", pool)
                active = False
                require(not os.path.ismount(mountpoint), "export left the native fixture mounted")
                before = digest(image)
                inventory = json.loads(command(binary, "inspect", image, "--offline-image"))
                require(inventory["valid_configurations"] == 4, "not all label configurations validated")
                label = next(row for row in inventory["labels"] if row["label"] == 0)
                require(label["pool_guid"] == pool_guid, "candidate pool identity differs")
                candidates = [row for row in label["candidates"] if row["txg"] >= label["config_txg"]]
                require(bool(candidates), "no exported fixture candidate")
                selected = max(candidates, key=lambda row: (row["txg"], row["timestamp"]))
                common = ["--offline-image", "--pool-guid", pool_guid, "--label", "0", "--slot", str(selected["slot"]), "--dataset", "data"]
                partitioned = directory / "partitioned.img"
                with partitioned.open("xb") as target, image.open("rb") as source:
                    target.write(b"P" * 1048576)
                    shutil.copyfileobj(source, target)
                    target.write(b"Q" * 4096)
                for backing, extra in [(image, []), (partitioned, ["--offset", "1048576", "--length", str(image.stat().st_size)])]:
                    backing_hash = digest(backing)
                    options = common + extra
                    listing = json.loads(command(binary, "ls", backing, "/", *options))
                    require(listing_names(listing) == names, "candidate root listing differs from native")
                    for name in (long_name, "alias.bin", "sub/nested.bin"):
                        stat = json.loads(command(binary, "stat", backing, "/" + name, *options))
                        compare_stat(stat, expected, dataset_guid, version)
                        require(command(binary, "read", backing, "/" + name, *options) == payload,
                                "candidate hard-linked file bytes differ")
                    require(command(binary, "read", backing, "/" + long_name, *options, "--start", "507", "--bytes", "8199") == payload[507:8706], "unaligned range differs")
                    require(command(binary, "read", backing, "/" + long_name, *options, "--start", str(len(payload)), "--bytes", "5") == b"", "read beyond EOF exposed slack")
                    require(command(binary, "read", backing, "/empty", *options) == b"", "empty file has data")
                    require(command(binary, "read", backing, "/sparse", *options, "--start", str(sparse_size - 3), "--bytes", "100") == b"\0" * 3, "sparse tail differs")
                    require(command(binary, "readlink", backing, "/external-link", *options) == b"../../outside-not-followed", "symlink bytes differ")
                    command(binary, "read", backing, "/external-link", *options, fails=True)
                    require(digest(backing) == backing_hash, "candidate modified selected or adjacent image bytes")
                require(digest(image) == before, "exported image changed")
                scenario = {"zpl_version": version, "pool_guid": pool_guid, "dataset_guid": dataset_guid,
                            "txg": selected["txg"], "image_sha256": before, "status": "passed"}
                report["scenarios"].append(scenario)
                print(json.dumps(scenario), flush=True)
            finally:
                if active:
                    command("zpool", "export", pool)  # Only our successfully created random pool.
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
