#!/usr/bin/env python3
"""Compare ffs-zfs root bytes with zdb on NEW, isolated, exported file pools.

Requires an explicit scratch-pool opt-in and already-built candidate. Never
accepts an existing image, uses force/destroy/import, mounts a dataset or deletes
evidence. The ZFS kernel and native tools must be usable; missing prerequisites
and unsupported layouts are failures, not skipped successes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import struct
import subprocess
import tempfile


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise RuntimeError(detail)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--create-scratch-pool", action="store_true", required=True,
                        help="authorize native creation/export only of the runner's new random file pools")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    require(os.access(binary, os.X_OK), "candidate is not executable")
    for tool in ("zpool", "zfs", "zdb"):
        require(shutil.which(tool) is not None, f"required native tool missing: {tool}")
    root = Path(tempfile.mkdtemp(prefix="ffs-zfs-native-"))
    print(f"Retaining images, raw root bytes and command logs in {root}", flush=True)
    sequence = 0
    report = {"status": "running", "candidate_sha256": digest(binary), "scenarios": []}

    def command(*args: str | Path) -> bytes:
        nonlocal sequence
        sequence += 1
        argv = [str(arg) for arg in args]
        prefix = root / f"command-{sequence:03d}"
        prefix.with_suffix(".argv.json").write_text(json.dumps(argv) + "\n")
        result = subprocess.run(argv, capture_output=True, timeout=120, check=False,
                                env={**os.environ, "LC_ALL": "C", "ZDB_NO_ZLE": "1"})
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        prefix.with_suffix(".status").write_text(str(result.returncode) + "\n")
        require(result.returncode == 0, f"command failed: {argv!r}; see {prefix}.stderr")
        return result.stdout

    try:
        command("zpool", "version")
        for ashift in (9, 12):
            directory = root / f"ashift-{ashift}"
            directory.mkdir()
            image = directory / "leaf.img"
            with image.open("xb") as stream:
                stream.truncate(128 * 1024 * 1024)
            pool = "ffs_probe_" + secrets.token_hex(8)
            active = False
            try:
                # No -f: this succeeds only for the newly created blank file.
                command("zpool", "create", "-d", "-m", "none", "-o", "cachefile=none",
                        "-o", f"ashift={ashift}", pool, image)
                active = True
                guid = command("zpool", "get", "-H", "-o", "value", "guid", pool).decode().strip()
                require(guid.isdecimal() and int(guid) > 0, "native pool GUID was not a decimal identity")
                command("zfs", "create", "-o", "mountpoint=none", pool + "/data")
                command("zpool", "export", pool)
                active = False
                before = digest(image)
                command("zdb", "-lu", image)
                inventory = json.loads(command(binary, "inspect", image, "--offline-image"))
                require(inventory["valid_configurations"] == 4, "candidate did not validate all four label configurations")
                label = next(item for item in inventory["labels"] if item["label"] == 0)
                require(label["pool_guid"] == guid, "candidate pool identity differs from zpool")
                stride = 1 << min(max(ashift, 10), 13)
                require(label["slot_bytes"] == stride, "candidate uberblock stride differs from ashift")
                candidates = [item for item in label["candidates"] if item["txg"] >= label["config_txg"]]
                require(bool(candidates), "no candidate matches the exported configuration generation")
                selected = max(candidates, key=lambda item: (item["txg"], item["timestamp"]))
                slot = selected["slot"]
                with image.open("rb") as stream:
                    stream.seek(128 * 1024 + slot * stride)
                    uberblock = stream.read(stride)
                order = "<" if struct.unpack_from("<Q", uberblock)[0] == 0x00BAB10C else ">"
                require(struct.unpack_from(order + "Q", uberblock)[0] == 0x00BAB10C, "native uberblock magic differs")
                bp = struct.unpack_from(order + "16Q", uberblock, 40)
                logical = ((bp[6] & 0xFFFF) + 1) * 512
                physical = (((bp[6] >> 16) & 0xFFFF) + 1) * 512
                codec = (bp[6] >> 32) & 0x7F
                vdev = (bp[0] >> 32) & 0xFFFFFF
                offset = (bp[1] & ((1 << 63) - 1)) * 512
                flags = "r" if codec == 2 else "dr"
                spec = f"{vdev:x}:{offset:x}:{logical:x}/{physical:x}:{flags}"
                expected = command("zdb", "-e", "-p", directory, "-R", pool, spec)
                require(len(expected) == logical, "zdb did not return exactly the native logical root bytes")
                actual = command(binary, "root", image, "--offline-image", "--label", "0",
                                 "--slot", str(slot), "--pool-guid", guid)
                require(actual == expected, "candidate root differs byte-for-byte from zdb")
                require(digest(image) == before, "read verification changed the exported image")
                partitioned = directory / "partitioned.img"
                with partitioned.open("xb") as target, image.open("rb") as source:
                    target.write(b"P" * 1048576)
                    shutil.copyfileobj(source, target)
                    target.write(b"Q" * 4096)
                partition_hash = digest(partitioned)
                actual = command(binary, "root", partitioned, "--offline-image", "--offset", "1048576",
                                 "--length", str(image.stat().st_size), "--label", "0", "--slot", str(slot), "--pool-guid", guid)
                require(actual == expected, "partition base changed native offset-verifier or DVA semantics")
                require(digest(partitioned) == partition_hash, "candidate changed selected or adjacent partition bytes")
                scenario = {"ashift": ashift, "pool_guid": guid, "slot": slot, "txg": selected["txg"],
                            "root_sha256": hashlib.sha256(expected).hexdigest(), "image_sha256": before,
                            "partitioned_sha256": partition_hash, "status": "passed"}
                report["scenarios"].append(scenario)
                print(json.dumps(scenario), flush=True)
            finally:
                if active:
                    # Only the exact random pool whose create succeeded here.
                    # Export, never destroy; retain the new vdev and all evidence.
                    command("zpool", "export", pool)
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
