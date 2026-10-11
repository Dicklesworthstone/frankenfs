#!/usr/bin/env python3
"""Compare ffs-zfs root bytes and DSL heads with native tools on NEW exported pools.

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
import re
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


def head_identities(report: dict, pool: str) -> dict[str, str]:
    """Do not let duplicate candidate rows disappear in a dict comprehension."""
    result = {}
    for row in report["datasets"]:
        relative = row["relative_name"]
        require(isinstance(relative, str), "native fixture name was not losslessly represented")
        name = pool + ("/" + relative if relative else "")
        require(name not in result, "candidate returned duplicate dataset names")
        require(row["objectset_kind"] == 2, "native filesystem was reported as another object-set kind")
        require(str(row["guid"]).isdecimal() and int(row["guid"]) > 0, "invalid candidate dataset GUID")
        result[name] = str(row["guid"])
    return result


def native_child_map(text: str, names: set[str]) -> tuple[dict[str, int], int]:
    """Require native multi-leaf topology and exact scalar child references.

    This intentionally recognizes the OpenZFS zdb textual format documented by
    its dump_zap/dump_zap_stats implementation. Unknown output fails, not skips.
    """
    require(text.count("Fat ZAP stats:") == 1, "native oracle did not identify one fat-ZAP")
    leaf_counts = re.findall(r"^\s*Leaf blocks:\s*([0-9]+)\s*$", text, re.MULTILINE)
    entry_counts = re.findall(r"^\s*ZAP entries:\s*([0-9]+)\s*$", text, re.MULTILINE)
    require(len(leaf_counts) == 1 and int(leaf_counts[0]) > 1,
            "native fixture is not a multi-leaf fat-ZAP; no substitute coverage")
    require(len(entry_counts) == 1 and int(entry_counts[0]) == len(names),
            "native fat-ZAP entry count differs from the seeded children")
    result = {}
    for name, value in re.findall(r"^[ \t]*([^=\r\n]+?)[ \t]*=[ \t]*([0-9]+)[ \t]*$", text, re.MULTILINE):
        require(name not in result and name in names, "duplicate or unexpected native ZAP name")
        require(0 < int(value) < 1 << 48, "native child reference is out of range")
        result[name] = int(value)
    require(set(result) == names, "native fat-ZAP dump did not supply every child reference")
    return result, int(leaf_counts[0])


def candidate_child_map(report: dict) -> dict[str, int]:
    result = {}
    for entry in report["entries"]:
        name = entry["name"]
        require(isinstance(name, str) and list(name.encode("utf-8")) == entry["name_bytes"],
                "candidate altered the native child-name bytes")
        require(name not in result, "candidate returned a duplicate ZAP key")
        values = entry["values"]
        require(type(entry["integer_bytes"]) is int and entry["integer_bytes"] == 8
                and isinstance(values, list) and len(values) == 1
                and type(values[0]) is int and 0 < values[0] < 1 << 48,
                "candidate child value is not exactly one native uint64 reference")
        result[name] = values[0]
    return result


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
                command("zfs", "create", "-o", "mountpoint=none", pool + "/data/nested")
                # Names larger than a micro-ZAP slot force a real fat-ZAP;
                # enough native entries force multiple default-sized leaves.
                children = {"nested"}
                for index in range(128):
                    child = f"child_{index:03d}_" + "long_native_name_" * 5
                    command("zfs", "create", "-o", "mountpoint=none", pool + "/data/" + child)
                    children.add(child)
                native_heads = {}
                rows = command("zfs", "list", "-H", "-r", "-t", "filesystem,volume", "-o", "name,guid", pool)
                for row in rows.decode("utf-8", errors="strict").splitlines():
                    name, identity = row.split("\t")
                    require(name not in native_heads and identity.isdecimal(), "invalid native dataset identity listing")
                    native_heads[name] = identity
                require(set(native_heads) == {pool, pool + "/data"} | {pool + "/data/" + child for child in children},
                        "native dataset fixture incomplete")
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
                heads = json.loads(command(binary, "datasets", image, "--offline-image", "--label", "0",
                                           "--slot", str(slot), "--pool-guid", guid))
                require(head_identities(heads, pool) == native_heads, "candidate DSL names/GUIDs differ from native zfs list")
                require(heads["txg"] == selected["txg"], "candidate DSL view changed the selected TXG")
                data_dir = next(row["directory_object"] for row in heads["datasets"] if row["relative_name"] == "data")
                dnode = json.loads(command(binary, "object", image, str(data_dir), "--offline-image",
                                          "--label", "0", "--slot", str(slot), "--pool-guid", guid))
                require(dnode["bonus_type"] == 12 and len(dnode["bonus"]) == 256,
                        "candidate returned an invalid DSL directory bonus")
                require(dnode["byte_order"] in ("Little", "Big"), "unknown DSL directory byte order")
                child_object = int.from_bytes(bytes(dnode["bonus"])[32:40], dnode["byte_order"].lower())
                require(0 < child_object < 1 << 48, "missing or invalid native DSL child map")
                # Pool (no trailing slash) selects the MOS in native zdb. The
                # candidate nominates an object ID; zdb independently verifies
                # its topology and every native name -> object-number mapping.
                native_dump = command("zdb", "-e", "-p", directory, "-dddd", pool, str(child_object))
                native_map, native_leaves = native_child_map(native_dump.decode("utf-8", errors="strict"), children)
                mapping = json.loads(command(binary, "zap", image, str(child_object), "--offline-image",
                                             "--label", "0", "--slot", str(slot), "--pool-guid", guid))
                require(candidate_child_map(mapping) == native_map, "candidate fat-ZAP differs from native zdb")
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
                heads = json.loads(command(binary, "datasets", partitioned, "--offline-image", "--offset", "1048576",
                                           "--length", str(image.stat().st_size), "--label", "0", "--slot", str(slot), "--pool-guid", guid))
                require(head_identities(heads, pool) == native_heads, "partition base changed DSL identities")
                mapping = json.loads(command(binary, "zap", partitioned, str(child_object), "--offline-image",
                                             "--offset", "1048576", "--length", str(image.stat().st_size),
                                             "--label", "0", "--slot", str(slot), "--pool-guid", guid))
                require(candidate_child_map(mapping) == native_map, "partition base changed native fat-ZAP values")
                require(digest(partitioned) == partition_hash, "candidate changed selected or adjacent partition bytes")
                scenario = {"ashift": ashift, "pool_guid": guid, "slot": slot, "txg": selected["txg"],
                            "root_sha256": hashlib.sha256(expected).hexdigest(), "image_sha256": before,
                            "partitioned_sha256": partition_hash, "datasets": native_heads,
                            "fat_zap_object": child_object, "fat_zap_native_leaves": native_leaves,
                            "fat_zap_children": len(native_map), "status": "passed"}
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
