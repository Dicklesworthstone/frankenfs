#!/usr/bin/env python3
"""Compare snapshot and head reads against fresh native ZFS filesystems.

Explicitly opts into creating, mounting, snapshotting and exporting only new
random scratch file pools. Never imports, destroys, forces, accepts an existing
pool/image, or deletes retained evidence. Candidate reads occur after export.
Missing native tools, unsupported layouts and mismatches are failures, not skips.
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
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(part)
    return result.hexdigest()


def snapshot_identities(report: dict, pool_guid: str, dataset: str, txg: int) -> dict:
    require(report["pool_guid"] == pool_guid and report["dataset"] == dataset and report["txg"] == txg,
            "candidate snapshot inventory belongs to another pool view")
    result = {}
    guids = set()
    objects = set()
    for row in report["snapshots"]:
        name = bytes(row["name_bytes"]).decode("ascii", errors="strict")
        guid = str(row["guid"])
        cut = row["creation_txg"]
        require(name and name == row["name"] and name not in result, "invalid or duplicate snapshot name")
        require(not any(char in name for char in "/@#\0"), "invalid snapshot component")
        require(guid.isdecimal() and int(guid) > 0 and guid not in guids, "invalid or duplicate snapshot GUID")
        require(row["object"] > 0 and row["object"] not in objects, "duplicate snapshot object")
        require(row["objectset_kind"] == 2 and 0 < row["root_birth"] <= cut <= txg,
                "invalid historical root or snapshot TXG")
        result[name] = (guid, cut)
        guids.add(guid)
        objects.add(row["object"])
    return result


def listing_names(report: dict) -> set[bytes]:
    result = set()
    for row in report["entries"]:
        name = bytes(row["name_bytes"])
        require(name and name not in result and b"/" not in name and b"\0" not in name,
                "invalid or duplicate candidate directory entry")
        result.add(name)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--facade-binary", type=Path,
                        help="also execute the standalone public ffs native_reader example")
    parser.add_argument("--create-and-mount-scratch-pool", action="store_true", required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    require(os.access(binary, os.X_OK), "candidate is not executable")
    facade = args.facade_binary.resolve(strict=True) if args.facade_binary else None
    if facade:
        require(os.access(facade, os.X_OK), "public facade consumer is not executable")
    for tool in ("zpool", "zfs"):
        require(shutil.which(tool) is not None, f"required native tool missing: {tool}")
    root = Path(tempfile.mkdtemp(prefix="ffs-snapshots-native-"))
    print(f"Retaining images, snapshot oracles and command logs in {root}", flush=True)
    sequence = 0
    report = {"status": "running", "candidate_sha256": digest(binary), "scenarios": []}
    if facade:
        report["facade_sha256"] = digest(facade)

    def command(*argv: str | Path, fails: bool = False) -> bytes:
        nonlocal sequence
        sequence += 1
        prefix = root / f"command-{sequence:04d}"
        argv = [str(value) for value in argv]
        prefix.with_suffix(".argv.json").write_text(json.dumps(argv) + "\n")
        result = subprocess.run(argv, capture_output=True, timeout=120, check=False,
                                env={**os.environ, "LC_ALL": "C"})
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        prefix.with_suffix(".status").write_text(str(result.returncode) + "\n")
        require((result.returncode != 0) if fails else (result.returncode == 0),
                f"unexpected command result: {argv!r}; see {prefix}")
        if fails:
            require(result.stdout == b"", "failed snapshot selection emitted file data")
        return result.stdout

    def capture(path: Path, directory: Path, label: str) -> dict:
        payload = (path / "file.bin").read_bytes()
        stat = (path / "file.bin").stat()
        require((path / "alias.bin").read_bytes() == payload, "native hard-link bytes disagree")
        names = {os.fsencode(entry.name) for entry in path.iterdir()}
        result = {"payload": payload, "names": names, "link": os.fsencode(os.readlink(path / "link")),
                  "object": stat.st_ino, "size": stat.st_size, "mode": stat.st_mode,
                  "links": stat.st_nlink, "native_uid": stat.st_uid, "native_gid": stat.st_gid,
                  "mtime_ns": stat.st_mtime_ns}
        (directory / f"{label}-payload.bin").write_bytes(payload)
        (directory / f"{label}-stat.json").write_text(json.dumps(
            {key: value for key, value in result.items() if key not in {"payload", "names", "link"}}, indent=2) + "\n")
        return result

    def rewrite(path: Path, data: bytes) -> None:
        with path.open("r+b") as stream:
            stream.seek(0)
            stream.write(data)
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())

    try:
        command("zpool", "version")
        for version in (4, 5):
            directory = root / f"zpl-{version}"
            directory.mkdir()
            image = directory / "leaf.img"
            with image.open("xb") as stream:
                stream.truncate(256 * 1024 * 1024)
            mount = directory / "native"
            mount.mkdir()
            pool = "ffs_snapshot_" + secrets.token_hex(8)
            active = False
            try:
                command("zpool", "create", "-d", "-m", "none", "-o", "cachefile=none", "-o", "ashift=12", pool, image)
                active = True
                dataset = pool + "/data"
                command("zfs", "create", "-o", f"version={version}", "-o", "atime=off", "-o", "compression=lzjb",
                        "-o", f"mountpoint={mount}", dataset)
                require(os.path.ismount(mount), "new native dataset was not mounted")
                pool_guid = command("zpool", "get", "-Hp", "-o", "value", "guid", pool).decode().strip()
                head_guid = command("zfs", "get", "-Hp", "-o", "value", "guid", dataset).decode().strip()
                require(pool_guid.isdecimal() and head_guid.isdecimal(), "native GUIDs are invalid")
                path = mount / "file.bin"
                path.touch(exist_ok=False)
                old = (bytes(range(251)) * 8500)[:2 * 1024 * 1024 + 37]
                rewrite(path, old)
                os.link(path, mount / "alias.bin")
                os.symlink("file.bin", mount / "link")
                (mount / "gone").write_bytes(b"retained in before snapshot")
                with (mount / "sparse").open("xb") as stream:
                    stream.write(b"prefix")
                    stream.truncate((1 << 32) + 17)
                    stream.flush()
                    os.fsync(stream.fileno())
                expected = {}
                identities = {}
                for name in ("before", "after"):
                    if name == "after":
                        rewrite(path, b"SECOND\0" * 701)
                        (mount / "gone").rename(mount / "retained")
                        with (mount / "sparse").open("r+b") as stream:
                            stream.truncate(1025)
                            stream.flush()
                            os.fsync(stream.fileno())
                    command("zfs", "snapshot", dataset + "@" + name)
                    properties = command("zfs", "get", "-Hp", "-o", "property,value", "guid,createtxg", dataset + "@" + name)
                    values = dict(row.split("\t") for row in properties.decode().splitlines())
                    require(values["guid"].isdecimal() and values["createtxg"].isdecimal(), "invalid native snapshot identity")
                    identities[name] = (values["guid"], int(values["createtxg"]))
                    expected[name] = capture(mount / ".zfs" / "snapshot" / name, directory, name)
                rewrite(path, b"LIVE\x01" * 1703)
                (mount / "head-only").write_bytes(b"not in either snapshot")
                expected[None] = capture(mount, directory, "head")
                require(len({entry["payload"] for entry in expected.values()}) == 3, "fixture did not diverge across roots")
                require(len({entry["object"] for entry in expected.values()}) == 1, "fixture must reuse the same native file object")
                require((mount / ".zfs/snapshot/before/file.bin").read_bytes() == old,
                        "native before snapshot changed after live overwrites")
                command("zpool", "export", pool)
                active = False
                require(not os.path.ismount(mount), "export left the fixture mounted")
                before_hash = digest(image)
                inventory = json.loads(command(binary, "inspect", image, "--offline-image"))
                require(inventory["valid_configurations"] == 4, "candidate did not validate all labels")
                label = next(row for row in inventory["labels"] if row["label"] == 0)
                require(label["pool_guid"] == pool_guid, "candidate pool GUID mismatch")
                candidates = [row for row in label["candidates"] if row["txg"] >= label["config_txg"]]
                require(bool(candidates), "no candidate for fresh exported pool")
                selected = max(candidates, key=lambda row: (row["txg"], row["timestamp"]))
                common = ["--offline-image", "--pool-guid", pool_guid, "--label", "0", "--slot", str(selected["slot"]), "--dataset", "data"]
                partitioned = directory / "partitioned.img"
                with partitioned.open("xb") as target, image.open("rb") as source:
                    target.write(b"P" * 1048576)
                    shutil.copyfileobj(source, target)
                    target.write(b"Q" * 4096)
                for backing, extra in [(image, []), (partitioned, ["--offset", "1048576", "--length", str(image.stat().st_size)])]:
                    checksum = digest(backing)
                    options = common + extra
                    snapshots = json.loads(command(binary, "snapshots", backing, *options))
                    require(snapshot_identities(snapshots, pool_guid, "data", selected["txg"]) == identities,
                            "candidate snapshots differ from native GUIDs/creation TXGs")
                    for name in ("before", None, "after", "before"):
                        oracle = expected[name]
                        view = options + ([] if name is None else ["--snapshot", name])
                        listing = json.loads(command(binary, "ls", backing, "/", *view))
                        require(listing_names(listing) == oracle["names"], "historical listing differs from native snapshot")
                        stat = json.loads(command(binary, "stat", backing, "/file.bin", *view))
                        guid, cut = (head_guid, selected["txg"]) if name is None else identities[name]
                        require(stat["dataset_guid"] == guid and stat["view_txg"] == cut
                                and stat["txg"] == selected["txg"] and stat["snapshot"] == name
                                and stat["zpl_version"] == version, "file view identity differs from its native root")
                        for field in ("object", "size", "mode", "links", "native_uid", "native_gid"):
                            require(stat["metadata"][field] == oracle[field], f"historical stat differs: {field}")
                        time = stat["metadata"]["times_access_modify_change_create"][1]
                        require(time["seconds"] * 10**9 + time["nanoseconds"] == oracle["mtime_ns"], "historical mtime differs")
                        for file in ("file.bin", "alias.bin"):
                            require(command(binary, "read", backing, "/" + file, *view) == oracle["payload"], "historical content differs")
                        require(command(binary, "read", backing, "/file.bin", *view, "--start", "507", "--bytes", "8199") == oracle["payload"][507:8706], "historical unaligned read differs")
                        require(command(binary, "read", backing, "/file.bin", *view, "--start", str(oracle["size"]), "--bytes", "1") == b"", "historical EOF exposed slack")
                        require(command(binary, "readlink", backing, "/link", *view) == oracle["link"], "historical symlink differs")
                        if name == "before":
                            require(command(binary, "read", backing, "/sparse", *view, "--start", str((1 << 32) + 14), "--bytes", "100") == b"\0" * 3, "historical sparse tail differs")
                        if facade:
                            public = [backing, *extra, "--zfs-dataset", "data"]
                            if name is not None:
                                public += ["--zfs-snapshot", name]
                            raw_names = command(facade, *public, "list", "/")
                            require(raw_names.endswith(b"\0"), "facade listing lacks final delimiter")
                            entries = raw_names[:-1].split(b"\0")
                            require(len(entries) == len(set(entries))
                                    and set(entries) == oracle["names"] | {b".", b".."},
                                    "public facade selected another snapshot namespace")
                            require(command(facade, *public, "stat", "/file.bin")
                                    == f"zfs\tRegularFile\t{oracle['size']}\n".encode(),
                                    "public facade historical metadata differs")
                            for file in ("file.bin", "alias.bin"):
                                require(command(facade, *public, "read", "/" + file)
                                        == oracle["payload"], "public facade historical content differs")
                            require(command(facade, *public, "read", "/file.bin", "--start", "507",
                                            "--bytes", "8199") == oracle["payload"][507:8706],
                                    "public facade historical unaligned range differs")
                            require(command(facade, *public, "read", "/file.bin", "--start",
                                            str(oracle["size"]), "--bytes", "1") == b"",
                                    "public facade historical EOF exposed bytes")
                            command(facade, *public, "refuse-write", "/file.bin")
                            if name == "before":
                                require(command(facade, *public, "read", "/sparse", "--start",
                                                str((1 << 32) + 14), "--bytes", "100") == b"\0" * 3,
                                        "public facade historical sparse tail differs")
                    command(binary, "read", backing, "/file.bin", *options, "--snapshot", "missing", fails=True)
                    command(binary, "read", backing, "/gone", *options, fails=True)
                    if facade:
                        public = [backing, *extra, "--zfs-dataset", "data"]
                        command(facade, *public, "--zfs-snapshot", "missing", "read", "/file.bin", fails=True)
                        command(facade, *public, "read", "/gone", fails=True)
                    require(digest(backing) == checksum, "snapshot verification modified image or adjacent partitions")
                require(digest(image) == before_hash, "exported image changed")
                report["scenarios"].append({"zpl_version": version, "snapshots": identities,
                    "head_guid": head_guid, "txg": selected["txg"], "image_sha256": before_hash, "status": "passed"})
            finally:
                if active:
                    command("zpool", "export", pool)
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
