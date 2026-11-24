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
import secrets
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def check_required_tools(
    tools: list[str],
    which_fn: Callable[[str], str | None] = shutil.which,
) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for tool in tools:
        found = which_fn(tool)
        require(found is not None, f"required native tool missing: {tool}")
        resolved[tool] = str(found)
    return resolved


def verify_oracle_expectations(
    expectations: list[tuple[str, bytes]],
    fetch_fn: Callable[[str], bytes],
) -> int:
    require(len(expectations) > 0, "zero selected oracle expectations")
    checked = 0
    for name, expected in expectations:
        actual = fetch_fn(name)
        require(actual == expected, f"oracle expectation mismatch for {name}")
        checked += 1
    return checked


def assert_refused_without_mutation(
    target: Path,
    run_fn: Callable[[Path], subprocess.CompletedProcess[bytes]],
    expected_err: bytes,
) -> None:
    before_sha = digest(target)
    completed = run_fn(target)
    require(
        completed.returncode != 0
        and completed.stdout == b""
        and expected_err in completed.stderr,
        f"expected typed refusal containing {expected_err!r}, got rc={completed.returncode}",
    )
    require(digest(target) == before_sha, "refused candidate mutated offline image bytes")


def run_negative_controls(
    expectations: list[tuple[str, bytes]],
    fetch_fn: Callable[[str], bytes],
    binary: Path | None,
    root: Path,
) -> dict[str, object]:
    try:
        check_required_tools(
            ["zpool", "zfs", "zdb"],
            which_fn=lambda tool: None if tool == "zdb" else f"/sbin/{tool}",
        )
    except RuntimeError as err:
        require("required native tool missing: zdb" in str(err), "wrong missing-oracle error")
    else:
        raise RuntimeError("missing-oracle negative control did not fail")

    try:
        verify_oracle_expectations([], lambda _name: b"")
    except RuntimeError as err:
        require("zero selected oracle expectations" in str(err), "wrong empty-selection error")
    else:
        raise RuntimeError("empty-selection negative control did not fail")

    require(len(expectations) >= 4, "final-element negative control requires >= 4 items")
    tampered = list(expectations[:-1]) + [(expectations[-1][0], expectations[-1][1] + b"\xff")]
    try:
        verify_oracle_expectations(tampered, fetch_fn)
    except RuntimeError as err:
        require(tampered[-1][0] in str(err), "final-element mismatch did not name final item")
    else:
        raise RuntimeError("final-element mismatch negative control did not fail")

    try:
        snapshot_identities(
            {
                "pool_guid": "111",
                "dataset": "data",
                "txg": 10,
                "snapshots": [],
            },
            "222",
            "data",
            10,
        )
    except RuntimeError as err:
        require("another pool view" in str(err), "wrong snapshot_identities error")
    else:
        raise RuntimeError("snapshot_identities pool_guid mismatch did not fail")

    probe = root / "self-test-refusal.img"
    probe.write_bytes(b"ZFS_SNAPSHOT_REFUSAL_CANARY\n" * 512)
    try:
        assert_refused_without_mutation(
            probe,
            lambda _p: subprocess.CompletedProcess(["mock"], 0, b"", b""),
            b"denied",
        )
    except RuntimeError:
        pass
    else:
        raise RuntimeError("refusal validator accepted zero exit status")

    binary_checked = False
    if binary is not None:
        assert_refused_without_mutation(
            probe,
            lambda p: subprocess.run(
                [
                    str(binary),
                    "tx-write",
                    str(p),
                    "/file.bin",
                    "--data",
                    "x",
                    "--offline-image",
                    "--pool-guid",
                    "1",
                    "--label",
                    "0",
                    "--slot",
                    "0",
                ],
                capture_output=True,
                timeout=30,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            ),
            b"--allow-write",
        )
        assert_refused_without_mutation(
            probe,
            lambda p: subprocess.run(
                [
                    str(binary),
                    "tx-write",
                    str(p),
                    "/file.bin",
                    "--data",
                    "x",
                    "--offline-image",
                    "--allow-write",
                    "--pool-guid",
                    "1",
                    "--label",
                    "0",
                    "--slot",
                    "0",
                ],
                capture_output=True,
                timeout=30,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            ),
            b"Error",
        )
        assert_refused_without_mutation(
            probe,
            lambda p: subprocess.run(
                [
                    str(binary),
                    "recv",
                    str(p),
                    "--offline-image",
                    "--pool-guid",
                    "1",
                    "--label",
                    "0",
                    "--slot",
                    "0",
                    "--dataset",
                    "data/dst",
                ],
                capture_output=True,
                timeout=30,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            ),
            b"--allow-write",
        )
        assert_refused_without_mutation(
            probe,
            lambda p: subprocess.run(
                [
                    str(binary),
                    "recv-abort",
                    str(p),
                    "--offline-image",
                    "--pool-guid",
                    "1",
                    "--label",
                    "0",
                    "--slot",
                    "0",
                    "--dataset",
                    "data/dst",
                ],
                capture_output=True,
                timeout=30,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            ),
            b"--allow-write",
        )
        bad_tok = subprocess.run(
            [str(binary), "recv-token-inspect", "--token", "1-deadbeef-10-00"],
            capture_output=True,
            timeout=30,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        require(bad_tok.returncode != 0 and bad_tok.stdout == b"", "corrupt resume token must fail closed")
        assert_refused_without_mutation(
            probe,
            lambda p: subprocess.run(
                [
                    str(binary),
                    "pool-checkpoint",
                    str(p),
                    "--action",
                    "rewind",
                    "--offline-image",
                    "--pool-guid",
                    "1",
                    "--label",
                    "0",
                    "--slot",
                    "0",
                ],
                capture_output=True,
                timeout=30,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            ),
            b"--allow-write",
        )
        draid_conflict = subprocess.run(
            [
                str(binary),
                "root",
                str(probe),
                "--offline-image",
                "--auto-import",
                "--missing-draid-member",
                "1001",
            ],
            capture_output=True,
            timeout=30,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        require(
            draid_conflict.returncode != 0 and draid_conflict.stdout == b"",
            "--missing-draid-member + --auto-import must fail closed",
        )
        binary_checked = True

    return {
        "missing_oracle_refused": True,
        "empty_selection_refused": True,
        "final_element_mismatch_caught": True,
        "planted_defect_refused": True,
        "binary_refusal_checked": binary_checked,
    }


def make_tree_world_readable(root: Path) -> None:
    if not root.exists():
        return
    root.chmod(0o755)
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        for dirname in dirnames:
            target = base / dirname
            if not target.is_symlink():
                target.chmod(0o755)
        for filename in filenames:
            target = base / filename
            if not target.is_symlink():
                target.chmod(0o644)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(part)
    return result.hexdigest()


def snapshot_identities(
    report: dict,
    pool_guid: str,
    dataset: str,
    txg: int,
    expected_kind: int = 2,
) -> dict:
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
        require(row["objectset_kind"] == expected_kind and 0 < row["root_birth"] <= cut <= txg,
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
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--facade-binary", type=Path,
                        help="also execute the standalone public ffs native_reader example")
    parser.add_argument("--create-and-mount-scratch-pool", action="store_true")
    parser.add_argument("--self-test", action="store_true",
                        help="run deterministic fail-closed harness negative controls without zfs.ko")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True) if args.binary is not None else None
    if binary is not None:
        require(os.access(binary, os.X_OK), "candidate is not executable")
    facade = args.facade_binary.resolve(strict=True) if args.facade_binary else None
    if facade:
        require(os.access(facade, os.X_OK), "public facade consumer is not executable")

    if args.self_test:
        root = Path(tempfile.mkdtemp(prefix="ffs-snapshots-selftest-"))
        zvol_snap_ids = snapshot_identities(
            {
                "pool_guid": "42",
                "dataset": "vm/disk0",
                "txg": 50,
                "snapshots": [
                    {
                        "name": "s1",
                        "name_bytes": list(b"s1"),
                        "guid": "9001",
                        "object": 77,
                        "objectset_kind": 3,
                        "root_birth": 45,
                        "creation_txg": 48,
                    }
                ],
            },
            "42",
            "vm/disk0",
            50,
            expected_kind=3,
        )
        require(zvol_snap_ids == {"s1": ("9001", 48)}, "self-test failed to accept ZVOL snapshot kind=3")
        synthetic = [(f"snap-{idx}", f"snap-payload-{idx}".encode()) for idx in range(4)]
        lookup = dict(synthetic)
        summary = {
            "mode": "self-test",
            "status": "passed",
            "negative_controls": run_negative_controls(
                synthetic,
                lambda key: lookup[key],
                binary,
                root,
            ),
        }
        (root / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary), flush=True)
        return

    require(binary is not None, "--binary is required unless --self-test is passed")
    require(args.create_and_mount_scratch_pool,
            "--create-and-mount-scratch-pool is required unless --self-test is passed")
    resolved_tools = check_required_tools(["zpool", "zfs", "zdb"])
    root = Path(tempfile.mkdtemp(prefix="ffs-snapshots-native-"))
    root.chmod(0o755)
    print(f"Retaining images, snapshot oracles and command logs in {root}", flush=True)
    sequence = 0
    report = {"status": "running", "candidate_sha256": digest(binary),
              "tools": resolved_tools, "scenarios": []}
    if facade:
        report["facade_sha256"] = digest(facade)

    def command(*argv: str | Path, fails: bool = False, failure: str | None = None) -> bytes:
        nonlocal sequence
        sequence += 1
        prefix = root / f"command-{sequence:04d}"
        argv = [str(value) for value in argv]
        prefix.with_suffix(".argv.json").write_text(json.dumps(argv) + "\n")
        result = subprocess.run(argv, capture_output=True, timeout=120, check=False,
                                env={**os.environ, "LC_ALL": "C", "ZDB_NO_ZLE": "1"})
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        prefix.with_suffix(".status").write_text(str(result.returncode) + "\n")
        if failure is not None:
            err_tail = result.stderr.decode("utf-8", errors="replace").strip()[-600:]
            require(result.returncode != 0 and result.stdout == b""
                    and failure.encode() in result.stderr,
                    f"expected typed refusal containing {failure!r}: {argv!r}; see {prefix}; stderr={err_tail!r}")
        else:
            err_tail = result.stderr.decode("utf-8", errors="replace").strip()[-600:]
            require((result.returncode != 0) if fails else (result.returncode == 0),
                    f"unexpected command result: {argv!r}; see {prefix}; stderr={err_tail!r}")
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
            tx_pool = "ffs_snaptx_" + secrets.token_hex(8)
            tx_active = False
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

                # Dedicated exported scratch pool for offline native TXG mutations over a
                # snapshotted dataset + OpenZFS zdb -bccm deadlist/space-map verification
                # (strictly never importing; original `image` remains untouched).
                writable_dir = directory / "writable"
                writable_dir.mkdir()
                writable_img = writable_dir / "leaf.img"
                with writable_img.open("xb") as stream:
                    stream.truncate(256 * 1024 * 1024)
                tx_mount = directory / "tx-mount"
                tx_mount.mkdir()
                tx_create_flags = ["-d"]
                if version == 5:
                    tx_create_flags.extend([
                        "-o", "feature@async_destroy=enabled",
                        "-o", "feature@bookmarks=enabled",
                        "-o", "feature@empty_bpobj=enabled",
                        "-o", "feature@enabled_txg=enabled",
                        "-o", "feature@encryption=enabled",
                        "-o", "feature@extensible_dataset=enabled",
                        "-o", "feature@hole_birth=enabled",
                        "-o", "feature@lz4_compress=enabled",
                        "-o", "feature@spacemap_histogram=enabled",
                        "-o", "feature@spacemap_v2=enabled",
                    ])
                command("zpool", "create", *tx_create_flags, "-m", "none",
                        "-o", "cachefile=none", "-o", "ashift=12", tx_pool, writable_img)
                tx_active = True
                tx_dataset = tx_pool + "/data"
                command("zfs", "create", "-o", f"version={version}", "-o", "atime=off",
                        "-o", "compression=lzjb", "-o", f"mountpoint={tx_mount}", tx_dataset)
                require(os.path.ismount(tx_mount), "writable snapshotted scratch dataset was not mounted")
                tx_pool_guid = command("zpool", "get", "-Hp", "-o", "value", "guid", tx_pool).decode().strip()
                tx_head_guid = command("zfs", "get", "-Hp", "-o", "value", "guid", tx_dataset).decode().strip()
                require(tx_pool_guid.isdecimal() and tx_head_guid.isdecimal(), "invalid writable snapshot GUIDs")

                tx_file = tx_mount / "file.bin"
                tx_file.touch(exist_ok=False)
                rewrite(tx_file, old)
                os.link(tx_file, tx_mount / "alias.bin")
                os.symlink("file.bin", tx_mount / "link")
                (tx_mount / "gone").write_bytes(b"retained in before snapshot")
                with (tx_mount / "sparse").open("xb") as stream:
                    stream.write(b"prefix")
                    stream.truncate((1 << 32) + 17)
                    stream.flush()
                    os.fsync(stream.fileno())
                tx_expected = {}
                tx_identities = {}
                for snap_name in ("before", "after"):
                    if snap_name == "after":
                        rewrite(tx_file, b"SECOND\0" * 701)
                        (tx_mount / "gone").rename(tx_mount / "retained")
                        with (tx_mount / "sparse").open("r+b") as stream:
                            stream.truncate(1025)
                            stream.flush()
                            os.fsync(stream.fileno())
                    command("zfs", "snapshot", tx_dataset + "@" + snap_name)
                    props = command("zfs", "get", "-Hp", "-o", "property,value",
                                    "guid,createtxg", tx_dataset + "@" + snap_name)
                    vals = dict(row.split("\t") for row in props.decode().splitlines())
                    require(vals["guid"].isdecimal() and vals["createtxg"].isdecimal(),
                            "invalid writable snapshot identity")
                    tx_identities[snap_name] = (vals["guid"], int(vals["createtxg"]))
                    tx_expected[snap_name] = capture(
                        tx_mount / ".zfs" / "snapshot" / snap_name,
                        directory,
                        f"tx-{snap_name}",
                    )
                rewrite(tx_file, b"LIVE\x01" * 1703)
                (tx_mount / "head-only").write_bytes(b"not in either snapshot")
                command("zpool", "export", tx_pool)
                tx_active = False
                require(not os.path.ismount(tx_mount), "export left writable snapshotted dataset mounted")

                pre_tx_sha = digest(writable_img)
                shutil.copyfile(writable_img, directory / "tx-pre-baseline.img")
                tx_inv = json.loads(command(binary, "inspect", writable_img, "--offline-image"))
                tx_lbl = next(row for row in tx_inv["labels"] if row["label"] == 0)
                tx_cands = [row for row in tx_lbl["candidates"] if row["txg"] >= tx_lbl["config_txg"]]
                require(bool(tx_cands), "no exported candidate on writable snapshotted pool")
                tx_sel = max(tx_cands, key=lambda row: (row["txg"], row["timestamp"]))
                cur_slot = int(tx_sel["slot"])
                cur_txg = int(tx_sel["txg"])

                admit = json.loads(command(binary, "admit-write", writable_img, "--offline-image",
                                           "--pool-guid", tx_pool_guid, "--label", "0", "--slot", str(cur_slot)))
                require(admit["backing_writes"] is False and admit["admission"]["admitted_clean_write"] is True,
                        "admit-write did not report clean zero-write admission")
                require(digest(writable_img) == pre_tx_sha, "admit-write mutated exported snapshot image")

                defect_dir = directory / "planted-split-ub"
                defect_dir.mkdir()
                defect_img = defect_dir / "leaf.img"
                shutil.copyfile(writable_img, defect_img)
                with defect_img.open("r+b") as handle:
                    l3_base = defect_img.stat().st_size - 256 * 1024
                    handle.seek(l3_base + 128 * 1024 + cur_slot * 4096)
                    handle.write(b"\x00" * 16)
                defect_sha = digest(defect_img)
                command(binary, "tx-write", defect_img, "/file.bin", "--data", "denied",
                        "--offline-image", "--allow-write", "--pool-guid", tx_pool_guid,
                        "--label", "0", "--slot", str(cur_slot), "--dataset", "data",
                        failure="Uberblock")
                require(digest(defect_img) == defect_sha, "split-Uberblock refusal mutated defect image")

                def run_tx(*sub_args: str | Path, pool_guid_arg: str = tx_pool_guid) -> dict:
                    nonlocal cur_slot, cur_txg
                    out = json.loads(command(
                        binary,
                        *sub_args,
                        "--offline-image",
                        "--allow-write",
                        "--pool-guid",
                        pool_guid_arg,
                        "--label",
                        "0",
                        "--slot",
                        str(cur_slot),
                        "--dataset",
                        "data",
                    ))
                    require(out["outcome"] == "Committed" and int(out["committed_txg"]) > cur_txg,
                            f"snapshot COW TXG step {sub_args[0]!r} did not advance committed TXG")
                    cur_slot = int(out["published_slot"])
                    cur_txg = int(out["committed_txg"])
                    return out

                new_payload = (bytes(range(239)) * 310)[:70_000]
                new_payload_file = directory / "new-head-payload.bin"
                new_payload_file.write_bytes(new_payload)
                run_tx("tx-write", writable_img, "/file.bin", "--data-file", new_payload_file)
                run_tx("tx-truncate", writable_img, "/file.bin", "--size", "33333")
                run_tx("tx-rename", writable_img, "/head-only", "/head-renamed")
                run_tx("tx-unlink", writable_img, "/retained")
                run_tx("tx-create", writable_img, "/post-txg.txt", "--mode", "0644")
                run_tx("tx-write", writable_img, "/post-txg.txt",
                       "--data", "committed-after-snapshots\n", "--sha256")

                # Exercise native snapshot create, hold/release, bookmark, clone, rename, defer-destroy + auto-reclaim!
                if version == 5:
                    def run_ds_tx(ds_name: str, *sub_args: str | Path) -> dict:
                        nonlocal cur_slot, cur_txg
                        out = json.loads(command(
                            binary, *sub_args, "--offline-image", "--allow-write",
                            "--pool-guid", tx_pool_guid, "--label", "0",
                            "--slot", str(cur_slot), "--dataset", ds_name,
                        ))
                        require(out["outcome"] == "Committed" and int(out["committed_txg"]) > cur_txg,
                                f"DSL snapshot/clone step {sub_args[0]!r} did not advance committed TXG")
                        cur_slot = int(out["published_slot"])
                        cur_txg = int(out["committed_txg"])
                        return out

                    run_ds_tx("data", "tx-snapshot", writable_img, "native_s1")
                    run_ds_tx("data", "tx-hold", writable_img, "native_s1", "ci_pin")
                    holds_doc = json.loads(command(
                        binary, "holds", writable_img, "native_s1",
                        "--offline-image", "--pool-guid", tx_pool_guid, "--label", "0",
                        "--slot", str(cur_slot), "--dataset", "data",
                    ))
                    require([h["tag"] for h in holds_doc["holds"]] == ["ci_pin"],
                            "holds subcommand did not report ci_pin")
                    run_ds_tx("data", "tx-bookmark", writable_img, "native_bm1", "--snapshot", "native_s1")
                    run_ds_tx("data", "tx-clone", writable_img, "native_s1", "data/cloned_view")
                    run_ds_tx("data/cloned_view", "tx-create", writable_img, "/clone_only.txt", "--mode", "0644")
                    run_ds_tx("data/cloned_view", "tx-write", writable_img, "/clone_only.txt",
                              "--data", "diverged-clone-bytes\n")
                    require(command(binary, "read", writable_img, "/post-txg.txt",
                                    "--offline-image", "--pool-guid", tx_pool_guid, "--label", "0",
                                    "--slot", str(cur_slot), "--dataset", "data/cloned_view")
                            == b"committed-after-snapshots\n",
                            "cloned dataset lost inherited origin file")
                    run_ds_tx("data", "tx-rename-snapshot", writable_img, "native_s1", "native_s2")
                    # Held + cloned snapshot refuses non-deferred destroy, accepts --defer, and auto-destroys
                    # once hold is released and clone is destroyed!
                    command(binary, "tx-destroy-snapshot", writable_img, "native_s2",
                            "--offline-image", "--allow-write", "--pool-guid", tx_pool_guid,
                            "--label", "0", "--slot", str(cur_slot), "--dataset", "data",
                            failure="dependent clones or user holds")
                    run_ds_tx("data", "tx-destroy-snapshot", writable_img, "native_s2", "--defer")
                    run_ds_tx("data", "tx-release", writable_img, "native_s2", "ci_pin")
                    run_ds_tx("data/cloned_view", "tx-destroy-dataset", writable_img)

                    bm_doc = json.loads(command(
                        binary, "bookmarks", writable_img, "--offline-image",
                        "--pool-guid", tx_pool_guid, "--label", "0",
                        "--slot", str(cur_slot), "--dataset", "data",
                    ))
                    require([b["name"] for b in bm_doc["bookmarks"]] == ["native_bm1"],
                            "bookmark did not survive deferred origin snapshot auto-destroy")
                    run_ds_tx("data", "tx-destroy-bookmark", writable_img, "native_bm1")

                    # ZVOL snapshot, overwrite, shrink-resize, clone, read-only snapshot NBD, and clean destroy!
                    run_ds_tx(
                        "data",
                        "tx-zvol-create",
                        writable_img,
                        "snap_vol",
                        "--volsize",
                        "1M",
                        "--volblocksize",
                        "16K",
                        "--sparse",
                    )
                    v_pre = b"ZVOL_SNAP_PRE_512___" * 25 + b"0123456789AB"
                    v_post = b"ZVOL_HEAD_POST_512__" * 25 + b"ZYXWVUTSRQPO"
                    v_pre_file = directory / "zvol-pre.bin"
                    v_post_file = directory / "zvol-post.bin"
                    v_pre_file.write_bytes(v_pre)
                    v_post_file.write_bytes(v_post)
                    run_ds_tx(
                        "data/snap_vol",
                        "tx-zvol-write",
                        writable_img,
                        "--write-offset",
                        "512",
                        "--data-file",
                        v_pre_file,
                    )
                    run_ds_tx("data/snap_vol", "tx-snapshot", writable_img, "vsnap1")
                    run_ds_tx(
                        "data/snap_vol",
                        "tx-zvol-write",
                        writable_img,
                        "--write-offset",
                        "512",
                        "--data-file",
                        v_post_file,
                    )
                    run_ds_tx("data/snap_vol", "tx-zvol-resize", writable_img, "--volsize", "512K")
                    run_ds_tx(
                        "data/snap_vol",
                        "tx-clone",
                        writable_img,
                        "vsnap1",
                        "data/snap_vol_clone",
                    )
                    v_snaps = json.loads(
                        command(
                            binary,
                            "snapshots",
                            writable_img,
                            "--offline-image",
                            "--pool-guid",
                            tx_pool_guid,
                            "--label",
                            "0",
                            "--slot",
                            str(cur_slot),
                            "--dataset",
                            "data/snap_vol",
                        )
                    )
                    v_snap_ids = snapshot_identities(
                        v_snaps, tx_pool_guid, "data/snap_vol", cur_txg, expected_kind=3
                    )
                    require("vsnap1" in v_snap_ids, "ZVOL snapshot @vsnap1 missing from inventory")
                    # Strictly read-only NBD export of ZVOL snapshot refuses WRITE and serves pre-resize bytes.
                    ro_sock = directory / "zvol-snap-ro.sock"
                    ro_log = directory / "zvol-snap-ro.log"
                    ro_argv = [
                        str(binary),
                        "zvol-serve-nbd",
                        str(writable_img),
                        "--offline-image",
                        "--pool-guid",
                        tx_pool_guid,
                        "--label",
                        "0",
                        "--slot",
                        str(cur_slot),
                        "--dataset",
                        "data/snap_vol",
                        "--snapshot",
                        "vsnap1",
                        "--listen-unix",
                        str(ro_sock),
                    ]
                    with ro_log.open("wb") as rlog:
                        rproc = subprocess.Popen(ro_argv, stdout=rlog, stderr=subprocess.STDOUT)
                        try:
                            deadline = time.monotonic() + 30
                            while not ro_sock.exists():
                                require(rproc.poll() is None, f"RO zvol-serve-nbd exited early; see {ro_log}")
                                require(time.monotonic() < deadline, f"RO zvol-serve-nbd timed out; see {ro_log}")
                                time.sleep(0.05)
                            command(
                                binary,
                                "zvol-nbd-client",
                                "--connect-unix",
                                ro_sock,
                                "--export",
                                "data/snap_vol@vsnap1",
                                "write",
                                "--offset",
                                "512",
                                "--data-file",
                                v_post_file,
                                fails=True,
                            )
                            require(
                                command(
                                    binary,
                                    "zvol-nbd-client",
                                    "--connect-unix",
                                    ro_sock,
                                    "--export",
                                    "data/snap_vol@vsnap1",
                                    "read",
                                    "--offset",
                                    "512",
                                    "--bytes",
                                    "512",
                                )
                                == v_pre,
                                "RO snapshot NBD readback diverged from pre-overwrite ZVOL bytes",
                            )
                            rproc.send_signal(2)
                            require(rproc.wait(timeout=30) == 0, f"RO zvol-serve-nbd non-zero exit; see {ro_log}")
                        finally:
                            if rproc.poll() is None:
                                rproc.terminate()
                                rproc.wait(timeout=10)
                    # Destroy clone, snapshot, and volume so zdb -bccm verifies zero leaked deadlist/ZVOL blocks!
                    run_ds_tx("data/snap_vol_clone", "tx-zvol-destroy", writable_img)
                    run_ds_tx("data/snap_vol", "tx-destroy-snapshot", writable_img, "vsnap1")
                    run_ds_tx("data/snap_vol", "tx-zvol-destroy", writable_img)

                    # Native encrypted dataset snapshot lifecycle: raw keyless snapshot listing/scrub,
                    # keyed head vs snapshot readback, atomic key rotation (tx-change-key), and locked destroy!
                    with tempfile.TemporaryDirectory(prefix="ffs-zfs-snap-keys-") as snap_key_dir:
                        os.chmod(snap_key_dir, 0o700)
                        enc_key_v1 = Path(snap_key_dir) / "snap-v1.key"
                        enc_key_v2 = Path(snap_key_dir) / "snap-v2.key"
                        enc_key_v1.write_bytes(secrets.token_bytes(32))
                        enc_key_v2.write_bytes(secrets.token_bytes(32))
                        os.chmod(enc_key_v1, 0o600)
                        os.chmod(enc_key_v2, 0o600)
                        enc_v1_payload = b"ENCRYPTED_SNAPSHOT_V1_BLOCK_" * 900
                        enc_v2_payload = b"ENCRYPTED_HEAD_V2_OVERWRITE_" * 900
                        enc_v1_file = directory / "enc-snap-v1.bin"
                        enc_v2_file = directory / "enc-snap-v2.bin"
                        enc_v1_file.write_bytes(enc_v1_payload)
                        enc_v2_file.write_bytes(enc_v2_payload)

                        run_ds_tx(
                            "data", "tx-create-dataset", writable_img, "enc_snap",
                            "--encryption", "aes-256-gcm",
                            "--keylocation", "prompt",
                            "--new-key-file", enc_key_v1,
                            "--prop", "compression=lz4",
                        )
                        run_ds_tx(
                            "data/enc_snap", "tx-create", writable_img, "/secret.bin",
                            "--mode", "0640", "--key-file", enc_key_v1,
                        )
                        run_ds_tx(
                            "data/enc_snap", "tx-write", writable_img, "/secret.bin",
                            "--data-file", enc_v1_file, "--sha256", "--key-file", enc_key_v1,
                        )
                        run_ds_tx(
                            "data/enc_snap", "tx-snapshot", writable_img, "es1",
                            "--key-file", enc_key_v1,
                        )
                        run_ds_tx(
                            "data/enc_snap", "tx-write", writable_img, "/secret.bin",
                            "--data-file", enc_v2_file, "--sha256", "--key-file", enc_key_v1,
                        )
                        enc_snap_opts = [
                            "--offline-image", "--pool-guid", tx_pool_guid, "--label", "0",
                            "--slot", str(cur_slot), "--dataset", "data/enc_snap",
                        ]
                        enc_snaps = json.loads(command(binary, "snapshots", writable_img, *enc_snap_opts))
                        enc_snap_ids = snapshot_identities(enc_snaps, tx_pool_guid, "data/enc_snap", cur_txg)
                        require("es1" in enc_snap_ids, "encrypted snapshot @es1 missing from keyless inventory")
                        # Keyless raw scrub succeeds on both encrypted head and snapshot; keyless read refuses.
                        for s_extra in ([], ["--snapshot", "es1"]):
                            raw_sc = json.loads(command(binary, "scrub", writable_img, *enc_snap_opts, *s_extra))
                            require(
                                raw_sc["clean"] is True and raw_sc["key_status"] == "unavailable",
                                f"keyless encrypted snapshot scrub failed ({s_extra}): {raw_sc}",
                            )
                            command(binary, "read", writable_img, "/secret.bin", *enc_snap_opts, *s_extra, fails=True)
                        # Keyed read with v1 matches exact pre/post snapshot payloads.
                        require(
                            command(binary, "read", writable_img, "/secret.bin", *enc_snap_opts,
                                    "--snapshot", "es1", "--key-file", enc_key_v1) == enc_v1_payload,
                            "encrypted @es1 readback mismatch before change-key",
                        )
                        require(
                            command(binary, "read", writable_img, "/secret.bin", *enc_snap_opts,
                                    "--key-file", enc_key_v1) == enc_v2_payload,
                            "encrypted head readback mismatch before change-key",
                        )
                        # Rotate wrapping key v1 -> v2 and verify old key fails closed while v2 reads head + @es1!
                        run_ds_tx(
                            "data/enc_snap", "tx-change-key", writable_img,
                            "--key-file", enc_key_v1,
                            "--new-key-file", enc_key_v2,
                        )
                        enc_snap_opts = [
                            "--offline-image", "--pool-guid", tx_pool_guid, "--label", "0",
                            "--slot", str(cur_slot), "--dataset", "data/enc_snap",
                        ]
                        command(binary, "read", writable_img, "/secret.bin", *enc_snap_opts,
                                "--snapshot", "es1", "--key-file", enc_key_v1, fails=True)
                        require(
                            command(binary, "read", writable_img, "/secret.bin", *enc_snap_opts,
                                    "--snapshot", "es1", "--key-file", enc_key_v2) == enc_v1_payload,
                            "encrypted @es1 readback mismatch after change-key",
                        )
                        require(
                            command(binary, "read", writable_img, "/secret.bin", *enc_snap_opts,
                                    "--key-file", enc_key_v2) == enc_v2_payload,
                            "encrypted head readback mismatch after change-key",
                        )
                        for s_extra in ([], ["--snapshot", "es1"]):
                            keyed_sc = json.loads(
                                command(binary, "scrub", writable_img, *enc_snap_opts, *s_extra,
                                        "--key-file", enc_key_v2)
                            )
                            require(
                                keyed_sc["clean"] is True and keyed_sc["key_status"] == "available",
                                f"keyed encrypted snapshot scrub failed ({s_extra}): {keyed_sc}",
                            )
                        # Locked keyless destroy of encrypted snapshot + dataset so zdb -bccm verifies zero leaks!
                        # First, prove bidirectional OpenZFS send/receive + keyless raw encrypted (-w) + resumable recv!
                        sr_dir = directory / "send-recv-oracle"
                        sr_dir.mkdir()
                        sr_img = sr_dir / "sr.img"
                        sr_img.write_bytes(b"\0" * (96 * 1024 * 1024))
                        sr_pool = f"ffssr_{secrets.token_hex(6)}"
                        sr_mount = sr_dir / "mnt"
                        sr_mount.mkdir()
                        sr_active = False
                        try:
                            command("zpool", "create", "-f", "-m", "none", "-R", str(sr_mount), sr_pool, str(sr_img))
                            sr_active = True

                            # Direction A1: ffs-zfs send (full + incremental) -> OpenZFS zfs recv!
                            ffs_full_stream = sr_dir / "ffs-data-before.zfs"
                            ffs_incr_stream = sr_dir / "ffs-data-after.zfs"
                            send_rep_full = json.loads(command(
                                binary, "send", writable_img,
                                "--offline-image", "--pool-guid", tx_pool_guid, "--label", "0",
                                "--slot", str(cur_slot), "--dataset", "data",
                                "--snapshot", "before", "--out", ffs_full_stream,
                            ))
                            require(send_rep_full["report"]["substreams_sent"] == 1, f"bad ffs send report: {send_rep_full}")
                            send_rep_incr = json.loads(command(
                                binary, "send", writable_img,
                                "--offline-image", "--pool-guid", tx_pool_guid, "--label", "0",
                                "--slot", str(cur_slot), "--dataset", "data",
                                "--snapshot", "after", "--from-snapshot", "before",
                                "--out", ffs_incr_stream,
                            ))
                            require(send_rep_incr["report"]["substreams_sent"] == 1, f"bad ffs incr send report: {send_rep_incr}")

                            proc_recv1 = subprocess.run(
                                ["zfs", "recv", f"{sr_pool}/from_ffs"],
                                input=ffs_full_stream.read_bytes(),
                                capture_output=True, timeout=60, check=False,
                            )
                            require(proc_recv1.returncode == 0, f"OpenZFS zfs recv of ffs-zfs full stream failed: {proc_recv1.stderr.decode('utf-8', 'replace')}")
                            proc_recv2 = subprocess.run(
                                ["zfs", "recv", f"{sr_pool}/from_ffs"],
                                input=ffs_incr_stream.read_bytes(),
                                capture_output=True, timeout=60, check=False,
                            )
                            require(proc_recv2.returncode == 0, f"OpenZFS zfs recv of ffs-zfs incremental stream failed: {proc_recv2.stderr.decode('utf-8', 'replace')}")
                            command("zfs", "set", "mountpoint=/from_ffs", f"{sr_pool}/from_ffs")
                            command("zfs", "mount", f"{sr_pool}/from_ffs")
                            require((sr_mount / "from_ffs" / "file.bin").read_bytes() == tx_expected["after"]["payload"],
                                    "OpenZFS mount readback of ffs-zfs incremental stream mismatched @after")

                            # Direction A2: keyless raw encrypted ffs-zfs send -w -> OpenZFS zfs recv + load-key!
                            ffs_raw_stream = sr_dir / "ffs-enc-raw.zfs"
                            raw_rep = json.loads(command(
                                binary, "send", writable_img,
                                "--offline-image", "--pool-guid", tx_pool_guid, "--label", "0",
                                "--slot", str(cur_slot), "--dataset", "data/enc_snap",
                                "--snapshot", "es1", "--raw", "--out", ffs_raw_stream,
                            ))
                            require(raw_rep["report"]["raw"] is True, f"raw send flag missing: {raw_rep}")
                            proc_raw = subprocess.run(
                                ["zfs", "recv", f"{sr_pool}/enc_from_ffs"],
                                input=ffs_raw_stream.read_bytes(),
                                capture_output=True, timeout=60, check=False,
                            )
                            require(proc_raw.returncode == 0, f"OpenZFS zfs recv of ffs-zfs raw -w stream failed: {proc_raw.stderr.decode('utf-8', 'replace')}")
                            command("zfs", "load-key", "-L", f"file://{enc_key_v2}", f"{sr_pool}/enc_from_ffs")
                            command("zfs", "set", "mountpoint=/enc_from_ffs", f"{sr_pool}/enc_from_ffs")
                            command("zfs", "mount", f"{sr_pool}/enc_from_ffs")
                            require((sr_mount / "enc_from_ffs" / "secret.bin").read_bytes() == enc_v1_payload,
                                    "OpenZFS decrypted readback of ffs-zfs raw -w stream mismatched @es1")

                            # Direction B: OpenZFS zfs send (full, incremental, bookmark, raw -w, ZVOL) -> ffs-zfs recv
                            # plus interrupted resumable (-s) receive, recv-token-inspect, and recv-abort!
                            command("zfs", "create", "-o", "mountpoint=/oz_src", "-o", "compression=lz4",
                                    "-o", "app:origin=openzfs", f"{sr_pool}/oz_src")
                            oz_v1 = b"OPENZFS_SEND_V1_PAYLOAD_" * 1400
                            oz_v2 = b"OPENZFS_SEND_V2_UPDATED_" * 1200
                            (sr_mount / "oz_src" / "alpha.bin").write_bytes(oz_v1)
                            (sr_mount / "oz_src" / "drop.txt").write_bytes(b"drop-in-o2")
                            command("zfs", "snapshot", f"{sr_pool}/oz_src@o1")
                            command("zfs", "bookmark", f"{sr_pool}/oz_src@o1", f"{sr_pool}/oz_src#obm1")
                            (sr_mount / "oz_src" / "alpha.bin").write_bytes(oz_v2)
                            (sr_mount / "oz_src" / "drop.txt").unlink()
                            (sr_mount / "oz_src" / "beta.txt").write_bytes(b"added-in-o2")
                            command("zfs", "snapshot", f"{sr_pool}/oz_src@o2")

                            oz_full = sr_dir / "oz-full.zfs"
                            oz_incr = sr_dir / "oz-incr.zfs"
                            oz_full.write_bytes(command("zfs", "send", "-c", "-e", "-p", f"{sr_pool}/oz_src@o1"))
                            oz_incr.write_bytes(command("zfs", "send", "-c", "-e", "-i", f"{sr_pool}/oz_src#obm1", f"{sr_pool}/oz_src@o2"))

                            # Raw encrypted OpenZFS source dataset -> keyless ffs-zfs recv!
                            command(
                                "zfs", "create", "-o", "mountpoint=/oz_enc",
                                "-o", "encryption=aes-256-gcm", "-o", "keyformat=raw",
                                "-o", f"keylocation=file://{enc_key_v2}", f"{sr_pool}/oz_enc",
                            )
                            oz_enc_payload = b"OPENZFS_RAW_ENCRYPTED_SEND_" * 800
                            (sr_mount / "oz_enc" / "vault.bin").write_bytes(oz_enc_payload)
                            command("zfs", "snapshot", f"{sr_pool}/oz_enc@oe1")
                            oz_raw = sr_dir / "oz-raw.zfs"
                            oz_raw.write_bytes(command("zfs", "send", "-w", f"{sr_pool}/oz_enc@oe1"))

                            # Resumable (-s) interrupt -> recv-token-inspect -> OpenZFS zfs send -t -> ffs-zfs recv -s!
                            oz_trunc = sr_dir / "oz-full-trunc.zfs"
                            oz_full_bytes = oz_full.read_bytes()
                            oz_trunc.write_bytes(oz_full_bytes[: max(4096, len(oz_full_bytes) // 2)])
                            command(
                                binary, "recv", writable_img,
                                "--offline-image", "--allow-write", "--pool-guid", tx_pool_guid,
                                "--label", "0", "--slot", str(cur_slot), "--dataset", "data/oz_resumed",
                                "--in", oz_trunc, "-s", "--checkpoint-bytes", "4096",
                                fails=True,
                            )
                            # Refresh committed slot from label 0 after resumable checkpoints!
                            ref_inv = json.loads(command(binary, "inspect", writable_img, "--offline-image"))
                            ref_lbl = next(r for r in ref_inv["labels"] if r["label"] == 0)
                            ref_sel = max(
                                (r for r in ref_lbl["candidates"] if r["txg"] >= ref_lbl["config_txg"]),
                                key=lambda r: (r["txg"], r["timestamp"]),
                            )
                            cur_slot = int(ref_sel["slot"])
                            cur_txg = int(ref_sel["txg"])
                            tok_doc = json.loads(command(
                                binary, "recv-token-inspect", writable_img,
                                "--offline-image", "--pool-guid", tx_pool_guid, "--label", "0",
                                "--slot", str(cur_slot), "--dataset", "data/oz_resumed",
                            ))
                            resume_state = tok_doc["resume_state"]
                            require(resume_state is not None and resume_state["token"].startswith("1-"),
                                    f"expected persisted receive_resume_token, got {tok_doc}")
                            offline_tok = json.loads(command(
                                binary, "recv-token-inspect", "--token", resume_state["token"],
                            ))
                            require(offline_tok["toguid"] == resume_state["toguid"]
                                    and offline_tok["object"] == resume_state["object"],
                                    f"offline recv-token-inspect mismatch: {offline_tok}")

                            # Cross-implementation resume: OpenZFS `zfs send -t <ffs_token>` -> `ffs-zfs recv -s`!
                            oz_cont = sr_dir / "oz-cont.zfs"
                            oz_cont.write_bytes(command("zfs", "send", "-t", resume_state["token"]))
                            res_done = run_ds_tx(
                                "data/oz_resumed", "recv", writable_img,
                                "--in", oz_cont, "-s", "--checkpoint-bytes", "4096",
                            )
                            require(res_done["report"]["resumed"] is True, f"resumed flag false: {res_done}")
                            # Now apply OpenZFS bookmark incremental stream (#obm1 -> @o2)!
                            run_ds_tx("data/oz_resumed", "recv", writable_img, "--in", oz_incr)
                            oz_opts = [
                                "--offline-image", "--pool-guid", tx_pool_guid, "--label", "0",
                                "--slot", str(cur_slot), "--dataset", "data/oz_resumed",
                            ]
                            require(command(binary, "read", writable_img, "/alpha.bin", *oz_opts, "--snapshot", "o1") == oz_v1,
                                    "received OpenZFS @o1 alpha.bin mismatch")
                            require(command(binary, "read", writable_img, "/alpha.bin", *oz_opts) == oz_v2,
                                    "received OpenZFS @o2 alpha.bin mismatch")
                            require(command(binary, "read", writable_img, "/beta.txt", *oz_opts) == b"added-in-o2",
                                    "received OpenZFS @o2 beta.txt mismatch")
                            command(binary, "read", writable_img, "/drop.txt", *oz_opts, fails=True)

                            # Receive OpenZFS raw encrypted stream keylessly, then unlock & read with key!
                            run_ds_tx("data/oz_enc_recv", "recv", writable_img, "--in", oz_raw)
                            oz_enc_opts = [
                                "--offline-image", "--pool-guid", tx_pool_guid, "--label", "0",
                                "--slot", str(cur_slot), "--dataset", "data/oz_enc_recv",
                            ]
                            command(binary, "read", writable_img, "/vault.bin", *oz_enc_opts, fails=True)
                            require(command(binary, "read", writable_img, "/vault.bin", *oz_enc_opts,
                                            "--key-file", enc_key_v2) == oz_enc_payload,
                                    "OpenZFS raw encrypted stream received by ffs-zfs failed keyed readback")

                            # Also exercise recv-abort on an interrupted resumable receive!
                            command(
                                binary, "recv", writable_img,
                                "--offline-image", "--allow-write", "--pool-guid", tx_pool_guid,
                                "--label", "0", "--slot", str(cur_slot), "--dataset", "data/oz_aborted",
                                "--in", oz_trunc, "-s", "--checkpoint-bytes", "4096",
                                fails=True,
                            )
                            ref_inv2 = json.loads(command(binary, "inspect", writable_img, "--offline-image"))
                            ref_lbl2 = next(r for r in ref_inv2["labels"] if r["label"] == 0)
                            ref_sel2 = max(
                                (r for r in ref_lbl2["candidates"] if r["txg"] >= ref_lbl2["config_txg"]),
                                key=lambda r: (r["txg"], r["timestamp"]),
                            )
                            cur_slot = int(ref_sel2["slot"])
                            cur_txg = int(ref_sel2["txg"])
                            abort_doc = run_ds_tx("data/oz_aborted", "recv-abort", writable_img)
                            require(abort_doc["reclaimed_bytes"] > 0, f"recv-abort reclaimed 0 bytes: {abort_doc}")

                            # Clean up temporary received datasets (plus enc_snap) before zdb -bccm leak check!
                            run_ds_tx("data/oz_resumed", "tx-destroy-snapshot", writable_img, "o2")
                            run_ds_tx("data/oz_resumed", "tx-destroy-snapshot", writable_img, "o1")
                            run_ds_tx("data/oz_resumed", "tx-destroy-dataset", writable_img)
                            run_ds_tx("data/oz_enc_recv", "tx-destroy-snapshot", writable_img, "oe1")
                            run_ds_tx("data/oz_enc_recv", "tx-destroy-dataset", writable_img)
                        finally:
                            if sr_active:
                                command("zpool", "export", sr_pool)

                        run_ds_tx("data/enc_snap", "tx-destroy-snapshot", writable_img, "es1")
                        run_ds_tx("data/enc_snap", "tx-destroy-dataset", writable_img)

                command("zdb", "-lu", writable_img)
                bccm_text = command("zdb", "-e", "-p", writable_dir, "-bccm", tx_pool).decode("utf-8", errors="replace")
                require("No leaks (block sum matches space maps exactly)" in bccm_text,
                        "OpenZFS zdb -bccm reported leaks or deadlist errors after snapshot COW TXG writes")

                tx_opts = ["--offline-image", "--pool-guid", tx_pool_guid, "--label", "0",
                           "--slot", str(cur_slot), "--dataset", "data"]
                post_snaps = json.loads(command(binary, "snapshots", writable_img, *tx_opts))
                require(snapshot_identities(post_snaps, tx_pool_guid, "data", cur_txg) == tx_identities,
                        "snapshot identities changed after live head TXG commits")

                for snap_name in ("before", "after"):
                    oracle = tx_expected[snap_name]
                    s_view = tx_opts + ["--snapshot", snap_name]
                    s_list = json.loads(command(binary, "ls", writable_img, "/", *s_view))
                    require(listing_names(s_list) == oracle["names"],
                            f"post-TXG @{snap_name} listing changed")
                    s_stat = json.loads(command(binary, "stat", writable_img, "/file.bin", *s_view))
                    s_guid, s_cut = tx_identities[snap_name]
                    require(s_stat["dataset_guid"] == s_guid and s_stat["view_txg"] == s_cut
                            and s_stat["txg"] == cur_txg and s_stat["snapshot"] == snap_name
                            and s_stat["zpl_version"] == version,
                            f"post-TXG @{snap_name} stat identity drifted")
                    for field in ("object", "size", "mode", "links", "native_uid", "native_gid"):
                        require(s_stat["metadata"][field] == oracle[field],
                                f"post-TXG @{snap_name} stat field {field} changed")
                    s_time = s_stat["metadata"]["times_access_modify_change_create"][1]
                    require(s_time["seconds"] * 10**9 + s_time["nanoseconds"] == oracle["mtime_ns"],
                            f"post-TXG @{snap_name} mtime changed")
                    for fname in ("file.bin", "alias.bin"):
                        require(command(binary, "read", writable_img, "/" + fname, *s_view)
                                == oracle["payload"], f"post-TXG @{snap_name} {fname} bytes changed")
                    if snap_name == "before":
                        require(command(binary, "read", writable_img, "/gone", *s_view)
                                == b"retained in before snapshot",
                                "post-TXG @before /gone bytes changed")
                        require(command(binary, "read", writable_img, "/sparse", *s_view,
                                        "--start", str((1 << 32) + 14), "--bytes", "100") == b"\0" * 3,
                                "post-TXG @before sparse tail changed")
                    else:
                        require(command(binary, "read", writable_img, "/retained", *s_view)
                                == b"retained in before snapshot",
                                "post-TXG @after /retained bytes changed")
                    if facade:
                        pub_snap = [writable_img, "--zfs-dataset", "data", "--zfs-snapshot", snap_name]
                        require(command(facade, *pub_snap, "read", "/file.bin") == oracle["payload"],
                                f"public facade post-TXG @{snap_name} /file.bin changed")

                expected_head_names = {
                    b"file.bin",
                    b"alias.bin",
                    b"link",
                    b"sparse",
                    b"head-renamed",
                    b"post-txg.txt",
                }
                head_listing = json.loads(command(binary, "ls", writable_img, "/", *tx_opts))
                require(listing_names(head_listing) == expected_head_names,
                        "post-TXG live head listing mismatch")
                require(command(binary, "read", writable_img, "/file.bin", *tx_opts)
                        == new_payload[:33333], "post-TXG live head /file.bin mismatch")
                require(command(binary, "read", writable_img, "/alias.bin", *tx_opts)
                        == new_payload[:33333], "post-TXG live head /alias.bin mismatch")
                require(command(binary, "read", writable_img, "/head-renamed", *tx_opts)
                        == b"not in either snapshot", "post-TXG live head /head-renamed mismatch")
                require(command(binary, "read", writable_img, "/post-txg.txt", *tx_opts)
                        == b"committed-after-snapshots\n", "post-TXG live head /post-txg.txt mismatch")
                command(binary, "read", writable_img, "/head-only", *tx_opts, fails=True)
                command(binary, "read", writable_img, "/retained", *tx_opts, fails=True)
                if facade:
                    pub_head = [writable_img, "--zfs-dataset", "data"]
                    require(command(facade, *pub_head, "read", "/file.bin") == new_payload[:33333],
                            "public facade post-TXG live head /file.bin mismatch")
                    require(command(facade, *pub_head, "read", "/post-txg.txt")
                            == b"committed-after-snapshots\n",
                            "public facade post-TXG live head /post-txg.txt mismatch")

                snap_expectations = [
                    ("snap_before", tx_expected["before"]["payload"]),
                    ("snap_after", tx_expected["after"]["payload"]),
                    ("live_head_truncated", new_payload[:33333]),
                    ("live_post_txg", b"committed-after-snapshots\n"),
                ]
                snap_lookup = {
                    "snap_before": command(binary, "read", writable_img, "/file.bin", *tx_opts, "--snapshot", "before"),
                    "snap_after": command(binary, "read", writable_img, "/file.bin", *tx_opts, "--snapshot", "after"),
                    "live_head_truncated": command(binary, "read", writable_img, "/file.bin", *tx_opts),
                    "live_post_txg": command(binary, "read", writable_img, "/post-txg.txt", *tx_opts),
                }
                verify_oracle_expectations(
                    snap_expectations,
                    lambda key, table=snap_lookup: table[key],
                )
                neg_controls = run_negative_controls(
                    snap_expectations,
                    lambda key, table=snap_lookup: table[key],
                    binary,
                    directory,
                )
                require(digest(image) == before_hash, "original exported read-phase image changed")

                report["scenarios"].append({"zpl_version": version, "snapshots": identities,
                    "head_guid": head_guid, "txg": selected["txg"], "image_sha256": before_hash,
                    "tx_pool_guid": tx_pool_guid, "tx_head_guid": tx_head_guid,
                    "tx_snapshots": tx_identities, "tx_committed_txg": cur_txg,
                    "tx_published_slot": cur_slot, "tx_image_sha256": digest(writable_img),
                    "negative_controls": neg_controls, "status": "passed"})
            finally:
                if active:
                    command("zpool", "export", pool)
                if tx_active:
                    command("zpool", "export", tx_pool)
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        make_tree_world_readable(root)


if __name__ == "__main__":
    main()
