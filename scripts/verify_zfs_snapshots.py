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
from typing import Callable


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
        binary_checked = True

    return {
        "missing_oracle_refused": True,
        "empty_selection_refused": True,
        "final_element_mismatch_caught": True,
        "planted_defect_refused": True,
        "binary_refusal_checked": binary_checked,
    }


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
            require(result.returncode != 0 and result.stdout == b""
                    and failure.encode() in result.stderr,
                    f"expected typed refusal containing {failure!r}: {argv!r}; see {prefix}")
        else:
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
                        "-o", "feature@empty_bpobj=enabled",
                        "-o", "feature@enabled_txg=enabled",
                        "-o", "feature@hole_birth=enabled",
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

                def run_tx(*sub_args: str | Path) -> dict:
                    nonlocal cur_slot, cur_txg
                    out = json.loads(command(
                        binary,
                        *sub_args,
                        "--offline-image",
                        "--allow-write",
                        "--pool-guid",
                        tx_pool_guid,
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
                verify_oracle_expectations(snap_expectations, lambda key: snap_lookup[key])
                neg_controls = run_negative_controls(
                    snap_expectations,
                    lambda key: snap_lookup[key],
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


if __name__ == "__main__":
    main()
