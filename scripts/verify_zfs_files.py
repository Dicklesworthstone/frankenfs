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

    sample_stat = {
        "dataset_guid": "99",
        "zpl_version": 5,
        "metadata": {
            "object": 7,
            "size": 12,
            "mode": 0o100640,
            "links": 3,
            "native_uid": 0,
            "native_gid": 0,
            "times_access_modify_change_create": [
                {"seconds": 1, "nanoseconds": 0},
                {"seconds": 2, "nanoseconds": 5},
                {"seconds": 2, "nanoseconds": 5},
                {"seconds": 1, "nanoseconds": 0},
            ],
        },
    }
    try:
        compare_stat(
            sample_stat,
            {
                "object": 7,
                "size": 12,
                "mode": 0o100640,
                "links": 2,
                "native_uid": 0,
                "native_gid": 0,
                "mtime_ns": 2_000_000_005,
            },
            "99",
            5,
        )
    except RuntimeError as err:
        require("native stat mismatch: links" in str(err), "wrong stat mismatch error")
    else:
        raise RuntimeError("stat-mismatch negative control did not fail")

    probe = root / "self-test-refusal.img"
    probe.write_bytes(b"ZFS_ZPL_REFUSAL_CANARY\n" * 512)
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
                    "tx-create",
                    str(p),
                    "/denied.bin",
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
                    "tx-create",
                    str(p),
                    "/denied.bin",
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
        root = Path(tempfile.mkdtemp(prefix="ffs-zpl-selftest-"))
        synthetic = [(f"file-{idx}", f"zpl-payload-{idx}".encode()) for idx in range(4)]
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
    root = Path(tempfile.mkdtemp(prefix="ffs-zpl-native-"))
    print(f"Retaining all images, file oracles and logs in {root}", flush=True)
    # The native link's ../../ target exists outside the image. A refusal must
    # not be an accidental ENOENT after following a host path.
    canary = root / "outside-not-followed"
    canary_bytes = b"retained host traversal canary\0" + secrets.token_bytes(32)
    with canary.open("xb") as stream:
        stream.write(canary_bytes)
    sequence = 0
    report = {"status": "running", "candidate_sha256": digest(binary),
              "tools": resolved_tools, "scenarios": []}
    if facade:
        report["facade_sha256"] = digest(facade)

    def command(*argv: str | Path, fails: bool = False, failure: str | None = None) -> bytes:
        nonlocal sequence
        sequence += 1
        prefix = root / f"command-{sequence:03d}"
        argv = [str(arg) for arg in argv]
        prefix.with_suffix(".argv.json").write_text(json.dumps(argv) + "\n")
        completed = subprocess.run(argv, capture_output=True, timeout=120, check=False,
                                   env={**os.environ, "LC_ALL": "C", "ZDB_NO_ZLE": "1"})
        prefix.with_suffix(".stdout").write_bytes(completed.stdout)
        prefix.with_suffix(".stderr").write_bytes(completed.stderr)
        prefix.with_suffix(".status").write_text(str(completed.returncode) + "\n")
        if failure is not None:
            require(completed.returncode != 0 and completed.stdout == b""
                    and failure.encode() in completed.stderr,
                    f"expected typed refusal containing {failure!r}; see {prefix}")
        else:
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
            tx_pool = "ffs_zpltx_" + secrets.token_hex(8)
            tx_active = False
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
                    if facade:
                        view = [backing, *extra, "--zfs-dataset", "data"]
                        raw_names = command(facade, *view, "list", "/")
                        require(raw_names.endswith(b"\0"), "facade listing lacks its final delimiter")
                        entries = raw_names[:-1].split(b"\0")
                        require(len(entries) == len(set(entries))
                                and set(entries) == names | {b".", b".."},
                                "public facade directory names differ from native")
                        for name in (long_name, "alias.bin", "sub/nested.bin"):
                            path = "/" + name
                            require(command(facade, *view, "stat", path)
                                    == f"zfs\tRegularFile\t{len(payload)}\n".encode(),
                                    "public facade metadata differs from native")
                            require(command(facade, *view, "read", path) == payload,
                                    "public facade file bytes differ from native")
                        require(command(facade, *view, "read", "/" + long_name,
                                        "--start", "507", "--bytes", "8199") == payload[507:8706],
                                "public facade unaligned range differs")
                        require(command(facade, *view, "read", "/" + long_name,
                                        "--start", str(len(payload)), "--bytes", "5") == b"",
                                "public facade EOF exposed bytes")
                        require(command(facade, *view, "read", "/empty") == b"",
                                "public facade empty file has data")
                        require(command(facade, *view, "read", "/sparse", "--start",
                                        str(sparse_size - 3), "--bytes", "100") == b"\0" * 3,
                                "public facade sparse tail differs")
                        command(facade, *view, "refuse-write", "/" + long_name)
                        require(command(facade, *view, "read", "/external-link", fails=True) == b"",
                                "public facade followed the external symlink")
                        require(canary.read_bytes() == canary_bytes, "host traversal canary changed")
                    require(digest(backing) == backing_hash, "candidate modified selected or adjacent image bytes")
                require(digest(image) == before, "exported image changed")

                # Dedicated exported scratch pool for offline native TXG mutations,
                # OpenZFS zdb -bccm leak/checksum verification, and non-forced zpool import
                # live zfs.ko POSIX round-trip (original `image` remains untouched).
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
                command("zfs", "create", "-o", f"version={version}", "-o", "atime=off",
                        "-o", "compression=lzjb", "-o", f"mountpoint={tx_mount}", tx_pool + "/data")
                require(os.path.ismount(tx_mount), "writable scratch dataset was not mounted")
                tx_pool_guid = command("zpool", "get", "-H", "-p", "-o", "value", "guid", tx_pool).decode().strip()
                tx_dataset_guid = command("zfs", "get", "-H", "-p", "-o", "value", "guid", tx_pool + "/data").decode().strip()
                require(tx_pool_guid.isdecimal() and tx_dataset_guid.isdecimal(), "invalid writable scratch GUIDs")

                tx_long = tx_mount / long_name
                with tx_long.open("xb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                tx_long.chmod(0o640)
                (tx_mount / "sub").mkdir()
                os.link(tx_long, tx_mount / "alias.bin")
                os.link(tx_long, tx_mount / "sub" / "nested.bin")
                (tx_mount / "empty").touch(exist_ok=False)
                with (tx_mount / "sparse").open("xb") as stream:
                    stream.write(b"prefix")
                    stream.truncate(sparse_size)
                    stream.flush()
                    os.fsync(stream.fileno())
                command("zpool", "export", tx_pool)
                tx_active = False
                require(not os.path.ismount(tx_mount), "export left writable scratch dataset mounted")

                pre_tx_sha = digest(writable_img)
                shutil.copyfile(writable_img, directory / "tx-pre-baseline.img")
                tx_inv = json.loads(command(binary, "inspect", writable_img, "--offline-image"))
                tx_lbl = next(row for row in tx_inv["labels"] if row["label"] == 0)
                tx_cands = [row for row in tx_lbl["candidates"] if row["txg"] >= tx_lbl["config_txg"]]
                require(bool(tx_cands), "no exported candidate on writable ZPL scratch pool")
                tx_sel = max(tx_cands, key=lambda row: (row["txg"], row["timestamp"]))
                cur_slot = int(tx_sel["slot"])
                cur_txg = int(tx_sel["txg"])

                admit = json.loads(command(binary, "admit-write", writable_img, "--offline-image",
                                           "--pool-guid", tx_pool_guid, "--label", "0", "--slot", str(cur_slot)))
                require(admit["backing_writes"] is False and admit["admission"]["admitted_clean_write"] is True,
                        "admit-write did not report clean zero-write admission")
                require(digest(writable_img) == pre_tx_sha, "admit-write mutated exported ZPL image")

                defect_dir = directory / "planted-split-ub"
                defect_dir.mkdir()
                defect_img = defect_dir / "leaf.img"
                shutil.copyfile(writable_img, defect_img)
                with defect_img.open("r+b") as handle:
                    l3_base = defect_img.stat().st_size - 256 * 1024
                    handle.seek(l3_base + 128 * 1024 + cur_slot * 4096)
                    handle.write(b"\x00" * 16)
                defect_sha = digest(defect_img)
                command(binary, "tx-mkdir", defect_img, "/split_denied", "--offline-image", "--allow-write",
                        "--pool-guid", tx_pool_guid, "--label", "0", "--slot", str(cur_slot),
                        "--dataset", "data", failure="Uberblock")
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
                            f"ZPL TXG step {sub_args[0]!r} did not advance committed TXG")
                    cur_slot = int(out["published_slot"])
                    cur_txg = int(out["committed_txg"])
                    return out

                run_tx("tx-mkdir", writable_img, "/native_tx")
                run_tx("tx-create", writable_img, "/native_tx/cross.bin", "--mode", "0640")
                cross_payload = (bytes(range(241)) * 900)[:200_704]
                cross_payload_file = directory / "cross-payload.bin"
                cross_payload_file.write_bytes(cross_payload)
                run_tx("tx-write", writable_img, "/native_tx/cross.bin",
                       "--data-file", cross_payload_file, "--sha256")
                run_tx("tx-truncate", writable_img, "/native_tx/cross.bin", "--size", "150003")
                run_tx("tx-rename", writable_img, "/alias.bin", "/native_tx/moved_alias.bin")
                run_tx("tx-unlink", writable_img, "/empty")

                command("zdb", "-lu", writable_img)
                bccm_text = command("zdb", "-e", "-p", writable_dir, "-bccm", tx_pool).decode("utf-8", errors="replace")
                require("No leaks (block sum matches space maps exactly)" in bccm_text,
                        "OpenZFS zdb -bccm reported leaks or errors after ZPL TXG writes")

                tx_opts = ["--offline-image", "--pool-guid", tx_pool_guid, "--label", "0",
                           "--slot", str(cur_slot), "--dataset", "data"]
                require(command(binary, "read", writable_img, "/native_tx/cross.bin", *tx_opts)
                        == cross_payload[:150003], "candidate post-TXG truncated read mismatch")
                require(command(binary, "read", writable_img, "/native_tx/moved_alias.bin", *tx_opts)
                        == payload, "candidate post-TXG moved hard-link read mismatch")
                command(binary, "read", writable_img, "/alias.bin", *tx_opts, fails=True)
                command(binary, "read", writable_img, "/empty", *tx_opts, fails=True)
                if facade:
                    require(command(facade, writable_img, "--zfs-dataset", "data",
                                    "read", "/native_tx/cross.bin") == cross_payload[:150003],
                            "public facade post-TXG truncated read mismatch")
                    require(command(facade, writable_img, "--zfs-dataset", "data",
                                    "read", "/native_tx/moved_alias.bin") == payload,
                            "public facade post-TXG moved hard-link read mismatch")

                # Non-forced live zfs.ko kernel re-import and POSIX verification.
                command("zpool", "import", "-d", writable_dir, "-o", "cachefile=none", tx_pool)
                tx_active = True
                require(os.path.ismount(tx_mount), "re-imported native scratch dataset was not mounted")
                k_cross = tx_mount / "native_tx" / "cross.bin"
                k_moved = tx_mount / "native_tx" / "moved_alias.bin"
                require(k_cross.read_bytes() == cross_payload[:150003],
                        "kernel zfs.ko POSIX read disagreed on /native_tx/cross.bin")
                require((k_cross.stat().st_mode & 0o7777) == 0o640,
                        "kernel zfs.ko mode bits disagreed on /native_tx/cross.bin")
                require(k_moved.read_bytes() == payload and k_moved.stat().st_nlink == 3,
                        "kernel zfs.ko moved hard-link content or st_nlink disagreed")
                require((tx_mount / long_name).read_bytes() == payload
                        and (tx_mount / "sub" / "nested.bin").read_bytes() == payload,
                        "kernel zfs.ko sibling hard-links disagreed after rename")
                require(not (tx_mount / "alias.bin").exists(), "renamed /alias.bin still visible in zfs.ko")
                require(not (tx_mount / "empty").exists(), "unlinked /empty still visible in zfs.ko")
                require((tx_mount / "sparse").stat().st_size == sparse_size,
                        "kernel zfs.ko sparse file size changed")

                kernel_expectations = [
                    ("cross_full", cross_payload[:150003]),
                    ("cross_unaligned", cross_payload[4091:12299]),
                    ("moved_alias", payload),
                    ("nested_hardlink", payload[:65536]),
                ]
                kernel_lookup = {
                    "cross_full": k_cross.read_bytes(),
                    "cross_unaligned": k_cross.read_bytes()[4091:12299],
                    "moved_alias": k_moved.read_bytes(),
                    "nested_hardlink": (tx_mount / "sub" / "nested.bin").read_bytes()[:65536],
                }
                verify_oracle_expectations(kernel_expectations, lambda key: kernel_lookup[key])
                neg_controls = run_negative_controls(
                    kernel_expectations,
                    lambda key: kernel_lookup[key],
                    binary,
                    directory,
                )

                command("zpool", "export", tx_pool)
                tx_active = False
                require(not os.path.ismount(tx_mount), "post-import export left writable scratch dataset mounted")
                require(digest(image) == before, "original exported read-phase image changed")

                scenario = {"zpl_version": version, "pool_guid": pool_guid, "dataset_guid": dataset_guid,
                            "txg": selected["txg"], "image_sha256": before,
                            "tx_pool_guid": tx_pool_guid, "tx_dataset_guid": tx_dataset_guid,
                            "tx_committed_txg": cur_txg, "tx_published_slot": cur_slot,
                            "tx_image_sha256": digest(writable_img),
                            "negative_controls": neg_controls, "status": "passed"}
                report["scenarios"].append(scenario)
                print(json.dumps(scenario), flush=True)
            finally:
                if active:
                    command("zpool", "export", pool)  # Only our successfully created random pool.
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
