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
import re
import secrets
import shutil
import struct
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise RuntimeError(detail)


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
    # 1. Missing required oracle must fail closed, never skip.
    try:
        check_required_tools(
            ["zpool", "zfs", "zdb"],
            which_fn=lambda tool: None if tool == "zdb" else f"/sbin/{tool}",
        )
    except RuntimeError as err:
        require("required native tool missing: zdb" in str(err), "wrong missing-oracle error")
    else:
        raise RuntimeError("missing-oracle negative control did not fail")

    # 2. Empty selected expectation set must fail closed.
    try:
        verify_oracle_expectations([], lambda _name: b"")
    except RuntimeError as err:
        require("zero selected oracle expectations" in str(err), "wrong empty-selection error")
    else:
        raise RuntimeError("empty-selection negative control did not fail")

    # 3. Final-element corruption must fail after earlier elements pass.
    require(len(expectations) >= 4, "final-element negative control requires >= 4 items")
    tampered = list(expectations[:-1]) + [(expectations[-1][0], expectations[-1][1] + b"\xff")]
    try:
        verify_oracle_expectations(tampered, fetch_fn)
    except RuntimeError as err:
        require(tampered[-1][0] in str(err), "final-element mismatch did not name final item")
    else:
        raise RuntimeError("final-element mismatch negative control did not fail")

    # 4. Planted ZFS topology/candidate defects must fail closed without disk mutation.
    try:
        native_child_map("Fat ZAP stats:\n  Leaf blocks: 1\n  ZAP entries: 1\n  a = 5\n", {"a"})
    except RuntimeError as err:
        require("not a multi-leaf fat-ZAP" in str(err), "wrong single-leaf fat-ZAP error")
    else:
        raise RuntimeError("single-leaf fat-ZAP negative control did not fail")

    probe = root / "self-test-refusal.img"
    probe.write_bytes(b"ZFS_REFUSAL_CANARY\n" * 512)
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
                    "tx-mkdir",
                    str(p),
                    "/denied",
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
                    "tx-mkdir",
                    str(p),
                    "/denied",
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


def head_identities(report: dict, pool: str) -> dict[str, str]:
    """Do not let duplicate candidate rows disappear in a dict comprehension."""
    result = {}
    seen_origin = False
    for row in report["datasets"]:
        relative = row["relative_name"]
        require(isinstance(relative, str), "native fixture name was not losslessly represented")
        require(str(row["guid"]).isdecimal() and int(row["guid"]) > 0, "invalid candidate dataset GUID")
        if row["objectset_kind"] is None:
            # OpenZFS 2.2+ creates an uninitialized hidden $ORIGIN DSL head with
            # a zero root pointer and zero birth (`bd2fac9c4`), omitted from `zfs list`.
            require(
                relative == "$ORIGIN" and row["root_birth"] == 0 and not seen_origin,
                "unexpected or non-zero uninitialized DSL head",
            )
            seen_origin = True
            continue
        name = pool + ("/" + relative if relative else "")
        require(name not in result, "candidate returned duplicate dataset names")
        require(row["objectset_kind"] == 2, "native filesystem was reported as another object-set kind")
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


def extract_uberblock_root_spec(image_path: Path, slot: int, stride: int) -> tuple[str, int]:
    with image_path.open("rb") as stream:
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
    return f"{vdev:x}:{offset:x}:{logical:x}/{physical:x}:{flags}", logical


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="already-built ffs-zfs executable")
    parser.add_argument("--create-scratch-pool", action="store_true",
                        help="authorize native creation/export only of the runner's new random file pools")
    parser.add_argument("--self-test", action="store_true",
                        help="run deterministic fail-closed harness negative controls without zfs.ko")
    args = parser.parse_args()

    binary = args.binary.resolve(strict=True) if args.binary is not None else None
    if binary is not None:
        require(os.access(binary, os.X_OK), "candidate is not executable")

    if args.self_test:
        root = Path(tempfile.mkdtemp(prefix="ffs-zfs-root-selftest-"))
        root.chmod(0o755)
        origin_identities = head_identities(
            {
                "datasets": [
                    {"relative_name": "", "guid": "101", "objectset_kind": 2, "root_birth": 4},
                    {"relative_name": "$ORIGIN", "guid": "102", "objectset_kind": None, "root_birth": 0},
                    {"relative_name": "data", "guid": "103", "objectset_kind": 2, "root_birth": 9},
                ]
            },
            "pool0",
        )
        require(
            origin_identities == {"pool0": "101", "pool0/data": "103"},
            "self-test failed to preserve visible heads while admitting $ORIGIN",
        )
        bad_origin_rejected = False
        try:
            head_identities(
                {
                    "datasets": [
                        {"relative_name": "rogue", "guid": "104", "objectset_kind": None, "root_birth": 0},
                    ]
                },
                "pool0",
            )
        except RuntimeError:
            bad_origin_rejected = True
        require(bad_origin_rejected, "self-test accepted non-$ORIGIN uninitialized DSL head")
        synthetic = [(f"item-{idx}", f"payload-{idx}".encode()) for idx in range(4)]
        lookup = dict(synthetic)
        summary = {
            "mode": "self-test",
            "status": "passed",
            "origin_head_handling_verified": True,
            "negative_controls": run_negative_controls(
                synthetic,
                lambda key: lookup[key],
                binary,
                root,
            ),
        }
        (root / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
        make_tree_world_readable(root)
        print(json.dumps(summary), flush=True)
        return

    require(binary is not None, "--binary is required unless --self-test is passed")
    require(args.create_scratch_pool, "--create-scratch-pool is required unless --self-test is passed")
    resolved_tools = check_required_tools(["zpool", "zfs", "zdb"])
    root = Path(tempfile.mkdtemp(prefix="ffs-zfs-native-"))
    root.chmod(0o755)
    print(f"Retaining images, raw root bytes and command logs in {root}", flush=True)
    sequence = 0
    report = {"status": "running", "candidate_sha256": digest(binary),
              "tools": resolved_tools, "scenarios": []}

    def command(*args: str | Path, failure: str | None = None) -> bytes:
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
        if failure is None:
            require(result.returncode == 0, f"command failed: {argv!r}; see {prefix}.stderr")
        else:
            require(result.returncode != 0 and result.stdout == b""
                    and failure.encode() in result.stderr,
                    f"expected typed refusal containing {failure!r}: {argv!r}; see {prefix}.stderr")
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
            tx_pool = "ffs_txroot_" + secrets.token_hex(8)
            tx_active = False
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
                spec, logical = extract_uberblock_root_spec(image, slot, stride)
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

                # Offline TXG write + OpenZFS zdb differential verification on a dedicated exported scratch pool
                # (never importing or mounting any dataset; original `image` stays untouched).
                writable_dir = directory / "writable"
                writable_dir.mkdir()
                writable_img = writable_dir / "leaf.img"
                with writable_img.open("xb") as stream:
                    stream.truncate(128 * 1024 * 1024)
                command("zpool", "create", "-d", "-m", "none", "-o", "cachefile=none",
                        "-o", f"ashift={ashift}", tx_pool, writable_img)
                tx_active = True
                tx_guid = command("zpool", "get", "-H", "-o", "value", "guid", tx_pool).decode().strip()
                require(tx_guid.isdecimal() and int(tx_guid) > 0, "invalid tx pool GUID")
                command("zfs", "create", "-o", "mountpoint=none", tx_pool + "/data")
                for idx in range(4):
                    command("zfs", "create", "-o", "mountpoint=none", f"{tx_pool}/data/child_{idx}")
                tx_native_heads = {}
                tx_rows = command("zfs", "list", "-H", "-r", "-t", "filesystem,volume", "-o", "name,guid", tx_pool)
                for row in tx_rows.decode("utf-8", errors="strict").splitlines():
                    t_name, t_id = row.split("\t")
                    tx_native_heads[t_name] = t_id
                command("zpool", "export", tx_pool)
                tx_active = False

                pre_tx_sha = digest(writable_img)
                shutil.copyfile(writable_img, directory / "tx-pre-baseline.img")
                tx_inv = json.loads(command(binary, "inspect", writable_img, "--offline-image"))
                tx_lbl = next(item for item in tx_inv["labels"] if item["label"] == 0)
                tx_cands = [item for item in tx_lbl["candidates"] if item["txg"] >= tx_lbl["config_txg"]]
                require(bool(tx_cands), "no exported candidate on writable scratch pool")
                tx_sel = max(tx_cands, key=lambda item: (item["txg"], item["timestamp"]))
                cur_slot = int(tx_sel["slot"])
                cur_txg = int(tx_sel["txg"])

                admit = json.loads(command(binary, "admit-write", writable_img, "--offline-image",
                                           "--pool-guid", tx_guid, "--label", "0", "--slot", str(cur_slot)))
                require(admit["backing_writes"] is False and admit["admission"]["admitted_clean_write"] is True,
                        "admit-write did not report clean zero-write admission")
                require(digest(writable_img) == pre_tx_sha, "admit-write mutated exported pool bytes")

                # Planted split-Uberblock defect on label 3 must be refused without --reconcile-torn-uberblocks.
                defect_dir = directory / "planted-split-ub"
                defect_dir.mkdir()
                defect_img = defect_dir / "leaf.img"
                shutil.copyfile(writable_img, defect_img)
                with defect_img.open("r+b") as handle:
                    l3_base = defect_img.stat().st_size - 256 * 1024
                    handle.seek(l3_base + 128 * 1024 + cur_slot * stride)
                    handle.write(b"\x00" * 16)
                defect_sha = digest(defect_img)
                command(binary, "tx-mkdir", defect_img, "/split_denied", "--offline-image", "--allow-write",
                        "--pool-guid", tx_guid, "--label", "0", "--slot", str(cur_slot),
                        failure="Uberblock")
                require(digest(defect_img) == defect_sha, "split-Uberblock refusal mutated defect image")

                # Execute offline root-dataset TXG commits (mkdir, create, multi-block SHA-256 write).
                mkdir_res = json.loads(command(binary, "tx-mkdir", writable_img, "/tx_root_dir",
                                               "--offline-image", "--allow-write", "--pool-guid", tx_guid,
                                               "--label", "0", "--slot", str(cur_slot)))
                require(mkdir_res["outcome"] == "Committed" and mkdir_res["committed_txg"] > cur_txg,
                        "tx-mkdir did not advance committed TXG")
                cur_slot = int(mkdir_res["published_slot"])
                cur_txg = int(mkdir_res["committed_txg"])

                create_res = json.loads(command(binary, "tx-create", writable_img, "/tx_root_dir/root_note.bin",
                                                "--mode", "0640", "--offline-image", "--allow-write",
                                                "--pool-guid", tx_guid, "--label", "0", "--slot", str(cur_slot)))
                require(create_res["outcome"] == "Committed" and create_res["committed_txg"] > cur_txg,
                        "tx-create did not advance committed TXG")
                cur_slot = int(create_res["published_slot"])
                cur_txg = int(create_res["committed_txg"])

                tx_payload = (bytes(range(251)) * 700)[:160_003]
                tx_payload_file = directory / "tx-root-payload.bin"
                tx_payload_file.write_bytes(tx_payload)
                write_res = json.loads(command(binary, "tx-write", writable_img, "/tx_root_dir/root_note.bin",
                                               "--data-file", tx_payload_file, "--sha256",
                                               "--offline-image", "--allow-write", "--pool-guid", tx_guid,
                                               "--label", "0", "--slot", str(cur_slot)))
                require(write_res["outcome"] == "Committed" and write_res["committed_txg"] > cur_txg,
                        "tx-write did not advance committed TXG")
                cur_slot = int(write_res["published_slot"])
                cur_txg = int(write_res["committed_txg"])

                command("zdb", "-lu", writable_img)
                bccm_text = command("zdb", "-e", "-p", writable_dir, "-bccm", tx_pool).decode("utf-8", errors="replace")
                require("No leaks (block sum matches space maps exactly)" in bccm_text,
                        "OpenZFS zdb -bccm reported leaks or errors after native TXG writes")
                tx_spec, tx_logical = extract_uberblock_root_spec(writable_img, cur_slot, stride)
                tx_expected_root = command("zdb", "-e", "-p", writable_dir, "-R", tx_pool, tx_spec)
                require(len(tx_expected_root) == tx_logical, "zdb did not return post-TXG logical root bytes")
                tx_actual_root = command(binary, "root", writable_img, "--offline-image", "--label", "0",
                                         "--slot", str(cur_slot), "--pool-guid", tx_guid)
                require(tx_actual_root == tx_expected_root, "post-TXG root bytes differ from zdb")
                tx_heads = json.loads(command(binary, "datasets", writable_img, "--offline-image", "--label", "0",
                                              "--slot", str(cur_slot), "--pool-guid", tx_guid))
                require(head_identities(tx_heads, tx_pool) == tx_native_heads and tx_heads["txg"] == cur_txg,
                        "post-TXG DSL dataset identities or TXG drifted")
                require(command(binary, "read", writable_img, "/tx_root_dir/root_note.bin",
                                "--offline-image", "--label", "0", "--slot", str(cur_slot),
                                "--pool-guid", tx_guid) == tx_payload,
                        "post-TXG root file payload mismatch")

                oracle_expectations = [
                    ("root_mos", tx_expected_root),
                    ("root_file_full", tx_payload),
                    ("root_file_slice", tx_payload[509:8701]),
                    ("datasets_guid_set", ",".join(sorted(tx_native_heads.values())).encode()),
                ]
                oracle_lookup = {
                    "root_mos": tx_actual_root,
                    "root_file_full": command(binary, "read", writable_img, "/tx_root_dir/root_note.bin",
                                              "--offline-image", "--label", "0", "--slot", str(cur_slot),
                                              "--pool-guid", tx_guid),
                    "root_file_slice": command(binary, "read", writable_img, "/tx_root_dir/root_note.bin",
                                               "--offline-image", "--label", "0", "--slot", str(cur_slot),
                                               "--pool-guid", tx_guid, "--start", "509", "--bytes", "8192"),
                    "datasets_guid_set": ",".join(sorted(head_identities(tx_heads, tx_pool).values())).encode(),
                }
                verify_oracle_expectations(
                    oracle_expectations,
                    lambda key, table=oracle_lookup: table[key],
                )
                neg_controls = run_negative_controls(
                    oracle_expectations,
                    lambda key, table=oracle_lookup: table[key],
                    binary,
                    directory,
                )
                require(digest(image) == before, "original exported read-phase image changed")

                scenario = {"ashift": ashift, "pool_guid": guid, "slot": slot, "txg": selected["txg"],
                            "root_sha256": hashlib.sha256(expected).hexdigest(), "image_sha256": before,
                            "partitioned_sha256": partition_hash, "datasets": native_heads,
                            "fat_zap_object": child_object, "fat_zap_native_leaves": native_leaves,
                            "fat_zap_children": len(native_map),
                            "tx_pool_guid": tx_guid, "tx_committed_txg": cur_txg, "tx_published_slot": cur_slot,
                            "tx_image_sha256": digest(writable_img), "negative_controls": neg_controls,
                            "status": "passed"}
                report["scenarios"].append(scenario)
                print(json.dumps(scenario), flush=True)
            finally:
                if active:
                    # Only the exact random pool whose create succeeded here.
                    # Export, never destroy; retain the new vdev and all evidence.
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
