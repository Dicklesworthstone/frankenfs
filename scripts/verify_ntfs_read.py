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


def check_required_tools(
    tools: list[str],
    which_fn: Callable[[str], str | None] = shutil.which,
) -> dict[str, str]:
    require(bool(tools), "tool requirement list must not be empty")
    resolved: dict[str, str] = {}
    for tool in tools:
        found = which_fn(tool)
        require(found is not None, f"missing required native oracle: {tool}")
        resolved[tool] = found
    return resolved


def verify_oracle_expectations(
    expectations: list[tuple[str, bytes]],
    oracle_reader: Callable[[str], bytes],
) -> int:
    require(bool(expectations), "zero selected oracle expectations; empty test set is a failure")
    checked = 0
    for path, expected in expectations:
        observed = oracle_reader(path)
        require(
            observed == expected,
            f"independent native oracle payload mismatch on {path} "
            f"(expected {len(expected)}B, observed {len(observed)}B)",
        )
        checked += 1
    return checked


def usa_restore(raw_page: bytes, magic: bytes) -> tuple[bytearray, int, int]:
    page = bytearray(raw_page)
    require(page[:4] == magic, f"expected {magic!r} magic, got {bytes(page[:4])!r}")
    usa_off, usa_count = struct.unpack_from("<HH", page, 4)
    require(usa_count == len(page) // 512 + 1, "unexpected USA fixup count")
    saved = bytes(page[usa_off:usa_off + usa_count * 2])
    token = saved[:2]
    for sec in range(1, usa_count):
        end = sec * 512
        require(page[end - 2:end] == token, f"USA fixup mismatch on {magic!r} sector {sec}")
        page[end - 2:end] = saved[sec * 2:sec * 2 + 2]
    return page, usa_off, usa_count


def usa_protect(restored: bytearray, usa_off: int, usa_count: int) -> bytes:
    out = bytearray(restored)
    token_val = (struct.unpack_from("<H", out, usa_off)[0] % 0xFFFE) + 1
    token = struct.pack("<H", token_val)
    out[usa_off:usa_off + 2] = token
    for sec in range(1, usa_count):
        end = sec * 512
        out[usa_off + sec * 2:usa_off + sec * 2 + 2] = out[end - 2:end]
        out[end - 2:end] = token
    return bytes(out)


def locate_logfile_first_run_offset(image: Path) -> int:
    with image.open("rb") as handle:
        boot = handle.read(512)
        sector = struct.unpack_from("<H", boot, 11)[0]
        cluster = sector * boot[13]
        mft_lcn = struct.unpack_from("<Q", boot, 48)[0]
        encoded = struct.unpack_from("<b", boot, 64)[0]
        rec_size = 1 << -encoded if encoded < 0 else encoded * cluster
        handle.seek(mft_lcn * cluster + 2 * rec_size)
        rec2_raw = handle.read(rec_size)
    rec2, _, _ = usa_restore(rec2_raw, b"FILE")
    pos = struct.unpack_from("<H", rec2, 20)[0]
    used = struct.unpack_from("<I", rec2, 24)[0]
    while pos + 4 <= used:
        kind = struct.unpack_from("<I", rec2, pos)[0]
        if kind == 0xFFFFFFFF:
            break
        length = struct.unpack_from("<I", rec2, pos + 4)[0]
        if kind == 0x80 and rec2[pos + 9] == 0:
            require(rec2[pos + 8] == 1, "$LogFile DATA unexpectedly resident")
            mp_off = struct.unpack_from("<H", rec2, pos + 32)[0]
            hdr = rec2[pos + mp_off]
            len_bytes = hdr & 0x0F
            lcn_bytes = (hdr >> 4) & 0x0F
            require(len_bytes > 0 and lcn_bytes > 0, "invalid $LogFile mapping pair header")
            raw_lcn = rec2[pos + mp_off + 1 + len_bytes:pos + mp_off + 1 + len_bytes + lcn_bytes]
            lcn = int.from_bytes(raw_lcn, "little", signed=True)
            require(lcn > 0, "invalid $LogFile physical LCN")
            return lcn * cluster
        pos += length
    raise RuntimeError("failed to locate $LogFile DATA run in MFT record 2")


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
        # Normal ntfscat applies MST fixups to $MFT records. This independent
        # parser checks the on-disk USA before applying it, so request raw
        # attribute bytes explicitly (ntfs-3g 2022.10.3 ntfscat.c:339-353).
        native_mft = command("ntfscat", "--raw", "-i", "0", image)
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


def verify_harness_negative_controls(
    command: Callable[..., bytes],
    binary: Path,
    tx_image: Path,
    expectations: list[tuple[str, bytes]],
    root: Path,
) -> dict[str, object]:
    # 1. Missing required oracle tool must raise, never skip.
    try:
        check_required_tools(
            ["mkntfs", "ntfscp", "ntfsls", "ntfscat"],
            which_fn=lambda tool: None if tool == "ntfscat" else f"/usr/bin/{tool}",
        )
    except RuntimeError as err:
        require("missing required native oracle: ntfscat" in str(err), "wrong missing-oracle message")
    else:
        raise RuntimeError("missing native oracle negative control did not fail")

    # 2. Empty selected expectation set must raise, never silently pass.
    try:
        verify_oracle_expectations([], lambda _path: b"")
    except RuntimeError as err:
        require("zero selected oracle expectations" in str(err), "wrong empty-selection message")
    else:
        raise RuntimeError("empty expectation negative control did not fail")

    # 3. Final-element corruption must raise after earlier elements succeed.
    require(len(expectations) >= 4, "final-element negative control needs >= 4 items")
    tampered = list(expectations[:-1]) + [
        (expectations[-1][0], expectations[-1][1] + b"\xff")
    ]
    try:
        verify_oracle_expectations(
            tampered,
            lambda path: command("ntfscat", tx_image, path),
        )
    except RuntimeError as err:
        require(tampered[-1][0] in str(err), "final-element failure did not name final path")
    else:
        raise RuntimeError("final-element mismatch negative control did not fail")

    # 4. Planted actual defect: USA-valid $LogFile RCRD checkpoint whose
    #    open_attribute_table_len is inflated by +40 (whole client record size
    #    instead of dump body size) while RSTR slots are marked dirty.
    planted = root / "tx-planted-defect.img"
    shutil.copyfile(tx_image, planted)
    logfile_off = locate_logfile_first_run_offset(planted)
    with planted.open("r+b") as handle:
        handle.seek(logfile_off)
        r0_raw = handle.read(4096)
        r1_raw = handle.read(4096)
        r0, r0_uoff, r0_ucnt = usa_restore(r0_raw, b"RSTR")
        r1, r1_uoff, r1_ucnt = usa_restore(r1_raw, b"RSTR")
        area_off = struct.unpack_from("<H", r0, 24)[0]
        seq_bits = struct.unpack_from("<I", r0, area_off + 16)[0]
        client_off = struct.unpack_from("<H", r0, area_off + 22)[0]
        ckpt_lsn = struct.unpack_from("<Q", r0, area_off + client_off + 8)[0]
        require(ckpt_lsn != 0, "expected nonzero client_restart_lsn in tx-native.img")

        struct.pack_into("<H", r0, area_off + 14, 0)
        struct.pack_into("<H", r1, area_off + 14, 0)
        handle.seek(logfile_off)
        handle.write(usa_protect(r0, r0_uoff, r0_ucnt))
        handle.write(usa_protect(r1, r1_uoff, r1_ucnt))

        addr_mask = (1 << (64 - seq_bits)) - 1
        ckpt_vbo = (ckpt_lsn & addr_mask) << 3
        ckpt_page_vbo = ckpt_vbo & ~4095
        within = ckpt_vbo - ckpt_page_vbo
        handle.seek(logfile_off + ckpt_page_vbo)
        rcrd_raw = handle.read(4096)
        rcrd, rc_uoff, rc_ucnt = usa_restore(rcrd_raw, b"RCRD")
        orig_len = struct.unpack_from("<I", rcrd, within + 48 + 48)[0]
        require(orig_len > 0, "expected open_attribute_table_len > 0 in checkpoint")
        struct.pack_into("<I", rcrd, within + 48 + 48, orig_len + 40)
        handle.seek(logfile_off + ckpt_page_vbo)
        handle.write(usa_protect(rcrd, rc_uoff, rc_ucnt))

    planted_sha = digest(planted)
    command(
        binary,
        "inspect",
        planted,
        "--offline-image",
        "--recover-logfile",
        failure="checkpoint dump",
    )
    command(
        binary,
        "recover",
        planted,
        "--offline-image",
        "--allow-write",
        failure="OpenAttributeTableDump",
    )
    require(digest(planted) == planted_sha, "refused recovery mutated planted-defect image")
    return {
        "missing_oracle_refused": True,
        "empty_selection_refused": True,
        "final_element_mismatch_caught": True,
        "planted_checkpoint_length_defect_refused": True,
        "planted_defect_sha256": planted_sha,
    }


def native_transaction_cases(
    command: Callable[..., bytes],
    binary: Path,
    facade: Path | None,
    root: Path,
) -> dict[str, object]:
    tx_image = root / "tx-native.img"
    with tx_image.open("xb") as target:
        target.truncate(64 * 1024 * 1024)
    command("mkntfs", "-F", "-Q", "-s", "512", "-c", "4096", tx_image)

    seed_src = root / "tx-seed.bin"
    seed_src.write_bytes(b"initial-ntfscp-seed\n")
    command("ntfscp", tx_image, seed_src, "/seed.txt")
    seed_sha = digest(tx_image)

    admit = json.loads(command(binary, "admit-write", tx_image, "--offline-image"))
    require(
        admit["backing_writes"] is False and admit["admission"]["admitted_clean_write"] is True,
        "admit-write did not confirm clean zero-write admission",
    )
    require(digest(tx_image) == seed_sha, "admit-write modified the offline NTFS image")
    command(
        binary,
        "tx-mkdir",
        tx_image,
        "/",
        "DeniedDir",
        "--offline-image",
        failure="--allow-write",
    )
    require(digest(tx_image) == seed_sha, "missing --allow-write modified the offline image")

    mkdir_out = json.loads(
        command(binary, "tx-mkdir", tx_image, "/", "NativeDir", "--offline-image", "--allow-write")
    )
    require(mkdir_out["outcome"] == "committed", "tx-mkdir did not commit")

    res_bytes = b"native-resident-tx-payload!\n"
    res_src = root / "tx-res.bin"
    res_src.write_bytes(res_bytes)
    res_create = json.loads(
        command(
            binary,
            "tx-create",
            tx_image,
            "/NativeDir",
            "res.txt",
            "--offline-image",
            "--allow-write",
            "--data-file",
            res_src,
        )
    )
    res_rec = int(res_create["result"]["record"])
    res_seq = int(res_create["result"]["sequence"])

    multi_bytes = (bytes(range(251)) * 1200)[:262144 + 73]
    multi_src = root / "tx-multi.bin"
    multi_src.write_bytes(multi_bytes)
    multi_create = json.loads(
        command(
            binary,
            "tx-create",
            tx_image,
            "/NativeDir",
            "multi.bin",
            "--offline-image",
            "--allow-write",
            "--data-file",
            multi_src,
        )
    )
    require(multi_create["token"]["commit_lsn"] > res_create["token"]["commit_lsn"],
            "commit LSN did not advance monotonically")

    seed_updated = (b"upgraded-nonresident-payload-" * 400)[:9731]
    seed_up_src = root / "tx-seed-up.bin"
    seed_up_src.write_bytes(seed_updated)
    command(
        binary,
        "tx-write",
        tx_image,
        "/seed.txt",
        "--offline-image",
        "--allow-write",
        "--data-file",
        seed_up_src,
    )

    doomed_create = json.loads(
        command(
            binary,
            "tx-create",
            tx_image,
            "/NativeDir",
            "doomed.bin",
            "--offline-image",
            "--allow-write",
            "--data",
            "temporary-slot",
        )
    )
    doomed_rec = int(doomed_create["result"]["record"])
    command(
        binary,
        "tx-unlink",
        tx_image,
        "/NativeDir/doomed.bin",
        "--offline-image",
        "--allow-write",
    )

    reused_bytes = b"reused-mft-slot-after-unlink\x00\xfe"
    reused_src = root / "tx-reused.bin"
    reused_src.write_bytes(reused_bytes)
    reused_create = json.loads(
        command(
            binary,
            "tx-create",
            tx_image,
            "/NativeDir",
            "reused.bin",
            "--offline-image",
            "--allow-write",
            "--data-file",
            reused_src,
        )
    )
    require(
        int(reused_create["result"]["record"]) == doomed_rec
        and int(reused_create["result"]["sequence"]) > int(doomed_create["result"]["sequence"]),
        "MFT slot reuse did not preserve incremented deallocation sequence number",
    )

    for _ in range(2):
        ren = json.loads(
            command(
                binary,
                "tx-rename",
                tx_image,
                "/NativeDir/res.txt",
                "/NativeDir/renamed-res.txt",
                "--offline-image",
                "--allow-write",
                "--expected-record",
                str(res_rec),
                "--expected-sequence",
                str(res_seq),
            )
        )
        require(
            int(ren["result"]["record"]) == res_rec and int(ren["result"]["sequence"]) == res_seq,
            "idempotent tx-rename changed file reference identity",
        )

    grow_out = json.loads(
        command(
            binary,
            "tx-grow-mft",
            tx_image,
            "--offline-image",
            "--allow-write",
            "--records",
            "16",
        )
    )
    require(int(grow_out["result"]["logical_records"]) >= 48, "tx-grow-mft did not expand $MFT")

    rec_out = json.loads(
        command(binary, "recover", tx_image, "--offline-image", "--allow-write")
    )
    require(rec_out["outcome"] == "clean", "clean recover check failed")
    tx_final_sha = digest(tx_image)

    alloc_check = json.loads(
        command(
            binary,
            "check-allocation",
            tx_image,
            "--offline-image",
            "--verify-record-ownership",
            "--verify-namespace",
            "--verify-mft-mirror",
        )
    )
    require(
        alloc_check["allocation_consistent"] is True
        and alloc_check["requested_checks_consistent"] is True
        and alloc_check["complete"] is True
        and alloc_check["record_ownership"]["consistent"] is True
        and alloc_check["namespace"]["consistent"] is True
        and alloc_check["mft_mirror"]["consistent"] is True,
        "structural allocation/ownership/mirror/namespace check failed after native transactions",
    )

    subdir_lines = {
        line.strip()
        for line in command("ntfsls", "-a", "-p", "/NativeDir", tx_image)
        .decode("utf-8", errors="strict")
        .splitlines()
        if line.strip()
    }
    require(
        {"renamed-res.txt", "multi.bin", "reused.bin"} <= subdir_lines,
        f"ntfsls /NativeDir missing committed files: {subdir_lines!r}",
    )
    require(
        "res.txt" not in subdir_lines and "doomed.bin" not in subdir_lines,
        f"ntfsls /NativeDir retained renamed/unlinked names: {subdir_lines!r}",
    )

    expectations = [
        ("/seed.txt", seed_updated),
        ("/NativeDir/renamed-res.txt", res_bytes),
        ("/NativeDir/multi.bin", multi_bytes),
        ("/NativeDir/reused.bin", reused_bytes),
    ]
    checked = verify_oracle_expectations(
        expectations,
        lambda path: command("ntfscat", tx_image, path),
    )
    for path, expected in expectations:
        require(
            command(binary, "read", tx_image, path, "--offline-image") == expected,
            f"ffs-ntfs read disagreed after native tx: {path}",
        )
        if facade:
            require(
                command(facade, tx_image, "read", path) == expected,
                f"public ffs facade disagreed after native tx: {path}",
            )
    require(digest(tx_image) == tx_final_sha, "read verification mutated tx-native.img")

    # Hibernation / Fast Startup refusal on an independently seeded hiberfil.sys volume.
    hiber_img = root / "tx-hiber.img"
    with hiber_img.open("xb") as target:
        target.truncate(64 * 1024 * 1024)
    command("mkntfs", "-F", "-Q", "-s", "512", "-c", "4096", hiber_img)
    hiber_src = root / "hiberfil.bin"
    hiber_src.write_bytes(b"HIBR" + bytes(4092))
    command("ntfscp", hiber_img, hiber_src, "/hiberfil.sys")
    hiber_sha = digest(hiber_img)
    command(binary, "admit-write", hiber_img, "--offline-image", failure="hiberfil.sys")
    command(
        binary,
        "tx-create",
        hiber_img,
        "/",
        "nope.txt",
        "--offline-image",
        "--allow-write",
        "--data",
        "x",
        failure="hiberfil.sys",
    )
    require(digest(hiber_img) == hiber_sha, "hiberfil.sys refusal mutated image bytes")

    neg_controls = verify_harness_negative_controls(
        command, binary, tx_image, expectations, root
    )
    return {
        "tx_image_sha256": tx_final_sha,
        "oracle_files_verified": checked,
        "hibernation_refused_sha256": hiber_sha,
        "negative_controls": neg_controls,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="already-built ffs-ntfs executable")
    parser.add_argument("--facade-binary", type=Path,
                        help="also execute the public ffs native_reader, including exact named streams")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    require(os.access(binary, os.X_OK), "candidate is not executable")
    facade = args.facade_binary.resolve(strict=True) if args.facade_binary else None
    if facade:
        require(os.access(facade, os.X_OK), "public facade consumer is not executable")
    tools = ["mkntfs", "ntfscp", "ntfsls", "ntfscat"]
    resolved_tools = check_required_tools(tools)
    root = Path(tempfile.mkdtemp(prefix="ffs-ntfs-native-"))
    print(f"Retaining images and command evidence in {root}", flush=True)
    sequence = 0
    report = {"status": "running", "candidate_sha256": digest(binary),
              "tools": resolved_tools, "streams_checked": []}
    if facade:
        report["facade_sha256"] = digest(facade)

    def command(*args: str | Path, failure: str | None = None) -> bytes:
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
        if failure is None:
            require(result.returncode == 0, f"command failed: {argv!r}; see {prefix}.stderr")
        else:
            require(result.returncode != 0 and result.stdout == b""
                    and failure.encode() in result.stderr,
                    f"expected typed failure without output: {argv!r}; see {prefix}.stderr")
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
            if facade:
                public = [facade, image]
                require(command(*public, "stat", "/" + name)
                        == f"ntfs\tRegularFile\t{len(expected)}\n".encode(),
                        "public facade metadata differs from native")
                require(command(*public, "read", "/" + name) == expected,
                        "public facade unnamed DATA differs from native")
                require(command(*public, "read", "/" + name, "--start", "507", "--bytes", "1031")
                        == expected[507:1538], "public facade unnamed range differs")
                command(*public, "refuse-write", "/" + name)
            report["streams_checked"].append({"record": int(record), "name": name, "size": len(expected)})
        if facade:
            raw_names = command(facade, image, "list", "/")
            require(raw_names.endswith(b"\0"), "public facade listing lacks its final delimiter")
            names = raw_names[:-1].split(b"\0")
            require(len(names) == len(set(names))
                    and {name.encode() for name in payloads} <= set(names),
                    "public facade native directory names are missing or duplicated")
        record = str(records["tiny.txt"])
        require(command("ntfscat", "-i", record, "-n", "note", image) == named, "native named stream differs")
        require(command(binary, "cat", image, record, "--offline-image", "--stream", "note") == named,
                "candidate named stream differs")
        require(command(binary, "read", image, "/tiny.txt", "--offline-image", "--stream", "note") == named,
                "candidate path-selected named stream differs")
        if facade:
            for selector, value in [("--stream", "note"), ("--stream-utf16", "006e,006f,0074,0065")]:
                require(command(facade, image, "read", "/tiny.txt", selector, value) == named,
                        "public facade native named DATA differs")
                for start in (len(named), len(named) + 5):
                    require(command(facade, image, "read", "/tiny.txt", selector, value,
                                    "--start", str(start), "--bytes", "17") == b"",
                            "public facade named DATA EOF exposed bytes")
            for name in ("NOTE", "missing"):
                command(facade, image, "read", "/tiny.txt", "--stream", name, failure="NotFound")
        for name, expected in extension_streams.items():
            require(command("ntfscat", "-i", record, "-n", name, image) == expected,
                    f"native extension-stream oracle differs: {name}")
            require(command(binary, "cat", image, record, "--offline-image", "--stream", name) == expected,
                    f"candidate extension stream differs: {name}")
            require(command(binary, "read", image, "/tiny.txt", "--offline-image", "--stream", name,
                            "--start", "507", "--bytes", "1031") == expected[507:1538],
                    f"candidate extension path/range differs: {name}")
            if facade:
                require(command(facade, image, "read", "/tiny.txt", "--stream", name) == expected,
                        f"public facade extension stream differs: {name}")
                require(command(facade, image, "read", "/tiny.txt", "--stream", name,
                                "--start", "507", "--bytes", "1031") == expected[507:1538],
                        f"public facade extension range differs: {name}")
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
        if facade:
            public = [facade, disk, "--offset", "1048576", "--length", str(image.stat().st_size)]
            require(command(*public, "read", "/large.bin") == payloads["large.bin"],
                    "bounded public facade unnamed DATA differs")
            require(command(*public, "read", "/tiny.txt", "--stream", "extension-31")
                    == extension_streams["extension-31"], "bounded public facade extension stream differs")
            require(command(*public, "read", "/tiny.txt", "--stream", "extension-31",
                            "--start", "507", "--bytes", "1031") == extension_streams["extension-31"][507:1538],
                    "bounded public facade extension range differs")
            command(*public, "read", "/tiny.txt", "--stream", "missing", failure="NotFound")
        require(digest(disk) == disk_before, "candidate modified image or adjacent partition bytes")
        compression = compressed_cases(command, binary, root)
        native_tx = native_transaction_cases(command, binary, facade, root)
        report.update(status="passed", image_sha256=before, partitioned_sha256=disk_before,
                      named_stream_checked=True, directory_and_path_reads_checked=True,
                      attribute_list_sha256=hashlib.sha256(raw_list).hexdigest(),
                      native_extension_records=extension_records, extension_streams_checked=len(extension_streams),
                      compression=compression, native_transactions=native_tx)
        print(json.dumps(report, indent=2))
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
