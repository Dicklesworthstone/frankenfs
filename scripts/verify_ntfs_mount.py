#!/usr/bin/env python3
"""Exercise a built ffs-ntfs through a real read-only Linux FUSE mount.

Creates only fresh, retained scratch images using mkntfs/ntfscp. Requires real
FUSE, over 256 native directory entries, independent ntfscat comparisons,
mounted reads/statfs/EROFS, and unchanged whole-image hashes. Missing tools and
failed operations are failures, never successful skips. Does not build Rust.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for data in iter(lambda: source.read(1024 * 1024), b""):
            result.update(data)
    return result.hexdigest()


def mounted_here(path: Path) -> bool:
    # Reading mountinfo never issues a request to a possibly stuck FUSE daemon.
    def unescape(value: str) -> str:
        return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)

    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 5 and unescape(fields[4]) == str(path):
            return True
    return False


def probe(mountpoint: Path, manifest_path: Path) -> None:
    """Runs in a timed child: no unbounded mounted filesystem call in parent."""
    manifest = json.loads(manifest_path.read_text())
    names = set(manifest)
    for _ in range(3):
        listing = os.listdir(mountpoint)
        require(len(listing) == len(set(listing)), "duplicate names in mounted readdir")
        require(names <= set(listing), "native files lost across readdir pages")
        for name, expected in manifest.items():
            path = mountpoint / name
            metadata = path.stat()
            require(metadata.st_size == expected["size"], f"wrong mounted size: {name}")
            require(metadata.st_mode & 0o222 == 0, f"writable projected mode: {name}")
            require(metadata.st_uid == os.getuid() and metadata.st_gid == os.getgid(),
                    f"wrong configured mount ownership: {name}")
    for name, expected in manifest.items():
        path = mountpoint / name
        require(digest(path) == expected["sha256"], f"mounted content differs: {name}")
        with path.open("rb") as stream:
            stream.seek(507)
            require(stream.read(1031).hex() == expected["range_hex"],
                    f"unaligned mounted range differs: {name}")
            stream.seek(expected["size"])
            require(stream.read(1) == b"", f"mounted EOF exposes allocation slack: {name}")
    victim = mountpoint / next(iter(manifest))
    for flags in (os.O_WRONLY, os.O_RDWR, os.O_RDONLY | os.O_TRUNC):
        try:
            descriptor = os.open(victim, flags)
        except OSError as error:
            require(error.errno == errno.EROFS, f"write-open returned errno {error.errno}, not EROFS")
        else:
            os.close(descriptor)
            raise RuntimeError("read-only mount admitted a write-capable open")
    stats = os.statvfs(mountpoint)
    require(stats.f_blocks > 0 and 0 <= stats.f_bfree <= stats.f_blocks,
            "invalid mounted allocation statistics")
    require(stats.f_files > 0 and 0 <= stats.f_ffree <= stats.f_files,
            "invalid mounted MFT statistics")
    require(stats.f_flag & os.ST_RDONLY != 0, "kernel did not mark the mount read-only")
    print(json.dumps({"files_checked": len(manifest), "directory_passes": 3,
                      "content_and_ranges": True, "write_open_errno": errno.EROFS}))


def probe_rw(mountpoint: Path, expected_out: Path) -> None:
    """Runs in a timed child against a real writable FUSE mount (`mount-write`)."""
    seeded = mountpoint / "seeded.bin"
    require(seeded.read_bytes() == b"initial-ntfscp-seed\n", "unexpected initial seeded.bin bytes")
    new_seed = (b"overwritten-through-writable-fuse-" * 200)[:6149]
    seeded.write_bytes(new_seed)

    bigdir = mountpoint / "bigdir"
    bigdir.mkdir(mode=0o755)
    big_entries: dict[str, str] = {}
    for idx in range(64):
        fname = f"item-{idx:03d}.bin"
        fpath = bigdir / fname
        data = (f"fuse-rw-item-{idx:03d}\n".encode() * 20)[:311]
        fpath.write_bytes(data)
        big_entries[fname] = hashlib.sha256(data).hexdigest()

    tempdir = mountpoint / "tempdir"
    tempdir.mkdir(mode=0o755)
    os.rmdir(tempdir)
    require(not tempdir.exists(), "rmdir left directory visible")

    # Document with hard link + 34 ADS streams (forcing $ATTRIBUTE_LIST spill), ADS rename, and ADS unlink.
    doc = mountpoint / "doc.txt"
    doc_payload = b"primary-unnamed-document-stream\n" * 40
    doc.write_bytes(doc_payload)
    os.link(doc, mountpoint / "doc-link.txt")
    require((mountpoint / "doc-link.txt").stat().st_nlink == 2, "hard-link nlink != 2")

    ads_expected: dict[str, str] = {}
    for idx in range(34):
        sname = f"ads-{idx:02d}"
        spath = mountpoint / f"doc.txt:{sname}"
        sbytes = bytes((b + idx * 3) % 251 for b in range(180)) * (1 if idx % 7 else 28)
        spath.write_bytes(sbytes)
        ads_expected[sname] = hashlib.sha256(sbytes).hexdigest()

    os.rename(mountpoint / "doc.txt:ads-04", mountpoint / "doc.txt:ads-04-renamed")
    ads_expected["ads-04-renamed"] = ads_expected.pop("ads-04")
    os.unlink(mountpoint / "doc.txt:ads-00")
    ads_expected.pop("ads-00")

    # Open-unlink retention: keep fd open across unlink, read/write, then close.
    open_unlinked = mountpoint / "open-unlinked.bin"
    open_unlinked.write_bytes(b"alive-while-unlinked")
    ou_fd = os.open(open_unlinked, os.O_RDWR)
    try:
        os.unlink(open_unlinked)
        require(not open_unlinked.exists(), "unlinked file still visible in namespace")
        os.pwrite(ou_fd, b"ALIVE", 0)
        require(os.pread(ou_fd, 64, 0) == b"ALIVE-while-unlinked", "open-unlinked pread mismatch")
    finally:
        os.close(ou_fd)

    # Open-destination atomic overwrite (`os.replace` while destination fd stays open!).
    open_victim = mountpoint / "open-victim.bin"
    open_victim.write_bytes(b"old-victim-open-fd-data")
    rep_src = mountpoint / "replace-src.bin"
    rep_bytes = b"new-atomic-replacement-winner-data\n" * 35
    rep_src.write_bytes(rep_bytes)
    vic_fd = os.open(open_victim, os.O_RDONLY)
    try:
        os.replace(rep_src, open_victim)
        require(not rep_src.exists(), "replace source still exists")
        require(open_victim.read_bytes() == rep_bytes, "replaced destination did not serve new bytes")
        require(os.pread(vic_fd, 64, 0) == b"old-victim-open-fd-data",
                "open victim fd lost old bytes across atomic os.replace")
        root_names = os.listdir(mountpoint)
        require(all(not n.startswith(".ffs-unlinked-") for n in root_names),
                "hidden orphan name leaked into mounted readdir")
    finally:
        os.close(vic_fd)

    # chmod (0o444 <-> 0o644 + negative control for 0o600 and EACCES), utime, truncate growth & shrink, fsync.
    meta_file = mountpoint / "meta.bin"
    meta_file.write_bytes(b"prefix")
    os.truncate(meta_file, 9000)
    grown_bytes = meta_file.read_bytes()
    require(grown_bytes == b"prefix" + b"\x00" * (9000 - 6), "truncate growth did not zero-fill")
    os.truncate(meta_file, 4099)
    shrunk_bytes = meta_file.read_bytes()
    require(shrunk_bytes == b"prefix" + b"\x00" * (4099 - 6), "truncate shrink mismatch")
    os.utime(meta_file, (1_721_000_100, 1_721_000_200))
    os.chmod(meta_file, 0o444)
    require((meta_file.stat().st_mode & 0o777) == 0o444, "chmod 0o444 did not project read-only mode")
    try:
        bad_fd = os.open(meta_file, os.O_WRONLY)
    except OSError as err:
        require(err.errno == errno.EACCES, f"expected EACCES on 0o444 file, got {err.errno}")
    else:
        os.close(bad_fd)
        raise RuntimeError("0o444 read-only NTFS file admitted O_WRONLY open")
    try:
        os.chmod(meta_file, 0o600)
    except OSError:
        pass
    else:
        raise RuntimeError("unsupported restrictive mode 0o600 succeeded on NTFS")
    os.chmod(meta_file, 0o644)

    # Mounted RW symlink + readlink + user.* xattr CRUD (`setxattr`/`getxattr`/`listxattr`/`removexattr`).
    sym_path = mountpoint / "rw-link"
    os.symlink("doc.txt", sym_path)
    require(os.readlink(sym_path) == "doc.txt", "mounted symlink readlink mismatch")
    os.setxattr(meta_file, "user.ntfs_ea", b"ea-value-1")
    require(os.getxattr(meta_file, "user.ntfs_ea") == b"ea-value-1", "mounted getxattr mismatch")
    require("user.ntfs_ea" in os.listxattr(meta_file), "mounted listxattr omitted user.ntfs_ea")
    os.removexattr(meta_file, "user.ntfs_ea")
    require("user.ntfs_ea" not in os.listxattr(meta_file), "mounted removexattr left user.ntfs_ea")

    sync_fd = os.open(doc, os.O_RDONLY)
    try:
        os.fsync(sync_fd)
    finally:
        os.close(sync_fd)

    summary = {
        "seeded_sha256": hashlib.sha256(new_seed).hexdigest(),
        "doc_sha256": hashlib.sha256(doc_payload).hexdigest(),
        "open_victim_sha256": hashlib.sha256(rep_bytes).hexdigest(),
        "meta_sha256": hashlib.sha256(shrunk_bytes).hexdigest(),
        "meta_mtime": 1_721_000_200,
        "bigdir": big_entries,
        "ads": ads_expected,
    }
    expected_out.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"rw_bigdir_files": len(big_entries), "rw_ads_streams": len(ads_expected),
                      "open_replace_checked": True, "chmod_utime_truncate_checked": True}))


class Run:
    def __init__(self, root: Path, binary: Path) -> None:
        self.root = root
        self.binary = binary
        self.sequence = 0

    def command(self, *args: str | Path, timeout: int = 120) -> bytes:
        self.sequence += 1
        prefix = self.root / f"command-{self.sequence:04d}"
        argv = [str(arg) for arg in args]
        prefix.with_suffix(".argv.json").write_text(json.dumps(argv) + "\n")
        try:
            result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False,
                                    env={**os.environ, "LC_ALL": "C"})
        except subprocess.TimeoutExpired as error:
            prefix.with_suffix(".stdout").write_bytes(error.stdout or b"")
            prefix.with_suffix(".stderr").write_bytes(error.stderr or b"")
            prefix.with_suffix(".status").write_text("timeout\n")
            raise
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        prefix.with_suffix(".status").write_text(str(result.returncode) + "\n")
        if result.returncode != 0:
            err_tail = result.stderr.decode("utf-8", errors="replace").strip()[-1200:]
            raise RuntimeError(
                f"command failed ({result.returncode}): {argv!r}; see {prefix}.stderr; stderr={err_tail!r}"
            )
        return result.stdout

    def mount_probe(self, image: Path, manifest: Path, offset: int, length: int) -> dict:
        resolved_root = self.root.resolve()
        sanctioned_prefixes = [Path("/tmp"), Path("/mnt"), Path("/media"), Path(f"/run/user/{os.getuid()}")]
        try:
            sanctioned_prefixes.append(Path.home().resolve())
        except RuntimeError:
            pass
        if any(resolved_root == p or p in resolved_root.parents for p in sanctioned_prefixes):
            mountpoint = self.root / (image.stem + "-mount")
            mountpoint.mkdir()
        else:
            mountpoint = Path(tempfile.mkdtemp(prefix=f"ffs-ntfs-{image.stem}-mnt-", dir="/tmp"))
        log_path = self.root / (image.stem + "-mount.log")
        argv = [str(self.binary), "mount", str(image), str(mountpoint), "--offline-image",
                "--offset", str(offset), "--length", str(length), "--uid", str(os.getuid()),
                "--gid", str(os.getgid())]
        (self.root / (image.stem + "-mount.argv.json")).write_text(json.dumps(argv) + "\n")
        with log_path.open("wb") as log:
            process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while not mounted_here(mountpoint):
                    require(process.poll() is None, f"mount exited; see {log_path}")
                    require(time.monotonic() < deadline, f"mount did not appear; see {log_path}")
                    time.sleep(0.05)
                output = self.command(sys.executable, Path(__file__).resolve(), "--probe",
                                      mountpoint, "--manifest", manifest, timeout=180)
                report = json.loads(output)
                self.command("fusermount3", "-u", mountpoint, timeout=30)
                require(process.wait(timeout=30) == 0, f"mount did not exit cleanly; see {log_path}")
                require(not mounted_here(mountpoint), "successful unmount left a mounted filesystem")
                return report
            finally:
                # Never recursively delete a tree and never touch another mount.
                # Failures retain the image, mountpoint, logs and failed result.
                try:
                    if mounted_here(mountpoint):
                        self.command("fusermount3", "-u", mountpoint, timeout=30)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=10)

    def mount_write_probe(self, image: Path, expected_out: Path) -> dict:
        resolved_root = self.root.resolve()
        sanctioned_prefixes = [Path("/tmp"), Path("/mnt"), Path("/media"), Path(f"/run/user/{os.getuid()}")]
        try:
            sanctioned_prefixes.append(Path.home().resolve())
        except RuntimeError:
            pass
        if any(resolved_root == p or p in resolved_root.parents for p in sanctioned_prefixes):
            mountpoint = self.root / (image.stem + "-rw-mount")
            mountpoint.mkdir()
        else:
            mountpoint = Path(tempfile.mkdtemp(prefix=f"ffs-ntfs-{image.stem}-rwmnt-", dir="/tmp"))
        log_path = self.root / (image.stem + "-rw-mount.log")
        argv = [str(self.binary), "mount-write", str(image), str(mountpoint),
                "--offline-image", "--allow-write", "--uid", str(os.getuid()), "--gid", str(os.getgid())]
        (self.root / (image.stem + "-rw-mount.argv.json")).write_text(json.dumps(argv) + "\n")
        with log_path.open("wb") as log:
            process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while not mounted_here(mountpoint):
                    require(process.poll() is None, f"mount-write exited; see {log_path}")
                    require(time.monotonic() < deadline, f"mount-write did not appear; see {log_path}")
                    time.sleep(0.05)
                output = self.command(sys.executable, Path(__file__).resolve(), "--probe-rw",
                                      mountpoint, "--manifest", expected_out, timeout=240)
                report = json.loads(output)
                self.command("fusermount3", "-u", mountpoint, timeout=30)
                require(process.wait(timeout=30) == 0, f"mount-write did not exit cleanly; see {log_path}")
                require(not mounted_here(mountpoint), "successful unmount left a writable filesystem mounted")
                return report
            finally:
                try:
                    if mounted_here(mountpoint):
                        self.command("fusermount3", "-u", mountpoint, timeout=30)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=10)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="already-built ffs-ntfs executable")
    parser.add_argument("--probe", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--probe-rw", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--manifest", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.probe is not None:
        require(args.manifest is not None, "mounted probe requires its manifest")
        probe(args.probe, args.manifest)
        return
    if args.probe_rw is not None:
        require(args.manifest is not None, "writable mounted probe requires its output manifest path")
        probe_rw(args.probe_rw, args.manifest)
        return
    require(args.binary is not None, "--binary is required")
    binary = args.binary.resolve(strict=True)
    require(os.access(binary, os.X_OK), "candidate is not executable")
    require(Path("/dev/fuse").exists() and Path("/proc/self/mountinfo").exists(),
            "a real Linux FUSE environment is required; no skip credit")
    tools = ["mkntfs", "ntfscp", "ntfscat", "ntfsls", "fusermount3"]
    for tool in tools:
        require(shutil.which(tool) is not None, f"missing required tool: {tool}")
    root = Path(tempfile.mkdtemp(prefix="ffs-ntfs-mounted-"))
    print(f"Retaining native images and logs in {root}", flush=True)
    run = Run(root, binary)
    report = {"status": "running", "candidate_sha256": digest(binary),
              "tools": {tool: shutil.which(tool) for tool in tools}, "mounts": []}
    try:
        image = root / "native.img"
        with image.open("xb") as target:
            target.truncate(64 * 1024 * 1024)
        # Only this newly created scratch regular file is passed to the formatter.
        run.command("mkntfs", "-F", "-Q", "-s", "512", "-c", "4096", image)
        manifest = {}
        for index in range(320):
            name = f"entry-{index:04d}.bin"
            payload = (f"native entry {index}\n".encode() * 100)[:1037]
            if index == 0:
                payload = b""
            elif index == 319:
                payload = (bytes(range(251)) * 9000)[:2 * 1024 * 1024 + 37]
            source = root / name
            source.write_bytes(payload)
            run.command("ntfscp", image, source, "/" + name)
            manifest[name] = {"size": len(payload), "sha256": digest(source),
                              "range_hex": payload[507:1538].hex()}
        # Independent byte oracle for every seeded file, not just candidates
        # agreeing with their own parser or with a claimed directory count.
        before = digest(image)
        for name, expected in manifest.items():
            native = run.command("ntfscat", image, "/" + name)
            require(hashlib.sha256(native).hexdigest() == expected["sha256"],
                    f"native reference differs from source: {name}")
        manifest_path = root / "expected.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        report["mounts"].append(run.mount_probe(image, manifest_path, 0, image.stat().st_size))
        require(digest(image) == before, "mounted reads changed the native image")
        disk = root / "partitioned.img"
        with disk.open("xb") as target, image.open("rb") as source:
            target.write(b"P" * 1048576)
            shutil.copyfileobj(source, target)
            target.write(b"Q" * 4096)
        disk_before = digest(disk)
        report["mounts"].append(run.mount_probe(disk, manifest_path, 1048576, image.stat().st_size))
        require(digest(disk) == disk_before, "mounted reads changed the selected or adjacent volumes")

        # Native logged transaction volume: populate >40 entries (promoting root $I30
        # to external INDX B+tree), overwrite, rename, unlink+reuse MFT slot, and grow
        # $MFT via ffs-ntfs tx-*, verify independently with ntfsls/ntfscat, then mount
        # over real Linux /dev/fuse and verify mounted readdir/stat/reads/EOF/EROFS.
        tx_image = root / "tx-mounted.img"
        with tx_image.open("xb") as target:
            target.truncate(64 * 1024 * 1024)
        run.command("mkntfs", "-F", "-Q", "-s", "512", "-c", "4096", tx_image)
        run.command(binary, "tx-grow-mft", tx_image, "--offline-image", "--allow-write", "--records", "24")
        tx_manifest: dict[str, dict[str, object]] = {}
        for index in range(44):
            name = f"tx-entry-{index:04d}.bin"
            if index == 0:
                payload = b""
                run.command(binary, "tx-create", tx_image, "/", name, "--offline-image", "--allow-write", "--empty")
            else:
                payload = (f"native-tx-mounted-{index}\n".encode() * 90)[:1613]
                if index == 43:
                    payload = (bytes(range(251)) * 9000)[:2 * 1024 * 1024 + 37]
                src = root / f"src-{name}"
                src.write_bytes(payload)
                run.command(binary, "tx-create", tx_image, "/", name, "--offline-image", "--allow-write",
                            "--data-file", src)
            tx_manifest[name] = {
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "range_hex": payload[507:1538].hex(),
            }

        # Upgrade tx-entry-0010.bin via tx-write, rename tx-entry-0020.bin, and unlink+reuse a slot.
        upgraded = (b"tx-write-mounted-upgrade-" * 500)[:9731]
        up_src = root / "src-tx-upgraded.bin"
        up_src.write_bytes(upgraded)
        run.command(binary, "tx-write", tx_image, "/tx-entry-0010.bin", "--offline-image", "--allow-write",
                    "--data-file", up_src)
        tx_manifest["tx-entry-0010.bin"] = {
            "size": len(upgraded),
            "sha256": hashlib.sha256(upgraded).hexdigest(),
            "range_hex": upgraded[507:1538].hex(),
        }

        run.command(binary, "tx-rename", tx_image, "/tx-entry-0020.bin", "/tx-entry-0020-renamed.bin",
                    "--offline-image", "--allow-write")
        tx_manifest["tx-entry-0020-renamed.bin"] = tx_manifest.pop("tx-entry-0020.bin")

        run.command(binary, "tx-create", tx_image, "/", "tx-doomed.bin", "--offline-image", "--allow-write",
                    "--data", "doomed-mounted-entry")
        run.command(binary, "tx-unlink", tx_image, "/tx-doomed.bin", "--offline-image", "--allow-write")
        reused_payload = (b"reused-slot-mounted-" * 120)[:2111]
        reused_src = root / "src-tx-reused.bin"
        reused_src.write_bytes(reused_payload)
        run.command(binary, "tx-create", tx_image, "/", "tx-reused.bin", "--offline-image", "--allow-write",
                    "--data-file", reused_src)
        tx_manifest["tx-reused.bin"] = {
            "size": len(reused_payload),
            "sha256": hashlib.sha256(reused_payload).hexdigest(),
            "range_hex": reused_payload[507:1538].hex(),
        }

        tx_before = digest(tx_image)
        root_listing = {
            line.strip()
            for line in run.command("ntfsls", "-a", tx_image).decode("utf-8", errors="strict").splitlines()
            if line.strip()
        }
        require("tx-doomed.bin" not in root_listing and "tx-entry-0020.bin" not in root_listing,
                "ntfsls still shows unlinked or renamed source entry on tx-mounted.img")
        require(set(tx_manifest) <= root_listing,
                "ntfsls omitted native transaction entries on tx-mounted.img")
        for name, expected in tx_manifest.items():
            native = run.command("ntfscat", tx_image, "/" + name)
            require(hashlib.sha256(native).hexdigest() == expected["sha256"],
                    f"ntfscat disagreed on native-tx file before mount: {name}")
        tx_manifest_path = root / "tx-expected.json"
        tx_manifest_path.write_text(json.dumps(tx_manifest, indent=2) + "\n")
        report["mounts"].append(run.mount_probe(tx_image, tx_manifest_path, 0, tx_image.stat().st_size))
        require(digest(tx_image) == tx_before, "mounted reads changed tx-mounted.img")

        # Live writable FUSE (`mount-write`) over an independently formatted + ntfscp-seeded volume,
        # followed by independent ntfsls/ntfscat/check-allocation verification AND bidirectional
        # external ntfscp -> read-only FUSE re-mount verification!
        rw_image = root / "rw-mounted.img"
        with rw_image.open("xb") as target:
            target.truncate(64 * 1024 * 1024)
        run.command("mkntfs", "-F", "-Q", "-s", "512", "-c", "4096", rw_image)
        seed_src = root / "rw-seed.bin"
        seed_src.write_bytes(b"initial-ntfscp-seed\n")
        run.command("ntfscp", rw_image, seed_src, "/seeded.bin")
        run.command(binary, "tx-grow-mft", rw_image, "--offline-image", "--allow-write", "--records", "128")
        rw_summary_path = root / "rw-summary.json"
        rw_probe_report = run.mount_write_probe(rw_image, rw_summary_path)
        report["mounts"].append(rw_probe_report)

        rw_summary = json.loads(rw_summary_path.read_text())
        rw_alloc = json.loads(run.command(
            binary, "check-allocation", rw_image, "--offline-image",
            "--verify-record-ownership", "--verify-namespace", "--verify-mft-mirror",
        ))
        require(
            rw_alloc["allocation_consistent"] is True
            and rw_alloc["requested_checks_consistent"] is True
            and int(rw_alloc["record_ownership"]["extension_records_examined"]) >= 2,
            "check-allocation failed or missed $ATTRIBUTE_LIST extensions after writable FUSE unmount",
        )
        for rel_path, key in [
            ("/seeded.bin", "seeded_sha256"),
            ("/doc.txt", "doc_sha256"),
            ("/doc-link.txt", "doc_sha256"),
            ("/open-victim.bin", "open_victim_sha256"),
            ("/meta.bin", "meta_sha256"),
        ]:
            oracle_bytes = run.command("ntfscat", rw_image, rel_path)
            require(hashlib.sha256(oracle_bytes).hexdigest() == rw_summary[key],
                    f"ntfscat disagreed after writable FUSE unmount on {rel_path}")
        for fname, exp_sha in rw_summary["bigdir"].items():
            oracle_bytes = run.command("ntfscat", rw_image, f"/bigdir/{fname}")
            require(hashlib.sha256(oracle_bytes).hexdigest() == exp_sha,
                    f"ntfscat disagreed on writable FUSE /bigdir/{fname}")
        inode_lines = run.command("ntfsls", "-a", "-i", rw_image).decode("utf-8", errors="strict").splitlines()
        doc_rec = None
        for line in inode_lines:
            m = re.fullmatch(r"\s*(\d+)\s+doc\.txt\s*", line)
            if m:
                doc_rec = int(m[1])
                break
        require(doc_rec is not None, "ntfsls -i did not locate doc.txt after writable FUSE unmount")
        for sname in ("ads-04-renamed", "ads-14", "ads-33"):
            s_oracle = run.command("ntfscat", "-i", str(doc_rec), "-n", sname, rw_image)
            require(hashlib.sha256(s_oracle).hexdigest() == rw_summary["ads"][sname],
                    f"ntfscat disagreed on writable FUSE spilled ADS stream {sname}")

        # Bidirectional external ntfscp modification -> read-only FUSE mount verification!
        after_src = root / "after-fuse-ntfscp.bin"
        after_bytes = (b"added-by-ntfscp-after-writable-fuse\n" * 60)[:1999]
        after_src.write_bytes(after_bytes)
        run.command("ntfscp", rw_image, after_src, "/after-fuse.bin")
        ro_recheck_manifest = {
            "after-fuse.bin": {
                "size": len(after_bytes),
                "sha256": hashlib.sha256(after_bytes).hexdigest(),
                "range_hex": after_bytes[507:1538].hex(),
            },
            "seeded.bin": {
                "size": 6149,
                "sha256": rw_summary["seeded_sha256"],
                "range_hex": run.command("ntfscat", rw_image, "/seeded.bin")[507:1538].hex(),
            },
        }
        ro_recheck_path = root / "rw-then-ro-expected.json"
        ro_recheck_path.write_text(json.dumps(ro_recheck_manifest, indent=2) + "\n")
        rw_after_ntfscp_sha = digest(rw_image)
        report["mounts"].append(run.mount_probe(rw_image, ro_recheck_path, 0, rw_image.stat().st_size))
        require(digest(rw_image) == rw_after_ntfscp_sha, "post-ntfscp read-only FUSE mount altered rw-mounted.img")

        # Native `ffs-ntfs format` -> `mount-write` -> `ffs-ntfs resize --relocate` -> `ffs-ntfs check` + ntfs-3g oracle!
        fmt_rw_img = root / "native-formatted-rw.img"
        run.command(binary, "format", fmt_rw_img, "--size-mib", "32", "--label", "FFS_FMT_RW")
        run.command(binary, "tx-grow-mft", fmt_rw_img, "--offline-image", "--allow-write", "--records", "128")
        seed_fmt_src = root / "fmt-rw-seed.bin"
        seed_fmt_src.write_bytes(b"initial-ntfscp-seed\n")
        run.command("ntfscp", fmt_rw_img, seed_fmt_src, "/seeded.bin")
        fmt_rw_summary = root / "fmt-rw-summary.json"
        report["mounts"].append(run.mount_write_probe(fmt_rw_img, fmt_rw_summary))
        fmt_chk = json.loads(run.command(binary, "check", fmt_rw_img, "--offline-image"))
        require(fmt_chk["clean"] is True, "ffs-ntfs check failed after mount-write on natively formatted image")

        # Relocating shrink of the mounted-written native-formatted image (32 MiB -> 16 MiB) + re-check!
        shrunk_rw_img = root / "native-formatted-shrunk-16m.img"
        shrink_rep = json.loads(run.command(
            binary, "resize", fmt_rw_img,
            "--output", shrunk_rw_img,
            "--size-mib", "16",
            "--relocate",
            "--offline-image",
        ))
        require(shrink_rep["check_clean"] is True and shrink_rep["plan"]["relocated_clusters"] > 0,
                "relocating shrink after mount-write failed or did not relocate $MFTMirr")
        fmt_summary_obj = json.loads(fmt_rw_summary.read_text())
        for rel_path, key in [("/seeded.bin", "seeded_sha256"), ("/doc.txt", "doc_sha256")]:
            oracle_bytes = run.command("ntfscat", shrunk_rw_img, rel_path)
            require(hashlib.sha256(oracle_bytes).hexdigest() == fmt_summary_obj[key],
                    f"ntfscat mismatch on shrunk native-formatted image for {rel_path}")
        if shutil.which("ntfsfix") is not None:
            run.command("ntfsfix", "-n", shrunk_rw_img)

        # Conditional Linux kernel `ntfs3` loop-mount probe (never pretends FUSE/ntfsfix is kernel ntfs3).
        ntfs3_probe = "skipped_unprivileged"
        if os.geteuid() == 0 and Path("/proc/filesystems").read_text().find("ntfs3") >= 0:
            kmnt = root / "kernel-ntfs3-mnt"
            kmnt.mkdir()
            mnt_proc = subprocess.run(
                ["mount", "-t", "ntfs3", "-o", "loop,ro", str(shrunk_rw_img), str(kmnt)],
                capture_output=True,
                check=False,
            )
            if mnt_proc.returncode == 0:
                try:
                    k_bytes = (kmnt / "doc.txt").read_bytes()
                    require(hashlib.sha256(k_bytes).hexdigest() == fmt_summary_obj["doc_sha256"],
                            "kernel ntfs3 loop mount read mismatched doc.txt")
                    ntfs3_probe = "passed_kernel_ntfs3_loop_ro"
                finally:
                    subprocess.run(["umount", str(kmnt)], check=False)
            else:
                ntfs3_probe = f"skipped_mount_error:{mnt_proc.stderr.decode(errors='replace').strip()[:120]}"

        report.update(status="passed", native_sha256=before, partitioned_sha256=disk_before,
                      tx_mounted_sha256=tx_before, rw_mounted_sha256=rw_after_ntfscp_sha,
                      native_formatted_and_resized_mount_checked=True,
                      ntfs3_kernel_mount=ntfs3_probe,
                      oracle_honesty_note="ntfsfix -n is Linux ntfs-3g probe; Windows chkdsk is not executed on Linux")
        print(json.dumps(report, indent=2))
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
