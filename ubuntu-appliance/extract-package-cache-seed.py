#!/usr/bin/env python3
"""Safely extract reusable Ubuntu debs from a previous package snapshot."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
from typing import NoReturn


MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 8192
MAX_ARCHIVE_PAYLOAD_BYTES = 5 * 1024 * 1024 * 1024
TAR_BLOCK_BYTES = 512
MAX_ARCHIVE_DECOMPRESSED_BYTES = (
    MAX_ARCHIVE_PAYLOAD_BYTES
    + MAX_ARCHIVE_MEMBERS * (TAR_BLOCK_BYTES * 2)
    + 1024 * 1024
)
MAX_DEB_BYTES = 1024 * 1024 * 1024
MAX_DEB_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_MEMBER_NAME_BYTES = 255
SNAPSHOT_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
APT_SHA256_RE = re.compile(r"^SHA256:([0-9a-fA-F]{64})$")
DEB_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_~%:-]*\.deb$")


class SeedError(Exception):
    """A bounded, operator-facing cache-seed failure."""


def fail(message: str) -> NoReturn:
    raise SeedError(message)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--snapshot", required=True)
    result.add_argument("--expected-ubuntu-snapshot-id", required=True)
    result.add_argument("--apt-print-uris", required=True)
    result.add_argument("--output", required=True)
    return result


def open_regular(path: Path, label: str, maximum_size: int | None = None) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail(f"could not securely open {label}")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"{label} must be a regular file")
        if metadata.st_size <= 0:
            fail(f"{label} must not be empty")
        if maximum_size is not None and metadata.st_size > maximum_size:
            fail(f"{label} exceeds its size limit")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def safe_deb_name(name: str) -> str | None:
    normalized = name[2:] if name.startswith("./") else name
    path = PurePosixPath(normalized)
    try:
        name_bytes = path.name.encode("utf-8")
    except UnicodeError:
        return None
    if (
        not normalized.endswith(".deb")
        or path.is_absolute()
        or len(path.parts) != 1
        or path.name in {"", ".", ".."}
        or len(name_bytes) > MAX_MEMBER_NAME_BYTES
        or not DEB_FILENAME_RE.fullmatch(path.name)
    ):
        return None
    return path.name


def expected_debs(
    plan_path: Path,
    expected_snapshot_id: str,
) -> dict[str, tuple[int, str]]:
    descriptor = open_regular(plan_path, "APT URI plan", 16 * 1024 * 1024)
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8", errors="strict") as plan:
            expected: dict[str, tuple[int, str]] = {}
            for raw_line in plan:
                line = raw_line.strip()
                if not line.startswith("'"):
                    continue
                try:
                    fields = shlex.split(line, posix=True)
                except ValueError:
                    fail("APT URI plan contains malformed quoting")
                if len(fields) != 4:
                    fail("APT URI plan contains an unexpected package record")
                uri, filename, size_bytes, digest = fields
                if not uri.startswith(
                    f"https://snapshot.ubuntu.com/ubuntu/{expected_snapshot_id}/"
                ):
                    fail("APT URI plan contains an unexpected package URI")
                safe_name = safe_deb_name(filename)
                if safe_name != filename:
                    fail("APT URI plan contains an unsafe package filename")
                if not size_bytes.isascii() or not size_bytes.isdigit():
                    fail("APT URI plan contains an invalid package size")
                size = int(size_bytes)
                if size <= 0 or size > MAX_DEB_BYTES:
                    fail("APT URI plan package exceeds its size limit")
                digest_match = APT_SHA256_RE.fullmatch(digest)
                if digest_match is None:
                    fail("APT URI plan package record lacks a strong SHA256 digest")
                if filename in expected:
                    fail("APT URI plan contains a duplicate package filename")
                expected[filename] = (size, digest_match.group(1).lower())
    except UnicodeError:
        fail("APT URI plan is not valid UTF-8")
    if not expected:
        fail("APT URI plan did not select any Ubuntu packages")
    return expected


def checked_output_directory(path: Path) -> Path:
    try:
        metadata = path.lstat()
    except OSError:
        fail("cache-seed output directory is unavailable")
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        fail("cache-seed output must be a real directory")
    try:
        if next(path.iterdir(), None) is not None:
            fail("cache-seed output directory must be empty")
    except OSError:
        fail("cache-seed output directory is unreadable")
    return path


class BoundedDecompressedReader:
    """Read a zstd stream without allowing tar metadata to trigger large reads."""

    def __init__(self, stream: object, maximum_bytes: int) -> None:
        self.stream = stream
        self.maximum_bytes = maximum_bytes
        self.bytes_read = 0

    def read_up_to(self, size: int) -> bytes:
        if size <= 0:
            return b""
        remaining = self.maximum_bytes - self.bytes_read
        if remaining <= 0:
            fail("previous package snapshot decompressed data exceeds its size limit")
        read_size = min(size, remaining + 1)
        data = self.stream.read(read_size)  # type: ignore[attr-defined]
        self.bytes_read += len(data)
        if self.bytes_read > self.maximum_bytes:
            fail("previous package snapshot decompressed data exceeds its size limit")
        return data

    def read_exact(self, size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            chunk = self.read_up_to(size - len(result))
            if not chunk:
                fail("previous package snapshot is malformed or truncated")
            result.extend(chunk)
        return bytes(result)

    def discard_exact(self, size: int) -> None:
        remaining = size
        while remaining:
            chunk = self.read_up_to(min(remaining, 1024 * 1024))
            if not chunk:
                fail("previous package snapshot is malformed or truncated")
            remaining -= len(chunk)


def parse_tar_octal(field: bytes, label: str) -> int:
    value = field.strip(b"\0 ")
    if not value:
        return 0
    if any(byte < ord("0") or byte > ord("7") for byte in value):
        fail(f"previous package snapshot has an invalid {label}")
    return int(value, 8)


def parse_tar_text(field: bytes, label: str) -> str:
    encoded = field.split(b"\0", 1)[0]
    try:
        return encoded.decode("utf-8", errors="strict")
    except UnicodeError:
        fail(f"previous package snapshot has an invalid {label}")


def parse_ustar_header(header: bytes) -> tuple[str, bytes, int]:
    if len(header) != TAR_BLOCK_BYTES:
        fail("previous package snapshot is malformed or truncated")
    expected_checksum = parse_tar_octal(header[148:156], "tar checksum")
    actual_checksum = sum(header[:148]) + (8 * ord(" ")) + sum(header[156:])
    if expected_checksum != actual_checksum:
        fail("previous package snapshot has an invalid tar checksum")
    if header[257:263] != b"ustar\0" or header[263:265] != b"00":
        fail("previous package snapshot must use the USTAR archive format")

    name = parse_tar_text(header[:100], "tar member name")
    prefix = parse_tar_text(header[345:500], "tar member prefix")
    if prefix:
        name = f"{prefix}/{name}"
    if not name:
        fail("previous package snapshot contains an unnamed archive member")
    size = parse_tar_octal(header[124:136], "tar member size")
    type_flag = header[156:157]
    if type_flag == b"\0":
        type_flag = b"0"
    # James package snapshots are emitted as strict USTAR and contain only the
    # repository directory plus regular files. Reject PAX/GNU extension
    # records before reading their declared payload: Python's tarfile parser
    # otherwise materializes those records internally before yielding them.
    if type_flag not in {b"0", b"5"}:
        fail("previous package snapshot contains an unsupported archive member type")
    if type_flag == b"5" and size != 0:
        fail("previous package snapshot contains an invalid directory member")
    return name, type_flag, size


def copy_payload(
    reader: BoundedDecompressedReader,
    size: int,
    destination: Path,
) -> str:
    remaining = size
    digest = hashlib.sha256()
    try:
        with destination.open("xb") as output:
            while remaining:
                chunk = reader.read_up_to(min(remaining, 1024 * 1024))
                if not chunk:
                    fail("previous package snapshot member was truncated")
                output.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
        destination.chmod(0o644)
    except FileExistsError:
        fail("previous package snapshot contains a duplicate package filename")
    return digest.hexdigest()


def discard_zero_padding(reader: BoundedDecompressedReader, size: int) -> None:
    padding_size = (-size) % TAR_BLOCK_BYTES
    if padding_size and any(reader.read_exact(padding_size)):
        fail("previous package snapshot contains nonzero tar padding")


def consume_archive_end(reader: BoundedDecompressedReader) -> None:
    if any(reader.read_exact(TAR_BLOCK_BYTES)):
        fail("previous package snapshot has an invalid tar end marker")
    while True:
        trailing = reader.read_up_to(1024 * 1024)
        if not trailing:
            return
        if any(trailing):
            fail("previous package snapshot contains data after its tar end marker")


def extract_candidates(
    snapshot_fd: int,
    expected_snapshot_id: str,
    expected: dict[str, tuple[int, str]],
    output: Path,
) -> list[Path]:
    try:
        decompressor = subprocess.Popen(
            [
                "zstd",
                "--decompress",
                "--stdout",
                "--quiet",
                "-M128M",
            ],
            stdin=snapshot_fd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (FileNotFoundError, OSError):
        fail("zstd is required to inspect the previous package snapshot")
    assert decompressor.stdout is not None
    stream = BoundedDecompressedReader(
        decompressor.stdout,
        MAX_ARCHIVE_DECOMPRESSED_BYTES,
    )
    observed_names: set[str] = set()
    extracted: list[Path] = []
    snapshot_marker: bytes | None = None
    member_count = 0
    payload_bytes = 0
    deb_bytes = 0
    failed = False
    try:
        while True:
            header = stream.read_exact(TAR_BLOCK_BYTES)
            if not any(header):
                consume_archive_end(stream)
                break
            member_name, type_flag, member_size = parse_ustar_header(header)
            member_count += 1
            if member_count > MAX_ARCHIVE_MEMBERS:
                fail("previous package snapshot contains too many archive members")
            payload_bytes += member_size
            if payload_bytes > MAX_ARCHIVE_PAYLOAD_BYTES:
                fail("previous package snapshot payload exceeds its size limit")

            normalized_name = (
                member_name[2:] if member_name.startswith("./") else member_name
            )
            if normalized_name == "UBUNTU-SNAPSHOT-ID":
                if snapshot_marker is not None:
                    fail("previous package snapshot contains a duplicate snapshot marker")
                if type_flag != b"0" or member_size > 64:
                    fail("previous package snapshot has an invalid snapshot marker")
                snapshot_marker = stream.read_exact(member_size)
                discard_zero_padding(stream, member_size)
                continue

            if not normalized_name.endswith(".deb"):
                stream.discard_exact(member_size)
                discard_zero_padding(stream, member_size)
                continue
            safe_name = safe_deb_name(member_name)
            if safe_name is None:
                fail("previous package snapshot contains an unsafe deb member path")
            if safe_name in observed_names:
                fail("previous package snapshot contains a duplicate deb member")
            observed_names.add(safe_name)
            if type_flag != b"0":
                fail("previous package snapshot deb members must be regular files")
            if member_size <= 0 or member_size > MAX_DEB_BYTES:
                fail("previous package snapshot deb member exceeds its size limit")
            deb_bytes += member_size
            if deb_bytes > MAX_DEB_TOTAL_BYTES:
                fail("previous package snapshot deb payload exceeds its size limit")
            expected_identity = expected.get(safe_name)
            if expected_identity is None or member_size != expected_identity[0]:
                stream.discard_exact(member_size)
            else:
                destination = output / safe_name
                actual_sha256 = copy_payload(stream, member_size, destination)
                if actual_sha256 == expected_identity[1]:
                    extracted.append(destination)
                else:
                    # A corrupt or forged cache hint is not a release failure;
                    # omit it and let the authenticated download fetch the
                    # exact current package.
                    destination.unlink()
            discard_zero_padding(stream, member_size)
    except SeedError:
        failed = True
        raise
    except (OSError, EOFError):
        failed = True
        fail("previous package snapshot is malformed or truncated")
    finally:
        decompressor.stdout.close()
        if failed and decompressor.poll() is None:
            decompressor.kill()
        stderr = decompressor.stderr.read() if decompressor.stderr is not None else b""
        return_code = decompressor.wait()
    if return_code != 0:
        del stderr
        fail("previous package snapshot decompression failed")
    expected_marker = f"{expected_snapshot_id}\n".encode("ascii")
    if snapshot_marker != expected_marker:
        fail("previous package snapshot UBUNTU-SNAPSHOT-ID does not match the requested snapshot")
    return extracted


def exclude_local_package_names(packages: list[Path]) -> int:
    """Keep all unauthenticated candidate bytes opaque until APT verifies them."""

    accepted = 0
    for package in packages:
        if package.name.lower().startswith("cybex-james"):
            package.unlink()
            continue
        accepted += 1
    return accepted


def clean_output(output: Path) -> None:
    for child in output.iterdir():
        if child.is_symlink() or child.is_file():
            child.unlink()
        elif child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def main() -> None:
    arguments = parser().parse_args()
    if not SNAPSHOT_ID_RE.fullmatch(arguments.expected_ubuntu_snapshot_id):
        raise SystemExit("expected Ubuntu snapshot ID is invalid")
    output: Path | None = None
    snapshot_fd = -1
    try:
        output = checked_output_directory(Path(arguments.output))
        expected = expected_debs(
            Path(arguments.apt_print_uris),
            arguments.expected_ubuntu_snapshot_id,
        )
        snapshot_fd = open_regular(
            Path(arguments.snapshot),
            "previous package snapshot",
            MAX_SNAPSHOT_BYTES,
        )
        packages = extract_candidates(
            snapshot_fd,
            arguments.expected_ubuntu_snapshot_id,
            expected,
            output,
        )
        # Do not invoke dpkg, tar, or another inner archive parser on these
        # bytes. They are admitted only after matching the strong SHA256 from
        # APT's current authenticated snapshot plan.
        accepted = exclude_local_package_names(packages)
    except SeedError as error:
        if output is not None:
            clean_output(output)
        raise SystemExit(f"error: {error}") from None
    finally:
        if snapshot_fd >= 0:
            os.close(snapshot_fd)
    print(f"seeded {accepted} validated Ubuntu package(s) from the previous snapshot")


if __name__ == "__main__":
    main()
