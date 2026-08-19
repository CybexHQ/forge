#!/usr/bin/env python3
"""Atomically expose one already-verified package snapshot at its signed URL.

This helper is intentionally only a filesystem transport primitive.  The
caller must first run ``tools/james-release.py verify`` against the complete
signed candidate.  It then binds the exact snapshot bytes to the descriptor in
that manifest, exposes no other candidate file, and journals ownership outside
the served tree so cleanup cannot remove an unrelated file.
"""

from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import NoReturn, Sequence
from urllib.parse import unquote, urlsplit


MANIFEST_SCHEMA = "cybex.james.release.v1"
APPLIANCE_SCHEMA = "cybex.james.appliance-release.v1"
LEDGER_SCHEMA = "cybex.james.canonical-package-stage.v1"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024
SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class StageError(Exception):
    """Bounded operator-facing staging failure."""


def fail(message: str) -> NoReturn:
    raise StageError(message)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def open_regular(path: Path, label: str, maximum: int) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail(f"could not securely open {label}")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            fail(f"{label} metadata is unsafe")
        return descriptor, metadata
    except BaseException:
        os.close(descriptor)
        raise


def read_bounded(path: Path, label: str, maximum: int) -> bytes:
    descriptor, metadata = open_regular(path, label, maximum)
    try:
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                fail(f"{label} exceeds its size limit")
            chunks.append(chunk)
        if consumed != metadata.st_size or stable_identity(
            os.fstat(descriptor)
        ) != stable_identity(metadata):
            fail(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def hash_descriptor(descriptor: int, maximum: int, label: str) -> tuple[str, int]:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > maximum
    ):
        fail(f"{label} metadata is unsafe")
    digest = hashlib.sha256()
    consumed = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        consumed += len(chunk)
        if consumed > maximum:
            fail(f"{label} exceeds its size limit")
        digest.update(chunk)
    if consumed != metadata.st_size or stable_identity(
        os.fstat(descriptor)
    ) != stable_identity(metadata):
        fail(f"{label} changed while it was hashed")
    return digest.hexdigest(), consumed


def hash_path(path: Path, label: str, maximum: int) -> tuple[str, int]:
    descriptor, _metadata = open_regular(path, label, maximum)
    try:
        return hash_descriptor(descriptor, maximum, label)
    finally:
        os.close(descriptor)


def stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Metadata that must not change while reading, excluding access time."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} fields are invalid")
    return value


def canonical_base64(value: object, label: str, expected_bytes: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        fail(f"{label} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError):
        fail(f"{label} is invalid")
    if (
        len(decoded) != expected_bytes
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        fail(f"{label} is invalid")
    return value


def canonical_https_prefix(value: str) -> tuple[str, str]:
    try:
        value.encode("ascii")
        parsed = urlsplit(value)
        port = parsed.port
    except (UnicodeEncodeError, ValueError):
        fail("served prefix is invalid")
    hostname = parsed.hostname or ""
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        canonical_host = hostname.lower()
        if not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
            r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*",
            canonical_host,
        ):
            fail("served prefix host is invalid")
    else:
        canonical_host = address.compressed
        if address.version == 6:
            canonical_host = f"[{canonical_host}]"
    canonical_netloc = canonical_host + ("" if port in (None, 443) else f":{port}")
    if (
        not value
        or len(value.encode("utf-8")) > 2048
        or value != value.strip()
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.netloc != canonical_netloc
        or not parsed.path.startswith("/")
        or value.endswith("/")
        or unquote(parsed.path) != parsed.path
        or "//" in parsed.path
        or any(part in (".", "..") for part in parsed.path.split("/"))
        or port is not None and not 1 <= port <= 65535
    ):
        fail("served prefix must be a canonical HTTPS URL without a trailing slash")
    return canonical_netloc, parsed.path


def parse_manifest(
    path: Path, served_prefix: str
) -> tuple[dict[str, object], bytes]:
    body = read_bounded(path, "candidate manifest", MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("candidate manifest is not valid JSON")
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        fail("candidate manifest schema is invalid")
    version = manifest.get("version")
    if (
        not isinstance(version, str)
        or len(version) > 128
        or not SEMVER_RE.fullmatch(version)
    ):
        fail("candidate release version is invalid")
    appliance = exact_keys(
        manifest.get("appliance_release_v1"),
        {
            "schema",
            "release_id",
            "ubuntu_snapshot_id",
            "cybex_repository_snapshot",
            "required_package_versions",
            "expected_kernel",
            "minimum_protocol",
            "minimum_state_schema",
            "rollback_compatible",
            "release_notes",
            "signature",
        },
        "appliance release descriptor",
    )
    if appliance["schema"] != APPLIANCE_SCHEMA or appliance["release_id"] != version:
        fail("appliance release descriptor does not match the candidate")
    canonical_base64(appliance["signature"], "appliance release signature", 64)
    snapshot = exact_keys(
        appliance["cybex_repository_snapshot"],
        {"url", "sha256", "size_bytes"},
        "package snapshot descriptor",
    )
    url = snapshot["url"]
    digest = snapshot["sha256"]
    size = snapshot["size_bytes"]
    if (
        not isinstance(url, str)
        or len(url.encode("utf-8")) > 2048
        or not isinstance(digest, str)
        or not SHA256_RE.fullmatch(digest)
    ):
        fail("package snapshot identity is invalid")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > MAX_PACKAGE_BYTES
    ):
        fail("package snapshot size is invalid")
    _prefix_netloc, prefix_path = canonical_https_prefix(served_prefix)
    expected_name = f"cybex-james-appliance-packages-{version}-x86_64-linux.tar.zst"
    if url != f"{served_prefix}/{version}/{expected_name}":
        fail("signed package URL does not map exactly beneath the served prefix")
    return {
        "release_id": version,
        "url": url,
        "filename": expected_name,
        "sha256": digest,
        "size_bytes": size,
        "manifest_sha256": hashlib.sha256(body).hexdigest(),
    }, body


def open_owned_directory(path: Path, label: str, *, private: bool) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail(f"could not securely open {label}")
    metadata = os.fstat(descriptor)
    unsafe_mode = metadata.st_mode & (0o077 if private else 0o022)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or unsafe_mode
    ):
        os.close(descriptor)
        fail(f"{label} ownership or permissions are unsafe")
    return descriptor


def directory_is_outside(root: Path, state: Path) -> bool:
    return root != state and root not in state.parents and state not in root.parents


def write_exclusive(directory_fd: int, name: str, body: bytes, mode: int) -> None:
    temporary = f".{name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, mode, dir_fd=directory_fd)
    except OSError:
        fail("could not create private staging journal")
    try:
        consumed = 0
        while consumed < len(body):
            consumed += os.write(descriptor, body[consumed:])
        os.fsync(descriptor)
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            fail("canonical package staging journal already exists")
        os.fsync(directory_fd)
    finally:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def read_regular_at(directory_fd: int, name: str, label: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError:
        fail(f"could not securely open {label}")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            fail(f"{label} metadata is unsafe")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                fail(f"{label} exceeds its size limit")
            chunks.append(chunk)
        if consumed != metadata.st_size or stable_identity(
            os.fstat(descriptor)
        ) != stable_identity(metadata):
            fail(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def open_lock(directory_fd: int, name: str) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except OSError:
        fail("could not securely open the staging lock")
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        fail("staging lock metadata is unsafe")
    return descriptor


def remove_owned_private_temp(directory_fd: int, name: str) -> None:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) not in (0o400, 0o444)
    ):
        fail("private package staging file metadata is unsafe")
    os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


def inspect_target(directory_fd: int, name: str, identity: dict[str, object]) -> bool:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        return False
    except OSError:
        fail("could not securely open staged package snapshot")
    try:
        metadata = os.fstat(descriptor)
        digest, size = hash_descriptor(
            descriptor, MAX_PACKAGE_BYTES, "staged package snapshot"
        )
        if (
            metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o444
            or digest != identity["sha256"]
            or size != identity["size_bytes"]
        ):
            fail("staged package snapshot does not match the owned exact bytes")
        return True
    finally:
        os.close(descriptor)


def ledger_value(
    identity: dict[str, object], owner: str, directory_created: bool, original_mode: int
) -> dict[str, object]:
    return {
        "schema": LEDGER_SCHEMA,
        "owner": owner,
        "manifest_sha256": identity["manifest_sha256"],
        "release_id": identity["release_id"],
        "url": identity["url"],
        "filename": identity["filename"],
        "sha256": identity["sha256"],
        "size_bytes": identity["size_bytes"],
        "directory_created": directory_created,
        "directory_original_mode": original_mode,
    }


def load_ledger(state_fd: int, name: str) -> dict[str, object] | None:
    try:
        body = read_regular_at(state_fd, name, "staging journal", 16 * 1024)
    except StageError as error:
        try:
            os.stat(name, dir_fd=state_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        raise error
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("staging journal is invalid")
    expected = {
        "schema",
        "owner",
        "manifest_sha256",
        "release_id",
        "url",
        "filename",
        "sha256",
        "size_bytes",
        "directory_created",
        "directory_original_mode",
    }
    if not isinstance(value, dict) or set(value) != expected or value["schema"] != LEDGER_SCHEMA:
        fail("staging journal is invalid")
    return value


def release_directory_metadata(root_fd: int, release_id: str) -> os.stat_result | None:
    try:
        metadata = os.stat(release_id, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        fail("canonical release staging directory is unsafe")
    return metadata


def open_release_directory(root_fd: int, release_id: str) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(release_id, flags, dir_fd=root_fd)
    except OSError:
        fail("could not securely open canonical release staging directory")


def copy_snapshot_to_private_temp(
    snapshot: Path,
    state_fd: int,
    temporary: str,
    identity: dict[str, object],
) -> None:
    source_fd, source_metadata = open_regular(
        snapshot, "candidate package snapshot", MAX_PACKAGE_BYTES
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        output_fd = os.open(temporary, flags, 0o400, dir_fd=state_fd)
    except OSError:
        os.close(source_fd)
        fail("could not create private package staging file")
    try:
        digest = hashlib.sha256()
        consumed = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > MAX_PACKAGE_BYTES:
                fail("candidate package snapshot exceeds its size limit")
            digest.update(chunk)
            written = 0
            while written < len(chunk):
                written += os.write(output_fd, chunk[written:])
        if consumed != source_metadata.st_size or stable_identity(
            os.fstat(source_fd)
        ) != stable_identity(source_metadata):
            fail("candidate package snapshot changed while it was copied")
        if digest.hexdigest() != identity["sha256"] or consumed != identity["size_bytes"]:
            fail("candidate package snapshot does not match its signed descriptor")
        os.fchmod(output_fd, 0o444)
        os.fsync(output_fd)
    finally:
        os.close(output_fd)
        os.close(source_fd)


def validate_common(arguments: argparse.Namespace) -> tuple[
    dict[str, object], Path, Path, str, str
]:
    if not OWNER_RE.fullmatch(arguments.owner):
        fail("owner must be a bounded non-secret identifier")
    identity, _body = parse_manifest(Path(arguments.manifest), arguments.served_prefix)
    root = Path(arguments.artifact_root)
    state = Path(arguments.state_dir)
    if not root.is_absolute() or not state.is_absolute():
        fail("artifact root and state directory must be absolute")
    try:
        canonical_root = root.resolve(strict=True)
        canonical_state = state.resolve(strict=True)
    except OSError:
        fail("artifact root and state directory must already exist")
    if canonical_root != root or canonical_state != state:
        fail("artifact root and state directory must not use symlinks")
    if not directory_is_outside(root, state):
        fail("private staging state must be outside the served artifact tree")
    key = hashlib.sha256(str(identity["url"]).encode("ascii")).hexdigest()
    return identity, root, state, f"{key}.json", f"{key}.lock"


def stage(arguments: argparse.Namespace) -> None:
    identity, root, state, ledger_name, lock_name = validate_common(arguments)
    snapshot = Path(arguments.package_snapshot)
    if snapshot.name != identity["filename"]:
        fail("candidate package snapshot filename does not match its descriptor")
    snapshot_sha, snapshot_size = hash_path(
        snapshot, "candidate package snapshot", MAX_PACKAGE_BYTES
    )
    if snapshot_sha != identity["sha256"] or snapshot_size != identity["size_bytes"]:
        fail("candidate package snapshot does not match its signed descriptor")
    try:
        if snapshot.resolve(strict=True).is_relative_to(root):
            fail("candidate package snapshot source must be outside the served tree")
    except OSError:
        fail("candidate package snapshot is unavailable")
    root_fd = open_owned_directory(root, "served artifact root", private=False)
    state_fd = open_owned_directory(state, "private staging state", private=True)
    try:
        lock_fd = open_lock(state_fd, lock_name)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            remove_owned_private_temp(
                state_fd, f".{ledger_name}.package.tmp"
            )
            directory_metadata = release_directory_metadata(
                root_fd, str(identity["release_id"])
            )
            existing_ledger = load_ledger(state_fd, ledger_name)
            directory_created = (
                bool(existing_ledger["directory_created"])
                if existing_ledger is not None
                else directory_metadata is None
            )
            original_mode = (
                int(existing_ledger["directory_original_mode"])
                if existing_ledger is not None
                else 0o555
                if directory_metadata is None
                else stat.S_IMODE(directory_metadata.st_mode)
            )
            expected_ledger = ledger_value(
                identity, arguments.owner, directory_created, original_mode
            )
            if directory_metadata is not None and existing_ledger is None:
                release_fd = open_release_directory(
                    root_fd, str(identity["release_id"])
                )
                try:
                    if os.listdir(release_fd):
                        fail(
                            "refusing to adopt an unowned canonical release directory"
                        )
                finally:
                    os.close(release_fd)
            if existing_ledger is None:
                write_exclusive(
                    state_fd, ledger_name, canonical_json(expected_ledger), 0o600
                )
            elif existing_ledger != expected_ledger:
                fail("canonical package URL is already owned by a different staging identity")
            if directory_metadata is None:
                try:
                    os.mkdir(str(identity["release_id"]), 0o700, dir_fd=root_fd)
                except FileExistsError:
                    pass
            release_fd = open_release_directory(root_fd, str(identity["release_id"]))
            try:
                entries = os.listdir(release_fd)
                allowed_entries = {str(identity["filename"])}
                if any(entry not in allowed_entries for entry in entries):
                    fail(
                        "canonical release directory exposes files other than "
                        "the package snapshot"
                    )
                if not inspect_target(release_fd, str(identity["filename"]), identity):
                    os.fchmod(release_fd, 0o700)
                    temporary = f".{ledger_name}.package.tmp"
                    try:
                        copy_snapshot_to_private_temp(
                            snapshot, state_fd, temporary, identity
                        )
                        try:
                            os.link(
                                temporary,
                                str(identity["filename"]),
                                src_dir_fd=state_fd,
                                dst_dir_fd=release_fd,
                                follow_symlinks=False,
                            )
                        except OSError as error:
                            if error.errno == errno.EXDEV:
                                fail(
                                    "private staging state must share a filesystem "
                                    "with the artifact root"
                                )
                            if error.errno == errno.EEXIST:
                                fail("canonical package target appeared during staging")
                            fail("could not atomically expose the canonical package snapshot")
                        os.fsync(release_fd)
                    finally:
                        try:
                            os.unlink(temporary, dir_fd=state_fd)
                            os.fsync(state_fd)
                        except FileNotFoundError:
                            pass
                os.fchmod(release_fd, 0o555)
                os.fsync(release_fd)
                if set(os.listdir(release_fd)) != allowed_entries:
                    fail("canonical release directory is not package-only")
                inspect_target(release_fd, str(identity["filename"]), identity)
            finally:
                os.close(release_fd)
            os.fsync(root_fd)
        finally:
            os.close(lock_fd)
    finally:
        os.close(state_fd)
        os.close(root_fd)
    print(
        "staged exact canonical package: "
        f"release={identity['release_id']} sha256={identity['sha256']}"
    )


def verify(arguments: argparse.Namespace) -> None:
    identity, root, state, ledger_name, lock_name = validate_common(arguments)
    root_fd = open_owned_directory(root, "served artifact root", private=False)
    state_fd = open_owned_directory(state, "private staging state", private=True)
    try:
        lock_fd = open_lock(state_fd, lock_name)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            ledger = load_ledger(state_fd, ledger_name)
            if ledger is None or ledger != ledger_value(
                identity,
                arguments.owner,
                bool(ledger and ledger.get("directory_created")),
                int(ledger.get("directory_original_mode", 0)) if ledger else 0,
            ):
                fail("canonical package staging journal does not match this request")
            metadata = release_directory_metadata(root_fd, str(identity["release_id"]))
            if metadata is None or stat.S_IMODE(metadata.st_mode) != 0o555:
                fail("canonical release staging directory is unavailable or mutable")
            release_fd = open_release_directory(root_fd, str(identity["release_id"]))
            try:
                if set(os.listdir(release_fd)) != {str(identity["filename"])}:
                    fail("canonical release directory is not package-only")
                if not inspect_target(release_fd, str(identity["filename"]), identity):
                    fail("canonical package snapshot is unavailable")
            finally:
                os.close(release_fd)
        finally:
            os.close(lock_fd)
    finally:
        os.close(state_fd)
        os.close(root_fd)
    print(
        "verified exact canonical package stage: "
        f"release={identity['release_id']} sha256={identity['sha256']}"
    )


def cleanup(arguments: argparse.Namespace) -> None:
    identity, root, state, ledger_name, lock_name = validate_common(arguments)
    root_fd = open_owned_directory(root, "served artifact root", private=False)
    state_fd = open_owned_directory(state, "private staging state", private=True)
    try:
        lock_fd = open_lock(state_fd, lock_name)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            remove_owned_private_temp(
                state_fd, f".{ledger_name}.package.tmp"
            )
            ledger = load_ledger(state_fd, ledger_name)
            directory_metadata = release_directory_metadata(
                root_fd, str(identity["release_id"])
            )
            if ledger is None:
                if directory_metadata is None:
                    return
                release_fd = open_release_directory(root_fd, str(identity["release_id"]))
                try:
                    if str(identity["filename"]) in os.listdir(release_fd):
                        fail("refusing to remove an unowned canonical package snapshot")
                finally:
                    os.close(release_fd)
                return
            expected_ledger = ledger_value(
                identity,
                arguments.owner,
                bool(ledger.get("directory_created")),
                int(ledger.get("directory_original_mode", 0)),
            )
            if ledger != expected_ledger:
                fail("canonical package staging journal does not match this request")
            if directory_metadata is not None:
                release_fd = open_release_directory(root_fd, str(identity["release_id"]))
                try:
                    entries = set(os.listdir(release_fd))
                    if entries not in (
                        set(),
                        {str(identity["filename"])},
                    ):
                        fail(
                            "refusing cleanup after the canonical release "
                            "directory changed"
                        )
                    if inspect_target(release_fd, str(identity["filename"]), identity):
                        os.fchmod(release_fd, 0o700)
                        os.unlink(str(identity["filename"]), dir_fd=release_fd)
                        os.fsync(release_fd)
                    remaining = os.listdir(release_fd)
                    if remaining:
                        restored_mode = (
                            0o555
                            if bool(ledger["directory_created"])
                            else int(ledger["directory_original_mode"])
                        )
                        os.fchmod(release_fd, restored_mode)
                finally:
                    os.close(release_fd)
                if not remaining and bool(ledger["directory_created"]):
                    os.rmdir(str(identity["release_id"]), dir_fd=root_fd)
                elif not remaining:
                    release_fd = open_release_directory(root_fd, str(identity["release_id"]))
                    try:
                        os.fchmod(release_fd, int(ledger["directory_original_mode"]))
                    finally:
                        os.close(release_fd)
                os.fsync(root_fd)
            os.unlink(ledger_name, dir_fd=state_fd)
            os.fsync(state_fd)
        finally:
            os.close(lock_fd)
    finally:
        os.close(state_fd)
        os.close(root_fd)
    print(f"removed owned canonical package stage: release={identity['release_id']}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    commands = result.add_subparsers(dest="command", required=True)
    for name, handler in (("stage", stage), ("verify", verify), ("cleanup", cleanup)):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--manifest", required=True)
        command.add_argument("--artifact-root", required=True)
        command.add_argument("--served-prefix", required=True)
        command.add_argument("--state-dir", required=True)
        command.add_argument("--owner", required=True)
        if name == "stage":
            command.add_argument("--package-snapshot", required=True)
        command.set_defaults(handler=handler)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        arguments.handler(arguments)
    except StageError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except OSError:
        print(
            "error: the operating system could not complete canonical package staging",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
