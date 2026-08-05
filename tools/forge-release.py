#!/usr/bin/env python3
"""Build deterministic, signed Cybex Forge release manifests.

The private Ed25519 key is opened without following symlinks and is passed to
OpenSSL through an inherited file descriptor. Its bytes and path are never
written to output or included in errors.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, NoReturn, Sequence
from urllib.parse import urlsplit


SCHEMA = "cybex.forge.release.v1"
INSTALLER_ISO_ARCHITECTURE = "x86_64-linux"
INSTALLER_ISO_MAX_BYTES = 16 * 1024 * 1024 * 1024
INSTALLER_ISO_TEMPLATE_SIGNATURE_DOMAIN = (
    "CYBEX-FORGE-INSTALLER-ISO-TEMPLATE-V2"
)
INSTALLER_ISO_TEMPLATE_BASE_OS = "ubuntu"
INSTALLER_ISO_TEMPLATE_BASE_OS_VERSION = "26.04"
INSTALLER_ISO_TEMPLATE_PERSONALIZATION_SIZE = 8192
APPLIANCE_RELEASE_SIGNATURE_DOMAIN = "CYBEX-FORGE-APPLIANCE-RELEASE-V1"
APPLIANCE_RELEASE_SCHEMA = "cybex.forge.appliance-release.v1"
WORKSTATION_NETBOOT_SIGNATURE_DOMAIN = "CYBEX-FORGE-WORKSTATION-NETBOOT-V1"
WORKSTATION_NETBOOT_SCHEMA = "cybex.forge.workstation-netboot.v1"
WORKSTATION_NETBOOT_MANIFEST_SCHEMA = "cybex.forge.workstation-netboot-manifest.v1"
WORKSTATION_NETBOOT_ARCHITECTURE = "x86_64-linux"
WORKSTATION_NETBOOT_FORMAT = "split-squashfs-v1"
WORKSTATION_NETBOOT_REQUIRED_FORGE_PROTOCOL = 4
WORKSTATION_NETBOOT_MAX_BYTES = 8 * 1024 * 1024 * 1024
WORKSTATION_NETBOOT_COMPONENTS = (
    "bzImage",
    "initrd",
    "nix-store.squashfs",
)
ED25519_PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
PUBLISHED_AT_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
URL_MAX_BYTES = 2048
WEAK_PUBLIC_KEYS_PATH = (
    Path(__file__).resolve().parents[1]
    / "trust"
    / "ed25519-weak-public-keys.txt"
)


class ReleaseError(Exception):
    """A safe, operator-facing release-tool failure."""


def _fail(message: str) -> NoReturn:
    raise ReleaseError(message)


def _open_regular(path: Path, label: str, *, private: bool = False) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        if private:
            _fail("could not securely open the supplied private key")
        _fail(f"could not securely open {label}")
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            _fail(f"{label} must be a regular file")
        if private:
            if metadata.st_uid != os.geteuid():
                _fail("private key must be owned by the effective user")
            if metadata.st_nlink != 1:
                _fail("private key must have exactly one hard link")
            if metadata.st_mode & 0o077:
                _fail("private key permissions must not grant group or other access")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _private_key_identity(fd: int) -> tuple[int, ...]:
    metadata = os.fstat(fd)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o077
    ):
        _fail("private key metadata is unsafe")
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


def _require_stable_private_key(fd: int, expected: tuple[int, ...]) -> None:
    if _private_key_identity(fd) != expected:
        _fail("private key changed while OpenSSL was using it")


def _openssl(
    arguments: Sequence[str],
    *,
    input_bytes: bytes | None = None,
    pass_fds: Sequence[int] = (),
    action: str,
) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *arguments],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            pass_fds=tuple(pass_fds),
        )
    except FileNotFoundError:
        _fail("OpenSSL is required")
    if result.returncode != 0:
        _fail(f"OpenSSL could not {action}")
    return result.stdout


def _private_fd_path(fd: int) -> str:
    return f"/proc/self/fd/{fd}"


def _public_der(private_fd: int) -> bytes:
    os.lseek(private_fd, 0, os.SEEK_SET)
    public_der = _openssl(
        [
            "pkey",
            "-in",
            _private_fd_path(private_fd),
            "-pubout",
            "-outform",
            "DER",
        ],
        pass_fds=[private_fd],
        action="derive an Ed25519 public key from the supplied private key",
    )
    if (
        len(public_der) != len(ED25519_PUBLIC_DER_PREFIX) + 32
        or not public_der.startswith(ED25519_PUBLIC_DER_PREFIX)
    ):
        _fail("the supplied private key is not Ed25519")
    return public_der


def _sign(private_fd: int, message: bytes) -> bytes:
    os.lseek(private_fd, 0, os.SEEK_SET)
    with tempfile.TemporaryFile(prefix="cybex-forge-release-message-") as message_file:
        message_file.write(message)
        message_file.flush()
        message_file.seek(0)
        signature = _openssl(
            [
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                _private_fd_path(private_fd),
                "-in",
                _private_fd_path(message_file.fileno()),
            ],
            pass_fds=[private_fd, message_file.fileno()],
            action="sign the Forge release manifest",
        )
    if len(signature) != 64:
        _fail("OpenSSL returned an invalid Ed25519 signature")
    return signature


def _self_verify(public_der: bytes, signature: bytes, message: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="cybex-forge-release-verify-") as directory:
        directory_path = Path(directory)
        public_path = directory_path / "public.der"
        signature_path = directory_path / "signature.bin"
        message_path = directory_path / "message.bin"
        public_path.write_bytes(public_der)
        signature_path.write_bytes(signature)
        message_path.write_bytes(message)
        public_path.chmod(0o600)
        signature_path.chmod(0o600)
        message_path.chmod(0o600)
        _openssl(
            [
                "pkeyutl",
                "-verify",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                str(public_path),
                "-rawin",
                "-sigfile",
                str(signature_path),
                "-in",
                str(message_path),
            ],
            action="self-verify the Forge release signature",
        )


def _canonical_base64(value: object, label: str, *, expected_bytes: int) -> bytes:
    if not isinstance(value, str) or not value or value != value.strip():
        _fail(f"{label} must be canonical standard Base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        _fail(f"{label} must be canonical standard Base64")
    if (
        len(decoded) != expected_bytes
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        _fail(f"{label} must decode to exactly {expected_bytes} bytes")
    return decoded


def _weak_public_keys() -> frozenset[bytes]:
    try:
        lines = WEAK_PUBLIC_KEYS_PATH.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        _fail("could not load the Ed25519 weak-key deny set")
    if len(lines) != 14 or len(set(lines)) != 14:
        _fail("Ed25519 weak-key deny set must contain exactly fourteen unique encodings")
    keys: set[bytes] = set()
    for value in lines:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            _fail("Ed25519 weak-key deny set is malformed")
        if (
            len(decoded) != 32
            or base64.b64encode(decoded).decode("ascii") != value
        ):
            _fail("Ed25519 weak-key deny set is malformed")
        keys.add(decoded)
    if len(keys) != 14:
        _fail("Ed25519 weak-key deny set must contain fourteen distinct encodings")
    return frozenset(keys)


def _trusted_public_key(value: object, label: str = "trusted public key") -> bytes:
    decoded = _canonical_base64(value, label, expected_bytes=32)
    if decoded in _weak_public_keys():
        _fail(f"{label} must not be a weak Ed25519 key")
    return decoded


def _validate_version(value: str) -> str:
    if len(value) > 128 or not SEMVER_RE.fullmatch(value):
        _fail("version must be canonical SemVer without a leading 'v'")
    return value


def _validate_url(value: str, label: str) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > URL_MAX_BYTES
        or value != value.strip()
        or any(character.isspace() or ord(character) < 0x20 for character in value)
    ):
        _fail(f"{label} must be a bounded absolute HTTP(S) URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        _fail(f"{label} must be a valid absolute HTTP(S) URL")
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port is not None and not 1 <= port <= 65535
    ):
        _fail(f"{label} must be an absolute HTTP(S) URL without credentials or a fragment")
    return value


def _validate_published_at(value: str) -> str:
    if not PUBLISHED_AT_RE.fullmatch(value):
        _fail("published-at must use UTC RFC3339 seconds, for example 2026-07-23T12:00:00Z")
    try:
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail("published-at is not a valid UTC timestamp")
    return value


def _inspect_artifact(
    path: Path, label: str, *, maximum_bytes: int | None = None
) -> tuple[str, int]:
    fd = _open_regular(path, label)
    try:
        before = os.fstat(fd)
        if before.st_size <= 0:
            _fail("artifact must not be empty")
        if maximum_bytes is not None and before.st_size > maximum_bytes:
            _fail(f"{label} exceeds the {maximum_bytes}-byte size limit")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            _fail("artifact changed while it was being hashed")
        return digest.hexdigest(), before.st_size
    finally:
        os.close(fd)


def _load_manifest(path: Path) -> dict[str, object]:
    fd = _open_regular(path, "release manifest")
    try:
        before = os.fstat(fd)
        if before.st_size <= 0 or before.st_size > 512 * 1024:
            _fail("release manifest size is outside its bound")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                _fail("release manifest was truncated while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            _fail("release manifest changed while it was being read")
    finally:
        os.close(fd)
    try:
        value = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("release manifest is not valid UTF-8 JSON")
    if not isinstance(value, dict):
        _fail("release manifest must be a JSON object")
    return value


def _load_bounded_json(
    path: Path, label: str, *, maximum_bytes: int
) -> tuple[dict[str, Any], bytes]:
    fd = _open_regular(path, label)
    try:
        before = os.fstat(fd)
        if before.st_size <= 0 or before.st_size > maximum_bytes:
            _fail(f"{label} size is outside its bound")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                _fail(f"{label} was truncated while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            _fail(f"{label} changed while it was being read")
    finally:
        os.close(fd)
    body = b"".join(chunks)
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail(f"{label} is not valid UTF-8 JSON")
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return value, body


def _validate_output(
    output: Path, protected_inputs: Sequence[tuple[Path, str]]
) -> None:
    if not output.name or output.name in {".", ".."}:
        _fail("output must name a manifest file")
    try:
        output_parent = output.parent.resolve(strict=True)
    except OSError:
        _fail("output directory does not exist")
    if not output_parent.is_dir():
        _fail("output parent must be a directory")
    resolved_output = output_parent / output.name
    for protected, label in protected_inputs:
        try:
            if resolved_output == protected.resolve(strict=True):
                _fail(f"output must not overwrite the {label}")
        except OSError:
            pass
    if output.is_symlink() or (output.exists() and not output.is_file()):
        _fail("existing output must be a regular file and not a symlink")


def _atomic_write(path: Path, body: bytes) -> None:
    parent = path.parent.resolve(strict=True)
    temporary_fd = -1
    temporary_name = ""
    try:
        temporary_fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=parent
        )
        os.fchmod(temporary_fd, 0o644)
        offset = 0
        while offset < len(body):
            offset += os.write(temporary_fd, body[offset:])
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        os.replace(temporary_name, path)
        temporary_name = ""
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def _canonical_message(version: str, sha256: str, artifact_url: str) -> bytes:
    return f"{version}\n{sha256.lower()}\n{artifact_url}\n".encode("utf-8")


def _installer_iso_template_message(descriptor: dict[str, Any]) -> bytes:
    return (
        f"{INSTALLER_ISO_TEMPLATE_SIGNATURE_DOMAIN}\n"
        f"{descriptor['version']}\n"
        f"{descriptor['architecture']}\n"
        f"{descriptor['base_os']}\n"
        f"{descriptor['base_os_version']}\n"
        f"{descriptor['url']}\n"
        f"{descriptor['size_bytes']}\n"
        f"{descriptor['template_sha256']}\n"
        f"{descriptor['personalization_offset']}\n"
        f"{descriptor['personalization_size']}\n"
        f"{descriptor['placeholder_sha256']}\n"
        f"{','.join(descriptor['provisioning_public_keys'])}\n"
    ).encode("utf-8")


def _installer_iso_template_inputs(
    arguments: argparse.Namespace,
    version: str,
) -> tuple[Path, str, int, list[str]] | None:
    path_value = arguments.installer_iso_template
    url_value = arguments.installer_iso_template_url
    offset_value = arguments.installer_iso_template_personalization_offset
    keys = arguments.provisioning_public_key or []
    supplied = bool(path_value or url_value or offset_value is not None or keys)
    if not supplied:
        return None
    if not path_value or not url_value or offset_value is None or not keys:
        _fail(
            "installer ISO template, URL, personalization offset, and at least one "
            "provisioning public key must be supplied together"
        )
    expected_name = (
        f"cybex-forge-appliance-template-{version}-{INSTALLER_ISO_ARCHITECTURE}.iso"
    )
    path = Path(path_value)
    if path.name != expected_name:
        _fail(f"installer ISO template must be named {expected_name}")
    url = _validate_url(url_value, "installer-iso-template-url")
    if urlsplit(url).path.rsplit("/", 1)[-1] != expected_name:
        _fail(f"installer-iso-template-url path must end in /{expected_name}")
    if offset_value < 0:
        _fail("installer ISO template personalization offset must be non-negative")
    normalized_keys: list[str] = []
    for key in keys:
        _trusted_public_key(key)
        normalized_keys.append(key)
    if len(normalized_keys) > 8 or len(set(normalized_keys)) != len(normalized_keys):
        _fail("provisioning public keys must contain between one and eight unique keys")
    if normalized_keys != sorted(normalized_keys):
        _fail("provisioning public keys must be supplied in sorted order")
    return path, url, offset_value, normalized_keys


def _inspect_installer_iso_template(
    inputs: tuple[Path, str, int, list[str]],
    version: str,
) -> dict[str, Any]:
    path, url, offset, provisioning_public_keys = inputs
    template_sha256, size_bytes = _inspect_artifact(
        path,
        "installer ISO template",
        maximum_bytes=INSTALLER_ISO_MAX_BYTES,
    )
    end = offset + INSTALLER_ISO_TEMPLATE_PERSONALIZATION_SIZE
    if end > size_bytes:
        _fail("installer ISO template personalization slot is outside the artifact")
    fd = _open_regular(path, "installer ISO template")
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        placeholder = os.read(fd, INSTALLER_ISO_TEMPLATE_PERSONALIZATION_SIZE)
    finally:
        os.close(fd)
    if placeholder != bytes(INSTALLER_ISO_TEMPLATE_PERSONALIZATION_SIZE):
        _fail("installer ISO template personalization slot must contain exactly zero bytes")
    return {
        "version": version,
        "architecture": INSTALLER_ISO_ARCHITECTURE,
        "base_os": INSTALLER_ISO_TEMPLATE_BASE_OS,
        "base_os_version": INSTALLER_ISO_TEMPLATE_BASE_OS_VERSION,
        "url": url,
        "size_bytes": size_bytes,
        "template_sha256": template_sha256,
        "personalization_offset": offset,
        "personalization_size": INSTALLER_ISO_TEMPLATE_PERSONALIZATION_SIZE,
        "placeholder_sha256": hashlib.sha256(placeholder).hexdigest(),
        "provisioning_public_keys": provisioning_public_keys,
    }


def _appliance_release_message(descriptor: dict[str, Any]) -> bytes:
    canonical = json.dumps(
        descriptor, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return APPLIANCE_RELEASE_SIGNATURE_DOMAIN.encode() + b"\n" + canonical


def _appliance_release_inputs(
    arguments: argparse.Namespace,
    version: str,
    notes_url: str,
) -> tuple[dict[str, Any], list[tuple[Path, str]]] | None:
    values = (
        arguments.appliance_package_snapshot,
        arguments.appliance_package_snapshot_metadata,
        arguments.appliance_package_snapshot_url,
    )
    if any(values) and not all(values):
        _fail(
            "appliance package snapshot, metadata, and URL must be supplied together"
        )
    if not any(values):
        return None
    bundle = Path(arguments.appliance_package_snapshot)
    metadata_path = Path(arguments.appliance_package_snapshot_metadata)
    expected_name = f"cybex-forge-appliance-packages-{version}-x86_64-linux.tar.zst"
    if bundle.name != expected_name:
        _fail(f"appliance package snapshot must be named {expected_name}")
    url = _validate_url(
        arguments.appliance_package_snapshot_url,
        "appliance-package-snapshot-url",
    )
    if urlsplit(url).path.rsplit("/", 1)[-1] != expected_name:
        _fail(f"appliance-package-snapshot-url path must end in /{expected_name}")
    metadata, _body = _load_bounded_json(
        metadata_path,
        "appliance package snapshot metadata",
        maximum_bytes=256 * 1024,
    )
    _require_exact_object_keys(
        metadata,
        {
            "schema",
            "release_id",
            "ubuntu_snapshot_id",
            "filename",
            "sha256",
            "size_bytes",
            "required_package_versions",
            "expected_kernel",
            "minimum_protocol",
            "minimum_state_schema",
            "rollback_compatible",
        },
        "appliance package snapshot metadata",
    )
    if (
        metadata["schema"] != "cybex.forge.appliance-package-snapshot.v1"
        or metadata["release_id"] != version
        or metadata["filename"] != expected_name
        or not isinstance(metadata["ubuntu_snapshot_id"], str)
        or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", metadata["ubuntu_snapshot_id"])
        or metadata["minimum_protocol"] != 4
        or metadata["minimum_state_schema"] != 1
        or metadata["rollback_compatible"] is not True
    ):
        _fail("appliance package snapshot metadata is incompatible")
    actual_sha, actual_size = _inspect_artifact(
        bundle,
        "appliance package snapshot",
        maximum_bytes=INSTALLER_ISO_MAX_BYTES,
    )
    if metadata["sha256"] != actual_sha or metadata["size_bytes"] != actual_size:
        _fail("appliance package snapshot metadata does not match the bundle")
    versions = metadata["required_package_versions"]
    required_names = {
        "cybex-forge",
        "cybex-forge-bootstrap",
        "cybex-forge-appliance",
        "linux-generic",
        "linux-firmware",
        "nix-bin",
    }
    if (
        not isinstance(versions, dict)
        or set(versions) != required_names
        or any(
            not isinstance(name, str)
            or not isinstance(package_version, str)
            or not package_version
            or len(package_version) > 256
            for name, package_version in versions.items()
        )
        or metadata["expected_kernel"] != versions["linux-generic"]
    ):
        _fail("appliance required package versions are invalid")
    descriptor = {
        "schema": APPLIANCE_RELEASE_SCHEMA,
        "release_id": version,
        "ubuntu_snapshot_id": metadata["ubuntu_snapshot_id"],
        "cybex_repository_snapshot": {
            "url": url,
            "sha256": actual_sha,
            "size_bytes": actual_size,
        },
        "required_package_versions": versions,
        "expected_kernel": metadata["expected_kernel"],
        "minimum_protocol": 4,
        "minimum_state_schema": 1,
        "rollback_compatible": True,
        "release_notes": notes_url,
    }
    return descriptor, [
        (bundle, "appliance package snapshot"),
        (metadata_path, "appliance package snapshot metadata"),
    ]


def _validate_revision(value: str, label: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        _fail(f"{label} must be an exact lowercase 40-hex revision")
    return value


def _workstation_netboot_message(descriptor: dict[str, Any]) -> bytes:
    components = descriptor["components"]
    return (
        f"{WORKSTATION_NETBOOT_SIGNATURE_DOMAIN}\n"
        f"{descriptor['runtime_version']}\n"
        f"{descriptor['manage_source_revision']}\n"
        f"{descriptor['nixpkgs_revision']}\n"
        f"{descriptor['architecture']}\n"
        f"{descriptor['format']}\n"
        f"{descriptor['required_forge_protocol']}\n"
        f"{components['bzImage']['size_bytes']}\n"
        f"{components['bzImage']['sha256']}\n"
        f"{components['initrd']['size_bytes']}\n"
        f"{components['initrd']['sha256']}\n"
        f"{components['nix-store.squashfs']['size_bytes']}\n"
        f"{components['nix-store.squashfs']['sha256']}\n"
        f"{descriptor['manifest_sha256']}\n"
        f"{descriptor['size_bytes']}\n"
        f"{descriptor['sha256']}\n"
        f"{descriptor['url']}\n"
    ).encode("utf-8")


def _workstation_netboot_inputs(
    arguments: argparse.Namespace,
) -> tuple[Path, Path, str, str, str, str] | None:
    values = (
        arguments.workstation_netboot_bundle,
        arguments.workstation_netboot_tree,
        arguments.workstation_netboot_url,
        arguments.workstation_netboot_runtime_version,
        arguments.workstation_netboot_manage_revision,
        arguments.workstation_netboot_nixpkgs_revision,
    )
    if any(values) and not all(values):
        _fail(
            "workstation netboot bundle, tree, URL, runtime version, Manage revision, "
            "and nixpkgs revision must be supplied together"
        )
    if not any(values):
        return None

    runtime_version = _validate_version(arguments.workstation_netboot_runtime_version)
    manage_revision = _validate_revision(
        arguments.workstation_netboot_manage_revision,
        "workstation netboot Manage revision",
    )
    nixpkgs_revision = _validate_revision(
        arguments.workstation_netboot_nixpkgs_revision,
        "workstation netboot nixpkgs revision",
    )
    bundle = Path(arguments.workstation_netboot_bundle)
    expected_name = (
        f"cybex-workstation-netboot-{runtime_version}-{manage_revision[:12]}-"
        f"{WORKSTATION_NETBOOT_ARCHITECTURE}.tar.zst"
    )
    if bundle.name != expected_name:
        _fail(f"workstation netboot bundle must be named {expected_name}")
    url = _validate_url(
        arguments.workstation_netboot_url,
        "workstation-netboot-url",
    )
    if urlsplit(url).path.rsplit("/", 1)[-1] != expected_name:
        _fail(f"workstation-netboot-url path must end in /{expected_name}")

    tree = Path(arguments.workstation_netboot_tree)
    try:
        entries = {entry.name for entry in tree.iterdir()}
    except OSError:
        _fail("could not inspect the workstation netboot tree")
    expected_entries = {"manifest.json", *WORKSTATION_NETBOOT_COMPONENTS}
    if entries != expected_entries:
        _fail("workstation netboot tree must contain exactly the four release files")
    return bundle, tree, url, runtime_version, manage_revision, nixpkgs_revision


def _inspect_workstation_netboot(
    inputs: tuple[Path, Path, str, str, str, str],
) -> tuple[dict[str, Any], list[tuple[Path, str]]]:
    bundle, tree, url, runtime_version, manage_revision, nixpkgs_revision = inputs
    bundle_sha256, bundle_size = _inspect_artifact(
        bundle,
        "workstation netboot bundle",
        maximum_bytes=WORKSTATION_NETBOOT_MAX_BYTES,
    )
    manifest_path = tree / "manifest.json"
    manifest, manifest_body = _load_bounded_json(
        manifest_path,
        "workstation netboot manifest",
        maximum_bytes=256 * 1024,
    )
    canonical_manifest_body = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    if manifest_body != canonical_manifest_body:
        _fail("workstation netboot manifest must be canonical compact sorted JSON")
    _require_exact_object_keys(
        manifest,
        {
            "schema",
            "runtime_version",
            "architecture",
            "format",
            "required_forge_protocol",
            "manage_source_revision",
            "nixpkgs_revision",
            "source_date_epoch",
            "toplevel",
            "kernel_cmdline_template",
            "components",
            "provenance",
        },
        "workstation netboot manifest",
    )
    expected_manifest_values = {
        "schema": WORKSTATION_NETBOOT_MANIFEST_SCHEMA,
        "runtime_version": runtime_version,
        "architecture": WORKSTATION_NETBOOT_ARCHITECTURE,
        "format": WORKSTATION_NETBOOT_FORMAT,
        "required_forge_protocol": WORKSTATION_NETBOOT_REQUIRED_FORGE_PROTOCOL,
        "manage_source_revision": manage_revision,
        "nixpkgs_revision": nixpkgs_revision,
    }
    for field, expected in expected_manifest_values.items():
        if manifest[field] != expected:
            _fail(f"workstation netboot manifest {field} does not match the release input")
    if not isinstance(manifest["source_date_epoch"], int) or isinstance(
        manifest["source_date_epoch"], bool
    ) or manifest["source_date_epoch"] < 0:
        _fail("workstation netboot manifest source_date_epoch is invalid")
    if not isinstance(manifest["toplevel"], str) or not re.fullmatch(
        r"/nix/store/[0-9a-z]{32}-[^\s/]+", manifest["toplevel"]
    ):
        _fail("workstation netboot manifest toplevel is invalid")
    cmdline = manifest["kernel_cmdline_template"]
    if (
        not isinstance(cmdline, str)
        or len(cmdline.encode("utf-8")) > 8192
        or cmdline.count("{squashfs_url}") != 1
        or "{" in cmdline.replace("{squashfs_url}", "")
        or "}" in cmdline.replace("{squashfs_url}", "")
        or any(character.isspace() and character != " " for character in cmdline)
    ):
        _fail("workstation netboot manifest kernel command line is invalid")
    if not isinstance(manifest["provenance"], dict):
        _fail("workstation netboot manifest provenance must be an object")

    manifest_components = _require_exact_object_keys(
        manifest["components"],
        set(WORKSTATION_NETBOOT_COMPONENTS),
        "workstation netboot manifest components",
    )
    components: dict[str, dict[str, Any]] = {}
    protected: list[tuple[Path, str]] = [
        (bundle, "workstation netboot bundle"),
        (manifest_path, "workstation netboot manifest"),
    ]
    for name in WORKSTATION_NETBOOT_COMPONENTS:
        path = tree / name
        sha256, size_bytes = _inspect_artifact(path, f"workstation netboot {name}")
        declared = _require_exact_object_keys(
            manifest_components[name],
            {"sha256", "size_bytes"},
            f"workstation netboot manifest component {name}",
        )
        if _require_sha256(declared["sha256"], f"components.{name}.sha256") != sha256:
            _fail(f"workstation netboot manifest {name} SHA-256 does not match")
        if (
            not isinstance(declared["size_bytes"], int)
            or isinstance(declared["size_bytes"], bool)
            or declared["size_bytes"] != size_bytes
        ):
            _fail(f"workstation netboot manifest {name} size does not match")
        components[name] = {"sha256": sha256, "size_bytes": size_bytes}
        protected.append((path, f"workstation netboot {name}"))

    _verify_workstation_netboot_archive(
        bundle,
        tree,
        int(manifest["source_date_epoch"]),
    )

    descriptor: dict[str, Any] = {
        "schema": WORKSTATION_NETBOOT_SCHEMA,
        "runtime_version": runtime_version,
        "manage_source_revision": manage_revision,
        "nixpkgs_revision": nixpkgs_revision,
        "architecture": WORKSTATION_NETBOOT_ARCHITECTURE,
        "format": WORKSTATION_NETBOOT_FORMAT,
        "required_forge_protocol": WORKSTATION_NETBOOT_REQUIRED_FORGE_PROTOCOL,
        "url": url,
        "sha256": bundle_sha256,
        "size_bytes": bundle_size,
        "manifest_sha256": hashlib.sha256(manifest_body).hexdigest(),
        "components": components,
    }
    return descriptor, protected


def _verify_workstation_netboot_archive(
    bundle: Path,
    tree: Path,
    source_date_epoch: int,
) -> None:
    expected_names = sorted(["manifest.json", *WORKSTATION_NETBOOT_COMPONENTS])
    try:
        decompressor = subprocess.Popen(
            ["zstd", "--decompress", "--stdout", "--quiet", str(bundle)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (FileNotFoundError, OSError):
        _fail("zstd is required to inspect the workstation netboot archive")
    assert decompressor.stdout is not None
    observed_names: list[str] = []
    archive_error: str | None = None
    try:
        with tarfile.open(fileobj=decompressor.stdout, mode="r|") as archive:
            for member in archive:
                name = member.name
                if name in observed_names:
                    _fail("workstation netboot archive contains a duplicate entry")
                observed_names.append(name)
                if name not in expected_names:
                    _fail("workstation netboot archive contains an unexpected entry")
                if not member.isreg() or member.islnk() or member.issym():
                    _fail("workstation netboot archive entries must be regular files")
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.mode != 0o644
                    or member.mtime != source_date_epoch
                    or member.pax_headers
                ):
                    _fail("workstation netboot archive metadata is not deterministic")
                expected_path = tree / name
                expected_size = expected_path.stat().st_size
                if member.size != expected_size:
                    _fail("workstation netboot archive entry size does not match its tree")
                extracted = archive.extractfile(member)
                if extracted is None:
                    _fail("workstation netboot archive entry could not be read")
                digest = hashlib.sha256()
                consumed = 0
                while True:
                    chunk = extracted.read(1024 * 1024)
                    if not chunk:
                        break
                    consumed += len(chunk)
                    if consumed > expected_size:
                        _fail("workstation netboot archive entry exceeded its declared size")
                    digest.update(chunk)
                if consumed != expected_size:
                    _fail("workstation netboot archive entry was truncated")
                expected_digest, _size = _inspect_artifact(
                    expected_path,
                    f"workstation netboot archive source {name}",
                )
                if digest.hexdigest() != expected_digest:
                    _fail("workstation netboot archive entry does not match its tree")
    except (tarfile.TarError, OSError, EOFError):
        archive_error = "workstation netboot archive is malformed or truncated"
    finally:
        decompressor.stdout.close()
        stderr = decompressor.stderr.read() if decompressor.stderr is not None else b""
        return_code = decompressor.wait()
    if archive_error is not None:
        _fail(archive_error)
    if return_code != 0:
        del stderr
        _fail("workstation netboot archive decompression failed")
    if observed_names != expected_names:
        _fail("workstation netboot archive entries are not the exact sorted allowlist")


def _manifest_command(arguments: argparse.Namespace) -> None:
    artifact = Path(arguments.artifact)
    private_key = Path(arguments.private_key)
    output = Path(arguments.output)
    version = _validate_version(arguments.version)
    artifact_url = _validate_url(arguments.artifact_url, "artifact-url")
    release_url = _validate_url(arguments.release_url, "release-url")
    notes_url = _validate_url(arguments.notes_url or arguments.release_url, "notes-url")
    published_at = _validate_published_at(arguments.published_at)
    installer_iso_template_inputs = _installer_iso_template_inputs(arguments, version)
    if installer_iso_template_inputs is None:
        _fail("installer_iso_template_v2 is required for every Forge release")
    installer_iso_template: dict[str, Any] | None = None
    appliance_release_inputs = _appliance_release_inputs(arguments, version, notes_url)
    appliance_release: dict[str, Any] | None = None
    workstation_netboot_inputs = _workstation_netboot_inputs(arguments)
    workstation_netboot: dict[str, Any] | None = None
    protected_inputs = [(artifact, "artifact"), (private_key, "private key")]
    if installer_iso_template_inputs is not None:
        installer_iso_template = _inspect_installer_iso_template(
            installer_iso_template_inputs, version
        )
        protected_inputs.append(
            (installer_iso_template_inputs[0], "installer ISO template")
        )
    if appliance_release_inputs is not None:
        appliance_release, appliance_release_protected = appliance_release_inputs
        protected_inputs.extend(appliance_release_protected)
    if workstation_netboot_inputs is not None:
        workstation_netboot, workstation_protected = _inspect_workstation_netboot(
            workstation_netboot_inputs
        )
        protected_inputs.extend(workstation_protected)
    _validate_output(output, protected_inputs)
    sha256, _artifact_size = _inspect_artifact(artifact, "artifact")
    private_fd = _open_regular(private_key, "private key", private=True)
    try:
        private_identity = _private_key_identity(private_fd)
        public_der = _public_der(private_fd)
        _require_stable_private_key(private_fd, private_identity)
        message = _canonical_message(version, sha256, artifact_url)
        signature = _sign(private_fd, message)
        _require_stable_private_key(private_fd, private_identity)
        installer_template_signature = None
        if installer_iso_template is not None:
            installer_template_signature = _sign(
                private_fd,
                _installer_iso_template_message(installer_iso_template),
            )
            _require_stable_private_key(private_fd, private_identity)
        appliance_release_signature = None
        if appliance_release is not None:
            appliance_release_signature = _sign(
                private_fd,
                _appliance_release_message(appliance_release),
            )
            _require_stable_private_key(private_fd, private_identity)
        workstation_netboot_signature = None
        if workstation_netboot is not None:
            workstation_netboot_signature = _sign(
                private_fd,
                _workstation_netboot_message(workstation_netboot),
            )
            _require_stable_private_key(private_fd, private_identity)
    finally:
        os.close(private_fd)
    _self_verify(public_der, signature, message)
    if installer_iso_template is not None and installer_template_signature is not None:
        _self_verify(
            public_der,
            installer_template_signature,
            _installer_iso_template_message(installer_iso_template),
        )
    if appliance_release is not None and appliance_release_signature is not None:
        _self_verify(
            public_der,
            appliance_release_signature,
            _appliance_release_message(appliance_release),
        )
    if workstation_netboot is not None and workstation_netboot_signature is not None:
        _self_verify(
            public_der,
            workstation_netboot_signature,
            _workstation_netboot_message(workstation_netboot),
        )

    manifest = {
        "schema": SCHEMA,
        "version": version,
        "release_url": release_url,
        "notes_url": notes_url,
        "published_at": published_at,
        "artifact": {"url": artifact_url, "sha256": sha256},
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    if installer_iso_template is not None and installer_template_signature is not None:
        installer_iso_template["signature"] = base64.b64encode(
            installer_template_signature
        ).decode("ascii")
        manifest["installer_iso_template_v2"] = installer_iso_template
    if appliance_release is not None and appliance_release_signature is not None:
        appliance_release["signature"] = base64.b64encode(
            appliance_release_signature
        ).decode("ascii")
        manifest["appliance_release_v1"] = appliance_release
    if workstation_netboot is not None and workstation_netboot_signature is not None:
        workstation_netboot["signature"] = base64.b64encode(
            workstation_netboot_signature
        ).decode("ascii")
        manifest["workstation_netboot"] = workstation_netboot
    body = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    _atomic_write(output, body)
    print(f"wrote signed Forge release manifest: {output}")


def _public_key_command(arguments: argparse.Namespace) -> None:
    private_fd = _open_regular(Path(arguments.private_key), "private key", private=True)
    try:
        private_identity = _private_key_identity(private_fd)
        public_der = _public_der(private_fd)
        _require_stable_private_key(private_fd, private_identity)
    finally:
        os.close(private_fd)
    raw_public_key = public_der[len(ED25519_PUBLIC_DER_PREFIX) :]
    if raw_public_key in _weak_public_keys():
        _fail("private key derives a weak Ed25519 public key")
    print(base64.b64encode(raw_public_key).decode("ascii"))


def _validate_public_key_command(arguments: argparse.Namespace) -> None:
    _trusted_public_key(arguments.trusted_public_key)
    print("validated canonical non-weak Ed25519 public key")


def _inspect_workstation_netboot_command(arguments: argparse.Namespace) -> None:
    inputs = _workstation_netboot_inputs(arguments)
    if inputs is None:
        _fail("workstation netboot inspection inputs are missing")
    descriptor, _protected = _inspect_workstation_netboot(inputs)
    print(
        "verified workstation netboot candidate: "
        f"runtime_version={descriptor['runtime_version']} "
        f"sha256={descriptor['sha256']}"
    )


def _require_exact_object_keys(
    value: object, expected: set[str], label: str
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        _fail(f"{label} fields are not the exact expected set")
    return value


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _verify_command(arguments: argparse.Namespace) -> None:
    manifest_path = Path(arguments.manifest)
    artifact_path = Path(arguments.artifact)
    verify_workstation_netboot = bool(
        arguments.workstation_netboot_bundle or arguments.workstation_netboot_tree
    )
    verify_installer_template = True
    verify_appliance_release = bool(arguments.appliance_package_snapshot)
    if bool(arguments.workstation_netboot_bundle) != bool(arguments.workstation_netboot_tree):
        _fail("workstation-netboot-bundle and workstation-netboot-tree must be supplied together")
    expected_manifest_fields = {
        "schema",
        "version",
        "release_url",
        "notes_url",
        "published_at",
        "artifact",
        "signature",
        "installer_iso_template_v2",
    }
    if verify_workstation_netboot:
        expected_manifest_fields.add("workstation_netboot")
    if verify_appliance_release:
        expected_manifest_fields.add("appliance_release_v1")
    manifest = _require_exact_object_keys(
        _load_manifest(manifest_path),
        expected_manifest_fields,
        "release manifest",
    )
    if manifest["schema"] != SCHEMA:
        _fail(f"release manifest schema must be {SCHEMA}")
    if not isinstance(manifest["version"], str):
        _fail("release manifest version must be a string")
    version = _validate_version(manifest["version"])
    if artifact_path.name != "cybex-forge-x86_64-linux":
        _fail("binary artifact must be named cybex-forge-x86_64-linux")
    release_url = _validate_url(str(manifest["release_url"]), "release-url")
    notes_url = _validate_url(str(manifest["notes_url"]), "notes-url")
    if not isinstance(manifest["published_at"], str):
        _fail("release manifest published-at must be a string")
    _validate_published_at(manifest["published_at"])
    artifact = _require_exact_object_keys(
        manifest["artifact"], {"url", "sha256"}, "binary artifact"
    )
    artifact_url = _validate_url(str(artifact["url"]), "artifact-url")
    if urlsplit(artifact_url).path.rsplit("/", 1)[-1] != artifact_path.name:
        _fail("artifact-url filename does not bind the binary artifact")
    if release_url == artifact_url or notes_url == artifact_url:
        _fail("release and notes URLs must not alias the binary artifact")

    expected_artifact_sha = _require_sha256(artifact["sha256"], "artifact.sha256")
    actual_artifact_sha, _artifact_size = _inspect_artifact(
        artifact_path, "binary artifact"
    )
    if actual_artifact_sha != expected_artifact_sha:
        _fail("binary artifact SHA-256 does not match the release manifest")
    public_key = _trusted_public_key(arguments.trusted_public_key)
    binary_signature = _canonical_base64(
        manifest["signature"], "binary signature", expected_bytes=64
    )
    public_der = ED25519_PUBLIC_DER_PREFIX + public_key
    _self_verify(
        public_der,
        binary_signature,
        _canonical_message(version, expected_artifact_sha, artifact_url),
    )
    template_sha = None
    if verify_installer_template:
        descriptor = _require_exact_object_keys(
            manifest["installer_iso_template_v2"],
            {
                "version",
                "architecture",
                "base_os",
                "base_os_version",
                "url",
                "size_bytes",
                "template_sha256",
                "personalization_offset",
                "personalization_size",
                "placeholder_sha256",
                "provisioning_public_keys",
                "signature",
            },
            "installer ISO template descriptor",
        )
        signature_text = descriptor.pop("signature")
        if descriptor["version"] != version:
            _fail("installer ISO template version does not match the release")
        if descriptor["architecture"] != INSTALLER_ISO_ARCHITECTURE:
            _fail(f"installer ISO template architecture must be {INSTALLER_ISO_ARCHITECTURE}")
        if (
            descriptor["base_os"] != INSTALLER_ISO_TEMPLATE_BASE_OS
            or descriptor["base_os_version"]
            != INSTALLER_ISO_TEMPLATE_BASE_OS_VERSION
        ):
            _fail("installer ISO template must target Ubuntu 26.04")
        if descriptor["personalization_size"] != INSTALLER_ISO_TEMPLATE_PERSONALIZATION_SIZE:
            _fail("installer ISO template personalization size must be 8192")
        if not isinstance(descriptor["personalization_offset"], int) or isinstance(
            descriptor["personalization_offset"], bool
        ):
            _fail("installer ISO template personalization offset is invalid")
        if not isinstance(descriptor["provisioning_public_keys"], list):
            _fail("installer ISO template provisioning keys are invalid")
        inspection_arguments = argparse.Namespace(
            installer_iso_template=arguments.installer_iso_template,
            installer_iso_template_url=descriptor["url"],
            installer_iso_template_personalization_offset=descriptor[
                "personalization_offset"
            ],
            provisioning_public_key=descriptor["provisioning_public_keys"],
        )
        inputs = _installer_iso_template_inputs(inspection_arguments, version)
        if inputs is None:
            _fail("installer ISO template verification inputs are missing")
        inspected = _inspect_installer_iso_template(inputs, version)
        if descriptor != inspected:
            _fail("installer ISO template descriptor does not match the supplied ISO")
        template_signature = _canonical_base64(
            signature_text,
            "installer ISO template signature",
            expected_bytes=64,
        )
        _self_verify(
            public_der,
            template_signature,
            _installer_iso_template_message(descriptor),
        )
        template_sha = descriptor["template_sha256"]
    appliance_snapshot_sha = None
    if verify_appliance_release:
        descriptor = _require_exact_object_keys(
            manifest["appliance_release_v1"],
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
        signature_text = descriptor.pop("signature")
        if (
            descriptor["schema"] != APPLIANCE_RELEASE_SCHEMA
            or descriptor["release_id"] != version
            or descriptor["minimum_protocol"] != 4
            or descriptor["minimum_state_schema"] != 1
            or descriptor["rollback_compatible"] is not True
        ):
            _fail("appliance release descriptor is incompatible")
        snapshot = _require_exact_object_keys(
            descriptor["cybex_repository_snapshot"],
            {"url", "sha256", "size_bytes"},
            "appliance repository snapshot",
        )
        snapshot_path = Path(arguments.appliance_package_snapshot)
        expected_snapshot_name = (
            f"cybex-forge-appliance-packages-{version}-x86_64-linux.tar.zst"
        )
        if snapshot_path.name != expected_snapshot_name:
            _fail(f"appliance package snapshot must be named {expected_snapshot_name}")
        snapshot_url = _validate_url(
            str(snapshot["url"]), "appliance-package-snapshot-url"
        )
        if urlsplit(snapshot_url).path.rsplit("/", 1)[-1] != expected_snapshot_name:
            _fail("appliance package snapshot URL does not bind its filename")
        actual_snapshot_sha, actual_snapshot_size = _inspect_artifact(
            snapshot_path,
            "appliance package snapshot",
            maximum_bytes=INSTALLER_ISO_MAX_BYTES,
        )
        if (
            snapshot["sha256"] != actual_snapshot_sha
            or snapshot["size_bytes"] != actual_snapshot_size
        ):
            _fail("appliance package snapshot does not match its descriptor")
        signature = _canonical_base64(
            signature_text,
            "appliance release signature",
            expected_bytes=64,
        )
        _self_verify(
            public_der,
            signature,
            _appliance_release_message(descriptor),
        )
        appliance_snapshot_sha = actual_snapshot_sha
    workstation_sha = None
    if verify_workstation_netboot:
        descriptor = _require_exact_object_keys(
            manifest["workstation_netboot"],
            {
                "schema",
                "runtime_version",
                "manage_source_revision",
                "nixpkgs_revision",
                "architecture",
                "format",
                "required_forge_protocol",
                "url",
                "sha256",
                "size_bytes",
                "manifest_sha256",
                "components",
                "signature",
            },
            "workstation netboot descriptor",
        )
        signature_text = descriptor.pop("signature")
        inspection_arguments = argparse.Namespace(
            workstation_netboot_bundle=arguments.workstation_netboot_bundle,
            workstation_netboot_tree=arguments.workstation_netboot_tree,
            workstation_netboot_url=descriptor["url"],
            workstation_netboot_runtime_version=descriptor["runtime_version"],
            workstation_netboot_manage_revision=descriptor["manage_source_revision"],
            workstation_netboot_nixpkgs_revision=descriptor["nixpkgs_revision"],
        )
        inputs = _workstation_netboot_inputs(inspection_arguments)
        if inputs is None:
            _fail("workstation netboot verification inputs are missing")
        inspected, _protected = _inspect_workstation_netboot(inputs)
        if descriptor != inspected:
            _fail("workstation netboot descriptor does not match the supplied bundle tree")
        workstation_signature = _canonical_base64(
            signature_text,
            "workstation netboot signature",
            expected_bytes=64,
        )
        _self_verify(
            public_der,
            workstation_signature,
            _workstation_netboot_message(descriptor),
        )
        workstation_sha = descriptor["sha256"]
    print(
        "verified signed Forge release manifest: "
        f"version={version} binary_sha256={actual_artifact_sha}"
        + (
            f" workstation_netboot_sha256={workstation_sha}"
            if workstation_sha is not None
            else ""
        )
        + (
            f" installer_iso_template_sha256={template_sha}"
            if template_sha is not None
            else ""
        )
        + (
            f" appliance_package_snapshot_sha256={appliance_snapshot_sha}"
            if appliance_snapshot_sha is not None
            else ""
        )
    )



def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build signed Cybex Forge release manifests without exposing private key bytes."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    manifest = commands.add_parser(
        "manifest",
        allow_abbrev=False,
        help="hash an artifact and atomically write a signed manifest",
    )
    manifest.add_argument("--artifact", required=True, help="regular Forge binary artifact")
    manifest.add_argument("--artifact-url", required=True, help="exact HTTP(S) download URL")
    manifest.add_argument("--version", required=True, help="canonical Cargo SemVer without a leading v")
    manifest.add_argument("--private-key", required=True, help="mode-0600 Ed25519 PEM private key")
    manifest.add_argument("--output", required=True, help="manifest output path in an existing directory")
    manifest.add_argument("--release-url", required=True, help="HTTP(S) release page URL")
    manifest.add_argument("--notes-url", help="HTTP(S) release notes URL; defaults to --release-url")
    manifest.add_argument(
        "--installer-iso-template",
        required=True,
        help="Ubuntu provisionable ISO template with an all-zero fixed slot",
    )
    manifest.add_argument(
        "--installer-iso-template-url",
        required=True,
        help="exact immutable HTTP(S) URL for --installer-iso-template",
    )
    manifest.add_argument(
        "--installer-iso-template-personalization-offset",
        required=True,
        type=int,
        help="exact byte offset of the 8192-byte personalization slot",
    )
    manifest.add_argument(
        "--provisioning-public-key",
        action="append",
        help="sorted standard-Base64 online provisioning Ed25519 public key; repeat for rotation overlap",
    )
    manifest.add_argument(
        "--appliance-package-snapshot",
        help="deterministic offline APT repository tar.zst for managed root generations",
    )
    manifest.add_argument(
        "--appliance-package-snapshot-metadata",
        help="bounded build metadata for --appliance-package-snapshot",
    )
    manifest.add_argument(
        "--appliance-package-snapshot-url",
        help="exact immutable HTTP(S) URL for --appliance-package-snapshot",
    )
    manifest.add_argument(
        "--workstation-netboot-bundle",
        help="optional deterministic workstation netboot tar.zst; requires all workstation-netboot options",
    )
    manifest.add_argument(
        "--workstation-netboot-tree",
        help="directory containing exactly manifest.json, bzImage, initrd, and nix-store.squashfs",
    )
    manifest.add_argument(
        "--workstation-netboot-url",
        help="exact immutable HTTP(S) URL for --workstation-netboot-bundle",
    )
    manifest.add_argument(
        "--workstation-netboot-runtime-version",
        help="canonical independent workstation runtime SemVer",
    )
    manifest.add_argument(
        "--workstation-netboot-manage-revision",
        help="exact lowercase 40-hex Manage source revision",
    )
    manifest.add_argument(
        "--workstation-netboot-nixpkgs-revision",
        help="exact lowercase 40-hex nixpkgs revision",
    )
    manifest.add_argument(
        "--published-at",
        required=True,
        help="fixed UTC RFC3339 timestamp with second precision",
    )
    manifest.set_defaults(handler=_manifest_command)

    public_key = commands.add_parser(
        "public-key", help="derive the canonical standard-Base64 raw Ed25519 public key"
    )
    public_key.add_argument("--private-key", required=True, help="mode-0600 Ed25519 PEM private key")
    public_key.set_defaults(handler=_public_key_command)

    validate_public_key = commands.add_parser(
        "validate-public-key",
        help="validate a canonical non-weak raw Ed25519 public trust key",
    )
    validate_public_key.add_argument(
        "--trusted-public-key",
        required=True,
        help="canonical standard-Base64 raw Ed25519 public key",
    )
    validate_public_key.set_defaults(handler=_validate_public_key_command)

    inspect_netboot = commands.add_parser(
        "inspect-workstation-netboot",
        help="validate an unsigned deterministic workstation netboot candidate",
    )
    inspect_netboot.add_argument("--workstation-netboot-bundle", required=True)
    inspect_netboot.add_argument("--workstation-netboot-tree", required=True)
    inspect_netboot.add_argument("--workstation-netboot-url", required=True)
    inspect_netboot.add_argument("--workstation-netboot-runtime-version", required=True)
    inspect_netboot.add_argument("--workstation-netboot-manage-revision", required=True)
    inspect_netboot.add_argument("--workstation-netboot-nixpkgs-revision", required=True)
    inspect_netboot.set_defaults(handler=_inspect_workstation_netboot_command)

    verify = commands.add_parser(
        "verify",
        allow_abbrev=False,
        help="independently verify a signed Ubuntu appliance release candidate",
    )
    verify.add_argument("--manifest", required=True, help="signed release manifest")
    verify.add_argument("--artifact", required=True, help="exact binary artifact")
    verify.add_argument(
        "--installer-iso-template",
        required=True,
        help="exact provisionable Ubuntu installer ISO template",
    )
    verify.add_argument(
        "--appliance-package-snapshot",
        help="exact signed managed Ubuntu package snapshot bundle",
    )
    verify.add_argument(
        "--workstation-netboot-bundle",
        help="exact signed workstation netboot bundle",
    )
    verify.add_argument(
        "--workstation-netboot-tree",
        help="exact extracted workstation netboot component tree",
    )
    verify.add_argument(
        "--trusted-public-key",
        required=True,
        help="canonical standard-Base64 raw Ed25519 public key",
    )
    verify.set_defaults(handler=_verify_command)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        arguments.handler(arguments)
    except ReleaseError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("error: the operating system could not complete the release operation", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
