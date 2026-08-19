#!/usr/bin/env python3
"""Build deterministic, signed Cybex James release manifests.

The private Ed25519 key is opened without following symlinks and is passed to
OpenSSL through an inherited file descriptor. Its bytes and path are never
written to output or included in errors.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
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


SCHEMA = "cybex.james.release.v1"
RELEASE_COMPATIBILITY_SCHEMA = "cybex.james.release-compatibility.v1"
RELEASE_COMPATIBILITY_SIGNATURE_DOMAIN = (
    "CYBEX-JAMES-RELEASE-COMPATIBILITY-V1"
)
COMPONENT_COMPATIBILITY_SCHEMA = "cybex.component-compatibility.v1"
RELEASE_MANIFEST_FILENAME = "cybex-james-release.json"
RELEASE_COMPATIBILITY_FILENAME = "cybex-james-release-compatibility.json"
INSTALLER_ISO_ARCHITECTURE = "x86_64-linux"
INSTALLER_ISO_MAX_BYTES = 16 * 1024 * 1024 * 1024
INSTALLER_ISO_TEMPLATE_SIGNATURE_DOMAIN = (
    "CYBEX-JAMES-INSTALLER-ISO-TEMPLATE-V2"
)
INSTALLER_ISO_TEMPLATE_BASE_OS = "ubuntu"
INSTALLER_ISO_TEMPLATE_BASE_OS_VERSION = "26.04"
INSTALLER_ISO_TEMPLATE_PERSONALIZATION_SIZE = 8192
INSTALLER_ISO_TEMPLATE_NETWORK_PACKAGE_DELIVERY = "network-snapshot-v1"
INSTALLER_ISO_TEMPLATE_BUILD_SCHEMA = "cybex.james.installer-template-build.v1"
APPLIANCE_PACKAGE_SNAPSHOT_MAX_BYTES = 4 * 1024 * 1024 * 1024
MANAGE_SOURCE_METADATA_SCHEMA = "cybex.james.manage-source.v1"
MANAGE_SOURCE_METADATA_MAX_BYTES = 16 * 1024
MANAGE_SOURCE_ARCHIVE_MAX_BYTES = 256 * 1024 * 1024
MANAGE_SOURCE_INSTALLER_REQUIRED_PATHS = frozenset(
    {
        "agent/cybex-agent/Cargo.toml",
        "agent/cybex-agent/Cargo.lock",
        "agent/cybex-agent/src/hardware_inventory.rs",
        "agent/cybex-agent/src/installer_boot.rs",
        "agent/cybex-agent/src/lib.rs",
        "agent/cybex-agent/src/main.rs",
        "agent/cybex-agent/src/managed_wifi.rs",
        "deploy/nixos/cybex-agent-module.nix",
        "deploy/nixos/cybex-apply-blueprint.sh",
        "deploy/nixos/cybex-authd-packages.nix",
        "deploy/nixos/cybex-authd.nix",
        "deploy/nixos/cybex-blueprints.nix",
        "deploy/nixos/cybex-himmelblau-packages.nix",
        "deploy/nixos/cybex-himmelblau.nix",
        "deploy/nixos/cybex-ldap.nix",
    }
)
JAMES_DEBIAN_PACKAGE_MAX_BYTES = 512 * 1024 * 1024
APPLIANCE_RELEASE_SIGNATURE_DOMAIN = "CYBEX-JAMES-APPLIANCE-RELEASE-V1"
APPLIANCE_RELEASE_SCHEMA = "cybex.james.appliance-release.v1"
WORKSTATION_NETBOOT_SIGNATURE_DOMAIN = "CYBEX-JAMES-WORKSTATION-NETBOOT-V1"
WORKSTATION_NETBOOT_SCHEMA = "cybex.james.workstation-netboot.v1"
WORKSTATION_NETBOOT_MANIFEST_SCHEMA = "cybex.james.workstation-netboot-manifest.v1"
WORKSTATION_NETBOOT_ARCHITECTURE = "x86_64-linux"
WORKSTATION_NETBOOT_FORMAT = "split-squashfs-v1"
WORKSTATION_NETBOOT_REQUIRED_JAMES_PROTOCOL = 4
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
    with tempfile.TemporaryFile(prefix="cybex-james-release-message-") as message_file:
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
            action="sign the James release manifest",
        )
    if len(signature) != 64:
        _fail("OpenSSL returned an invalid Ed25519 signature")
    return signature


def _self_verify(public_der: bytes, signature: bytes, message: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="cybex-james-release-verify-") as directory:
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
            action="self-verify the James release signature",
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


def _compare_semver(left_value: str, right_value: str) -> int:
    """Return SemVer precedence for left versus right, ignoring build metadata."""

    def parts(value: str) -> tuple[tuple[int, int, int], list[str] | None]:
        value = _validate_version(value).split("+", 1)[0]
        core, separator, prerelease = value.partition("-")
        major, minor, patch = (int(component) for component in core.split("."))
        return (major, minor, patch), prerelease.split(".") if separator else None

    left_core, left_prerelease = parts(left_value)
    right_core, right_prerelease = parts(right_value)
    if left_core != right_core:
        return 1 if left_core > right_core else -1
    if left_prerelease is None or right_prerelease is None:
        if left_prerelease is right_prerelease:
            return 0
        return 1 if left_prerelease is None else -1
    for left_identifier, right_identifier in zip(
        left_prerelease, right_prerelease, strict=False
    ):
        if left_identifier == right_identifier:
            continue
        left_numeric = left_identifier.isdigit()
        right_numeric = right_identifier.isdigit()
        if left_numeric and right_numeric:
            return 1 if int(left_identifier) > int(right_identifier) else -1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return 1 if left_identifier > right_identifier else -1
    if len(left_prerelease) == len(right_prerelease):
        return 0
    return 1 if len(left_prerelease) > len(right_prerelease) else -1


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


def _validate_manage_origin(value: object, label: str = "expected manage origin") -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > URL_MAX_BYTES
        or value != value.strip()
        or any(character.isspace() or ord(character) < 0x20 for character in value)
    ):
        _fail(f"{label} must be a canonical HTTPS origin")
    try:
        value.encode("ascii")
        parsed = urlsplit(value)
        port = parsed.port
    except (UnicodeEncodeError, ValueError):
        _fail(f"{label} must be a canonical HTTPS origin")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port is not None
        and not 1 <= port <= 65535
    ):
        _fail(
            f"{label} must use canonical https://host[:port] form without "
            "credentials, path, query, or fragment"
        )
    hostname = parsed.hostname
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        canonical_host = hostname.lower()
        if not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
            r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*",
            canonical_host,
        ):
            _fail(f"{label} host is not canonical")
    else:
        canonical_host = address.compressed
        if address.version == 6:
            canonical_host = f"[{canonical_host}]"
    canonical_port = "" if port in (None, 443) else f":{port}"
    canonical = f"https://{canonical_host}{canonical_port}"
    if value != canonical:
        _fail(f"{label} must equal its canonical lowercase HTTPS origin")
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
    message = (
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
    )
    package_delivery = descriptor.get("package_delivery")
    # Legacy embedded-package V2 descriptors omit this field; do not append an
    # empty line because that would change their signed canonical bytes.
    if package_delivery is not None:
        message += f"{package_delivery}\n"
    manage_origin = descriptor.get("manage_origin")
    # Published predecessor descriptors predate the origin contract. Preserve
    # their canonical signed bytes, while every descriptor generated by the
    # current tool appends its required origin as the final line.
    if manage_origin is not None:
        message += f"{manage_origin}\n"
    return message.encode("utf-8")


def _installer_iso_template_inputs(
    arguments: argparse.Namespace,
    version: str,
    *,
    require_build_metadata: bool,
) -> tuple[Path, str, int, list[str], str | None, str, Path | None] | None:
    path_value = arguments.installer_iso_template
    url_value = arguments.installer_iso_template_url
    offset_value = arguments.installer_iso_template_personalization_offset
    keys = arguments.provisioning_public_key or []
    package_delivery = arguments.installer_iso_template_package_delivery
    expected_manage_origin_value = arguments.expected_manage_origin
    metadata_value = getattr(arguments, "installer_iso_template_metadata", None)
    supplied = bool(
        path_value
        or url_value
        or offset_value is not None
        or keys
        or package_delivery is not None
        or expected_manage_origin_value
        or metadata_value
    )
    if not supplied:
        return None
    if (
        not path_value
        or not url_value
        or offset_value is None
        or not keys
        or not expected_manage_origin_value
        or require_build_metadata
        and not metadata_value
    ):
        _fail(
            "installer ISO template, URL, personalization offset, explicit expected "
            "manage origin, and at least one provisioning public key must be supplied "
            "together; manifest generation also requires template build metadata"
        )
    expected_name = (
        f"cybex-james-appliance-template-{version}-{INSTALLER_ISO_ARCHITECTURE}.iso"
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
    if package_delivery not in (None, INSTALLER_ISO_TEMPLATE_NETWORK_PACKAGE_DELIVERY):
        _fail("installer ISO template package delivery is invalid")
    expected_manage_origin = _validate_manage_origin(expected_manage_origin_value)
    metadata_path = Path(metadata_value) if metadata_value else None
    return (
        path,
        url,
        offset_value,
        normalized_keys,
        package_delivery,
        expected_manage_origin,
        metadata_path,
    )


def _validate_installer_iso_template_metadata(
    metadata_path: Path,
    descriptor: dict[str, Any],
) -> None:
    metadata, _body = _load_bounded_json(
        metadata_path,
        "installer ISO template build metadata",
        maximum_bytes=64 * 1024,
    )
    required_fields = {
        "schema",
        "version",
        "architecture",
        "base_os",
        "base_os_version",
        "manage_origin",
        "size_bytes",
        "template_sha256",
        "personalization_offset",
        "personalization_size",
        "placeholder_sha256",
        "provisioning_public_keys",
    }
    optional_fields = {"package_delivery", "ubuntu_snapshot_id"}
    if not required_fields <= set(metadata) or not set(metadata) <= (
        required_fields | optional_fields
    ):
        _fail("installer ISO template build metadata fields are not the exact supported set")
    if metadata["schema"] != INSTALLER_ISO_TEMPLATE_BUILD_SCHEMA:
        _fail(
            "installer ISO template build metadata schema must be "
            f"{INSTALLER_ISO_TEMPLATE_BUILD_SCHEMA}"
        )
    metadata_origin = _validate_manage_origin(
        metadata["manage_origin"], "installer ISO template metadata manage origin"
    )
    if metadata_origin != descriptor["manage_origin"]:
        _fail("installer ISO template metadata does not match the expected manage origin")
    comparable_fields = {
        "version",
        "architecture",
        "base_os",
        "base_os_version",
        "manage_origin",
        "size_bytes",
        "template_sha256",
        "personalization_offset",
        "personalization_size",
        "placeholder_sha256",
        "provisioning_public_keys",
    }
    if any(metadata[field] != descriptor[field] for field in comparable_fields):
        _fail("installer ISO template build metadata does not match the supplied ISO")
    metadata_delivery = metadata.get("package_delivery")
    if metadata_delivery != descriptor.get("package_delivery"):
        _fail("installer ISO template build metadata package delivery does not match")
    snapshot_id = metadata.get("ubuntu_snapshot_id")
    if metadata_delivery == INSTALLER_ISO_TEMPLATE_NETWORK_PACKAGE_DELIVERY:
        if not isinstance(snapshot_id, str) or not re.fullmatch(
            r"[0-9]{8}T[0-9]{6}Z", snapshot_id
        ):
            _fail("network installer ISO template metadata requires an Ubuntu snapshot ID")
    elif snapshot_id is not None:
        _fail("embedded installer ISO template metadata must not name an Ubuntu snapshot")


def _inspect_installer_iso_template(
    inputs: tuple[Path, str, int, list[str], str | None, str, Path | None],
    version: str,
) -> dict[str, Any]:
    (
        path,
        url,
        offset,
        provisioning_public_keys,
        package_delivery,
        expected_manage_origin,
        metadata_path,
    ) = inputs
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
    descriptor = {
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
        "manage_origin": expected_manage_origin,
    }
    if package_delivery is not None:
        descriptor["package_delivery"] = package_delivery
    if metadata_path is not None:
        _validate_installer_iso_template_metadata(metadata_path, descriptor)
    return descriptor


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
    expected_name = f"cybex-james-appliance-packages-{version}-x86_64-linux.tar.zst"
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
            "manage_origin",
            "manage_source_revision",
            "manage_source_sha256",
            "manage_source_size_bytes",
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
        metadata["schema"] != "cybex.james.appliance-package-snapshot.v1"
        or metadata["release_id"] != version
        or metadata["filename"] != expected_name
        or not isinstance(metadata["ubuntu_snapshot_id"], str)
        or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", metadata["ubuntu_snapshot_id"])
        or metadata["minimum_protocol"] != 4
        or metadata["minimum_state_schema"] != 2
        or metadata["rollback_compatible"] is not True
    ):
        _fail("appliance package snapshot metadata is incompatible")
    metadata_manage_origin = _validate_manage_origin(
        metadata["manage_origin"], "appliance package snapshot metadata manage origin"
    )
    expected_manage_origin = _validate_manage_origin(arguments.expected_manage_origin)
    if metadata_manage_origin != expected_manage_origin:
        _fail(
            "appliance package snapshot metadata does not match the explicit "
            "expected manage origin"
        )
    manage_source_revision = _validate_revision(
        metadata["manage_source_revision"],
        "appliance package Manage source revision",
    )
    _require_sha256(
        metadata["manage_source_sha256"],
        "appliance package Manage source SHA-256",
    )
    _require_positive_int(
        metadata["manage_source_size_bytes"],
        "appliance package Manage source size",
        maximum=MANAGE_SOURCE_ARCHIVE_MAX_BYTES,
    )
    workstation_manage_revision = getattr(
        arguments, "workstation_netboot_manage_revision", None
    )
    if workstation_manage_revision is not None:
        workstation_manage_revision = _validate_revision(
            workstation_manage_revision,
            "workstation netboot Manage revision",
        )
        if manage_source_revision != workstation_manage_revision:
            _fail(
                "appliance package Manage source revision does not match the "
                "workstation netboot Manage revision"
            )
    actual_sha, actual_size = _inspect_artifact(
        bundle,
        "appliance package snapshot",
        maximum_bytes=APPLIANCE_PACKAGE_SNAPSHOT_MAX_BYTES,
    )
    if metadata["sha256"] != actual_sha or metadata["size_bytes"] != actual_size:
        _fail("appliance package snapshot metadata does not match the bundle")
    versions = metadata["required_package_versions"]
    required_names = {
        "cybex-james",
        "cybex-james-bootstrap",
        "cybex-james-appliance",
        "linux-generic",
        "linux-firmware",
        "nix-bin",
        "python3",
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
        "minimum_state_schema": 2,
        "rollback_compatible": True,
        "release_notes": notes_url,
    }
    return descriptor, [
        (bundle, "appliance package snapshot"),
        (metadata_path, "appliance package snapshot metadata"),
    ]


def _normalized_tar_name(name: str, label: str) -> str:
    normalized = name[2:] if name.startswith("./") else name
    components = normalized.split("/")
    if (
        not normalized
        or normalized.startswith("/")
        or any(component in ("", ".", "..") for component in components)
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        _fail(f"{label} contains an unsafe member name")
    return normalized


def _copy_tar_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
    label: str,
    maximum_bytes: int,
) -> tuple[str, int]:
    if member.size <= 0 or member.size > maximum_bytes:
        _fail(f"{label} size is outside its bound")
    extracted = archive.extractfile(member)
    if extracted is None:
        _fail(f"{label} could not be read")
    digest = hashlib.sha256()
    consumed = 0
    try:
        with destination.open("xb") as output:
            while True:
                chunk = extracted.read(1024 * 1024)
                if not chunk:
                    break
                consumed += len(chunk)
                if consumed > member.size:
                    _fail(f"{label} exceeded its declared size")
                digest.update(chunk)
                output.write(chunk)
    except OSError:
        _fail(f"could not materialize {label} for verification")
    if consumed != member.size:
        _fail(f"{label} is truncated")
    return digest.hexdigest(), consumed


def _verify_manage_source_git_archive(path: Path, revision: str) -> None:
    try:
        size_bytes = path.stat().st_size
    except OSError:
        _fail("could not inspect the packaged Manage source archive")
    if (
        size_bytes <= 0
        or size_bytes > MANAGE_SOURCE_ARCHIVE_MAX_BYTES
        or size_bytes % (20 * 512) != 0
    ):
        _fail("packaged Manage source archive framing is not deterministic")
    try:
        with path.open("rb") as archive_file:
            identity = subprocess.run(
                ["git", "get-tar-commit-id"],
                stdin=archive_file,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        _fail("git is required to verify the packaged Manage source archive")
    if identity.returncode != 0 or identity.stdout != f"{revision}\n".encode("ascii"):
        _fail("packaged Manage source archive does not bind its declared revision")

    observed: set[str] = set()
    regular_files: set[str] = set()
    regular_bytes = 0
    source_mtime: int | None = None
    logical_end = 0
    try:
        with tarfile.open(path, mode="r:") as source_archive:
            for member in source_archive:
                name = _normalized_tar_name(member.name, "packaged Manage source archive")
                if name in observed:
                    _fail("packaged Manage source archive contains a duplicate entry")
                observed.add(name)
                if len(observed) > 100_000:
                    _fail("packaged Manage source archive contains too many entries")
                if not (member.isdir() or member.isreg()) or member.islnk() or member.issym():
                    _fail(
                        "packaged Manage source archive contains a symlink, hardlink, "
                        "or nonregular entry"
                    )
                expected_mode = 0o755 if member.isdir() else None
                if member.isreg() and member.mode not in (0o644, 0o755):
                    _fail("packaged Manage source archive file mode is not deterministic")
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname != "root"
                    or member.gname != "root"
                    or (expected_mode is not None and member.mode != expected_mode)
                ):
                    _fail("packaged Manage source archive ownership is not deterministic")
                pax_headers = dict(member.pax_headers)
                if pax_headers.pop("comment", None) != revision:
                    _fail("packaged Manage source archive lost its revision marker")
                if pax_headers and pax_headers != {"path": member.name}:
                    _fail("packaged Manage source archive has unsupported extended metadata")
                if source_mtime is None:
                    if not isinstance(member.mtime, int) or member.mtime < 0:
                        _fail("packaged Manage source archive timestamp is invalid")
                    source_mtime = member.mtime
                elif member.mtime != source_mtime:
                    _fail("packaged Manage source archive timestamps are not deterministic")
                if member.isreg():
                    regular_files.add(name)
                    if member.size < 0:
                        _fail("packaged Manage source archive contains an invalid size")
                    regular_bytes += member.size
                    if regular_bytes > MANAGE_SOURCE_ARCHIVE_MAX_BYTES:
                        _fail("packaged Manage source archive contents exceed their bound")
                    extracted = source_archive.extractfile(member)
                    if extracted is None:
                        _fail("packaged Manage source archive entry could not be read")
                    consumed = 0
                    while chunk := extracted.read(1024 * 1024):
                        consumed += len(chunk)
                        if consumed > member.size:
                            _fail(
                                "packaged Manage source archive entry exceeded its declared size"
                            )
                    if consumed != member.size:
                        _fail("packaged Manage source archive entry is truncated")
            logical_end = source_archive.offset
    except ReleaseError:
        raise
    except (tarfile.TarError, OSError, EOFError):
        _fail("packaged Manage source archive is malformed or truncated")
    if not MANAGE_SOURCE_INSTALLER_REQUIRED_PATHS <= regular_files:
        _fail("packaged Manage source archive omits a required installer source path")
    try:
        with path.open("rb") as archive_file:
            archive_file.seek(logical_end)
            trailing = archive_file.read()
    except OSError:
        _fail("could not inspect packaged Manage source archive framing")
    if not 1024 <= len(trailing) <= 20 * 512 or any(trailing):
        _fail("packaged Manage source archive has noncanonical trailing bytes")


def _inspect_packaged_manage_source(
    snapshot: Path, version: str
) -> dict[str, object]:
    expected_package_name = f"cybex-james_{version}-1_amd64.deb"
    with tempfile.TemporaryDirectory(prefix="cybex-james-manage-source-") as directory:
        directory_path = Path(directory)
        package_path = directory_path / expected_package_name
        try:
            decompressor = subprocess.Popen(
                ["zstd", "--decompress", "--stdout", "--quiet", str(snapshot)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except (FileNotFoundError, OSError):
            _fail("zstd is required to inspect the appliance package snapshot")
        assert decompressor.stdout is not None
        package_count = 0
        archive_error: str | None = None
        try:
            with tarfile.open(fileobj=decompressor.stdout, mode="r|") as archive:
                for member in archive:
                    name = member.name[2:] if member.name.startswith("./") else member.name
                    if name != expected_package_name:
                        continue
                    package_count += 1
                    if package_count != 1:
                        _fail("appliance package snapshot contains duplicate cybex-james packages")
                    if (
                        not member.isreg()
                        or member.islnk()
                        or member.issym()
                        or member.uid != 0
                        or member.gid != 0
                        or member.mode != 0o644
                        or member.mtime != 0
                        or member.pax_headers
                    ):
                        _fail("packaged cybex-james Debian metadata is not deterministic")
                    _copy_tar_member(
                        archive,
                        member,
                        package_path,
                        "packaged cybex-james Debian",
                        JAMES_DEBIAN_PACKAGE_MAX_BYTES,
                    )
        except ReleaseError:
            raise
        except (tarfile.TarError, OSError, EOFError):
            archive_error = "appliance package snapshot is malformed or truncated"
        finally:
            decompressor.stdout.close()
            stderr = decompressor.stderr.read() if decompressor.stderr is not None else b""
            if decompressor.stderr is not None:
                decompressor.stderr.close()
            return_code = decompressor.wait()
        if archive_error is not None:
            _fail(archive_error)
        if return_code != 0:
            del stderr
            _fail("appliance package snapshot decompression failed")
        if package_count != 1:
            _fail("appliance package snapshot omits its exact cybex-james package")

        try:
            data_tar = subprocess.Popen(
                ["dpkg-deb", "--fsys-tarfile", str(package_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except (FileNotFoundError, OSError):
            _fail("dpkg-deb is required to inspect the packaged Manage source")
        assert data_tar.stdout is not None
        source_directory = "usr/share/cybex-james/manage-source"
        source_prefix = source_directory + "/"
        source_directory_seen = False
        archive_path = directory_path / "manage-source.tar"
        archive_sha256: str | None = None
        archive_size: int | None = None
        metadata_body: bytes | None = None
        entry_revisions: dict[str, str] = {}
        data_error: str | None = None
        try:
            with tarfile.open(fileobj=data_tar.stdout, mode="r|") as package_archive:
                for member in package_archive:
                    name = member.name[2:] if member.name.startswith("./") else member.name
                    if name == source_directory:
                        if source_directory_seen:
                            _fail("cybex-james package contains a duplicate Manage source directory")
                        source_directory_seen = True
                        if (
                            not member.isdir()
                            or member.uid != 0
                            or member.gid != 0
                            or member.mode != 0o755
                            or member.pax_headers
                        ):
                            _fail("packaged Manage source directory metadata is unsafe")
                        continue
                    if not name.startswith(source_prefix):
                        continue
                    relative_name = name[len(source_prefix) :]
                    match = re.fullmatch(r"([0-9a-f]{40})\.(json|tar)", relative_name)
                    if match is None or "/" in relative_name:
                        _fail("cybex-james package contains an unexpected Manage source entry")
                    revision, kind = match.groups()
                    if kind in entry_revisions:
                        _fail("cybex-james package contains duplicate Manage source entries")
                    entry_revisions[kind] = revision
                    if (
                        not member.isreg()
                        or member.islnk()
                        or member.issym()
                        or member.uid != 0
                        or member.gid != 0
                        or member.mode != 0o444
                        or member.pax_headers
                    ):
                        _fail(
                            "packaged Manage source is a symlink, hardlink, nonregular, "
                            "or has unsafe metadata"
                        )
                    if kind == "tar":
                        archive_sha256, archive_size = _copy_tar_member(
                            package_archive,
                            member,
                            archive_path,
                            "packaged Manage source archive",
                            MANAGE_SOURCE_ARCHIVE_MAX_BYTES,
                        )
                    else:
                        if member.size <= 0 or member.size > MANAGE_SOURCE_METADATA_MAX_BYTES:
                            _fail("packaged Manage source metadata size is outside its bound")
                        extracted = package_archive.extractfile(member)
                        if extracted is None:
                            _fail("packaged Manage source metadata could not be read")
                        metadata_body = extracted.read(MANAGE_SOURCE_METADATA_MAX_BYTES + 1)
                        if len(metadata_body) != member.size:
                            _fail("packaged Manage source metadata is truncated")
        except ReleaseError:
            raise
        except (tarfile.TarError, OSError, EOFError):
            data_error = "cybex-james Debian data archive is malformed or truncated"
        finally:
            data_tar.stdout.close()
            data_stderr = data_tar.stderr.read() if data_tar.stderr is not None else b""
            if data_tar.stderr is not None:
                data_tar.stderr.close()
            data_return_code = data_tar.wait()
        if data_error is not None:
            _fail(data_error)
        if data_return_code != 0:
            del data_stderr
            _fail("dpkg-deb could not inspect the packaged Manage source")
        if (
            not source_directory_seen
            or set(entry_revisions) != {"json", "tar"}
            or entry_revisions["json"] != entry_revisions["tar"]
            or metadata_body is None
            or archive_sha256 is None
            or archive_size is None
        ):
            _fail("cybex-james package omits its exact Manage source archive contract")
        revision = entry_revisions["tar"]
        try:
            metadata = json.loads(metadata_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("packaged Manage source metadata is invalid JSON")
        metadata = _require_exact_object_keys(
            metadata,
            {"filename", "revision", "schema", "sha256", "size_bytes"},
            "packaged Manage source metadata",
        )
        canonical_metadata = (
            json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("ascii")
        if metadata_body != canonical_metadata:
            _fail("packaged Manage source metadata is not canonical compact sorted JSON")
        if (
            metadata["schema"] != MANAGE_SOURCE_METADATA_SCHEMA
            or metadata["revision"] != revision
            or metadata["filename"] != f"{revision}.tar"
            or _require_sha256(
                metadata["sha256"], "packaged Manage source metadata SHA-256"
            )
            != archive_sha256
            or _require_positive_int(
                metadata["size_bytes"],
                "packaged Manage source metadata size",
                maximum=MANAGE_SOURCE_ARCHIVE_MAX_BYTES,
            )
            != archive_size
        ):
            _fail("packaged Manage source metadata does not match its archive")
        _verify_manage_source_git_archive(archive_path, revision)
        return {
            "revision": revision,
            "sha256": archive_sha256,
            "size_bytes": archive_size,
        }


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
        f"{descriptor['required_james_protocol']}\n"
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
            "required_james_protocol",
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
        "required_james_protocol": WORKSTATION_NETBOOT_REQUIRED_JAMES_PROTOCOL,
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
        "required_james_protocol": WORKSTATION_NETBOOT_REQUIRED_JAMES_PROTOCOL,
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
    _verify_workstation_netboot_ustar(bundle)
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


def _verify_workstation_netboot_ustar(bundle: Path) -> None:
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

    def read_exact(size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = decompressor.stdout.read(remaining)
            if not chunk:
                _fail("workstation netboot archive is malformed or truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    entries = 0
    try:
        while True:
            header = read_exact(512)
            if header == bytes(512):
                if read_exact(512) != bytes(512):
                    _fail("workstation netboot archive has an invalid end marker")
                while trailing := decompressor.stdout.read(64 * 1024):
                    if any(trailing):
                        _fail("workstation netboot archive has nonzero trailing data")
                break
            if header[257:263] != b"ustar\0" or header[263:265] != b"00":
                _fail("workstation netboot archive must use strict ustar headers")
            if header[156:157] not in (b"\0", b"0"):
                _fail("workstation netboot archive extensions are not permitted")
            try:
                size_field = header[124:136].rstrip(b"\0 ") or b"0"
                payload_size = int(size_field, 8)
            except ValueError:
                _fail("workstation netboot archive has an invalid size field")
            if payload_size > WORKSTATION_NETBOOT_MAX_BYTES:
                _fail("workstation netboot archive entry exceeds its size bound")
            read_exact((payload_size + 511) // 512 * 512)
            entries += 1
            if entries > len(WORKSTATION_NETBOOT_COMPONENTS) + 1:
                _fail("workstation netboot archive contains too many entries")
    finally:
        decompressor.stdout.close()
        if decompressor.stderr is not None:
            decompressor.stderr.read()
            decompressor.stderr.close()
        return_code = decompressor.wait()
    if return_code != 0:
        _fail("workstation netboot archive decompression failed")


def _manifest_command(arguments: argparse.Namespace) -> None:
    artifact = Path(arguments.artifact)
    private_key = Path(arguments.private_key)
    output = Path(arguments.output)
    version = _validate_version(arguments.version)
    artifact_url = _validate_url(arguments.artifact_url, "artifact-url")
    release_url = _validate_url(arguments.release_url, "release-url")
    notes_url = _validate_url(arguments.notes_url or arguments.release_url, "notes-url")
    published_at = _validate_published_at(arguments.published_at)
    installer_iso_template_inputs = _installer_iso_template_inputs(
        arguments, version, require_build_metadata=True
    )
    if installer_iso_template_inputs is None:
        _fail("installer_iso_template_v2 is required for every James release")
    installer_iso_template: dict[str, Any] | None = None
    appliance_release_inputs = _appliance_release_inputs(arguments, version, notes_url)
    appliance_release: dict[str, Any] | None = None
    if (
        installer_iso_template_inputs[4]
        == INSTALLER_ISO_TEMPLATE_NETWORK_PACKAGE_DELIVERY
        and appliance_release_inputs is None
    ):
        _fail("network installer ISO templates require an appliance package snapshot")
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
        assert installer_iso_template_inputs[6] is not None
        protected_inputs.append(
            (
                installer_iso_template_inputs[6],
                "installer ISO template build metadata",
            )
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
    print(f"wrote signed James release manifest: {output}")


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


def _validate_manage_origin_command(arguments: argparse.Namespace) -> None:
    _validate_manage_origin(arguments.expected_manage_origin)
    print("validated canonical expected Management origin")


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


def _require_positive_int(value: object, label: str, *, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value <= 0
        or value > maximum
    ):
        _fail(f"{label} must be a positive bounded integer")
    return value


def _canonical_json_body(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError):
        _fail("JSON value cannot be represented canonically")


def _validate_compatibility_vocabulary(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 64
        or any(
            not isinstance(entry, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", entry)
            for entry in value
        )
        or len(set(value)) != len(value)
    ):
        _fail(f"{label} must be a non-empty bounded list of unique identifiers")
    return value


def _validate_compatibility_contract(
    value: object, *, require_current_runtime_contract: bool = True
) -> dict[str, Any]:
    contract = _require_exact_object_keys(
        value,
        {"schema", "protocol_version", "manage", "james", "workstation_runtime"},
        "component compatibility contract",
    )
    if contract["schema"] != COMPONENT_COMPATIBILITY_SCHEMA:
        _fail(
            "component compatibility contract schema must be "
            f"{COMPONENT_COMPATIBILITY_SCHEMA}"
        )
    _require_positive_int(
        contract["protocol_version"],
        "component compatibility protocol version",
        maximum=2**31 - 1,
    )
    manage = _require_exact_object_keys(
        contract["manage"],
        {"minimum_james_protocol", "maximum_james_protocol"},
        "Manage compatibility range",
    )
    james = _require_exact_object_keys(
        contract["james"],
        {"minimum_manage_protocol", "maximum_manage_protocol"},
        "James compatibility range",
    )
    manage_minimum = _require_positive_int(
        manage["minimum_james_protocol"],
        "Manage minimum James protocol",
        maximum=2**31 - 1,
    )
    manage_maximum = _require_positive_int(
        manage["maximum_james_protocol"],
        "Manage maximum James protocol",
        maximum=2**31 - 1,
    )
    james_minimum = _require_positive_int(
        james["minimum_manage_protocol"],
        "James minimum Manage protocol",
        maximum=2**31 - 1,
    )
    james_maximum = _require_positive_int(
        james["maximum_manage_protocol"],
        "James maximum Manage protocol",
        maximum=2**31 - 1,
    )
    if manage_minimum > manage_maximum or james_minimum > james_maximum:
        _fail("component compatibility protocol range is inverted")

    runtime = _require_exact_object_keys(
        contract["workstation_runtime"],
        {
            "compatibility_epoch",
            "descriptor_schema",
            "manifest_schema",
            "architecture",
            "format",
            "required_james_protocol",
            "import_states",
            "import_error_codes",
            "resolution_states",
            "resolution_error_codes",
            "report_receipt_states",
            "report_receipt_error_codes",
        },
        "workstation runtime compatibility contract",
    )
    _require_positive_int(
        runtime["compatibility_epoch"],
        "workstation runtime compatibility epoch",
        maximum=2**31 - 1,
    )
    _require_positive_int(
        runtime["required_james_protocol"],
        "workstation runtime required James protocol",
        maximum=2**31 - 1,
    )
    if require_current_runtime_contract:
        expected_runtime_scalars = {
            "descriptor_schema": WORKSTATION_NETBOOT_SCHEMA,
            "manifest_schema": WORKSTATION_NETBOOT_MANIFEST_SCHEMA,
            "architecture": WORKSTATION_NETBOOT_ARCHITECTURE,
            "format": WORKSTATION_NETBOOT_FORMAT,
            "required_james_protocol": WORKSTATION_NETBOOT_REQUIRED_JAMES_PROTOCOL,
        }
        for field, expected in expected_runtime_scalars.items():
            if runtime[field] != expected:
                _fail(f"workstation runtime compatibility {field} is unsupported")
    else:
        for field in ("descriptor_schema", "manifest_schema", "architecture", "format"):
            value = runtime[field]
            if (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > 128
                or any(
                    character.isspace() or ord(character) < 32 or ord(character) == 127
                    for character in value
                )
            ):
                _fail(f"historical workstation runtime compatibility {field} is invalid")
    for field in (
        "import_states",
        "import_error_codes",
        "resolution_states",
        "resolution_error_codes",
        "report_receipt_states",
        "report_receipt_error_codes",
    ):
        _validate_compatibility_vocabulary(
            runtime[field], f"workstation runtime {field}"
        )
    return contract


def _runtime_compatibility_tuple(contract: dict[str, Any]) -> dict[str, object]:
    runtime = contract["workstation_runtime"]
    return {
        field: runtime[field]
        for field in (
            "compatibility_epoch",
            "descriptor_schema",
            "manifest_schema",
            "architecture",
            "format",
            "required_james_protocol",
        )
    }


def _verify_component_compatibility_command(arguments: argparse.Namespace) -> None:
    james_value, _ = _load_bounded_json(
        Path(arguments.james_compatibility),
        "James component compatibility contract",
        maximum_bytes=1024 * 1024,
    )
    manage_value, _ = _load_bounded_json(
        Path(arguments.manage_compatibility),
        "Manage component compatibility contract",
        maximum_bytes=1024 * 1024,
    )
    james = _validate_compatibility_contract(james_value)
    manage = _validate_compatibility_contract(
        manage_value, require_current_runtime_contract=False
    )
    james_protocol = james["protocol_version"]
    manage_protocol = manage["protocol_version"]
    if not (
        manage["manage"]["minimum_james_protocol"]
        <= james_protocol
        <= manage["manage"]["maximum_james_protocol"]
    ):
        _fail(f"Manage does not accept selected James protocol {james_protocol}")
    if not (
        james["james"]["minimum_manage_protocol"]
        <= manage_protocol
        <= james["james"]["maximum_manage_protocol"]
    ):
        _fail(f"selected James does not accept Manage protocol {manage_protocol}")
    if _runtime_compatibility_tuple(james) != _runtime_compatibility_tuple(manage):
        _fail("James and Manage workstation runtime compatibility tuples do not match")
    print(
        "verified semantic James/Manage compatibility: "
        f"james_protocol={james_protocol} manage_protocol={manage_protocol} "
        f"runtime_epoch={james['workstation_runtime']['compatibility_epoch']}"
    )


def _release_manifest_artifact_identities(
    value: object,
) -> tuple[str, dict[str, object], list[tuple[bytes, bytes]]]:
    if not isinstance(value, dict):
        _fail("release manifest must be a JSON object")
    required_fields = {
        "schema",
        "version",
        "release_url",
        "notes_url",
        "published_at",
        "artifact",
        "signature",
        "installer_iso_template_v2",
    }
    optional_fields = {"appliance_release_v1", "workstation_netboot"}
    if not required_fields <= set(value) or not set(value) <= (
        required_fields | optional_fields
    ):
        _fail("release manifest fields are not the exact supported set")
    if value["schema"] != SCHEMA:
        _fail(f"release manifest schema must be {SCHEMA}")
    if not isinstance(value["version"], str):
        _fail("release manifest version must be a string")
    version = _validate_version(value["version"])
    if not isinstance(value["release_url"], str) or not isinstance(
        value["notes_url"], str
    ):
        _fail("release manifest URLs must be strings")
    _validate_url(value["release_url"], "release-url")
    _validate_url(value["notes_url"], "notes-url")
    if not isinstance(value["published_at"], str):
        _fail("release manifest published-at must be a string")
    _validate_published_at(value["published_at"])

    artifact = _require_exact_object_keys(
        value["artifact"], {"url", "sha256"}, "binary artifact"
    )
    if not isinstance(artifact["url"], str):
        _fail("artifact-url must be a string")
    artifact_url = _validate_url(artifact["url"], "artifact-url")
    if urlsplit(artifact_url).path.rsplit("/", 1)[-1] != "cybex-james-x86_64-linux":
        _fail("artifact-url filename does not bind the James binary")
    artifact_sha256 = _require_sha256(artifact["sha256"], "artifact.sha256")
    binary_signature = _canonical_base64(
        value["signature"], "binary signature", expected_bytes=64
    )
    signed_messages = [
        (
            binary_signature,
            _canonical_message(version, artifact_sha256, artifact_url),
        )
    ]

    template_fields = {
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
        "manage_origin",
        "signature",
    }
    template_value = value["installer_iso_template_v2"]
    if isinstance(template_value, dict) and "package_delivery" in template_value:
        template_fields.add("package_delivery")
    template = _require_exact_object_keys(
        template_value, template_fields, "installer ISO template descriptor"
    )
    if (
        template["version"] != version
        or template["architecture"] != INSTALLER_ISO_ARCHITECTURE
        or template["base_os"] != INSTALLER_ISO_TEMPLATE_BASE_OS
        or template["base_os_version"] != INSTALLER_ISO_TEMPLATE_BASE_OS_VERSION
        or template["personalization_size"]
        != INSTALLER_ISO_TEMPLATE_PERSONALIZATION_SIZE
    ):
        _fail("installer ISO template descriptor is incompatible")
    if not isinstance(template["url"], str):
        _fail("installer ISO template URL must be a string")
    template_url = _validate_url(template["url"], "installer-iso-template-url")
    expected_template_name = (
        f"cybex-james-appliance-template-{version}-{INSTALLER_ISO_ARCHITECTURE}.iso"
    )
    if urlsplit(template_url).path.rsplit("/", 1)[-1] != expected_template_name:
        _fail("installer ISO template URL does not bind its release filename")
    template_size = _require_positive_int(
        template["size_bytes"],
        "installer ISO template size",
        maximum=INSTALLER_ISO_MAX_BYTES,
    )
    template_sha256 = _require_sha256(
        template["template_sha256"], "installer_iso_template_v2.template_sha256"
    )
    _require_sha256(
        template["placeholder_sha256"],
        "installer_iso_template_v2.placeholder_sha256",
    )
    if (
        not isinstance(template["personalization_offset"], int)
        or isinstance(template["personalization_offset"], bool)
        or template["personalization_offset"] < 0
        or template["personalization_offset"]
        + INSTALLER_ISO_TEMPLATE_PERSONALIZATION_SIZE
        > template_size
    ):
        _fail("installer ISO template personalization offset is invalid")
    keys = template["provisioning_public_keys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= 8:
        _fail("installer ISO template provisioning keys are invalid")
    if (
        any(not isinstance(entry, str) for entry in keys)
        or len(set(keys)) != len(keys)
        or keys != sorted(keys)
    ):
        _fail("installer ISO template provisioning keys are invalid")
    for key in keys:
        _trusted_public_key(key, "installer ISO template provisioning public key")
    manage_origin = _validate_manage_origin(
        template["manage_origin"], "installer_iso_template_v2.manage_origin"
    )
    package_delivery = template.get("package_delivery")
    if package_delivery not in (
        None,
        INSTALLER_ISO_TEMPLATE_NETWORK_PACKAGE_DELIVERY,
    ):
        _fail("installer ISO template package delivery is invalid")
    template_unsigned = dict(template)
    template_signature = _canonical_base64(
        template_unsigned.pop("signature"),
        "installer ISO template signature",
        expected_bytes=64,
    )
    signed_messages.append(
        (template_signature, _installer_iso_template_message(template_unsigned))
    )

    appliance_identity: dict[str, object] | None = None
    if "appliance_release_v1" in value:
        appliance = _require_exact_object_keys(
            value["appliance_release_v1"],
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
        if (
            appliance["schema"] != APPLIANCE_RELEASE_SCHEMA
            or appliance["release_id"] != version
            or appliance["minimum_protocol"] != WORKSTATION_NETBOOT_REQUIRED_JAMES_PROTOCOL
            or appliance["minimum_state_schema"] != 2
            or appliance["rollback_compatible"] is not True
        ):
            _fail("appliance release descriptor is incompatible")
        snapshot = _require_exact_object_keys(
            appliance["cybex_repository_snapshot"],
            {"url", "sha256", "size_bytes"},
            "appliance repository snapshot",
        )
        if not isinstance(snapshot["url"], str):
            _fail("appliance package snapshot URL must be a string")
        snapshot_url = _validate_url(
            snapshot["url"], "appliance-package-snapshot-url"
        )
        expected_snapshot_name = (
            f"cybex-james-appliance-packages-{version}-x86_64-linux.tar.zst"
        )
        if urlsplit(snapshot_url).path.rsplit("/", 1)[-1] != expected_snapshot_name:
            _fail("appliance package snapshot URL does not bind its release filename")
        snapshot_sha256 = _require_sha256(
            snapshot["sha256"], "appliance package snapshot SHA-256"
        )
        snapshot_size = _require_positive_int(
            snapshot["size_bytes"],
            "appliance package snapshot size",
            maximum=APPLIANCE_PACKAGE_SNAPSHOT_MAX_BYTES,
        )
        appliance_unsigned = dict(appliance)
        appliance_signature = _canonical_base64(
            appliance_unsigned.pop("signature"),
            "appliance release signature",
            expected_bytes=64,
        )
        signed_messages.append(
            (appliance_signature, _appliance_release_message(appliance_unsigned))
        )
        appliance_identity = {
            "url": snapshot_url,
            "sha256": snapshot_sha256,
            "size_bytes": snapshot_size,
            "minimum_state_schema": appliance["minimum_state_schema"],
        }
    if (
        package_delivery == INSTALLER_ISO_TEMPLATE_NETWORK_PACKAGE_DELIVERY
        and appliance_identity is None
    ):
        _fail("network installer ISO template is missing its appliance release")

    workstation_identity: dict[str, object] | None = None
    if "workstation_netboot" in value:
        workstation = _require_exact_object_keys(
            value["workstation_netboot"],
            {
                "schema",
                "runtime_version",
                "manage_source_revision",
                "nixpkgs_revision",
                "architecture",
                "format",
                "required_james_protocol",
                "url",
                "sha256",
                "size_bytes",
                "manifest_sha256",
                "components",
                "signature",
            },
            "workstation netboot descriptor",
        )
        if (
            workstation["schema"] != WORKSTATION_NETBOOT_SCHEMA
            or workstation["architecture"] != WORKSTATION_NETBOOT_ARCHITECTURE
            or workstation["format"] != WORKSTATION_NETBOOT_FORMAT
            or workstation["required_james_protocol"]
            != WORKSTATION_NETBOOT_REQUIRED_JAMES_PROTOCOL
            or not isinstance(workstation["runtime_version"], str)
            or not isinstance(workstation["manage_source_revision"], str)
            or not isinstance(workstation["nixpkgs_revision"], str)
        ):
            _fail("workstation netboot descriptor is incompatible")
        runtime_version = _validate_version(workstation["runtime_version"])
        manage_revision = _validate_revision(
            workstation["manage_source_revision"],
            "workstation netboot Manage revision",
        )
        _validate_revision(
            workstation["nixpkgs_revision"],
            "workstation netboot nixpkgs revision",
        )
        if not isinstance(workstation["url"], str):
            _fail("workstation netboot URL must be a string")
        workstation_url = _validate_url(
            workstation["url"], "workstation-netboot-url"
        )
        expected_workstation_name = (
            f"cybex-workstation-netboot-{runtime_version}-{manage_revision[:12]}-"
            f"{WORKSTATION_NETBOOT_ARCHITECTURE}.tar.zst"
        )
        if (
            urlsplit(workstation_url).path.rsplit("/", 1)[-1]
            != expected_workstation_name
        ):
            _fail("workstation netboot URL does not bind its release filename")
        _require_sha256(workstation["sha256"], "workstation netboot SHA-256")
        _require_sha256(
            workstation["manifest_sha256"],
            "workstation netboot manifest SHA-256",
        )
        _require_positive_int(
            workstation["size_bytes"],
            "workstation netboot size",
            maximum=WORKSTATION_NETBOOT_MAX_BYTES,
        )
        components = _require_exact_object_keys(
            workstation["components"],
            set(WORKSTATION_NETBOOT_COMPONENTS),
            "workstation netboot components",
        )
        for name in WORKSTATION_NETBOOT_COMPONENTS:
            component = _require_exact_object_keys(
                components[name],
                {"sha256", "size_bytes"},
                f"workstation netboot component {name}",
            )
            _require_sha256(component["sha256"], f"workstation component {name}")
            _require_positive_int(
                component["size_bytes"],
                f"workstation component {name} size",
                maximum=WORKSTATION_NETBOOT_MAX_BYTES,
            )
        workstation_unsigned = dict(workstation)
        workstation_signature = _canonical_base64(
            workstation_unsigned.pop("signature"),
            "workstation netboot signature",
            expected_bytes=64,
        )
        signed_messages.append(
            (
                workstation_signature,
                _workstation_netboot_message(workstation_unsigned),
            )
        )
        workstation_identity = workstation_unsigned

    identities: dict[str, object] = {
        "james_binary": {"url": artifact_url, "sha256": artifact_sha256},
        "appliance_iso_template": {
            "url": template_url,
            "sha256": template_sha256,
            "size_bytes": template_size,
            "manage_origin": manage_origin,
        },
        "appliance_package_snapshot": appliance_identity,
        "workstation_runtime": workstation_identity,
    }
    return version, identities, signed_messages


def _release_compatibility_unsigned_payload(
    manifest: dict[str, Any],
    manifest_body: bytes,
    manifest_url_value: object,
    compatibility: dict[str, Any],
    public_key_value: object,
) -> tuple[dict[str, object], list[tuple[bytes, bytes]]]:
    if not isinstance(manifest_url_value, str):
        _fail("release-manifest-url must be a string")
    manifest_url = _validate_url(manifest_url_value, "release-manifest-url")
    if urlsplit(manifest_url).path.rsplit("/", 1)[-1] != RELEASE_MANIFEST_FILENAME:
        _fail(f"release-manifest-url path must end in /{RELEASE_MANIFEST_FILENAME}")
    public_key = base64.b64encode(
        _trusted_public_key(public_key_value, "release compatibility public key")
    ).decode("ascii")
    contract = _validate_compatibility_contract(compatibility)
    version, artifacts, signed_messages = _release_manifest_artifact_identities(
        manifest
    )
    runtime = artifacts["workstation_runtime"]
    if runtime is not None:
        assert isinstance(runtime, dict)
        runtime_contract = contract["workstation_runtime"]
        assert isinstance(runtime_contract, dict)
        expected_runtime_contract = {
            "descriptor_schema": runtime["schema"],
            "architecture": runtime["architecture"],
            "format": runtime["format"],
            "required_james_protocol": runtime["required_james_protocol"],
        }
        for field, expected in expected_runtime_contract.items():
            if runtime_contract[field] != expected:
                _fail(
                    f"release workstation runtime does not match compatibility {field}"
                )
    compatibility_body = _canonical_json_body(contract)
    return (
        {
            "schema": RELEASE_COMPATIBILITY_SCHEMA,
            "james_release_version": version,
            "release_manifest": {
                "url": manifest_url,
                "sha256": hashlib.sha256(manifest_body).hexdigest(),
            },
            "compatibility": contract,
            "compatibility_sha256": hashlib.sha256(compatibility_body).hexdigest(),
            "artifacts": artifacts,
            "public_key": public_key,
        },
        signed_messages,
    )


def _release_compatibility_message(payload: dict[str, object]) -> bytes:
    return (
        RELEASE_COMPATIBILITY_SIGNATURE_DOMAIN.encode("ascii")
        + b"\n"
        + _canonical_json_body(payload)
    )


def _verified_release_compatibility_payload(
    asset: object,
    asset_body: bytes,
    trusted_public_key_value: object,
    *,
    require_current_runtime_contract: bool = True,
    require_current_installer_origin: bool = True,
) -> dict[str, Any]:
    if asset_body != _canonical_json_body(asset):
        _fail("release compatibility asset must be canonical compact sorted JSON")
    expected_asset_fields = {
        "schema",
        "james_release_version",
        "release_manifest",
        "compatibility",
        "compatibility_sha256",
        "artifacts",
        "public_key",
        "signature",
    }
    asset = _require_exact_object_keys(
        asset, expected_asset_fields, "release compatibility asset"
    )
    if asset["schema"] != RELEASE_COMPATIBILITY_SCHEMA:
        _fail(
            f"release compatibility asset schema must be {RELEASE_COMPATIBILITY_SCHEMA}"
        )
    if not isinstance(asset["james_release_version"], str):
        _fail("release compatibility James version must be a string")
    _validate_version(asset["james_release_version"])
    release_manifest = _require_exact_object_keys(
        asset["release_manifest"],
        {"url", "sha256"},
        "referenced release manifest",
    )
    if not isinstance(release_manifest["url"], str):
        _fail("referenced release manifest URL must be a string")
    manifest_url = _validate_url(
        release_manifest["url"], "release compatibility manifest URL"
    )
    if urlsplit(manifest_url).path.rsplit("/", 1)[-1] != RELEASE_MANIFEST_FILENAME:
        _fail(
            f"release compatibility manifest URL must end in /{RELEASE_MANIFEST_FILENAME}"
        )
    _require_sha256(
        release_manifest["sha256"], "referenced release manifest SHA-256"
    )
    artifacts = _require_exact_object_keys(
        asset["artifacts"],
        {
            "james_binary",
            "appliance_iso_template",
            "appliance_package_snapshot",
            "workstation_runtime",
        },
        "release compatibility artifacts",
    )
    template_identity_value = artifacts["appliance_iso_template"]
    if not isinstance(template_identity_value, dict):
        _fail("release compatibility installer ISO template identity is invalid")
    template_identity_fields = {"url", "sha256", "size_bytes"}
    if "manage_origin" in template_identity_value:
        template_identity_fields.add("manage_origin")
    elif require_current_installer_origin:
        _fail("current release compatibility installer ISO template requires manage_origin")
    template_identity = _require_exact_object_keys(
        template_identity_value,
        template_identity_fields,
        "release compatibility installer ISO template identity",
    )
    if not isinstance(template_identity["url"], str):
        _fail("release compatibility installer ISO template URL must be a string")
    _validate_url(
        template_identity["url"],
        "release compatibility installer ISO template URL",
    )
    _require_sha256(
        template_identity["sha256"],
        "release compatibility installer ISO template SHA-256",
    )
    _require_positive_int(
        template_identity["size_bytes"],
        "release compatibility installer ISO template size",
        maximum=INSTALLER_ISO_MAX_BYTES,
    )
    if "manage_origin" in template_identity:
        _validate_manage_origin(
            template_identity["manage_origin"],
            "release compatibility installer ISO template manage origin",
        )
    contract = _validate_compatibility_contract(
        asset["compatibility"],
        require_current_runtime_contract=require_current_runtime_contract,
    )
    compatibility_sha256 = _require_sha256(
        asset["compatibility_sha256"],
        "release compatibility contract SHA-256",
    )
    if compatibility_sha256 != hashlib.sha256(
        _canonical_json_body(contract)
    ).hexdigest():
        _fail("release compatibility contract SHA-256 does not match its contract")
    signature = _canonical_base64(
        asset["signature"], "release compatibility signature", expected_bytes=64
    )
    embedded_public_key = _trusted_public_key(
        asset["public_key"], "release compatibility public key"
    )
    trusted_public_key = _trusted_public_key(trusted_public_key_value)
    if embedded_public_key != trusted_public_key:
        _fail("release compatibility public key does not match the trusted public key")
    payload = dict(asset)
    payload.pop("signature")
    _self_verify(
        ED25519_PUBLIC_DER_PREFIX + trusted_public_key,
        signature,
        _release_compatibility_message(payload),
    )
    return payload


def _enforce_runtime_identity_transition(
    previous_asset_path: Path,
    current_payload: dict[str, object],
    trusted_public_key: str,
) -> None:
    previous_asset, previous_body = _load_bounded_json(
        previous_asset_path,
        "previous release compatibility asset",
        maximum_bytes=1024 * 1024,
    )
    previous_payload = _verified_release_compatibility_payload(
        previous_asset,
        previous_body,
        trusted_public_key,
        require_current_runtime_contract=False,
        require_current_installer_origin=False,
    )
    previous_epoch = previous_payload["compatibility"]["workstation_runtime"][
        "compatibility_epoch"
    ]
    current_epoch = current_payload["compatibility"]["workstation_runtime"][
        "compatibility_epoch"
    ]
    previous_runtime = previous_payload["artifacts"]["workstation_runtime"]
    current_runtime = current_payload["artifacts"]["workstation_runtime"]
    if current_epoch < previous_epoch:
        _fail("workstation runtime compatibility epoch must not decrease")
    if previous_runtime is None:
        if previous_epoch != current_epoch and not isinstance(current_runtime, dict):
            _fail(
                "a workstation runtime artifact is required when its compatibility "
                "epoch changes"
            )
        return
    if not isinstance(previous_runtime, dict):
        _fail("previous workstation runtime artifact identity is invalid")
    if not isinstance(current_runtime, dict):
        _fail(
            "a published workstation runtime artifact must not be removed from "
            "a successor release"
        )
    previous_version_value = previous_runtime.get("runtime_version")
    current_version_value = current_runtime.get("runtime_version")
    if not isinstance(previous_version_value, str):
        _fail("previous workstation runtime version is invalid")
    if not isinstance(current_version_value, str):
        _fail("current workstation runtime version is invalid")
    previous_version = _validate_version(previous_version_value)
    current_version = _validate_version(current_version_value)
    version_order = _compare_semver(current_version, previous_version)
    if version_order < 0:
        _fail(
            "current workstation runtime version must not be older than the latest "
            "published predecessor"
        )
    if version_order == 0 and (
        current_version != previous_version
        or _canonical_json_body(current_runtime)
        != _canonical_json_body(previous_runtime)
    ):
        _fail(
            "workstation runtime descriptor identity changed at equal SemVer "
            "precedence; bump the workstation runtime version"
        )
    previous_sha256 = _require_sha256(
        previous_runtime.get("sha256"),
        "previous workstation runtime SHA-256",
    )
    current_sha256 = _require_sha256(
        current_runtime.get("sha256"),
        "current workstation runtime SHA-256",
    )
    if version_order > 0 and previous_sha256 == current_sha256:
        _fail(
            "workstation runtime bundle SHA-256 must change when its runtime "
            "version advances"
        )
    if previous_epoch != current_epoch and previous_sha256 == current_sha256:
        _fail(
            "workstation runtime bundle SHA-256 must change when its compatibility "
            "epoch changes"
        )


def _enforce_appliance_state_schema_transition(
    previous_payload: dict[str, object], current_payload: dict[str, object]
) -> None:
    previous = previous_payload["artifacts"]["appliance_package_snapshot"]
    current = current_payload["artifacts"]["appliance_package_snapshot"]
    if previous is None:
        return
    if current is None:
        _fail(
            "a published appliance package snapshot must not be removed from "
            "a successor release"
        )
    if not isinstance(previous, dict) or not isinstance(current, dict):
        _fail("appliance package snapshot identity is invalid")
    # Compatibility assets published before state schema v2 did not project
    # the field; their signed appliance descriptors were fixed at schema 1.
    previous_schema = previous.get("minimum_state_schema", 1)
    current_schema = current.get("minimum_state_schema")
    if (
        not isinstance(previous_schema, int)
        or isinstance(previous_schema, bool)
        or not isinstance(current_schema, int)
        or isinstance(current_schema, bool)
        or current_schema < previous_schema
    ):
        _fail("appliance minimum state schema must not decrease")


def _enforce_installer_manage_origin_transition(
    previous_payload: dict[str, object], current_payload: dict[str, object]
) -> None:
    previous_template = previous_payload["artifacts"]["appliance_iso_template"]
    current_template = current_payload["artifacts"]["appliance_iso_template"]
    if not isinstance(previous_template, dict) or not isinstance(current_template, dict):
        _fail("installer ISO template identity is invalid")
    previous_origin = previous_template.get("manage_origin")
    if previous_origin is None:
        # A signed predecessor from before the origin contract may establish
        # the lineage exactly once. Current parsing already requires the field.
        return
    current_origin = current_template.get("manage_origin")
    if previous_origin != current_origin:
        _fail("installer Management origin must not change within a release lineage")


def _verify_signed_messages(
    public_der: bytes, signed_messages: Sequence[tuple[bytes, bytes]]
) -> None:
    for signature, message in signed_messages:
        _self_verify(public_der, signature, message)


def _release_compatibility_command(arguments: argparse.Namespace) -> None:
    manifest_path = Path(arguments.manifest)
    compatibility_path = Path(arguments.compatibility)
    private_key_path = Path(arguments.private_key)
    output = Path(arguments.output)
    previous_compatibility_path = (
        Path(arguments.previous_compatibility)
        if arguments.previous_compatibility
        else None
    )
    manifest, manifest_body = _load_bounded_json(
        manifest_path, "release manifest", maximum_bytes=512 * 1024
    )
    compatibility, _compatibility_source_body = _load_bounded_json(
        compatibility_path,
        "component compatibility contract",
        maximum_bytes=512 * 1024,
    )
    protected_inputs = [
        (manifest_path, "release manifest"),
        (compatibility_path, "component compatibility contract"),
        (private_key_path, "private key"),
    ]
    if previous_compatibility_path is not None:
        protected_inputs.append(
            (previous_compatibility_path, "previous release compatibility asset")
        )
    _validate_output(output, protected_inputs)
    private_fd = _open_regular(private_key_path, "private key", private=True)
    try:
        private_identity = _private_key_identity(private_fd)
        public_der = _public_der(private_fd)
        _require_stable_private_key(private_fd, private_identity)
        raw_public_key = public_der[len(ED25519_PUBLIC_DER_PREFIX) :]
        public_key = base64.b64encode(raw_public_key).decode("ascii")
        payload, manifest_signed_messages = _release_compatibility_unsigned_payload(
            manifest,
            manifest_body,
            arguments.manifest_url,
            compatibility,
            public_key,
        )
        _verify_signed_messages(public_der, manifest_signed_messages)
        if previous_compatibility_path is not None:
            _enforce_runtime_identity_transition(
                previous_compatibility_path,
                payload,
                public_key,
            )
            previous_asset, previous_body = _load_bounded_json(
                previous_compatibility_path,
                "previous release compatibility asset",
                maximum_bytes=1024 * 1024,
            )
            previous_payload = _verified_release_compatibility_payload(
                previous_asset,
                previous_body,
                public_key,
                require_current_runtime_contract=False,
                require_current_installer_origin=False,
            )
            _enforce_appliance_state_schema_transition(previous_payload, payload)
            _enforce_installer_manage_origin_transition(previous_payload, payload)
        message = _release_compatibility_message(payload)
        signature = _sign(private_fd, message)
        _require_stable_private_key(private_fd, private_identity)
    finally:
        os.close(private_fd)
    _self_verify(public_der, signature, message)
    asset = {**payload, "signature": base64.b64encode(signature).decode("ascii")}
    _atomic_write(output, _canonical_json_body(asset))
    print(f"wrote signed James release compatibility asset: {output}")


def _verify_release_compatibility_command(arguments: argparse.Namespace) -> None:
    asset_path = Path(arguments.asset)
    manifest_path = Path(arguments.manifest)
    compatibility_path = Path(arguments.compatibility)
    asset, asset_body = _load_bounded_json(
        asset_path, "release compatibility asset", maximum_bytes=1024 * 1024
    )
    actual_payload = _verified_release_compatibility_payload(
        asset, asset_body, arguments.trusted_public_key
    )

    manifest, manifest_body = _load_bounded_json(
        manifest_path, "release manifest", maximum_bytes=512 * 1024
    )
    compatibility, _compatibility_source_body = _load_bounded_json(
        compatibility_path,
        "component compatibility contract",
        maximum_bytes=512 * 1024,
    )
    expected_payload, manifest_signed_messages = _release_compatibility_unsigned_payload(
        manifest,
        manifest_body,
        arguments.manifest_url,
        compatibility,
        arguments.trusted_public_key,
    )
    if actual_payload != expected_payload:
        _fail(
            "release compatibility asset does not exactly match its manifest and contract"
        )
    public_der = ED25519_PUBLIC_DER_PREFIX + _trusted_public_key(
        arguments.trusted_public_key
    )
    _verify_signed_messages(public_der, manifest_signed_messages)
    print(
        "verified signed James release compatibility asset: "
        f"version={actual_payload['james_release_version']} "
        f"manifest_sha256={actual_payload['release_manifest']['sha256']} "
        f"compatibility_sha256={actual_payload['compatibility_sha256']}"
    )


def _verify_release_successor_command(arguments: argparse.Namespace) -> None:
    current_path = Path(arguments.current_compatibility)
    previous_path = Path(arguments.previous_compatibility)
    current_asset, current_body = _load_bounded_json(
        current_path,
        "current release compatibility asset",
        maximum_bytes=1024 * 1024,
    )
    current_payload = _verified_release_compatibility_payload(
        current_asset,
        current_body,
        arguments.trusted_public_key,
    )
    previous_asset, previous_body = _load_bounded_json(
        previous_path,
        "previous release compatibility asset",
        maximum_bytes=1024 * 1024,
    )
    previous_payload = _verified_release_compatibility_payload(
        previous_asset,
        previous_body,
        arguments.trusted_public_key,
        require_current_runtime_contract=False,
        require_current_installer_origin=False,
    )
    current_version = current_payload["james_release_version"]
    previous_version = previous_payload["james_release_version"]
    if _compare_semver(current_version, previous_version) <= 0:
        _fail(
            "current James release version must have greater SemVer precedence "
            "than the latest published predecessor"
        )
    _enforce_runtime_identity_transition(
        previous_path,
        current_payload,
        arguments.trusted_public_key,
    )
    _enforce_appliance_state_schema_transition(previous_payload, current_payload)
    _enforce_installer_manage_origin_transition(previous_payload, current_payload)
    print(
        "verified James release successor: "
        f"previous={previous_version} current={current_version}"
    )


def _verify_command(arguments: argparse.Namespace) -> None:
    manifest_path = Path(arguments.manifest)
    artifact_path = Path(arguments.artifact)
    verify_workstation_netboot = bool(
        arguments.workstation_netboot_bundle or arguments.workstation_netboot_tree
    )
    verify_installer_template = True
    verify_appliance_release = bool(arguments.appliance_package_snapshot)
    if arguments.appliance_package_snapshot_metadata and not verify_appliance_release:
        _fail(
            "appliance-package-snapshot-metadata requires "
            "appliance-package-snapshot"
        )
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
    if artifact_path.name != "cybex-james-x86_64-linux":
        _fail("binary artifact must be named cybex-james-x86_64-linux")
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
        descriptor_fields = {
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
            "manage_origin",
            "signature",
        }
        descriptor_value = manifest["installer_iso_template_v2"]
        if isinstance(descriptor_value, dict) and "package_delivery" in descriptor_value:
            descriptor_fields.add("package_delivery")
        descriptor = _require_exact_object_keys(
            descriptor_value,
            descriptor_fields,
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
        manifest_manage_origin = _validate_manage_origin(
            descriptor["manage_origin"], "installer_iso_template_v2.manage_origin"
        )
        expected_manage_origin = _validate_manage_origin(arguments.expected_manage_origin)
        if manifest_manage_origin != expected_manage_origin:
            _fail(
                "installer ISO template manage origin does not match the explicit "
                "expected origin"
            )
        package_delivery = descriptor.get("package_delivery")
        if package_delivery not in (
            None,
            INSTALLER_ISO_TEMPLATE_NETWORK_PACKAGE_DELIVERY,
        ):
            _fail("installer ISO template package delivery is invalid")
        if (
            package_delivery == INSTALLER_ISO_TEMPLATE_NETWORK_PACKAGE_DELIVERY
            and "appliance_release_v1" not in manifest
        ):
            _fail("network installer ISO template is missing its appliance release")
        inspection_arguments = argparse.Namespace(
            installer_iso_template=arguments.installer_iso_template,
            installer_iso_template_url=descriptor["url"],
            installer_iso_template_personalization_offset=descriptor[
                "personalization_offset"
            ],
            provisioning_public_key=descriptor["provisioning_public_keys"],
            installer_iso_template_package_delivery=package_delivery,
            expected_manage_origin=arguments.expected_manage_origin,
            installer_iso_template_metadata=None,
        )
        inputs = _installer_iso_template_inputs(
            inspection_arguments, version, require_build_metadata=False
        )
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
    packaged_manage_source: dict[str, object] | None = None
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
            or descriptor["minimum_state_schema"] != 2
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
            f"cybex-james-appliance-packages-{version}-x86_64-linux.tar.zst"
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
            maximum_bytes=APPLIANCE_PACKAGE_SNAPSHOT_MAX_BYTES,
        )
        if (
            snapshot["sha256"] != actual_snapshot_sha
            or snapshot["size_bytes"] != actual_snapshot_size
        ):
            _fail("appliance package snapshot does not match its descriptor")
        if arguments.appliance_package_snapshot_metadata:
            inspection_arguments = argparse.Namespace(
                appliance_package_snapshot=arguments.appliance_package_snapshot,
                appliance_package_snapshot_metadata=(
                    arguments.appliance_package_snapshot_metadata
                ),
                appliance_package_snapshot_url=snapshot_url,
                expected_manage_origin=arguments.expected_manage_origin,
                workstation_netboot_manage_revision=(
                    manifest.get("workstation_netboot", {}).get(
                        "manage_source_revision"
                    )
                    if isinstance(manifest.get("workstation_netboot"), dict)
                    else None
                ),
            )
            inspected_release = _appliance_release_inputs(
                inspection_arguments, version, descriptor["release_notes"]
            )
            if inspected_release is None or descriptor != inspected_release[0]:
                _fail(
                    "appliance package snapshot metadata does not match its "
                    "signed descriptor"
                )
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
        if verify_workstation_netboot:
            packaged_manage_source = _inspect_packaged_manage_source(
                snapshot_path, version
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
                "required_james_protocol",
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
        if verify_appliance_release and (
            packaged_manage_source is None
            or packaged_manage_source["revision"] != descriptor["manage_source_revision"]
        ):
            _fail(
                "packaged Manage source revision does not match the signed "
                "workstation netboot descriptor"
            )
        workstation_sha = descriptor["sha256"]
    print(
        "verified signed James release manifest: "
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
        description="Build signed Cybex James release manifests without exposing private key bytes."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    manifest = commands.add_parser(
        "manifest",
        allow_abbrev=False,
        help="hash an artifact and atomically write a signed manifest",
    )
    manifest.add_argument("--artifact", required=True, help="regular James binary artifact")
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
        "--installer-iso-template-metadata",
        required=True,
        help="exact bounded build metadata emitted with --installer-iso-template",
    )
    manifest.add_argument(
        "--expected-manage-origin",
        required=True,
        help="explicit canonical HTTPS Management origin compiled into the installer bootstrap",
    )
    manifest.add_argument(
        "--installer-iso-template-personalization-offset",
        required=True,
        type=int,
        help="exact byte offset of the 8192-byte personalization slot",
    )
    manifest.add_argument(
        "--installer-iso-template-package-delivery",
        choices=[INSTALLER_ISO_TEMPLATE_NETWORK_PACKAGE_DELIVERY],
        help="package source contract for a network-delivered thin installer",
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

    verify_components = commands.add_parser(
        "verify-component-compatibility",
        allow_abbrev=False,
        help="verify semantic compatibility between selected James and Manage contracts",
    )
    verify_components.add_argument(
        "--james-compatibility", required=True, help="James component compatibility contract"
    )
    verify_components.add_argument(
        "--manage-compatibility", required=True, help="Manage component compatibility contract"
    )
    verify_components.set_defaults(handler=_verify_component_compatibility_command)

    compatibility = commands.add_parser(
        "compatibility",
        allow_abbrev=False,
        help="bind a release manifest and compatibility contract in a signed asset",
    )
    compatibility.add_argument(
        "--manifest", required=True, help="exact signed James release manifest"
    )
    compatibility.add_argument(
        "--manifest-url",
        required=True,
        help="exact immutable URL for cybex-james-release.json",
    )
    compatibility.add_argument(
        "--compatibility",
        required=True,
        help="exact component compatibility contract",
    )
    compatibility.add_argument(
        "--private-key", required=True, help="mode-0600 Ed25519 PEM private key"
    )
    compatibility.add_argument(
        "--previous-compatibility",
        help=(
            "latest previously published signed release compatibility asset; "
            "required by production aggregation when a prior release exists"
        ),
    )
    compatibility.add_argument(
        "--output",
        required=True,
        help="cybex-james-release-compatibility.json output path",
    )
    compatibility.set_defaults(handler=_release_compatibility_command)

    verify_compatibility = commands.add_parser(
        "verify-compatibility",
        allow_abbrev=False,
        help="independently verify a signed release compatibility asset",
    )
    verify_compatibility.add_argument(
        "--asset", required=True, help="signed release compatibility asset"
    )
    verify_compatibility.add_argument(
        "--manifest", required=True, help="exact referenced James release manifest"
    )
    verify_compatibility.add_argument(
        "--manifest-url",
        required=True,
        help="exact immutable URL for the referenced release manifest",
    )
    verify_compatibility.add_argument(
        "--compatibility",
        required=True,
        help="exact expected component compatibility contract",
    )
    verify_compatibility.add_argument(
        "--trusted-public-key",
        required=True,
        help="canonical standard-Base64 raw Ed25519 public key",
    )
    verify_compatibility.set_defaults(
        handler=_verify_release_compatibility_command
    )

    verify_successor = commands.add_parser(
        "verify-successor",
        allow_abbrev=False,
        help=(
            "verify that a signed release compatibility asset is a safe SemVer "
            "and runtime-epoch successor to the latest published asset"
        ),
    )
    verify_successor.add_argument(
        "--previous-compatibility",
        required=True,
        help="latest published signed release compatibility asset",
    )
    verify_successor.add_argument(
        "--current-compatibility",
        required=True,
        help="signed candidate release compatibility asset",
    )
    verify_successor.add_argument(
        "--trusted-public-key",
        required=True,
        help="canonical standard-Base64 raw Ed25519 public key",
    )
    verify_successor.set_defaults(handler=_verify_release_successor_command)

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

    validate_manage_origin = commands.add_parser(
        "validate-manage-origin",
        allow_abbrev=False,
        help="validate an explicit canonical HTTPS Management origin",
    )
    validate_manage_origin.add_argument(
        "--expected-manage-origin",
        required=True,
        help="canonical https://host[:non-default-port] origin without credentials, path, query, or fragment",
    )
    validate_manage_origin.set_defaults(handler=_validate_manage_origin_command)

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
        "--expected-manage-origin",
        required=True,
        help="explicit canonical HTTPS Management origin expected in the signed template descriptor",
    )
    verify.add_argument(
        "--appliance-package-snapshot",
        help="exact signed managed Ubuntu package snapshot bundle",
    )
    verify.add_argument(
        "--appliance-package-snapshot-metadata",
        help="exact package-snapshot build metadata binding the installed bootstrap origin",
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
