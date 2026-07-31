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
import tempfile
from typing import Any, NoReturn, Sequence
from urllib.parse import urlsplit


SCHEMA = "cybex.forge.release.v1"
INSTALLER_ISO_SIGNATURE_DOMAIN = "CYBEX-FORGE-INSTALLER-ISO-V1"
INSTALLER_ISO_ARCHITECTURE = "x86_64-linux"
INSTALLER_ISO_MAX_BYTES = 16 * 1024 * 1024 * 1024
PUBLIC_EVIDENCE_MAX_BYTES = 2 * 1024 * 1024
PUBLIC_EVIDENCE_SCHEMA = "cybex.incus.public-evidence.v1"
RELEASE_SMOKE_EVIDENCE_SCHEMA = "cybex.incus.forge-appliance-release-smoke.v1"
QUALIFICATION_SCHEMA = "cybex.forge.appliance-qualification.v1"
REQUIRED_RELEASE_SMOKE_CHECKS = (
    "exact_signed_descriptor",
    "release_binary_identity",
    "guided_ready_marker",
    "embedded_media_version",
    "embedded_release_binary_version",
    "embedded_release_binary_sha256",
    "embedded_production_trust",
    "guided_installer_service",
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


def _installer_iso_message(
    version: str,
    architecture: str,
    size_bytes: int,
    sha256: str,
    artifact_url: str,
) -> bytes:
    return (
        f"{INSTALLER_ISO_SIGNATURE_DOMAIN}\n"
        f"{version}\n"
        f"{architecture}\n"
        f"{size_bytes}\n"
        f"{sha256.lower()}\n"
        f"{artifact_url}\n"
    ).encode("utf-8")


def _installer_iso_inputs(
    arguments: argparse.Namespace,
    version: str,
) -> tuple[Path, str, str] | None:
    supplied = (arguments.installer_iso, arguments.installer_iso_url)
    if any(supplied) and not all(supplied):
        _fail("installer-iso and installer-iso-url must be supplied together")
    if not any(supplied):
        if arguments.installer_iso_architecture is not None:
            _fail("installer-iso-architecture requires installer-iso")
        return None

    architecture = arguments.installer_iso_architecture or INSTALLER_ISO_ARCHITECTURE
    if architecture != INSTALLER_ISO_ARCHITECTURE:
        _fail(f"installer ISO architecture must be {INSTALLER_ISO_ARCHITECTURE}")
    expected_name = (
        f"cybex-forge-appliance-{version}-{INSTALLER_ISO_ARCHITECTURE}.iso"
    )
    path = Path(arguments.installer_iso)
    if path.name != expected_name:
        _fail(f"installer ISO artifact must be named {expected_name}")
    url = _validate_url(arguments.installer_iso_url, "installer-iso-url")
    if urlsplit(url).path.rsplit("/", 1)[-1] != expected_name:
        _fail(f"installer-iso-url path must end in /{expected_name}")
    return path, url, architecture


def _manifest_command(arguments: argparse.Namespace) -> None:
    artifact = Path(arguments.artifact)
    private_key = Path(arguments.private_key)
    output = Path(arguments.output)
    version = _validate_version(arguments.version)
    artifact_url = _validate_url(arguments.artifact_url, "artifact-url")
    release_url = _validate_url(arguments.release_url, "release-url")
    notes_url = _validate_url(arguments.notes_url or arguments.release_url, "notes-url")
    published_at = _validate_published_at(arguments.published_at)
    installer_iso = _installer_iso_inputs(arguments, version)
    protected_inputs = [(artifact, "artifact"), (private_key, "private key")]
    if installer_iso is not None:
        protected_inputs.append((installer_iso[0], "installer ISO artifact"))
    _validate_output(output, protected_inputs)
    sha256, _artifact_size = _inspect_artifact(artifact, "artifact")
    installer_metadata: tuple[str, int] | None = None
    if installer_iso is not None:
        installer_metadata = _inspect_artifact(
            installer_iso[0],
            "installer ISO artifact",
            maximum_bytes=INSTALLER_ISO_MAX_BYTES,
        )

    private_fd = _open_regular(private_key, "private key", private=True)
    try:
        private_identity = _private_key_identity(private_fd)
        public_der = _public_der(private_fd)
        _require_stable_private_key(private_fd, private_identity)
        message = _canonical_message(version, sha256, artifact_url)
        signature = _sign(private_fd, message)
        _require_stable_private_key(private_fd, private_identity)
        installer_signature = None
        if installer_iso is not None and installer_metadata is not None:
            installer_sha256, installer_size = installer_metadata
            installer_signature = _sign(
                private_fd,
                _installer_iso_message(
                    version,
                    installer_iso[2],
                    installer_size,
                    installer_sha256,
                    installer_iso[1],
                ),
            )
            _require_stable_private_key(private_fd, private_identity)
    finally:
        os.close(private_fd)
    _self_verify(public_der, signature, message)
    if (
        installer_iso is not None
        and installer_metadata is not None
        and installer_signature is not None
    ):
        installer_sha256, installer_size = installer_metadata
        _self_verify(
            public_der,
            installer_signature,
            _installer_iso_message(
                version,
                installer_iso[2],
                installer_size,
                installer_sha256,
                installer_iso[1],
            ),
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
    if (
        installer_iso is not None
        and installer_metadata is not None
        and installer_signature is not None
    ):
        installer_sha256, installer_size = installer_metadata
        manifest["installer_iso"] = {
            "url": installer_iso[1],
            "sha256": installer_sha256,
            "size_bytes": installer_size,
            "architecture": installer_iso[2],
            "signature": base64.b64encode(installer_signature).decode("ascii"),
        }
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
    installer_path = Path(arguments.installer_iso)
    manifest = _require_exact_object_keys(
        _load_manifest(manifest_path),
        {
            "schema",
            "version",
            "release_url",
            "notes_url",
            "published_at",
            "artifact",
            "signature",
            "installer_iso",
        },
        "release manifest",
    )
    if manifest["schema"] != SCHEMA:
        _fail(f"release manifest schema must be {SCHEMA}")
    if not isinstance(manifest["version"], str):
        _fail("release manifest version must be a string")
    version = _validate_version(manifest["version"])
    if artifact_path.name != "cybex-forge-x86_64-linux":
        _fail("binary artifact must be named cybex-forge-x86_64-linux")
    expected_iso_name = (
        f"cybex-forge-appliance-{version}-{INSTALLER_ISO_ARCHITECTURE}.iso"
    )
    if installer_path.name != expected_iso_name:
        _fail(f"installer ISO artifact must be named {expected_iso_name}")

    release_url = _validate_url(str(manifest["release_url"]), "release-url")
    notes_url = _validate_url(str(manifest["notes_url"]), "notes-url")
    if not isinstance(manifest["published_at"], str):
        _fail("release manifest published-at must be a string")
    _validate_published_at(manifest["published_at"])
    artifact = _require_exact_object_keys(
        manifest["artifact"], {"url", "sha256"}, "binary artifact"
    )
    installer = _require_exact_object_keys(
        manifest["installer_iso"],
        {"url", "sha256", "size_bytes", "architecture", "signature"},
        "installer ISO",
    )
    artifact_url = _validate_url(str(artifact["url"]), "artifact-url")
    installer_url = _validate_url(str(installer["url"]), "installer-iso-url")
    if urlsplit(artifact_url).path.rsplit("/", 1)[-1] != artifact_path.name:
        _fail("artifact-url filename does not bind the binary artifact")
    if urlsplit(installer_url).path.rsplit("/", 1)[-1] != expected_iso_name:
        _fail("installer-iso-url filename does not bind the installer ISO")
    if release_url == artifact_url or notes_url == artifact_url:
        _fail("release and notes URLs must not alias the binary artifact")

    expected_artifact_sha = _require_sha256(artifact["sha256"], "artifact.sha256")
    expected_installer_sha = _require_sha256(
        installer["sha256"], "installer_iso.sha256"
    )
    actual_artifact_sha, _artifact_size = _inspect_artifact(
        artifact_path, "binary artifact"
    )
    actual_installer_sha, actual_installer_size = _inspect_artifact(
        installer_path,
        "installer ISO artifact",
        maximum_bytes=INSTALLER_ISO_MAX_BYTES,
    )
    if actual_artifact_sha != expected_artifact_sha:
        _fail("binary artifact SHA-256 does not match the release manifest")
    if actual_installer_sha != expected_installer_sha:
        _fail("installer ISO SHA-256 does not match the release manifest")
    if (
        not isinstance(installer["size_bytes"], int)
        or isinstance(installer["size_bytes"], bool)
        or installer["size_bytes"] != actual_installer_size
    ):
        _fail("installer ISO byte length does not match the release manifest")
    if installer["architecture"] != INSTALLER_ISO_ARCHITECTURE:
        _fail(f"installer ISO architecture must be {INSTALLER_ISO_ARCHITECTURE}")

    public_key = _trusted_public_key(arguments.trusted_public_key)
    binary_signature = _canonical_base64(
        manifest["signature"], "binary signature", expected_bytes=64
    )
    installer_signature = _canonical_base64(
        installer["signature"], "installer ISO signature", expected_bytes=64
    )
    public_der = ED25519_PUBLIC_DER_PREFIX + public_key
    _self_verify(
        public_der,
        binary_signature,
        _canonical_message(version, expected_artifact_sha, artifact_url),
    )
    _self_verify(
        public_der,
        installer_signature,
        _installer_iso_message(
            version,
            INSTALLER_ISO_ARCHITECTURE,
            actual_installer_size,
            expected_installer_sha,
            installer_url,
        ),
    )
    print(
        "verified signed Forge release manifest: "
        f"version={version} binary_sha256={actual_artifact_sha} "
        f"installer_iso_sha256={actual_installer_sha}"
    )


def _require_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return value


def _require_true(value: object, label: str) -> None:
    if value is not True:
        _fail(f"{label} must be true")


def _require_revision(value: object, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        _fail(f"{label} must be a lowercase 40-hex commit revision")
    return value


def _require_integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label} must be an integer greater than or equal to {minimum}")
    return value


def _verify_qualification_command(arguments: argparse.Namespace) -> None:
    evidence_path = Path(arguments.evidence)
    artifact_path = Path(arguments.artifact)
    installer_path = Path(arguments.installer_iso)
    output = Path(arguments.output)
    version = _validate_version(arguments.version)
    run_id = arguments.run_id
    if (
        not isinstance(run_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id)
    ):
        _fail("qualification run id is not a safe bounded identifier")
    forge_revision = _require_revision(
        arguments.forge_source_revision, "Forge source revision"
    )
    manage_revision = _require_revision(
        arguments.manage_source_revision, "Manage source revision"
    )
    if evidence_path.name != f"{run_id}-evidence.json":
        _fail("qualification evidence filename does not bind the run id")
    if output.name != "cybex-forge-appliance-qualification.json":
        _fail("qualification output must use the stable release asset filename")
    _validate_output(
        output,
        (
            (evidence_path, "qualification evidence"),
            (artifact_path, "binary artifact"),
            (installer_path, "installer ISO artifact"),
        ),
    )

    loaded_evidence, _evidence_body = _load_bounded_json(
        evidence_path,
        "qualification evidence",
        maximum_bytes=PUBLIC_EVIDENCE_MAX_BYTES,
    )
    evidence = _require_exact_object_keys(
        loaded_evidence,
        {"schema", "generated_at", "selector", "runs", "ok"},
        "qualification evidence",
    )
    if evidence["schema"] != PUBLIC_EVIDENCE_SCHEMA:
        _fail(f"qualification evidence schema must be {PUBLIC_EVIDENCE_SCHEMA}")
    generated_at = evidence["generated_at"]
    if (
        not isinstance(generated_at, str)
        or len(generated_at) > 64
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]{1,9})?(?:Z|\+00:00)",
            generated_at,
        )
        is None
    ):
        _fail("qualification evidence generated_at is not a bounded UTC timestamp")
    _require_true(evidence["ok"], "qualification evidence ok")
    selector = _require_exact_object_keys(
        evidence["selector"], {"run_id", "run_prefix"}, "qualification selector"
    )
    if selector["run_id"] != run_id or selector["run_prefix"] is not None:
        _fail("qualification evidence selector does not bind the exact run id")
    runs = evidence["runs"]
    if not isinstance(runs, list) or len(runs) != 1:
        _fail("qualification evidence must contain exactly one run")
    run = _require_exact_object_keys(
        runs[0],
        {"run_id", "ok", "excluded_json_files", "artifacts"},
        "qualification run",
    )
    if run["run_id"] != run_id:
        _fail("qualification run id does not match the selected run")
    _require_true(run["ok"], "qualification run ok")
    if _require_integer(
        run["excluded_json_files"], "excluded qualification artifacts"
    ) != 0:
        _fail("qualification export contains excluded JSON artifacts")
    artifacts = run["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        _fail("qualification run must contain exactly one bounded artifact")
    proof = _require_exact_object_keys(
        artifacts[0],
        {
            "artifact",
            "completed",
            "schema",
            "run_id",
            "status",
            "ok",
            "check_counts",
            "passed_checks",
            "component_source_identity",
            "release",
            "cleanup_ok",
            "private_state_cleanup_ok",
        },
        "qualification proof",
    )
    if proof["artifact"] != "forge-appliance-release-smoke.json":
        _fail("qualification proof is not the exact release-smoke artifact")
    if proof["schema"] != RELEASE_SMOKE_EVIDENCE_SCHEMA:
        _fail(
            "qualification proof schema must be "
            f"{RELEASE_SMOKE_EVIDENCE_SCHEMA}"
        )
    if proof["run_id"] != run_id or proof["status"] != "succeeded":
        _fail("qualification proof does not record the successful exact run")
    for field in (
        "completed",
        "ok",
        "cleanup_ok",
        "private_state_cleanup_ok",
    ):
        _require_true(proof[field], f"qualification proof {field}")

    check_counts = _require_exact_object_keys(
        proof["check_counts"],
        {"total", "failed", "skipped"},
        "qualification check counts",
    )
    total_checks = _require_integer(
        check_counts["total"], "qualification total checks"
    )
    if total_checks != len(REQUIRED_RELEASE_SMOKE_CHECKS):
        _fail("qualification proof does not contain exactly the required checks")
    if _require_integer(
        check_counts["failed"], "qualification failed checks"
    ) != 0:
        _fail("qualification proof contains failed checks")
    if _require_integer(
        check_counts["skipped"], "qualification skipped checks"
    ) != 0:
        _fail("qualification proof contains skipped checks")
    passed_checks = proof["passed_checks"]
    if not isinstance(passed_checks, list) or passed_checks != list(
        REQUIRED_RELEASE_SMOKE_CHECKS
    ):
        _fail("qualification proof does not name exactly the required passed checks")

    components = _require_exact_object_keys(
        proof["component_source_identity"],
        {"forge_checkout", "manage_checkout"},
        "qualification component source identity",
    )
    expected_components = {
        "forge_checkout": forge_revision,
        "manage_checkout": manage_revision,
    }
    for name, revision in expected_components.items():
        component = _require_exact_object_keys(
            components[name],
            {"revision", "dirty"},
            f"qualification {name} identity",
        )
        if component["revision"] != revision or component["dirty"] is not False:
            _fail(f"qualification {name} identity is not the exact clean source")

    release = _require_exact_object_keys(
        proof["release"],
        {
            "version",
            "architecture",
            "binary_sha256",
            "iso_sha256",
            "iso_size_bytes",
            "public_key_sha256",
            "exact_supplied_artifacts",
            "synthetic_successors_created",
        },
        "qualification release",
    )
    if release["version"] != version:
        _fail("qualification release version does not match the candidate")
    if release["architecture"] != INSTALLER_ISO_ARCHITECTURE:
        _fail(
            f"qualification architecture must be {INSTALLER_ISO_ARCHITECTURE}"
        )
    _require_true(
        release["exact_supplied_artifacts"],
        "qualification exact supplied artifacts",
    )
    if release["synthetic_successors_created"] is not False:
        _fail("qualification must not create synthetic successor releases")

    artifact_sha256, _artifact_size = _inspect_artifact(
        artifact_path, "binary artifact"
    )
    installer_sha256, installer_size = _inspect_artifact(
        installer_path,
        "installer ISO artifact",
        maximum_bytes=INSTALLER_ISO_MAX_BYTES,
    )
    expected_release_values: tuple[tuple[str, object], ...] = (
        ("binary_sha256", artifact_sha256),
        ("iso_sha256", installer_sha256),
        ("iso_size_bytes", installer_size),
    )
    for field, expected in expected_release_values:
        if release[field] != expected:
            _fail(f"qualification release {field} does not match the candidate")
    public_key = _trusted_public_key(arguments.trusted_public_key)
    public_key_sha256 = hashlib.sha256(public_key).hexdigest()
    if release["public_key_sha256"] != public_key_sha256:
        _fail("qualification public key digest does not match the release trust root")

    qualification = {
        "schema": QUALIFICATION_SCHEMA,
        "run_id": run_id,
        "source": {
            "forge_revision": forge_revision,
            "manage_revision": manage_revision,
        },
        "release": {
            "version": version,
            "architecture": INSTALLER_ISO_ARCHITECTURE,
            "binary_sha256": artifact_sha256,
            "iso_sha256": installer_sha256,
            "iso_size_bytes": installer_size,
            "public_key_sha256": public_key_sha256,
            "exact_supplied_artifacts": True,
            "synthetic_successors_created": False,
        },
        "passed_checks": list(REQUIRED_RELEASE_SMOKE_CHECKS),
        "cleanup": {
            "disposable_vm": True,
            "private_state": True,
        },
    }
    _atomic_write(
        output,
        (json.dumps(qualification, indent=2, ensure_ascii=True) + "\n").encode(
            "utf-8"
        ),
    )
    print(
        "verified Forge appliance qualification: "
        f"run_id={run_id} version={version} checks={total_checks}"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build signed Cybex Forge release manifests without exposing private key bytes."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    manifest = commands.add_parser("manifest", help="hash an artifact and atomically write a signed manifest")
    manifest.add_argument("--artifact", required=True, help="regular Forge binary artifact")
    manifest.add_argument("--artifact-url", required=True, help="exact HTTP(S) download URL")
    manifest.add_argument("--version", required=True, help="canonical Cargo SemVer without a leading v")
    manifest.add_argument("--private-key", required=True, help="mode-0600 Ed25519 PEM private key")
    manifest.add_argument("--output", required=True, help="manifest output path in an existing directory")
    manifest.add_argument("--release-url", required=True, help="HTTP(S) release page URL")
    manifest.add_argument("--notes-url", help="HTTP(S) release notes URL; defaults to --release-url")
    manifest.add_argument(
        "--installer-iso",
        help="optional regular Forge appliance installer ISO; requires --installer-iso-url",
    )
    manifest.add_argument(
        "--installer-iso-url",
        help="exact HTTP(S) download URL for --installer-iso",
    )
    manifest.add_argument(
        "--installer-iso-architecture",
        choices=[INSTALLER_ISO_ARCHITECTURE],
        help=f"installer architecture (default: {INSTALLER_ISO_ARCHITECTURE})",
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

    verify = commands.add_parser(
        "verify",
        help="independently verify a signed binary/installer release candidate",
    )
    verify.add_argument("--manifest", required=True, help="signed release manifest")
    verify.add_argument("--artifact", required=True, help="exact binary artifact")
    verify.add_argument("--installer-iso", required=True, help="exact installer ISO")
    verify.add_argument(
        "--trusted-public-key",
        required=True,
        help="canonical standard-Base64 raw Ed25519 public key",
    )
    verify.set_defaults(handler=_verify_command)

    qualification = commands.add_parser(
        "verify-qualification",
        help="verify bounded exact-candidate VM evidence and write a normalized release proof",
    )
    qualification.add_argument(
        "--evidence", required=True, help="bounded Manage public-evidence JSON"
    )
    qualification.add_argument(
        "--artifact", required=True, help="exact signed Forge binary artifact"
    )
    qualification.add_argument(
        "--installer-iso", required=True, help="exact signed installer ISO"
    )
    qualification.add_argument(
        "--trusted-public-key",
        required=True,
        help="canonical standard-Base64 raw Ed25519 public key",
    )
    qualification.add_argument(
        "--version", required=True, help="exact canonical candidate SemVer"
    )
    qualification.add_argument(
        "--forge-source-revision",
        required=True,
        help="exact lowercase 40-hex Forge commit",
    )
    qualification.add_argument(
        "--manage-source-revision",
        required=True,
        help="exact lowercase 40-hex Manage commit",
    )
    qualification.add_argument(
        "--run-id", required=True, help="exact release-smoke run identifier"
    )
    qualification.add_argument(
        "--output",
        required=True,
        help="cybex-forge-appliance-qualification.json output path",
    )
    qualification.set_defaults(handler=_verify_qualification_command)
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
