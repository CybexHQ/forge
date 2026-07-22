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
from typing import NoReturn, Sequence
from urllib.parse import urlsplit


SCHEMA = "cybex.forge.release.v1"
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
        if private and metadata.st_mode & 0o077:
            _fail("private key permissions must not grant group or other access")
        return fd
    except BaseException:
        os.close(fd)
        raise


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


def _hash_artifact(path: Path) -> str:
    fd = _open_regular(path, "artifact")
    try:
        before = os.fstat(fd)
        if before.st_size <= 0:
            _fail("artifact must not be empty")
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
        return digest.hexdigest()
    finally:
        os.close(fd)


def _validate_output(output: Path, artifact: Path, private_key: Path) -> None:
    if not output.name or output.name in {".", ".."}:
        _fail("output must name a manifest file")
    try:
        output_parent = output.parent.resolve(strict=True)
    except OSError:
        _fail("output directory does not exist")
    if not output_parent.is_dir():
        _fail("output parent must be a directory")
    resolved_output = output_parent / output.name
    for protected, label in ((artifact, "artifact"), (private_key, "private key")):
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


def _manifest_command(arguments: argparse.Namespace) -> None:
    artifact = Path(arguments.artifact)
    private_key = Path(arguments.private_key)
    output = Path(arguments.output)
    version = _validate_version(arguments.version)
    artifact_url = _validate_url(arguments.artifact_url, "artifact-url")
    release_url = _validate_url(arguments.release_url, "release-url")
    notes_url = _validate_url(arguments.notes_url or arguments.release_url, "notes-url")
    published_at = _validate_published_at(arguments.published_at)
    _validate_output(output, artifact, private_key)
    sha256 = _hash_artifact(artifact)

    private_fd = _open_regular(private_key, "private key", private=True)
    try:
        public_der = _public_der(private_fd)
        message = _canonical_message(version, sha256, artifact_url)
        signature = _sign(private_fd, message)
    finally:
        os.close(private_fd)
    _self_verify(public_der, signature, message)

    manifest = {
        "schema": SCHEMA,
        "version": version,
        "release_url": release_url,
        "notes_url": notes_url,
        "published_at": published_at,
        "artifact": {"url": artifact_url, "sha256": sha256},
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    body = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    _atomic_write(output, body)
    print(f"wrote signed Forge release manifest: {output}")


def _public_key_command(arguments: argparse.Namespace) -> None:
    private_fd = _open_regular(Path(arguments.private_key), "private key", private=True)
    try:
        public_der = _public_der(private_fd)
    finally:
        os.close(private_fd)
    raw_public_key = public_der[len(ED25519_PUBLIC_DER_PREFIX) :]
    print(base64.b64encode(raw_public_key).decode("ascii"))


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
