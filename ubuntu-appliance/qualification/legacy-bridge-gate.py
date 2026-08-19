#!/usr/bin/env python3
"""Capture and verify the legacy appliance updater's package-solver plan.

The capture command must run on a disposable, clean installation of the
predecessor release.  It invokes the legacy updater's explicit-all-DEBs APT
transaction with only ``--simulate`` added.  The verify command is suitable
for the release builder: it binds the audited capture to the exact candidate
package set and rejects plans outside the reviewed monotone allowlist.
"""

from __future__ import annotations

import argparse
from functools import cmp_to_key
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import ssl
import stat
import subprocess
import sys
import tempfile
from typing import NoReturn, Sequence
from urllib.parse import unquote, urlsplit


POLICY_SCHEMA = "cybex.james.legacy-update-bridge-policy.v1"
EVIDENCE_SCHEMA = "cybex.james.legacy-update-bridge-evidence.v1"
QUALIFICATION_SCHEMA = "cybex.james.ubuntu-appliance-qualification.v1"
INSTALLED_SCHEMA = "cybex.james.installed-appliance.v1"
PREDECESSOR_SCHEMA = "cybex.james.published-appliance-predecessor.v1"
LOCAL_PREDECESSOR_SCHEMA = (
    "cybex.james.local-published-appliance-predecessor.v1"
)
LOCAL_RELEASE_SET_SCHEMA = "cybex.james.local-immutable-release-set.v1"
LOCAL_RELEASE_INDEX_SCHEMA = "cybex.james.local-published-release-index.v1"
LOCAL_STAGE_LEDGER_SCHEMA = "cybex.james.canonical-package-stage.v1"
LEGACY_UPDATE_CONTRACT = "legacy_all_debs"
SELECTIVE_UPDATE_CONTRACT = "selective_roots_v2"
INSTALLED_RELEASE_PATH = Path("/usr/share/cybex-james/appliance-release.json")
INSTALLED_STATE_PATH = Path("/var/lib/cybex-james/control/appliance-release.json")
DPKG_STATUS_PATH = Path("/var/lib/dpkg/status")
CANDIDATE_PACKAGES_PATH = Path("/run/cybex-update-packages")
APT_GET_PATH = Path("/usr/bin/apt-get")
DPKG_PATH = Path("/usr/bin/dpkg")
DPKG_DEB_PATH = Path("/usr/bin/dpkg-deb")
FINDMNT_PATH = Path("/usr/bin/findmnt")
RELEASE_MANIFEST_FILENAME = "cybex-james-release.json"
RELEASE_COMPATIBILITY_FILENAME = "cybex-james-release-compatibility.json"
UPDATER_PATH = Path("usr/lib/cybex-james/cybex-james-appliance-update")
SNAPSHOT_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?$")
DEB_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.:_~%-]*\.deb$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.:~_-]{0,255}$")
TAG_RE = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
INST_RE = re.compile(
    r"^Inst (?P<package>[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?)"
    r"(?: \[(?P<old>[^] ]+)\])? \((?P<new>[^ )]+)(?: [^)]*)?\)$"
)
REMV_RE = re.compile(
    r"^Remv (?P<package>[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?)"
    r"(?: \[(?P<old>[^] ]+)\])?(?: \([^)]*\))?$"
)
SUMMARY_RE = re.compile(
    r"^(?P<upgraded>[0-9]+) upgraded, (?P<added>[0-9]+) newly installed, "
    r"(?P<removed>[0-9]+) to remove and (?P<held>[0-9]+) not upgraded\.$"
)
MAX_POLICY_BYTES = 128 * 1024
MAX_EVIDENCE_BYTES = 512 * 1024
MAX_QUALIFICATION_BYTES = 1024 * 1024
MAX_APT_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_PACKAGES = 512
MAX_ALLOWED_UPGRADES = 256
MAX_ALLOWED_ADDITIONS = 64
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_PACKAGE_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024
MAX_UPDATER_BYTES = 2 * 1024 * 1024
MAX_VERIFIER_OUTPUT_BYTES = 1024 * 1024
MAX_LOCAL_RELEASE_ROOT_ENTRIES = 512
MAX_LOCAL_RELEASE_DIRECTORY_ENTRIES = 512
MAX_LOCAL_PUBLISHED_RELEASES = 128
MAX_CHECKSUM_INDEX_BYTES = 64 * 1024
MAX_JAMES_BINARY_BYTES = 512 * 1024 * 1024
MAX_INSTALLER_TEMPLATE_BYTES = 16 * 1024 * 1024 * 1024
MAX_WORKSTATION_NETBOOT_BYTES = 8 * 1024 * 1024 * 1024
URL_MAX_BYTES = 2048
OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

LEGACY_UPDATER_COMMAND = (
    b'chroot "$candidate_path" /bin/sh -c '
    b"'apt-get --no-download --yes install /run/cybex-update-packages/*.deb'"
)
SELECTIVE_UPDATER_MARKERS = (
    b"cybex.james.verified-appliance-update.v1",
    b"package_targets=(",
    b"--no-remove",
    b"--no-allow-downgrades",
    b"--no-allow-change-held-packages",
)


class GateError(Exception):
    """A bounded release-gate failure."""


def fail(message: str) -> NoReturn:
    raise GateError(message)


def stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def open_regular(path: Path, label: str, maximum: int | None = None) -> bytes:
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
        if maximum is not None and metadata.st_size > maximum:
            fail(f"{label} exceeds its size limit")
        body = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            body.extend(chunk)
            if maximum is not None and len(body) > maximum:
                fail(f"{label} exceeds its size limit")
        if stable_file_identity(os.fstat(descriptor)) != stable_file_identity(
            metadata
        ):
            fail(f"{label} changed while it was read")
        return bytes(body)
    finally:
        os.close(descriptor)


def hash_regular(path: Path, label: str, maximum: int) -> tuple[str, int, bytes]:
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
        digest = hashlib.sha256()
        prefix = bytearray()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            if len(prefix) < 8:
                prefix.extend(chunk[: 8 - len(prefix)])
            total += len(chunk)
            if total > maximum:
                fail(f"{label} exceeds its size limit")
            digest.update(chunk)
        if total != metadata.st_size or stable_file_identity(
            os.fstat(descriptor)
        ) != stable_file_identity(metadata):
            fail(f"{label} changed while it was hashed")
        return digest.hexdigest(), total, bytes(prefix)
    finally:
        os.close(descriptor)


def load_json(path: Path, label: str, maximum: int) -> tuple[dict[str, object], bytes]:
    body = open_regular(path, label, maximum)
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is not valid JSON")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value, body


def write_exclusive(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o644,
    )
    try:
        written = 0
        while written < len(body):
            written += os.write(descriptor, body[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run_bounded(
    command: Sequence[str],
    label: str,
    *,
    maximum: int = MAX_VERIFIER_OUTPUT_BYTES,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        list(command),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=environment,
        check=False,
    )
    if len(result.stdout) > maximum:
        fail(f"{label} output exceeds its size limit")
    if result.returncode != 0:
        fail(f"{label} failed with exit code {result.returncode}")
    return result


def read_package_entries(directory: Path) -> list[Path]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(directory, flags)
    except OSError:
        fail("candidate package directory is unavailable")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            fail("candidate package directory must be a real directory")
        names = os.listdir(descriptor)
    finally:
        os.close(descriptor)
    return [directory / name for name in sorted(names, key=lambda item: item.encode("utf-8"))]


def exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        fail(f"{label} fields are invalid (missing={missing}, extra={extra})")


def text_field(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        fail(f"{label} is invalid")
    return value


def sha256_field(value: object, label: str) -> str:
    return text_field(value, label, SHA256_RE)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def semver_parts(value: object, label: str) -> tuple[tuple[int, int, int], list[str]]:
    if not isinstance(value, str):
        fail(f"{label} is invalid")
    match = SEMVER_RE.fullmatch(value)
    if match is None:
        fail(f"{label} must be canonical SemVer")
    core, separator, suffix = value.partition("-")
    prerelease = suffix.split("+", 1)[0].split(".") if separator else []
    return tuple(int(part) for part in core.split("+", 1)[0].split(".")), prerelease


def semver_compare(
    left: tuple[tuple[int, int, int], list[str]],
    right: tuple[tuple[int, int, int], list[str]],
) -> int:
    if left[0] != right[0]:
        return (left[0] > right[0]) - (left[0] < right[0])
    left_pre, right_pre = left[1], right[1]
    if not left_pre or not right_pre:
        return (not left_pre) - (not right_pre)
    for left_part, right_part in zip(left_pre, right_pre):
        if left_part == right_part:
            continue
        if left_part.isdigit() and right_part.isdigit():
            return (int(left_part) > int(right_part)) - (
                int(left_part) < int(right_part)
            )
        if left_part.isdigit() != right_part.isdigit():
            return -1 if left_part.isdigit() else 1
        return (left_part > right_part) - (left_part < right_part)
    return (len(left_pre) > len(right_pre)) - (len(left_pre) < len(right_pre))


def sha256_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def validate_predecessor_identity(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        fail("published predecessor identity must be an object")
    exact_keys(
        value,
        {
            "schema",
            "github_release_id",
            "tag_name",
            "release_id",
            "ubuntu_snapshot_id",
            "update_contract",
            "release_compatibility_sha256",
            "release_manifest_sha256",
            "package_snapshot_sha256",
            "package_snapshot_size_bytes",
            "appliance_updater_sha256",
            "packaged_release_sha256",
        },
        "published predecessor identity",
    )
    if value["schema"] != PREDECESSOR_SCHEMA:
        fail(f"published predecessor identity schema must be {PREDECESSOR_SCHEMA}")
    release_id = value["release_id"]
    semver_parts(release_id, "published predecessor release")
    assert isinstance(release_id, str)
    tag_name = text_field(value["tag_name"], "published predecessor tag", TAG_RE)
    if tag_name != f"v{release_id}":
        fail("published predecessor tag does not match its release")
    github_release_id = value["github_release_id"]
    if (
        not isinstance(github_release_id, int)
        or isinstance(github_release_id, bool)
        or github_release_id <= 0
    ):
        fail("published predecessor GitHub release id is invalid")
    snapshot_id = text_field(
        value["ubuntu_snapshot_id"],
        "published predecessor Ubuntu snapshot",
        SNAPSHOT_RE,
    )
    update_contract = value["update_contract"]
    if update_contract not in (LEGACY_UPDATE_CONTRACT, SELECTIVE_UPDATE_CONTRACT):
        fail("published predecessor update contract is unknown")
    for field in (
        "release_compatibility_sha256",
        "release_manifest_sha256",
        "package_snapshot_sha256",
        "appliance_updater_sha256",
        "packaged_release_sha256",
    ):
        sha256_field(value[field], f"published predecessor {field}")
    snapshot_size = value["package_snapshot_size_bytes"]
    if (
        not isinstance(snapshot_size, int)
        or isinstance(snapshot_size, bool)
        or snapshot_size <= 0
        or snapshot_size > MAX_PACKAGE_SNAPSHOT_BYTES
    ):
        fail("published predecessor package snapshot size is invalid")
    return {
        "github_release_id": github_release_id,
        "tag_name": tag_name,
        "release_id": release_id,
        "ubuntu_snapshot_id": snapshot_id,
        "update_contract": update_contract,
        "release_compatibility_sha256": value["release_compatibility_sha256"],
        "release_manifest_sha256": value["release_manifest_sha256"],
        "package_snapshot_sha256": value["package_snapshot_sha256"],
        "package_snapshot_size_bytes": snapshot_size,
        "appliance_updater_sha256": value["appliance_updater_sha256"],
        "packaged_release_sha256": value["packaged_release_sha256"],
    }


def canonical_https_prefix(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > URL_MAX_BYTES
        or value != value.strip()
    ):
        fail("local published release prefix is invalid")
    try:
        value.encode("ascii")
        parsed = urlsplit(value)
        port = parsed.port
    except (UnicodeEncodeError, ValueError):
        fail("local published release prefix is invalid")
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
            fail("local published release prefix host is invalid")
    else:
        canonical_host = address.compressed
        if address.version == 6:
            canonical_host = f"[{canonical_host}]"
    canonical_netloc = canonical_host + ("" if port in (None, 443) else f":{port}")
    if (
        parsed.scheme != "https"
        or not hostname
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
    ):
        fail("local published release prefix must be canonical HTTPS")
    return value


def validate_local_predecessor_identity(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        fail("local published predecessor identity must be an object")
    exact_keys(
        value,
        {
            "schema",
            "served_prefix",
            "release_id",
            "ubuntu_snapshot_id",
            "update_contract",
            "published_release_count",
            "release_index_sha256",
            "release_set_sha256",
            "release_compatibility_sha256",
            "release_manifest_sha256",
            "package_snapshot_sha256",
            "package_snapshot_size_bytes",
            "appliance_updater_sha256",
            "packaged_release_sha256",
        },
        "local published predecessor identity",
    )
    if value["schema"] != LOCAL_PREDECESSOR_SCHEMA:
        fail(
            "local published predecessor identity schema must be "
            f"{LOCAL_PREDECESSOR_SCHEMA}"
        )
    served_prefix = canonical_https_prefix(value["served_prefix"])
    release_id = value["release_id"]
    semver_parts(release_id, "local published predecessor release")
    assert isinstance(release_id, str)
    snapshot_id = text_field(
        value["ubuntu_snapshot_id"],
        "local published predecessor Ubuntu snapshot",
        SNAPSHOT_RE,
    )
    update_contract = value["update_contract"]
    if update_contract not in (LEGACY_UPDATE_CONTRACT, SELECTIVE_UPDATE_CONTRACT):
        fail("local published predecessor update contract is unknown")
    release_count = value["published_release_count"]
    if (
        not isinstance(release_count, int)
        or isinstance(release_count, bool)
        or release_count <= 0
        or release_count > MAX_LOCAL_PUBLISHED_RELEASES
    ):
        fail("local published release count is invalid")
    for field in (
        "release_index_sha256",
        "release_set_sha256",
        "release_compatibility_sha256",
        "release_manifest_sha256",
        "package_snapshot_sha256",
        "appliance_updater_sha256",
        "packaged_release_sha256",
    ):
        sha256_field(value[field], f"local published predecessor {field}")
    snapshot_size = value["package_snapshot_size_bytes"]
    if (
        not isinstance(snapshot_size, int)
        or isinstance(snapshot_size, bool)
        or snapshot_size <= 0
        or snapshot_size > MAX_PACKAGE_SNAPSHOT_BYTES
    ):
        fail("local published predecessor package snapshot size is invalid")
    return {
        "schema": LOCAL_PREDECESSOR_SCHEMA,
        "served_prefix": served_prefix,
        "release_id": release_id,
        "ubuntu_snapshot_id": snapshot_id,
        "update_contract": update_contract,
        "published_release_count": release_count,
        "release_index_sha256": value["release_index_sha256"],
        "release_set_sha256": value["release_set_sha256"],
        "release_compatibility_sha256": value[
            "release_compatibility_sha256"
        ],
        "release_manifest_sha256": value["release_manifest_sha256"],
        "package_snapshot_sha256": value["package_snapshot_sha256"],
        "package_snapshot_size_bytes": snapshot_size,
        "appliance_updater_sha256": value["appliance_updater_sha256"],
        "packaged_release_sha256": value["packaged_release_sha256"],
    }


def load_predecessor_identity(path: Path) -> tuple[dict[str, object], bytes]:
    value, body = load_json(path, "published predecessor identity", MAX_POLICY_BYTES)
    if value.get("schema") == LOCAL_PREDECESSOR_SCHEMA:
        identity = validate_local_predecessor_identity(value)
    else:
        identity = validate_predecessor_identity(value)
    if body != canonical_json(value):
        fail("published predecessor identity must be canonical compact sorted JSON")
    return identity, body


def load_local_predecessor_identity(path: Path) -> tuple[dict[str, object], bytes]:
    value, body = load_json(
        path, "local published predecessor identity", MAX_POLICY_BYTES
    )
    identity = validate_local_predecessor_identity(value)
    if body != canonical_json(value):
        fail(
            "local published predecessor identity must be canonical compact "
            "sorted JSON"
        )
    return identity, body


def load_github_predecessor_identity(path: Path) -> tuple[dict[str, object], bytes]:
    value, body = load_json(
        path, "GitHub published predecessor identity", MAX_POLICY_BYTES
    )
    identity = validate_predecessor_identity(value)
    if body != canonical_json(value):
        fail(
            "GitHub published predecessor identity must be canonical compact "
            "sorted JSON"
        )
    return identity, body


def validate_action(value: object, label: str, upgrade: bool) -> dict[str, str]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    fields = {"package", "from", "to"} if upgrade else {"package", "version"}
    exact_keys(value, fields, label)
    package = text_field(value["package"], f"{label} package", PACKAGE_RE)
    if upgrade:
        old = text_field(value["from"], f"{label} source version", VERSION_RE)
        new = text_field(value["to"], f"{label} target version", VERSION_RE)
        return {"package": package, "from": old, "to": new}
    version = text_field(value["version"], f"{label} version", VERSION_RE)
    return {"package": package, "version": version}


def validate_actions(
    value: object, label: str, *, upgrade: bool, maximum: int
) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > maximum:
        fail(f"{label} must be an array with at most {maximum} entries")
    actions = [
        validate_action(entry, f"{label}[{index}]", upgrade)
        for index, entry in enumerate(value)
    ]
    keys = [entry["package"] for entry in actions]
    if len(keys) != len(set(keys)):
        fail(f"{label} contains a duplicate package")
    if actions != sorted(actions, key=lambda item: item["package"].encode("ascii")):
        fail(f"{label} must be sorted by package")
    return actions


def validate_policy(
    value: dict[str, object],
    *,
    candidate_release: str | None = None,
    candidate_snapshot: str | None = None,
    predecessor_identity: dict[str, object] | None = None,
    predecessor_identity_sha256: str | None = None,
) -> dict[str, object]:
    exact_keys(
        value,
        {
            "schema",
            "predecessor_update_contract",
            "predecessor",
            "candidate",
            "allowed_upgrades",
            "allowed_additions",
        },
        "bridge policy",
    )
    if value["schema"] != POLICY_SCHEMA:
        fail(f"bridge policy schema must be {POLICY_SCHEMA}")
    if value["predecessor_update_contract"] != LEGACY_UPDATE_CONTRACT:
        fail("bridge policy must name the legacy_all_debs predecessor contract")
    predecessor = value["predecessor"]
    candidate = value["candidate"]
    if not isinstance(predecessor, dict) or not isinstance(candidate, dict):
        fail("bridge policy predecessor and candidate must be objects")
    exact_keys(
        predecessor,
        {
            "release_id",
            "ubuntu_snapshot_id",
            "installed_release_sha256",
            "installed_state_sha256",
            "dpkg_status_sha256",
            "qualification_evidence_sha256",
            "published_identity_sha256",
        },
        "bridge policy predecessor",
    )
    exact_keys(
        candidate,
        {"release_id", "ubuntu_snapshot_id"},
        "bridge policy candidate",
    )
    predecessor_release = predecessor["release_id"]
    predecessor_semver = semver_parts(predecessor_release, "predecessor release")
    assert isinstance(predecessor_release, str)
    predecessor_snapshot = text_field(
        predecessor["ubuntu_snapshot_id"], "predecessor Ubuntu snapshot", SNAPSHOT_RE
    )
    for field in (
        "installed_release_sha256",
        "installed_state_sha256",
        "dpkg_status_sha256",
        "qualification_evidence_sha256",
        "published_identity_sha256",
    ):
        sha256_field(predecessor[field], f"predecessor {field}")
    policy_candidate_release = candidate["release_id"]
    candidate_semver = semver_parts(policy_candidate_release, "candidate release")
    assert isinstance(policy_candidate_release, str)
    policy_candidate_snapshot = text_field(
        candidate["ubuntu_snapshot_id"], "candidate Ubuntu snapshot", SNAPSHOT_RE
    )
    if policy_candidate_snapshot <= predecessor_snapshot:
        fail("candidate Ubuntu snapshot must be newer than the predecessor snapshot")
    if semver_compare(candidate_semver, predecessor_semver) <= 0:
        fail("candidate release must be newer than the predecessor release")
    if candidate_release is not None and policy_candidate_release != candidate_release:
        fail("candidate release does not match the bridge policy")
    if candidate_snapshot is not None and policy_candidate_snapshot != candidate_snapshot:
        fail("candidate Ubuntu snapshot does not match the bridge policy")
    if predecessor_identity is not None:
        if predecessor_identity_sha256 is None:
            fail("published predecessor identity SHA-256 is unavailable")
        if predecessor["published_identity_sha256"] != predecessor_identity_sha256:
            fail("bridge policy does not bind the exact published predecessor identity")
        if predecessor_release != predecessor_identity["release_id"]:
            fail("bridge policy predecessor release is not the latest signed release")
        if predecessor_snapshot != predecessor_identity["ubuntu_snapshot_id"]:
            fail("bridge policy predecessor snapshot is not the latest signed release")
        if value["predecessor_update_contract"] != predecessor_identity["update_contract"]:
            fail("bridge policy predecessor update contract was misselected")
        if predecessor["installed_release_sha256"] != predecessor_identity[
            "packaged_release_sha256"
        ]:
            fail("bridge policy installed release is not the signed predecessor package")
    upgrades = validate_actions(
        value["allowed_upgrades"],
        "allowed upgrades",
        upgrade=True,
        maximum=MAX_ALLOWED_UPGRADES,
    )
    additions = validate_actions(
        value["allowed_additions"],
        "allowed additions",
        upgrade=False,
        maximum=MAX_ALLOWED_ADDITIONS,
    )
    overlap = {item["package"] for item in upgrades} & {
        item["package"] for item in additions
    }
    if overlap:
        fail("a package cannot be both an allowed upgrade and addition")
    return {
        "predecessor_release": predecessor_release,
        "predecessor_snapshot": predecessor_snapshot,
        "candidate_release": policy_candidate_release,
        "candidate_snapshot": policy_candidate_snapshot,
        "upgrades": upgrades,
        "additions": additions,
    }


def candidate_packages(directory: Path) -> tuple[list[Path], str]:
    packages: list[Path] = []
    for entry in read_package_entries(directory):
        if not DEB_RE.fullmatch(entry.name):
            continue
        entry_metadata = entry.lstat()
        if not stat.S_ISREG(entry_metadata.st_mode):
            fail("candidate package entries must be regular files")
        packages.append(entry)
    if not packages or len(packages) > MAX_PACKAGES:
        fail(f"candidate package set must contain between 1 and {MAX_PACKAGES} DEBs")
    digest = hashlib.sha256()
    seen: set[str] = set()
    for package in packages:
        if package.name in seen:
            fail("candidate package filenames must be unique")
        seen.add(package.name)
        package_sha256, package_size, prefix = hash_regular(
            package, "candidate package", 2 * 1024 * 1024 * 1024
        )
        if prefix != b"!<arch>\n":
            fail(f"candidate package {package.name} is not a Debian archive")
        digest.update(
            f"{package_sha256} {package_size} {package.name}\n".encode("ascii")
        )
    return packages, digest.hexdigest()


def validate_repository_checksums(packages_dir: Path) -> None:
    entries = read_package_entries(packages_dir)
    package_names = {
        entry.name
        for entry in entries
        if entry.is_file() and not entry.is_symlink() and DEB_RE.fullmatch(entry.name)
    }
    governed_names = package_names | {"Packages", "Packages.gz", "Release"}
    actual_names = {entry.name for entry in entries}
    if actual_names != governed_names | {"SHA256SUMS", "UBUNTU-SNAPSHOT-ID"}:
        fail("candidate repository contains an ungoverned file or directory")
    checksums_body = open_regular(
        packages_dir / "SHA256SUMS", "candidate repository checksums", 1024 * 1024
    )
    try:
        checksum_lines = checksums_body.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail("candidate repository checksums are not ASCII")
    observed: dict[str, str] = {}
    for line in checksum_lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?([^/]+)", line)
        if match is None:
            fail("candidate repository checksums contain an invalid entry")
        checksum, name = match.groups()
        if name in observed:
            fail("candidate repository checksums contain a duplicate entry")
        observed[name] = checksum
    if set(observed) != governed_names:
        fail("candidate repository checksums do not bind the exact repository file set")
    for name, expected in observed.items():
        actual, _size, _prefix = hash_regular(
            packages_dir / name,
            f"candidate repository file {name}",
            2 * 1024 * 1024 * 1024,
        )
        if actual != expected:
            fail(f"candidate repository file {name} failed its internal SHA-256")


def validate_snapshot_binding(
    bundle: Path,
    metadata_path: Path,
    packages_dir: Path,
    candidate_release: str,
    candidate_snapshot: str,
) -> None:
    bundle_sha256, bundle_size, _prefix = hash_regular(
        bundle, "candidate package snapshot", 4 * 1024 * 1024 * 1024
    )
    metadata, _metadata_body = load_json(
        metadata_path, "candidate package snapshot metadata", MAX_POLICY_BYTES
    )
    required_fields = {
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
    }
    exact_keys(metadata, required_fields, "candidate package snapshot metadata")
    if metadata["schema"] != "cybex.james.appliance-package-snapshot.v1":
        fail("candidate package snapshot metadata schema is invalid")
    if metadata["release_id"] != candidate_release:
        fail("candidate package snapshot metadata release does not match")
    if metadata["ubuntu_snapshot_id"] != candidate_snapshot:
        fail("candidate package snapshot metadata Ubuntu snapshot does not match")
    if metadata["filename"] != bundle.name:
        fail("candidate package snapshot metadata filename does not match")
    if metadata["sha256"] != bundle_sha256 or metadata["size_bytes"] != bundle_size:
        fail("candidate package snapshot bytes do not match their build metadata")

    marker = open_regular(
        packages_dir / "UBUNTU-SNAPSHOT-ID", "candidate snapshot marker", 128
    )
    if marker != f"{candidate_snapshot}\n".encode("ascii"):
        fail("candidate package repository snapshot marker does not match")
    validate_repository_checksums(packages_dir)


def local_asset_url(served_prefix: str, release_id: str, filename: str) -> str:
    return f"{served_prefix}/{release_id}/{filename}"


def local_artifact_maximum(filename: str) -> int:
    if filename == "cybex-james-x86_64-linux":
        return MAX_JAMES_BINARY_BYTES
    if filename.startswith("cybex-james-appliance-template-"):
        return MAX_INSTALLER_TEMPLATE_BYTES
    if filename.startswith("cybex-james-appliance-packages-"):
        return MAX_PACKAGE_SNAPSHOT_BYTES
    if filename.startswith("cybex-workstation-netboot-"):
        return MAX_WORKSTATION_NETBOOT_BYTES
    if filename == RELEASE_MANIFEST_FILENAME:
        return MAX_MANIFEST_BYTES
    if filename == RELEASE_COMPATIBILITY_FILENAME:
        return MAX_QUALIFICATION_BYTES
    if filename == "SHA256SUMS":
        return MAX_CHECKSUM_INDEX_BYTES
    fail("local published release contains an unsupported artifact")


def local_release_filenames(
    release_id: str, entries: set[str]
) -> tuple[list[str], str] | None:
    package_filename = (
        f"cybex-james-appliance-packages-{release_id}-x86_64-linux.tar.zst"
    )
    if entries == {package_filename}:
        return None
    template_filename = (
        f"cybex-james-appliance-template-{release_id}-x86_64-linux.iso"
    )
    fixed = {
        "cybex-james-x86_64-linux",
        template_filename,
        package_filename,
        RELEASE_MANIFEST_FILENAME,
        RELEASE_COMPATIBILITY_FILENAME,
        "SHA256SUMS",
    }
    netboot = sorted(entries - fixed)
    if len(entries) != 7 or len(netboot) != 1:
        fail("immutable local published release must contain exactly seven files")
    netboot_filename = netboot[0]
    if re.fullmatch(
        r"cybex-workstation-netboot-[0-9A-Za-z.+-]{1,128}-"
        r"[0-9a-f]{12}-x86_64-linux\.tar\.zst",
        netboot_filename,
    ) is None:
        fail("local published release workstation bundle filename is invalid")
    expected_order = [
        "cybex-james-x86_64-linux",
        template_filename,
        package_filename,
        netboot_filename,
        RELEASE_MANIFEST_FILENAME,
        RELEASE_COMPATIBILITY_FILENAME,
    ]
    if entries != set(expected_order) | {"SHA256SUMS"}:
        fail("immutable local published release file set is invalid")
    return expected_order, netboot_filename


def parse_local_checksum_index(
    body: bytes, expected_order: list[str]
) -> dict[str, str]:
    if not body or not body.endswith(b"\n") or b"\r" in body:
        fail("local published release checksum index is not canonical")
    try:
        lines = body.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail("local published release checksum index is not ASCII")
    if len(lines) != len(expected_order):
        fail("local published release checksum index has the wrong file count")
    checksums: dict[str, str] = {}
    for line, expected_name in zip(lines, expected_order):
        match = re.fullmatch(r"([0-9a-f]{64}) \*([^/]+)", line)
        if match is None or match.group(2) != expected_name:
            fail("local published release checksum index order is invalid")
        checksum, filename = match.groups()
        if filename in checksums:
            fail("local published release checksum index has a duplicate")
        checksums[filename] = checksum
    return checksums


def local_entry_kind(metadata: os.stat_result) -> str:
    if stat.S_ISDIR(metadata.st_mode):
        return "directory"
    if stat.S_ISREG(metadata.st_mode):
        return "regular"
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    return "other"


def local_entry_metadata(name: str, metadata: os.stat_result) -> dict[str, object]:
    return {
        "name": name,
        "kind": local_entry_kind(metadata),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "links": metadata.st_nlink,
        "size_bytes": metadata.st_size,
        "modified_ns": metadata.st_mtime_ns,
        "changed_ns": metadata.st_ctime_ns,
    }


def observe_local_semver_entry(
    path: Path, release_id: str
) -> tuple[dict[str, object], os.stat_result, set[str] | None]:
    try:
        metadata = path.lstat()
    except OSError:
        fail("local SemVer entry changed during discovery")
    observation = local_entry_metadata(release_id, metadata)
    if not stat.S_ISDIR(metadata.st_mode):
        return observation, metadata, None
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail("could not securely inspect local SemVer directory")
    try:
        names = os.listdir(descriptor)
        if len(names) > MAX_LOCAL_RELEASE_DIRECTORY_ENTRIES:
            fail("local SemVer directory has too many entries")
        if len(names) != len(set(names)):
            fail("local SemVer directory contains duplicate entries")
        children: list[dict[str, object]] = []
        for name in sorted(names, key=lambda item: item.encode("utf-8")):
            if (
                not name
                or len(name.encode("utf-8")) > 255
                or name in (".", "..")
                or "/" in name
            ):
                fail("local SemVer directory entry name is invalid")
            try:
                child_metadata = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False
                )
            except OSError:
                fail("local SemVer directory changed during discovery")
            children.append(local_entry_metadata(name, child_metadata))
        if (
            set(os.listdir(descriptor)) != set(names)
            or stable_file_identity(os.fstat(descriptor))
            != stable_file_identity(metadata)
        ):
            fail("local SemVer directory changed during discovery")
        observation["entries"] = children
        return observation, metadata, set(names)
    except UnicodeEncodeError:
        fail("local SemVer directory entry name is not UTF-8")
    finally:
        os.close(descriptor)


def looks_like_local_release_set(release_id: str, entries: set[str]) -> bool:
    package_filename = (
        f"cybex-james-appliance-packages-{release_id}-x86_64-linux.tar.zst"
    )
    template_filename = (
        f"cybex-james-appliance-template-{release_id}-x86_64-linux.iso"
    )
    fixed = {
        "cybex-james-x86_64-linux",
        template_filename,
        package_filename,
        RELEASE_MANIFEST_FILENAME,
        RELEASE_COMPATIBILITY_FILENAME,
        "SHA256SUMS",
    }
    netboot = entries - fixed
    return (
        len(entries) == 7
        and len(netboot) == 1
        and re.fullmatch(
            r"cybex-workstation-netboot-[0-9A-Za-z.+-]{1,128}-"
            r"[0-9a-f]{12}-x86_64-linux\.tar\.zst",
            next(iter(netboot)),
        )
        is not None
    )


def load_local_stage_journal(
    *,
    artifact_root: Path,
    state_directory: Path | None,
    served_prefix: str,
    release_id: str,
    release_directory: Path,
) -> tuple[str, str]:
    if state_directory is None:
        fail(
            "higher package-only SemVer entry requires its private staging journal"
        )
    if not state_directory.is_absolute():
        fail("local staging state directory must be absolute")
    try:
        canonical_state = state_directory.resolve(strict=True)
    except OSError:
        fail("local staging state directory is unavailable")
    if (
        canonical_state != state_directory
        or state_directory == artifact_root
        or state_directory in artifact_root.parents
        or artifact_root in state_directory.parents
    ):
        fail("local staging state directory must be canonical and outside the artifact root")
    state_metadata = state_directory.lstat()
    if (
        not stat.S_ISDIR(state_metadata.st_mode)
        or state_metadata.st_uid != os.geteuid()
        or state_metadata.st_mode & 0o077
    ):
        fail("local staging state directory metadata is unsafe")
    package_filename = (
        f"cybex-james-appliance-packages-{release_id}-x86_64-linux.tar.zst"
    )
    package_path = release_directory / package_filename
    try:
        package_metadata = package_path.lstat()
    except OSError:
        fail("higher staged local package snapshot is unavailable")
    if (
        not stat.S_ISREG(package_metadata.st_mode)
        or package_metadata.st_uid != os.geteuid()
        or package_metadata.st_nlink != 1
        or stat.S_IMODE(package_metadata.st_mode) != 0o444
        or package_metadata.st_size <= 0
        or package_metadata.st_size > MAX_PACKAGE_SNAPSHOT_BYTES
    ):
        fail("higher staged local package snapshot metadata is unsafe")
    package_sha256, package_size, _prefix = hash_regular(
        package_path,
        "higher staged local package snapshot",
        MAX_PACKAGE_SNAPSHOT_BYTES,
    )
    url = local_asset_url(served_prefix, release_id, package_filename)
    journal_name = f"{sha256_bytes(url.encode('ascii'))}.json"
    journal_path = state_directory / journal_name
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(journal_path, flags)
    except OSError:
        fail("higher package-only SemVer entry has no readable staging journal")
    try:
        journal_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(journal_metadata.st_mode)
            or journal_metadata.st_uid != os.geteuid()
            or journal_metadata.st_nlink != 1
            or stat.S_IMODE(journal_metadata.st_mode) != 0o600
            or journal_metadata.st_size <= 0
            or journal_metadata.st_size > 16 * 1024
        ):
            fail("local package staging journal metadata is unsafe")
        body = bytearray()
        while True:
            chunk = os.read(descriptor, 16 * 1024 + 1 - len(body))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > 16 * 1024:
                fail("local package staging journal exceeds its size limit")
        if stable_file_identity(os.fstat(descriptor)) != stable_file_identity(
            journal_metadata
        ):
            fail("local package staging journal changed while it was read")
    finally:
        os.close(descriptor)
    try:
        journal = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("local package staging journal is invalid JSON")
    if not isinstance(journal, dict):
        fail("local package staging journal must be an object")
    exact_keys(
        journal,
        {
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
        },
        "local package staging journal",
    )
    original_mode = journal["directory_original_mode"]
    if (
        journal["schema"] != LOCAL_STAGE_LEDGER_SCHEMA
        or not isinstance(journal["owner"], str)
        or OWNER_RE.fullmatch(journal["owner"]) is None
        or sha256_field(
            journal["manifest_sha256"],
            "local package staging journal manifest SHA-256",
        )
        != journal["manifest_sha256"]
        or journal["release_id"] != release_id
        or journal["url"] != url
        or journal["filename"] != package_filename
        or journal["sha256"] != package_sha256
        or not isinstance(journal["size_bytes"], int)
        or isinstance(journal["size_bytes"], bool)
        or journal["size_bytes"] != package_size
        or not isinstance(journal["directory_created"], bool)
        or not isinstance(original_mode, int)
        or isinstance(original_mode, bool)
        or original_mode < 0
        or original_mode > 0o777
        or original_mode & 0o022
    ):
        fail("local package staging journal does not bind the exact package stage")
    journal_body = bytes(body)
    if journal_body != canonical_json(journal):
        fail("local package staging journal is not canonical JSON")
    if stable_file_identity(state_directory.lstat()) != stable_file_identity(
        state_metadata
    ):
        fail("local staging state directory changed during inspection")
    return sha256_bytes(journal_body), package_sha256


def inspect_local_release_set(
    directory: Path,
    release_id: str,
    *,
    verify_all_bytes: bool,
) -> dict[str, object] | None:
    directory_metadata = directory.lstat()
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or stat.S_IMODE(directory_metadata.st_mode) != 0o555
        or directory_metadata.st_uid != os.geteuid()
    ):
        return None
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(directory, directory_flags)
    except OSError:
        fail("could not securely open immutable local release directory")
    try:
        entries_list = os.listdir(directory_fd)
        if (
            len(entries_list) != len(set(entries_list))
            or any(
                not isinstance(name, str)
                or not name
                or len(name.encode("utf-8")) > 255
                or name in (".", "..")
                or "/" in name
                for name in entries_list
            )
        ):
            fail("immutable local release directory entries are invalid")
        entries = set(entries_list)
        filenames = local_release_filenames(release_id, entries)
        if filenames is None:
            return None
        checksum_order, netboot_filename = filenames
        expected_modes = {
            name: 0o555 if name == "cybex-james-x86_64-linux" else 0o444
            for name in entries
        }
        sizes: dict[str, int] = {}
        for name in entries:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            maximum = local_artifact_maximum(name)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != expected_modes[name]
                or metadata.st_size <= 0
                or metadata.st_size > maximum
            ):
                fail("immutable local published release file metadata is unsafe")
            sizes[name] = metadata.st_size
        checksum_path = directory / "SHA256SUMS"
        checksum_body = open_regular(
            checksum_path,
            "local published release checksum index",
            MAX_CHECKSUM_INDEX_BYTES,
        )
        checksums = parse_local_checksum_index(checksum_body, checksum_order)
        artifact_records: list[dict[str, object]] = []
        for name in checksum_order:
            if verify_all_bytes or name in (
                RELEASE_MANIFEST_FILENAME,
                RELEASE_COMPATIBILITY_FILENAME,
            ):
                actual_sha256, actual_size, _prefix = hash_regular(
                    directory / name,
                    f"local published release artifact {name}",
                    local_artifact_maximum(name),
                )
                if actual_sha256 != checksums[name] or actual_size != sizes[name]:
                    fail("local published release artifact failed its exact checksum")
            artifact_records.append(
                {
                    "filename": name,
                    "sha256": checksums[name],
                    "size_bytes": sizes[name],
                }
            )
        checksum_sha256, checksum_size, _prefix = hash_regular(
            checksum_path,
            "local published release checksum index",
            MAX_CHECKSUM_INDEX_BYTES,
        )
        if checksum_size != sizes["SHA256SUMS"]:
            fail("local published release checksum index size changed")
        artifact_records.append(
            {
                "filename": "SHA256SUMS",
                "sha256": checksum_sha256,
                "size_bytes": checksum_size,
            }
        )
        artifact_records.sort(key=lambda item: str(item["filename"]).encode("ascii"))
        release_set = {
            "schema": LOCAL_RELEASE_SET_SCHEMA,
            "release_id": release_id,
            "artifacts": artifact_records,
        }
        if set(os.listdir(directory_fd)) != entries or stable_file_identity(
            os.fstat(directory_fd)
        ) != stable_file_identity(directory_metadata):
            fail("immutable local published release changed during inspection")
        return {
            "release_id": release_id,
            "release_set_sha256": sha256_bytes(canonical_json(release_set)),
            "artifacts": artifact_records,
            "directory": directory,
            "netboot_filename": netboot_filename,
        }
    finally:
        os.close(directory_fd)


def compare_local_release_sets(
    left: dict[str, object], right: dict[str, object]
) -> int:
    return semver_compare(
        semver_parts(left["release_id"], "local release index entry"),
        semver_parts(right["release_id"], "local release index entry"),
    )


def local_published_release_index(
    artifact_root: Path,
    served_prefix: str,
    staging_state_directory: Path | None,
) -> tuple[list[dict[str, object]], str]:
    if not artifact_root.is_absolute():
        fail("local published release root must be absolute")
    try:
        canonical_root = artifact_root.resolve(strict=True)
    except OSError:
        fail("local published release root is unavailable")
    if canonical_root != artifact_root:
        fail("local published release root must not use symlinks")
    root_metadata = artifact_root.lstat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or root_metadata.st_mode & 0o022
    ):
        fail("local published release root metadata is unsafe")
    entries = os.listdir(artifact_root)
    if len(entries) > MAX_LOCAL_RELEASE_ROOT_ENTRIES:
        fail("local published release root has too many entries")
    try:
        ordered_entries = sorted(entries, key=lambda item: item.encode("utf-8"))
    except UnicodeEncodeError:
        fail("local published release root entry name is not UTF-8")
    releases: list[dict[str, object]] = []
    semver_entries: list[dict[str, object]] = []
    for name in ordered_entries:
        if SEMVER_RE.fullmatch(name) is None:
            continue
        path = artifact_root / name
        observation, metadata, child_names = observe_local_semver_entry(path, name)
        observed = {
            "release_id": name,
            "classification": "excluded_legacy_entry",
            "observation_sha256": sha256_bytes(canonical_json(observation)),
        }
        if (
            stat.S_ISDIR(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o555
            and metadata.st_uid == os.geteuid()
            and child_names is not None
        ):
            package_filename = (
                f"cybex-james-appliance-packages-{name}-x86_64-linux.tar.zst"
            )
            if child_names == {package_filename}:
                observed["classification"] = "package_only_entry"
                observed["directory"] = path
            elif looks_like_local_release_set(name, child_names):
                inspected = inspect_local_release_set(
                    path, name, verify_all_bytes=True
                )
                if inspected is None:
                    fail("local published release classification changed")
                releases.append(inspected)
                observed["classification"] = "published_release"
                observed["release_set_sha256"] = inspected[
                    "release_set_sha256"
                ]
        semver_entries.append(observed)
    if not releases or len(releases) > MAX_LOCAL_PUBLISHED_RELEASES:
        fail("local published release index has no bounded immutable release")
    releases.sort(key=cmp_to_key(compare_local_release_sets))
    for left, right in zip(releases, releases[1:]):
        if compare_local_release_sets(left, right) == 0:
            fail("local published release index has ambiguous SemVer precedence")
    selected = releases[-1]
    selected_semver = semver_parts(
        selected["release_id"], "highest local published release"
    )
    index_entries: list[dict[str, object]] = []
    for observed in semver_entries:
        release_id = str(observed["release_id"])
        precedence = semver_compare(
            semver_parts(release_id, "local SemVer entry"), selected_semver
        )
        classification = observed["classification"]
        if precedence > 0:
            if classification != "package_only_entry":
                fail(
                    "higher local SemVer entry is neither an exact published "
                    "release nor an owned package-only stage"
                )
            stage_journal_sha256, package_sha256 = load_local_stage_journal(
                artifact_root=artifact_root,
                state_directory=staging_state_directory,
                served_prefix=served_prefix,
                release_id=release_id,
                release_directory=observed["directory"],
            )
            classification = "owned_package_stage"
            observed["stage_journal_sha256"] = stage_journal_sha256
            observed["package_sha256"] = package_sha256
        elif precedence == 0 and release_id != selected["release_id"]:
            fail("local SemVer entry is ambiguous with the published predecessor")
        index_entry = {
            key: value
            for key, value in observed.items()
            if key != "directory"
        }
        index_entry["classification"] = classification
        index_entries.append(index_entry)
    index_entries.sort(
        key=cmp_to_key(
            lambda left, right: semver_compare(
                semver_parts(left["release_id"], "local release index observation"),
                semver_parts(right["release_id"], "local release index observation"),
            )
        )
    )
    index_value = {
        "schema": LOCAL_RELEASE_INDEX_SCHEMA,
        "served_prefix": served_prefix,
        "releases": [
            {
                "release_id": release["release_id"],
                "release_set_sha256": release["release_set_sha256"],
            }
            for release in releases
        ],
        "semver_entries": index_entries,
    }
    if (
        set(os.listdir(artifact_root)) != set(entries)
        or stable_file_identity(artifact_root.lstat())
        != stable_file_identity(root_metadata)
    ):
        fail("local published release root changed during discovery")
    return releases, sha256_bytes(canonical_json(index_value))


def local_artifacts_by_name(
    release_set: dict[str, object],
) -> dict[str, dict[str, object]]:
    artifacts = release_set["artifacts"]
    assert isinstance(artifacts, list)
    return {str(artifact["filename"]): artifact for artifact in artifacts}


def require_local_asset_url(
    value: object,
    *,
    served_prefix: str,
    release_id: str,
    filename: str,
    label: str,
) -> str:
    expected = local_asset_url(served_prefix, release_id, filename)
    if value != expected:
        fail(f"{label} URL is not the exact canonical local release URL")
    return expected


def verify_local_predecessor_descriptors(
    *,
    release_set: dict[str, object],
    served_prefix: str,
    trusted_public_key: str,
    release_verifier: Path,
) -> dict[str, object]:
    release_id = str(release_set["release_id"])
    directory = release_set["directory"]
    assert isinstance(directory, Path)
    artifacts = local_artifacts_by_name(release_set)
    compatibility_path = directory / RELEASE_COMPATIBILITY_FILENAME
    manifest_path = directory / RELEASE_MANIFEST_FILENAME
    compatibility, compatibility_body = load_json(
        compatibility_path,
        "local published predecessor compatibility asset",
        MAX_QUALIFICATION_BYTES,
    )
    manifest, manifest_body = load_json(
        manifest_path,
        "local published predecessor release manifest",
        MAX_MANIFEST_BYTES,
    )
    if not release_verifier.is_file() or release_verifier.is_symlink():
        fail("release verifier must be a regular repository file")
    compatibility_contract = compatibility.get("compatibility")
    manifest_reference = compatibility.get("release_manifest")
    if not isinstance(compatibility_contract, dict) or not isinstance(
        manifest_reference, dict
    ):
        fail("local published predecessor compatibility asset is incomplete")
    if compatibility.get("schema") != "cybex.james.release-compatibility.v1":
        fail("local published predecessor compatibility schema is invalid")
    if manifest.get("schema") != "cybex.james.release.v1":
        fail("local published predecessor manifest schema is invalid")
    if manifest.get("version") != release_id:
        fail("local published predecessor directory does not match its manifest")
    if compatibility.get("james_release_version") != release_id:
        fail("local published predecessor compatibility release does not match")
    manifest_artifact = artifacts[RELEASE_MANIFEST_FILENAME]
    if (
        manifest_artifact["sha256"] != sha256_bytes(manifest_body)
        or manifest_reference.get("sha256") != manifest_artifact["sha256"]
    ):
        fail("local published predecessor manifest identity is inconsistent")
    manifest_url = require_local_asset_url(
        manifest_reference.get("url"),
        served_prefix=served_prefix,
        release_id=release_id,
        filename=RELEASE_MANIFEST_FILENAME,
        label="local published predecessor manifest",
    )
    with tempfile.TemporaryDirectory(prefix="cybex-local-predecessor-contract-") as directory_name:
        contract_path = Path(directory_name) / "compatibility.json"
        contract_path.write_bytes(canonical_json(compatibility_contract))
        run_bounded(
            [
                sys.executable,
                "-B",
                str(release_verifier),
                "verify-compatibility",
                "--asset",
                str(compatibility_path),
                "--manifest",
                str(manifest_path),
                "--manifest-url",
                manifest_url,
                "--compatibility",
                str(contract_path),
                "--trusted-public-key",
                trusted_public_key,
            ],
            "local published predecessor signature verification",
        )
    binary = manifest.get("artifact")
    template = manifest.get("installer_iso_template_v2")
    appliance = manifest.get("appliance_release_v1")
    workstation = manifest.get("workstation_netboot")
    if not all(
        isinstance(value, dict)
        for value in (binary, template, appliance, workstation)
    ):
        fail("local published predecessor manifest is missing a release artifact")
    assert isinstance(binary, dict)
    assert isinstance(template, dict)
    assert isinstance(appliance, dict)
    assert isinstance(workstation, dict)
    binary_name = "cybex-james-x86_64-linux"
    binary_artifact = artifacts[binary_name]
    require_local_asset_url(
        binary.get("url"),
        served_prefix=served_prefix,
        release_id=release_id,
        filename=binary_name,
        label="local published predecessor James binary",
    )
    if binary.get("sha256") != binary_artifact["sha256"]:
        fail("local published predecessor James binary identity is inconsistent")
    template_name = (
        f"cybex-james-appliance-template-{release_id}-x86_64-linux.iso"
    )
    template_artifact = artifacts[template_name]
    require_local_asset_url(
        template.get("url"),
        served_prefix=served_prefix,
        release_id=release_id,
        filename=template_name,
        label="local published predecessor installer template",
    )
    if (
        template.get("version") != release_id
        or template.get("template_sha256") != template_artifact["sha256"]
        or template.get("size_bytes") != template_artifact["size_bytes"]
    ):
        fail("local published predecessor installer identity is inconsistent")
    if appliance.get("release_id") != release_id:
        fail("local published predecessor appliance release id does not match")
    snapshot_id = text_field(
        appliance.get("ubuntu_snapshot_id"),
        "local published predecessor Ubuntu snapshot",
        SNAPSHOT_RE,
    )
    snapshot = appliance.get("cybex_repository_snapshot")
    if not isinstance(snapshot, dict):
        fail("local published predecessor package descriptor is missing")
    package_name = (
        f"cybex-james-appliance-packages-{release_id}-x86_64-linux.tar.zst"
    )
    package_artifact = artifacts[package_name]
    require_local_asset_url(
        snapshot.get("url"),
        served_prefix=served_prefix,
        release_id=release_id,
        filename=package_name,
        label="local published predecessor package snapshot",
    )
    if (
        snapshot.get("sha256") != package_artifact["sha256"]
        or snapshot.get("size_bytes") != package_artifact["size_bytes"]
    ):
        fail("local published predecessor package identity is inconsistent")
    netboot_name = str(release_set["netboot_filename"])
    netboot_artifact = artifacts[netboot_name]
    require_local_asset_url(
        workstation.get("url"),
        served_prefix=served_prefix,
        release_id=release_id,
        filename=netboot_name,
        label="local published predecessor workstation bundle",
    )
    if (
        workstation.get("sha256") != netboot_artifact["sha256"]
        or workstation.get("size_bytes") != netboot_artifact["size_bytes"]
    ):
        fail("local published predecessor workstation identity is inconsistent")
    compatibility_artifact = artifacts[RELEASE_COMPATIBILITY_FILENAME]
    if compatibility_artifact["sha256"] != sha256_bytes(compatibility_body):
        fail("local published predecessor compatibility bytes are inconsistent")
    return {
        "release_id": release_id,
        "ubuntu_snapshot_id": snapshot_id,
        "release_manifest_sha256": manifest_artifact["sha256"],
        "release_compatibility_sha256": compatibility_artifact["sha256"],
        "package_snapshot_sha256": package_artifact["sha256"],
        "package_snapshot_size_bytes": package_artifact["size_bytes"],
        "package_snapshot_filename": package_name,
    }


def stream_https_artifact(
    url: str,
    *,
    expected_sha256: str,
    expected_size: int,
    label: str,
    connection_factory: object = http.client.HTTPSConnection,
) -> None:
    try:
        parsed = urlsplit(url)
        port = parsed.port or 443
    except ValueError:
        fail(f"{label} HTTPS URL is invalid")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or unquote(parsed.path) != parsed.path
    ):
        fail(f"{label} HTTPS URL is invalid")
    factory = connection_factory
    try:
        connection = factory(
            parsed.hostname,
            port,
            timeout=30,
            context=ssl.create_default_context(),
        )
        connection.request(
            "GET",
            parsed.path,
            body=None,
            headers={
                "Accept": "application/octet-stream",
                "Accept-Encoding": "identity",
                "User-Agent": "Cybex-James-Local-Predecessor/1",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            fail(f"{label} HTTPS response was not an exact 200")
        if response.headers.get_all("Location"):
            fail(f"{label} HTTPS response attempted a redirect")
        if response.headers.get_all("Content-Encoding"):
            fail(f"{label} HTTPS response used content encoding")
        if response.headers.get_all("Content-Range"):
            fail(f"{label} HTTPS response was partial")
        lengths = response.headers.get_all("Content-Length") or []
        if lengths != [str(expected_size)]:
            fail(f"{label} HTTPS Content-Length does not match")
        digest = hashlib.sha256()
        consumed = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > expected_size:
                fail(f"{label} HTTPS body exceeded its signed size")
            digest.update(chunk)
        if consumed != expected_size or digest.hexdigest() != expected_sha256:
            fail(f"{label} HTTPS bytes do not match the immutable release set")
    except GateError:
        raise
    except (OSError, http.client.HTTPException, ssl.SSLError):
        fail(f"{label} HTTPS transport failed")
    finally:
        if "connection" in locals():
            try:
                connection.close()
            except OSError:
                pass


def require_release_asset_url(
    value: object,
    *,
    tag_name: str,
    filename: str,
    label: str,
    origin: tuple[str, str] | None = None,
) -> tuple[str, str]:
    if not isinstance(value, str):
        fail(f"{label} URL is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        fail(f"{label} URL must be canonical HTTPS")
    suffix = f"/releases/download/{tag_name}/{filename}"
    if not parsed.path.endswith(suffix):
        fail(f"{label} URL does not bind the selected published release")
    if origin is not None and (parsed.scheme, parsed.netloc) != origin:
        fail(f"{label} URL is not on the signed manifest origin")
    return parsed.scheme, parsed.netloc


def verify_published_predecessor_descriptors(
    *,
    compatibility_path: Path,
    manifest_path: Path,
    trusted_public_key: str,
    release_verifier: Path,
    github_release_id: int,
    tag_name: str,
) -> dict[str, object]:
    if github_release_id <= 0:
        fail("published predecessor GitHub release id is invalid")
    text_field(tag_name, "published predecessor tag", TAG_RE)
    if not release_verifier.is_file() or release_verifier.is_symlink():
        fail("release verifier must be a regular repository file")
    compatibility, compatibility_body = load_json(
        compatibility_path,
        "published predecessor compatibility asset",
        MAX_QUALIFICATION_BYTES,
    )
    manifest, manifest_body = load_json(
        manifest_path, "published predecessor release manifest", MAX_MANIFEST_BYTES
    )
    compatibility_contract = compatibility.get("compatibility")
    manifest_reference = compatibility.get("release_manifest")
    if not isinstance(compatibility_contract, dict) or not isinstance(
        manifest_reference, dict
    ):
        fail("published predecessor compatibility asset is incomplete")
    if compatibility.get("schema") != "cybex.james.release-compatibility.v1":
        fail("published predecessor compatibility asset schema is invalid")
    if manifest.get("schema") != "cybex.james.release.v1":
        fail("published predecessor manifest schema is invalid")
    manifest_url = manifest_reference.get("url")
    manifest_sha256 = manifest_reference.get("sha256")
    if manifest_sha256 != sha256_bytes(manifest_body):
        fail("published predecessor manifest bytes do not match signed compatibility")
    origin = require_release_asset_url(
        manifest_url,
        tag_name=tag_name,
        filename=RELEASE_MANIFEST_FILENAME,
        label="published predecessor manifest",
    )
    with tempfile.TemporaryDirectory(prefix="cybex-predecessor-contract-") as directory:
        contract_path = Path(directory) / "compatibility.json"
        contract_path.write_bytes(canonical_json(compatibility_contract))
        run_bounded(
            [
                sys.executable,
                "-B",
                str(release_verifier),
                "verify-compatibility",
                "--asset",
                str(compatibility_path),
                "--manifest",
                str(manifest_path),
                "--manifest-url",
                str(manifest_url),
                "--compatibility",
                str(contract_path),
                "--trusted-public-key",
                trusted_public_key,
            ],
            "published predecessor signature verification",
        )
    release_id = manifest.get("version")
    semver_parts(release_id, "published predecessor release")
    assert isinstance(release_id, str)
    if tag_name != f"v{release_id}":
        fail("published predecessor tag does not match the signed manifest release")
    if compatibility.get("james_release_version") != release_id:
        fail("published predecessor compatibility release does not match its manifest")
    binary = manifest.get("artifact")
    if not isinstance(binary, dict):
        fail("published predecessor manifest has no James binary descriptor")
    require_release_asset_url(
        binary.get("url"),
        tag_name=tag_name,
        filename="cybex-james-x86_64-linux",
        label="published predecessor James binary",
        origin=origin,
    )
    appliance = manifest.get("appliance_release_v1")
    if not isinstance(appliance, dict):
        fail("published predecessor manifest has no appliance release descriptor")
    if appliance.get("release_id") != release_id:
        fail("published predecessor appliance release id does not match")
    snapshot_id = text_field(
        appliance.get("ubuntu_snapshot_id"),
        "published predecessor Ubuntu snapshot",
        SNAPSHOT_RE,
    )
    snapshot = appliance.get("cybex_repository_snapshot")
    if not isinstance(snapshot, dict):
        fail("published predecessor has no package snapshot descriptor")
    snapshot_sha256 = sha256_field(
        snapshot.get("sha256"), "published predecessor package snapshot SHA-256"
    )
    snapshot_size = snapshot.get("size_bytes")
    if (
        not isinstance(snapshot_size, int)
        or isinstance(snapshot_size, bool)
        or snapshot_size <= 0
        or snapshot_size > MAX_PACKAGE_SNAPSHOT_BYTES
    ):
        fail("published predecessor package snapshot size is invalid")
    snapshot_filename = (
        f"cybex-james-appliance-packages-{release_id}-x86_64-linux.tar.zst"
    )
    require_release_asset_url(
        snapshot.get("url"),
        tag_name=tag_name,
        filename=snapshot_filename,
        label="published predecessor package snapshot",
        origin=origin,
    )
    return {
        "github_release_id": github_release_id,
        "tag_name": tag_name,
        "release_id": release_id,
        "ubuntu_snapshot_id": snapshot_id,
        "release_compatibility_sha256": sha256_bytes(compatibility_body),
        "release_manifest_sha256": sha256_bytes(manifest_body),
        "package_snapshot_sha256": snapshot_sha256,
        "package_snapshot_size_bytes": snapshot_size,
        "package_snapshot_filename": snapshot_filename,
    }


def extract_repository_snapshot(bundle: Path, destination: Path) -> None:
    listing = run_bounded(
        [
            "/usr/bin/tar",
            "--use-compress-program=/usr/bin/unzstd",
            "--list",
            "--file",
            str(bundle),
        ],
        "published predecessor package snapshot listing",
        maximum=4 * 1024 * 1024,
    )
    try:
        names = listing.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        fail("published predecessor package snapshot paths are not UTF-8")
    if not names or len(names) > MAX_PACKAGES + 16:
        fail("published predecessor package snapshot file count is unsafe")
    normalized: set[str] = set()
    for raw_name in names:
        name = raw_name[2:] if raw_name.startswith("./") else raw_name
        if name in ("", "."):
            continue
        path = PurePosixPath(name)
        if path.is_absolute() or len(path.parts) != 1 or path.parts[0] in (".", ".."):
            fail("published predecessor package snapshot contains an unsafe path")
        if name in normalized:
            fail("published predecessor package snapshot contains a duplicate path")
        normalized.add(name)
    run_bounded(
        [
            "/usr/bin/tar",
            "--use-compress-program=/usr/bin/unzstd",
            "--extract",
            "--no-same-owner",
            "--no-same-permissions",
            "--file",
            str(bundle),
            "--directory",
            str(destination),
        ],
        "published predecessor package snapshot extraction",
        maximum=64 * 1024,
    )


def packaged_updater_identity(
    packages_dir: Path,
    *,
    expected_release: str,
    expected_snapshot: str,
) -> tuple[str, str, str]:
    packages, _package_set_sha256 = candidate_packages(packages_dir)
    appliance_packages: list[Path] = []
    for package in packages:
        result = run_bounded(
            [str(DPKG_DEB_PATH), "--field", str(package), "Package"],
            "Debian package identity inspection",
            maximum=4096,
        )
        try:
            package_name = result.stdout.decode("ascii").strip()
        except UnicodeDecodeError:
            fail("Debian package identity is not ASCII")
        if package_name == "cybex-james-appliance":
            appliance_packages.append(package)
    if len(appliance_packages) != 1:
        fail("published predecessor must contain exactly one appliance package")
    with tempfile.TemporaryDirectory(prefix="cybex-predecessor-package-") as directory:
        extraction = Path(directory)
        run_bounded(
            [str(DPKG_DEB_PATH), "--extract", str(appliance_packages[0]), str(extraction)],
            "published predecessor appliance package extraction",
            maximum=64 * 1024,
        )
        updater = extraction / UPDATER_PATH
        packaged_release = extraction / "usr/share/cybex-james/appliance-release.json"
        metadata = updater.lstat()
        if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
            fail("published predecessor updater is not a regular executable")
        updater_body = open_regular(
            updater, "published predecessor packaged updater", MAX_UPDATER_BYTES
        )
        packaged_release_body = open_regular(
            packaged_release,
            "published predecessor packaged release descriptor",
            MAX_POLICY_BYTES,
        )
    try:
        packaged_release_value = json.loads(packaged_release_body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("published predecessor packaged release descriptor is invalid JSON")
    if not isinstance(packaged_release_value, dict):
        fail("published predecessor packaged release descriptor must be an object")
    if packaged_release_value.get("schema") != "cybex.james.appliance-release.v1":
        fail("published predecessor packaged release descriptor schema is invalid")
    if packaged_release_value.get("release_id") != expected_release:
        fail("published predecessor package does not match the signed release")
    if packaged_release_value.get("ubuntu_snapshot_id") != expected_snapshot:
        fail("published predecessor package does not match the signed Ubuntu snapshot")
    if not updater_body.startswith(b"#!/usr/bin/env bash\n"):
        fail("published predecessor updater has an unsupported executable format")
    has_legacy = updater_body.count(LEGACY_UPDATER_COMMAND) == 1
    has_selective = all(marker in updater_body for marker in SELECTIVE_UPDATER_MARKERS)
    if has_legacy and not has_selective:
        update_contract = LEGACY_UPDATE_CONTRACT
    elif has_selective and not has_legacy:
        update_contract = SELECTIVE_UPDATE_CONTRACT
    else:
        fail("published predecessor updater has an unknown update contract")
    return (
        update_contract,
        sha256_bytes(updater_body),
        sha256_bytes(packaged_release_body),
    )


def build_local_predecessor_identity(
    arguments: argparse.Namespace,
) -> dict[str, object]:
    served_prefix = canonical_https_prefix(arguments.served_prefix)
    releases, release_index_sha256 = local_published_release_index(
        arguments.artifact_root,
        served_prefix,
        arguments.staging_state_dir,
    )
    selected = releases[-1]
    descriptor = verify_local_predecessor_descriptors(
        release_set=selected,
        served_prefix=served_prefix,
        trusted_public_key=arguments.trusted_public_key,
        release_verifier=arguments.release_verifier,
    )
    artifacts = selected["artifacts"]
    assert isinstance(artifacts, list)
    for artifact in artifacts:
        filename = str(artifact["filename"])
        stream_https_artifact(
            local_asset_url(served_prefix, str(selected["release_id"]), filename),
            expected_sha256=str(artifact["sha256"]),
            expected_size=int(artifact["size_bytes"]),
            label=f"local published predecessor artifact {filename}",
        )
    selected_directory = selected["directory"]
    assert isinstance(selected_directory, Path)
    package_snapshot = selected_directory / str(
        descriptor["package_snapshot_filename"]
    )
    with tempfile.TemporaryDirectory(
        prefix="cybex-local-predecessor-snapshot-"
    ) as directory:
        packages_dir = Path(directory)
        extract_repository_snapshot(package_snapshot, packages_dir)
        marker = open_regular(
            packages_dir / "UBUNTU-SNAPSHOT-ID",
            "local published predecessor snapshot marker",
            128,
        )
        if marker != f"{descriptor['ubuntu_snapshot_id']}\n".encode("ascii"):
            fail("local published predecessor package snapshot marker does not match")
        validate_repository_checksums(packages_dir)
        (
            update_contract,
            updater_sha256,
            packaged_release_sha256,
        ) = packaged_updater_identity(
            packages_dir,
            expected_release=str(descriptor["release_id"]),
            expected_snapshot=str(descriptor["ubuntu_snapshot_id"]),
        )
    stable_package_sha256, stable_package_size, _prefix = hash_regular(
        package_snapshot,
        "local published predecessor package snapshot",
        MAX_PACKAGE_SNAPSHOT_BYTES,
    )
    if (
        stable_package_sha256 != descriptor["package_snapshot_sha256"]
        or stable_package_size != descriptor["package_snapshot_size_bytes"]
    ):
        fail("local published predecessor package changed during inspection")
    stable_releases, stable_index_sha256 = local_published_release_index(
        arguments.artifact_root,
        served_prefix,
        arguments.staging_state_dir,
    )
    if (
        stable_index_sha256 != release_index_sha256
        or stable_releases[-1]["release_id"] != selected["release_id"]
        or stable_releases[-1]["release_set_sha256"]
        != selected["release_set_sha256"]
    ):
        fail("local published release index changed during inspection")
    identity = {
        "schema": LOCAL_PREDECESSOR_SCHEMA,
        "served_prefix": served_prefix,
        "release_id": descriptor["release_id"],
        "ubuntu_snapshot_id": descriptor["ubuntu_snapshot_id"],
        "update_contract": update_contract,
        "published_release_count": len(releases),
        "release_index_sha256": release_index_sha256,
        "release_set_sha256": selected["release_set_sha256"],
        "release_compatibility_sha256": descriptor[
            "release_compatibility_sha256"
        ],
        "release_manifest_sha256": descriptor["release_manifest_sha256"],
        "package_snapshot_sha256": descriptor["package_snapshot_sha256"],
        "package_snapshot_size_bytes": descriptor[
            "package_snapshot_size_bytes"
        ],
        "appliance_updater_sha256": updater_sha256,
        "packaged_release_sha256": packaged_release_sha256,
    }
    validate_local_predecessor_identity(identity)
    return identity


def identify_local_predecessor(arguments: argparse.Namespace) -> None:
    identity = build_local_predecessor_identity(arguments)
    write_exclusive(arguments.output, canonical_json(identity))


def recheck_local_predecessor(arguments: argparse.Namespace) -> None:
    qualified, _qualified_body = load_local_predecessor_identity(
        arguments.qualified_identity
    )
    current = build_local_predecessor_identity(arguments)
    if qualified != current:
        fail("highest local published predecessor changed after qualification")
    print(
        "verified unchanged highest local published predecessor: "
        f"{current['release_id']} ({current['update_contract']})"
    )


def identify_predecessor(arguments: argparse.Namespace) -> None:
    descriptor = verify_published_predecessor_descriptors(
        compatibility_path=arguments.compatibility,
        manifest_path=arguments.manifest,
        trusted_public_key=arguments.trusted_public_key,
        release_verifier=arguments.release_verifier,
        github_release_id=arguments.github_release_id,
        tag_name=arguments.tag_name,
    )
    snapshot_sha256, snapshot_size, _prefix = hash_regular(
        arguments.package_snapshot,
        "published predecessor package snapshot",
        MAX_PACKAGE_SNAPSHOT_BYTES,
    )
    if arguments.package_snapshot.name != descriptor["package_snapshot_filename"]:
        fail("published predecessor package snapshot filename does not match")
    if (
        snapshot_sha256 != descriptor["package_snapshot_sha256"]
        or snapshot_size != descriptor["package_snapshot_size_bytes"]
    ):
        fail("published predecessor package snapshot bytes do not match its signature")
    with tempfile.TemporaryDirectory(prefix="cybex-predecessor-snapshot-") as directory:
        packages_dir = Path(directory)
        extract_repository_snapshot(arguments.package_snapshot, packages_dir)
        marker = open_regular(
            packages_dir / "UBUNTU-SNAPSHOT-ID",
            "published predecessor snapshot marker",
            128,
        )
        if marker != f"{descriptor['ubuntu_snapshot_id']}\n".encode("ascii"):
            fail("published predecessor package snapshot marker does not match")
        validate_repository_checksums(packages_dir)
        (
            update_contract,
            updater_sha256,
            packaged_release_sha256,
        ) = packaged_updater_identity(
            packages_dir,
            expected_release=str(descriptor["release_id"]),
            expected_snapshot=str(descriptor["ubuntu_snapshot_id"]),
        )
    identity = {
        "schema": PREDECESSOR_SCHEMA,
        "github_release_id": descriptor["github_release_id"],
        "tag_name": descriptor["tag_name"],
        "release_id": descriptor["release_id"],
        "ubuntu_snapshot_id": descriptor["ubuntu_snapshot_id"],
        "update_contract": update_contract,
        "release_compatibility_sha256": descriptor[
            "release_compatibility_sha256"
        ],
        "release_manifest_sha256": descriptor["release_manifest_sha256"],
        "package_snapshot_sha256": descriptor["package_snapshot_sha256"],
        "package_snapshot_size_bytes": descriptor["package_snapshot_size_bytes"],
        "appliance_updater_sha256": updater_sha256,
        "packaged_release_sha256": packaged_release_sha256,
    }
    validate_predecessor_identity(identity)
    write_exclusive(arguments.output, canonical_json(identity))


def recheck_predecessor(arguments: argparse.Namespace) -> None:
    identity, _identity_body = load_github_predecessor_identity(
        arguments.qualified_identity
    )
    descriptor = verify_published_predecessor_descriptors(
        compatibility_path=arguments.compatibility,
        manifest_path=arguments.manifest,
        trusted_public_key=arguments.trusted_public_key,
        release_verifier=arguments.release_verifier,
        github_release_id=arguments.github_release_id,
        tag_name=arguments.tag_name,
    )
    comparisons = {
        "github_release_id": descriptor["github_release_id"],
        "tag_name": descriptor["tag_name"],
        "release_id": descriptor["release_id"],
        "ubuntu_snapshot_id": descriptor["ubuntu_snapshot_id"],
        "release_compatibility_sha256": descriptor[
            "release_compatibility_sha256"
        ],
        "release_manifest_sha256": descriptor["release_manifest_sha256"],
        "package_snapshot_sha256": descriptor["package_snapshot_sha256"],
        "package_snapshot_size_bytes": descriptor["package_snapshot_size_bytes"],
    }
    for field, current in comparisons.items():
        if identity[field] != current:
            fail("latest signed predecessor changed after qualification")
    remote_snapshot_sha256 = sha256_field(
        arguments.package_snapshot_sha256,
        "latest predecessor remote package snapshot SHA-256",
    )
    if (
        remote_snapshot_sha256 != identity["package_snapshot_sha256"]
        or arguments.package_snapshot_size != identity["package_snapshot_size_bytes"]
    ):
        fail("latest predecessor package bytes changed after qualification")
    print(
        "verified unchanged signed predecessor under publish lock: "
        f"{identity['release_id']} ({identity['update_contract']})"
    )


def dpkg_compare(dpkg: Path, left: str, operation: str, right: str) -> bool:
    result = subprocess.run(
        [str(dpkg), "--compare-versions", left, operation, right],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode not in (0, 1):
        fail("dpkg could not compare solver package versions")
    return result.returncode == 0


def require_monotone_upgrades(
    upgrades: list[dict[str, str]], dpkg: Path, label: str
) -> None:
    if not dpkg.is_file() or dpkg.is_symlink():
        fail("installed predecessor dpkg is unavailable")
    for upgrade in upgrades:
        if not dpkg_compare(dpkg, upgrade["from"], "lt", upgrade["to"]):
            fail(
                f"{label} contains a non-upgrade version transition for "
                f"{upgrade['package']}"
            )


def require_read_only_candidate_mount(directory: Path) -> None:
    if not FINDMNT_PATH.is_file() or FINDMNT_PATH.is_symlink():
        fail("installed predecessor findmnt is unavailable")
    result = subprocess.run(
        [
            str(FINDMNT_PATH),
            "--noheadings",
            "--mountpoint",
            str(directory),
            "--output",
            "TARGET,VFS-OPTIONS,FS-OPTIONS",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout) > 4096:
        fail("candidate package directory must be an exact read-only mount")
    try:
        fields = result.stdout.decode("utf-8").strip().split(maxsplit=2)
    except UnicodeDecodeError:
        fail("candidate package mount metadata is invalid")
    if len(fields) != 3:
        fail("candidate package mount metadata is invalid")
    target, vfs_options, _filesystem_options = fields
    if target != str(directory):
        fail("candidate package directory is not its own mount point")
    if "ro" not in vfs_options.split(","):
        fail("candidate package directory must be mounted read-only")


def require_unchanged_package_set(
    directory: Path, expected_names: list[str], expected_sha256: str
) -> tuple[list[Path], str]:
    packages, package_set_sha256 = candidate_packages(directory)
    if [package.name for package in packages] != expected_names:
        fail("candidate package set changed during the APT solver run")
    if package_set_sha256 != expected_sha256:
        fail("candidate package bytes changed during the APT solver run")
    return packages, package_set_sha256


def parse_solver_plan(
    transcript: str, dpkg: Path
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    upgrades: list[dict[str, str]] = []
    additions: list[dict[str, str]] = []
    removals: list[dict[str, str]] = []
    summaries: list[tuple[int, int, int]] = []
    seen: set[tuple[str, str]] = set()
    for line in transcript.splitlines():
        inst = INST_RE.fullmatch(line)
        if inst:
            package = inst.group("package")
            old = inst.group("old")
            new = inst.group("new")
            key = ("install", package)
            if key in seen:
                fail("APT solver output contains a duplicate installation action")
            seen.add(key)
            if old is None:
                additions.append({"package": package, "version": new})
            elif dpkg_compare(dpkg, old, "lt", new):
                upgrades.append({"package": package, "from": old, "to": new})
            elif dpkg_compare(dpkg, old, "gt", new):
                fail(f"APT solver planned a downgrade of {package}")
            else:
                fail(f"APT solver planned an unreviewed reinstall of {package}")
            continue
        removal = REMV_RE.fullmatch(line)
        if removal:
            package = removal.group("package")
            old = removal.group("old") or "unknown"
            key = ("remove", package)
            if key in seen:
                fail("APT solver output contains a duplicate removal action")
            seen.add(key)
            removals.append({"package": package, "version": old})
            continue
        summary = SUMMARY_RE.fullmatch(line)
        if summary:
            summaries.append(
                (
                    int(summary.group("upgraded")),
                    int(summary.group("added")),
                    int(summary.group("removed")),
                )
            )
    if len(summaries) != 1:
        fail("APT solver output must contain exactly one transaction summary")
    expected = summaries[0]
    actual = (len(upgrades), len(additions), len(removals))
    if actual != expected:
        fail("APT solver action lines do not match its transaction summary")
    upgrades.sort(key=lambda item: item["package"].encode("ascii"))
    additions.sort(key=lambda item: item["package"].encode("ascii"))
    removals.sort(key=lambda item: item["package"].encode("ascii"))
    return upgrades, additions, removals


def enforce_plan(
    upgrades: list[dict[str, str]],
    additions: list[dict[str, str]],
    removals: list[dict[str, str]],
    policy: dict[str, object],
) -> None:
    if removals:
        names = ", ".join(item["package"] for item in removals[:8])
        fail(f"APT solver planned package removals: {names}")
    if upgrades != policy["upgrades"]:
        fail("APT solver upgrades do not exactly match the bounded bridge allowlist")
    if additions != policy["additions"]:
        fail("APT solver additions do not exactly match the bounded bridge allowlist")


def require_hash(path: Path, expected: object, label: str, maximum: int | None = None) -> bytes:
    body = open_regular(path, label, maximum)
    expected_hash = sha256_field(expected, f"expected {label} SHA-256")
    if sha256_bytes(body) != expected_hash:
        fail(f"{label} does not match the governed bridge policy")
    return body


def validate_predecessor(
    arguments: argparse.Namespace,
    policy_value: dict[str, object],
    policy: dict[str, object],
    predecessor_identity_body: bytes,
) -> dict[str, str]:
    predecessor = policy_value["predecessor"]
    assert isinstance(predecessor, dict)
    release_body = require_hash(
        INSTALLED_RELEASE_PATH,
        predecessor["installed_release_sha256"],
        "installed release descriptor",
        MAX_POLICY_BYTES,
    )
    state_body = require_hash(
        INSTALLED_STATE_PATH,
        predecessor["installed_state_sha256"],
        "installed appliance state",
        MAX_POLICY_BYTES,
    )
    require_hash(
        DPKG_STATUS_PATH,
        predecessor["dpkg_status_sha256"],
        "installed dpkg status",
        16 * 1024 * 1024,
    )
    qualification_body = require_hash(
        arguments.qualification_evidence,
        predecessor["qualification_evidence_sha256"],
        "predecessor qualification evidence",
        MAX_QUALIFICATION_BYTES,
    )
    try:
        release = json.loads(release_body)
        state = json.loads(state_body)
        qualification = json.loads(qualification_body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("predecessor provenance contains invalid JSON")
    if not all(isinstance(value, dict) for value in (release, state, qualification)):
        fail("predecessor provenance JSON must contain objects")
    if release.get("schema") != "cybex.james.appliance-release.v1":
        fail("installed release descriptor schema is invalid")
    if release.get("release_id") != policy["predecessor_release"]:
        fail("installed release does not match the bridge predecessor")
    if release.get("ubuntu_snapshot_id") != policy["predecessor_snapshot"]:
        fail("installed release Ubuntu snapshot does not match the bridge predecessor")
    if state.get("schema") != INSTALLED_SCHEMA:
        fail("installed appliance state schema is invalid")
    if state.get("release") != policy["predecessor_release"]:
        fail("installed appliance state release does not match the bridge predecessor")
    if str(state.get("root_generation")) != "0":
        fail("legacy bridge capture requires the clean installed root generation 0")
    if state.get("base_os") != "ubuntu" or state.get("base_os_version") != "26.04":
        fail("legacy bridge capture requires the supported Ubuntu appliance")
    if qualification.get("schema") != QUALIFICATION_SCHEMA:
        fail("predecessor qualification evidence schema is invalid")
    if qualification.get("ok") is not True or qualification.get("final_state") != "ready":
        fail("predecessor qualification did not finish ready")
    if qualification.get("release_version") != policy["predecessor_release"]:
        fail("predecessor qualification release does not match the bridge policy")
    if qualification.get("ubuntu_snapshot_id") != policy["predecessor_snapshot"]:
        fail("predecessor qualification snapshot does not match the bridge policy")
    if str(qualification.get("root_generation")) != "0":
        fail("predecessor qualification did not prove a clean root generation 0")
    return {
        "installed_release_sha256": sha256_bytes(release_body),
        "installed_state_sha256": sha256_bytes(state_body),
        "dpkg_status_sha256": str(predecessor["dpkg_status_sha256"]),
        "qualification_evidence_sha256": sha256_bytes(qualification_body),
        "published_identity_sha256": sha256_bytes(predecessor_identity_body),
    }


def capture(arguments: argparse.Namespace) -> None:
    predecessor_identity, predecessor_identity_body = load_predecessor_identity(
        arguments.predecessor_identity
    )
    policy_value, policy_body = load_json(
        arguments.policy, "bridge policy", MAX_POLICY_BYTES
    )
    policy = validate_policy(
        policy_value,
        predecessor_identity=predecessor_identity,
        predecessor_identity_sha256=sha256_bytes(predecessor_identity_body),
    )
    if policy_body != canonical_json(policy_value):
        fail("bridge policy must be canonical compact sorted JSON")
    if sha256_bytes(policy_body) != sha256_field(
        arguments.policy_sha256, "governed bridge policy SHA-256"
    ):
        fail("bridge policy does not match its governed SHA-256")
    provenance = validate_predecessor(
        arguments, policy_value, policy, predecessor_identity_body
    )
    packages_dir = CANDIDATE_PACKAGES_PATH
    require_read_only_candidate_mount(packages_dir)
    packages, package_set_sha256 = candidate_packages(packages_dir)
    package_names = [package.name for package in packages]
    apt_get = APT_GET_PATH
    dpkg = DPKG_PATH
    if not apt_get.is_file() or apt_get.is_symlink():
        fail("installed predecessor apt-get is unavailable")
    if not dpkg.is_file() or dpkg.is_symlink():
        fail("installed predecessor dpkg is unavailable")
    environment = dict(os.environ)
    environment.update({"LC_ALL": "C", "LANG": "C"})
    result = subprocess.run(
        [
            "/bin/sh",
            "-c",
            "exec /usr/bin/apt-get --simulate --no-download --yes install "
            "/run/cybex-update-packages/*.deb",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=environment,
        check=False,
    )
    if len(result.stdout) > MAX_APT_OUTPUT_BYTES:
        fail("APT solver output exceeds its size limit")
    try:
        transcript = result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        fail("APT solver output is not UTF-8")
    if result.returncode != 0:
        fail(f"legacy APT dry-run failed with exit code {result.returncode}")
    require_read_only_candidate_mount(packages_dir)
    packages, stable_package_set_sha256 = require_unchanged_package_set(
        packages_dir, package_names, package_set_sha256
    )
    if stable_package_set_sha256 != package_set_sha256:
        fail("candidate package set changed during the APT solver run")
    upgrades, additions, removals = parse_solver_plan(transcript, dpkg)
    enforce_plan(upgrades, additions, removals, policy)
    apt_version = subprocess.run(
        [str(apt_get), "--version"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
        text=True,
    ).stdout.splitlines()[0][:256]
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "ok": True,
        "predecessor_release_id": policy["predecessor_release"],
        "predecessor_ubuntu_snapshot_id": policy["predecessor_snapshot"],
        "candidate_release_id": policy["candidate_release"],
        "candidate_ubuntu_snapshot_id": policy["candidate_snapshot"],
        "policy_sha256": sha256_bytes(policy_body),
        "candidate_package_set_sha256": package_set_sha256,
        "candidate_package_count": len(packages),
        "installed_release_sha256": provenance["installed_release_sha256"],
        "installed_state_sha256": provenance["installed_state_sha256"],
        "dpkg_status_sha256": provenance["dpkg_status_sha256"],
        "qualification_evidence_sha256": provenance[
            "qualification_evidence_sha256"
        ],
        "published_identity_sha256": provenance["published_identity_sha256"],
        "command_contract": (
            "apt-get --simulate --no-download --yes install "
            "/run/cybex-update-packages/*.deb"
        ),
        "apt_version": apt_version,
        "upgrades": upgrades,
        "additions": additions,
        "removals": removals,
    }
    output = canonical_json(evidence)
    if len(output) > MAX_EVIDENCE_BYTES:
        fail("bridge evidence exceeds its size limit")
    write_exclusive(arguments.output, output)


def verify(arguments: argparse.Namespace) -> None:
    predecessor_identity, predecessor_identity_body = load_predecessor_identity(
        arguments.predecessor_identity
    )
    policy_value, policy_body = load_json(
        arguments.policy, "bridge policy", MAX_POLICY_BYTES
    )
    policy = validate_policy(
        policy_value,
        candidate_release=arguments.candidate_release,
        candidate_snapshot=arguments.candidate_snapshot,
        predecessor_identity=predecessor_identity,
        predecessor_identity_sha256=sha256_bytes(predecessor_identity_body),
    )
    if policy_body != canonical_json(policy_value):
        fail("bridge policy must be canonical compact sorted JSON")
    if sha256_bytes(policy_body) != sha256_field(
        arguments.policy_sha256, "governed bridge policy SHA-256"
    ):
        fail("bridge policy does not match its governed SHA-256")
    validate_snapshot_binding(
        arguments.snapshot_bundle,
        arguments.snapshot_metadata,
        arguments.packages_dir,
        str(policy["candidate_release"]),
        str(policy["candidate_snapshot"]),
    )
    packages, package_set_sha256 = candidate_packages(arguments.packages_dir)
    package_names = [package.name for package in packages]
    evidence_value, evidence_body = load_json(
        arguments.evidence, "bridge evidence", MAX_EVIDENCE_BYTES
    )
    expected_evidence_sha256 = sha256_field(
        arguments.evidence_sha256, "governed bridge evidence SHA-256"
    )
    if sha256_bytes(evidence_body) != expected_evidence_sha256:
        fail("bridge evidence does not match its governed SHA-256")
    if evidence_body != canonical_json(evidence_value):
        fail("bridge evidence must be canonical compact sorted JSON")
    exact_keys(
        evidence_value,
        {
            "schema",
            "ok",
            "predecessor_release_id",
            "predecessor_ubuntu_snapshot_id",
            "candidate_release_id",
            "candidate_ubuntu_snapshot_id",
            "policy_sha256",
            "candidate_package_set_sha256",
            "candidate_package_count",
            "installed_release_sha256",
            "installed_state_sha256",
            "dpkg_status_sha256",
            "qualification_evidence_sha256",
            "published_identity_sha256",
            "command_contract",
            "apt_version",
            "upgrades",
            "additions",
            "removals",
        },
        "bridge evidence",
    )
    if evidence_value["schema"] != EVIDENCE_SCHEMA or evidence_value["ok"] is not True:
        fail("bridge evidence is not a successful supported capture")
    expected_values = {
        "predecessor_release_id": policy["predecessor_release"],
        "predecessor_ubuntu_snapshot_id": policy["predecessor_snapshot"],
        "candidate_release_id": policy["candidate_release"],
        "candidate_ubuntu_snapshot_id": policy["candidate_snapshot"],
        "policy_sha256": sha256_bytes(policy_body),
        "candidate_package_set_sha256": package_set_sha256,
        "candidate_package_count": len(packages),
        "published_identity_sha256": sha256_bytes(predecessor_identity_body),
    }
    for field, expected in expected_values.items():
        if evidence_value[field] != expected:
            fail(f"bridge evidence {field} does not match the exact candidate")
    predecessor = policy_value["predecessor"]
    assert isinstance(predecessor, dict)
    for field in (
        "installed_release_sha256",
        "installed_state_sha256",
        "dpkg_status_sha256",
        "qualification_evidence_sha256",
    ):
        if evidence_value[field] != predecessor[field]:
            fail(f"bridge evidence {field} does not match predecessor provenance")
    if evidence_value["command_contract"] != (
        "apt-get --simulate --no-download --yes install "
        "/run/cybex-update-packages/*.deb"
    ):
        fail("bridge evidence did not exercise the legacy wildcard APT contract")
    upgrades = validate_actions(
        evidence_value["upgrades"],
        "evidence upgrades",
        upgrade=True,
        maximum=MAX_ALLOWED_UPGRADES,
    )
    additions = validate_actions(
        evidence_value["additions"],
        "evidence additions",
        upgrade=False,
        maximum=MAX_ALLOWED_ADDITIONS,
    )
    removals = evidence_value["removals"]
    removals = validate_actions(
        removals,
        "evidence removals",
        upgrade=False,
        maximum=MAX_ALLOWED_UPGRADES,
    )
    apt_version = evidence_value["apt_version"]
    if not isinstance(apt_version, str) or not (1 <= len(apt_version) <= 256):
        fail("bridge evidence APT version is invalid")
    require_monotone_upgrades(policy["upgrades"], DPKG_PATH, "bridge allowlist")
    require_monotone_upgrades(upgrades, DPKG_PATH, "bridge evidence")
    enforce_plan(upgrades, additions, removals, policy)
    require_unchanged_package_set(
        arguments.packages_dir, package_names, package_set_sha256
    )
    print(
        "legacy bridge gate passed: newer snapshot, zero downgrades/removals, "
        f"{len(upgrades)} reviewed upgrades and {len(additions)} reviewed additions"
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Capture or verify a monotone legacy James update bridge"
    )
    commands = result.add_subparsers(dest="command", required=True)
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--policy", required=True, type=Path)
    capture_parser.add_argument("--policy-sha256", required=True)
    capture_parser.add_argument("--predecessor-identity", required=True, type=Path)
    capture_parser.add_argument("--qualification-evidence", required=True, type=Path)
    capture_parser.add_argument("--output", required=True, type=Path)
    capture_parser.set_defaults(handler=capture)

    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--packages-dir", required=True, type=Path)
    verify_parser.add_argument("--snapshot-bundle", required=True, type=Path)
    verify_parser.add_argument("--snapshot-metadata", required=True, type=Path)
    verify_parser.add_argument("--policy", required=True, type=Path)
    verify_parser.add_argument("--policy-sha256", required=True)
    verify_parser.add_argument("--predecessor-identity", required=True, type=Path)
    verify_parser.add_argument("--evidence", required=True, type=Path)
    verify_parser.add_argument("--evidence-sha256", required=True)
    verify_parser.add_argument("--candidate-release", required=True)
    verify_parser.add_argument("--candidate-snapshot", required=True)
    verify_parser.set_defaults(handler=verify)

    identify_parser = commands.add_parser("identify-predecessor")
    identify_parser.add_argument("--compatibility", required=True, type=Path)
    identify_parser.add_argument("--manifest", required=True, type=Path)
    identify_parser.add_argument("--package-snapshot", required=True, type=Path)
    identify_parser.add_argument("--trusted-public-key", required=True)
    identify_parser.add_argument("--release-verifier", required=True, type=Path)
    identify_parser.add_argument("--github-release-id", required=True, type=int)
    identify_parser.add_argument("--tag-name", required=True)
    identify_parser.add_argument("--output", required=True, type=Path)
    identify_parser.set_defaults(handler=identify_predecessor)

    recheck_parser = commands.add_parser("recheck-predecessor")
    recheck_parser.add_argument("--qualified-identity", required=True, type=Path)
    recheck_parser.add_argument("--compatibility", required=True, type=Path)
    recheck_parser.add_argument("--manifest", required=True, type=Path)
    recheck_parser.add_argument("--trusted-public-key", required=True)
    recheck_parser.add_argument("--release-verifier", required=True, type=Path)
    recheck_parser.add_argument("--github-release-id", required=True, type=int)
    recheck_parser.add_argument("--tag-name", required=True)
    recheck_parser.add_argument("--package-snapshot-sha256", required=True)
    recheck_parser.add_argument("--package-snapshot-size", required=True, type=int)
    recheck_parser.set_defaults(handler=recheck_predecessor)

    identify_local_parser = commands.add_parser("identify-local-predecessor")
    identify_local_parser.add_argument(
        "--artifact-root", required=True, type=Path
    )
    identify_local_parser.add_argument("--staging-state-dir", type=Path)
    identify_local_parser.add_argument("--served-prefix", required=True)
    identify_local_parser.add_argument("--trusted-public-key", required=True)
    identify_local_parser.add_argument(
        "--release-verifier", required=True, type=Path
    )
    identify_local_parser.add_argument("--output", required=True, type=Path)
    identify_local_parser.set_defaults(handler=identify_local_predecessor)

    recheck_local_parser = commands.add_parser("recheck-local-predecessor")
    recheck_local_parser.add_argument(
        "--qualified-identity", required=True, type=Path
    )
    recheck_local_parser.add_argument(
        "--artifact-root", required=True, type=Path
    )
    recheck_local_parser.add_argument("--staging-state-dir", type=Path)
    recheck_local_parser.add_argument("--served-prefix", required=True)
    recheck_local_parser.add_argument("--trusted-public-key", required=True)
    recheck_local_parser.add_argument(
        "--release-verifier", required=True, type=Path
    )
    recheck_local_parser.set_defaults(handler=recheck_local_predecessor)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        arguments.handler(arguments)
    except (GateError, OSError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
