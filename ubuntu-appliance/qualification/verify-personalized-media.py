#!/usr/bin/env python3
"""Verify normalized template and envelope bytes without persisting secrets."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


DOMAIN = b"CYBEX-FORGE-PROVISIONING-ENVELOPE-V1\n"
DER_PREFIX = bytes.fromhex("302a300506032b6570032100")


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iso", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--headers", required=True)
    parser.add_argument("--session-id", required=True)
    arguments = parser.parse_args()
    secret = os.environ.get("CYBEX_FORGE_MEDIA_SECRET", "")
    if not secret:
        fail("media secret environment is missing")
    manifest = json.loads(Path(arguments.manifest).read_text(encoding="utf-8"))
    descriptor = manifest.get("installer_iso_template_v2")
    if not isinstance(descriptor, dict):
        fail("release manifest has no installer_iso_template_v2")
    offset = descriptor["personalization_offset"]
    size = descriptor["personalization_size"]
    if size != 8192 or offset < 0:
        fail("personalization slot is invalid")
    iso = Path(arguments.iso)
    if iso.stat().st_size != descriptor["size_bytes"]:
        fail("personalized ISO size does not match the template")

    normalized = hashlib.sha256()
    personalized = hashlib.sha256()
    envelope_digest = hashlib.sha256()
    envelope = bytearray()
    position = 0
    with iso.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            personalized.update(chunk)
            start = position
            end = position + len(chunk)
            overlap_start = max(start, offset)
            overlap_end = min(end, offset + size)
            if overlap_start < overlap_end:
                relative_start = overlap_start - start
                relative_end = overlap_end - start
                envelope.extend(chunk[relative_start:relative_end])
                normalized.update(chunk[:relative_start])
                normalized.update(bytes(relative_end - relative_start))
                normalized.update(chunk[relative_end:])
            else:
                normalized.update(chunk)
            position = end
    if len(envelope) != 8192:
        fail("personalization envelope is truncated")
    envelope_digest.update(envelope)
    if normalized.hexdigest() != descriptor["template_sha256"]:
        fail("normalized template digest does not match the offline descriptor")
    end = envelope.find(0)
    if end < 0 or any(envelope[end:]):
        fail("envelope padding is not canonical")
    body = bytes(envelope[:end]).removesuffix(b"\n")
    value = json.loads(body)
    if value.get("session_id") != arguments.session_id:
        fail("envelope session does not match")
    if value.get("media_secret") != secret:
        fail("envelope media secret does not match the visible session")
    if value.get("template_sha256") != descriptor["template_sha256"]:
        fail("envelope template binding does not match")
    signature_text = value.pop("signature", None)
    value.pop("zero_padding", None)
    try:
        signature = base64.urlsafe_b64decode(signature_text + "==")
    except Exception:
        fail("envelope signature encoding is invalid")
    if len(signature) != 64:
        fail("envelope signature has invalid length")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    verified = False
    with tempfile.TemporaryDirectory(prefix="cybex-envelope-verify-") as temporary:
        root = Path(temporary)
        message = root / "message"
        signature_path = root / "signature"
        message.write_bytes(DOMAIN + canonical)
        signature_path.write_bytes(signature)
        for index, key_text in enumerate(descriptor["provisioning_public_keys"]):
            try:
                key = base64.b64decode(key_text, validate=True)
            except Exception:
                fail("descriptor provisioning key is invalid")
            if len(key) != 32:
                fail("descriptor provisioning key length is invalid")
            public_key = root / f"key-{index}.der"
            public_key.write_bytes(DER_PREFIX + key)
            result = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    str(public_key),
                    "-rawin",
                    "-sigfile",
                    str(signature_path),
                    "-in",
                    str(message),
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                verified = True
                break
    if not verified:
        fail("envelope signature is not trusted by the offline descriptor")

    headers = Path(arguments.headers).read_text(encoding="utf-8").lower()
    expected_header = f"x-cybex-forge-envelope-sha256: {envelope_digest.hexdigest()}"
    if expected_header not in headers:
        fail("download response did not bind the exact envelope digest")
    print(
        json.dumps(
            {
                "template_sha256": descriptor["template_sha256"],
                "envelope_sha256": envelope_digest.hexdigest(),
                "personalized_sha256": personalized.hexdigest(),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
