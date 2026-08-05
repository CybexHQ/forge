from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
TOOL = REPOSITORY / "tools" / "forge-release.py"
WEAK_PUBLIC_KEYS = REPOSITORY / "trust" / "ed25519-weak-public-keys.txt"


class ForgeReleaseToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.private_key = self.directory / "release-key.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private_key)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.private_key.chmod(0o600)
        self.artifact = self.directory / "cybex-forge-x86_64-linux"
        self.artifact.write_bytes(b"deterministic Forge artifact\0\xff\n")
        self.template = self.directory / (
            "cybex-forge-appliance-template-0.1.1-x86_64-linux.iso"
        )
        self.personalization_offset = 4096
        media = bytearray(b"Cybex Ubuntu template\n" * 900)
        media[
            self.personalization_offset : self.personalization_offset + 8192
        ] = bytes(8192)
        self.template.write_bytes(media)
        self.provisioning_key = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def public_key(self) -> str:
        result = self.run_tool("public-key", "--private-key", str(self.private_key))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result.stdout.decode().strip()

    def manifest_arguments(self, output: Path) -> list[str]:
        return [
            "manifest",
            "--artifact",
            str(self.artifact),
            "--artifact-url",
            "https://releases.example.test/v0.1.1/cybex-forge-x86_64-linux",
            "--version",
            "0.1.1",
            "--private-key",
            str(self.private_key),
            "--output",
            str(output),
            "--release-url",
            "https://releases.example.test/v0.1.1",
            "--notes-url",
            "https://releases.example.test/v0.1.1/notes",
            "--installer-iso-template",
            str(self.template),
            "--installer-iso-template-url",
            "https://releases.example.test/v0.1.1/"
            "cybex-forge-appliance-template-0.1.1-x86_64-linux.iso",
            "--installer-iso-template-personalization-offset",
            str(self.personalization_offset),
            "--provisioning-public-key",
            self.provisioning_key,
            "--published-at",
            "2026-07-23T12:00:00Z",
        ]

    def verify_arguments(self, manifest: Path) -> list[str]:
        return [
            "verify",
            "--manifest",
            str(manifest),
            "--artifact",
            str(self.artifact),
            "--installer-iso-template",
            str(self.template),
            "--trusted-public-key",
            self.public_key(),
        ]

    def test_v2_manifest_is_deterministic_and_independently_verifiable(self) -> None:
        first = self.directory / "first.json"
        second = self.directory / "second.json"
        one = self.run_tool(*self.manifest_arguments(first))
        two = self.run_tool(*self.manifest_arguments(second))
        self.assertEqual(one.returncode, 0, one.stderr.decode())
        self.assertEqual(two.returncode, 0, two.stderr.decode())
        self.assertEqual(first.read_bytes(), second.read_bytes())

        manifest = json.loads(first.read_text(encoding="utf-8"))
        self.assertNotIn("installer_iso", manifest)
        descriptor = manifest["installer_iso_template_v2"]
        self.assertEqual(descriptor["base_os"], "ubuntu")
        self.assertEqual(descriptor["base_os_version"], "26.04")
        self.assertEqual(descriptor["personalization_size"], 8192)
        self.assertEqual(
            descriptor["template_sha256"],
            hashlib.sha256(self.template.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            descriptor["placeholder_sha256"], hashlib.sha256(bytes(8192)).hexdigest()
        )
        self.assertEqual(len(base64.b64decode(descriptor["signature"], validate=True)), 64)

        verified = self.run_tool(*self.verify_arguments(first))
        self.assertEqual(verified.returncode, 0, verified.stderr.decode())
        self.assertIn(descriptor["template_sha256"].encode(), verified.stdout)

    def test_v1_installer_options_are_rejected(self) -> None:
        output = self.directory / "release.json"
        for command in (
            [*self.manifest_arguments(output), "--installer-iso", "legacy.iso"],
            [*self.manifest_arguments(output), "--installer-iso-url", "https://example/legacy.iso"],
        ):
            rejected = self.run_tool(*command)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn(b"unrecognized arguments", rejected.stderr)

    def test_manifest_rejects_removed_v1_field(self) -> None:
        manifest_path = self.directory / "release.json"
        signed = self.run_tool(*self.manifest_arguments(manifest_path))
        self.assertEqual(signed.returncode, 0, signed.stderr.decode())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["installer_iso"] = {
            "url": "https://example.test/legacy.iso",
            "sha256": "0" * 64,
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        rejected = self.run_tool(*self.verify_arguments(manifest_path))
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"exact expected set", rejected.stderr)

    def test_template_is_required_and_tampering_is_rejected(self) -> None:
        output = self.directory / "release.json"
        arguments = self.manifest_arguments(output)
        start = arguments.index("--installer-iso-template")
        del arguments[start : start + 2]
        rejected = self.run_tool(*arguments)
        self.assertEqual(rejected.returncode, 2)

        signed = self.run_tool(*self.manifest_arguments(output))
        self.assertEqual(signed.returncode, 0, signed.stderr.decode())
        tampered = bytearray(self.template.read_bytes())
        tampered[self.personalization_offset] = 1
        self.template.write_bytes(tampered)
        rejected = self.run_tool(*self.verify_arguments(output))
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"personalization slot", rejected.stderr)

    def test_weak_public_keys_and_private_key_permissions_fail_closed(self) -> None:
        weak = WEAK_PUBLIC_KEYS.read_text(encoding="ascii").splitlines()[0]
        rejected = self.run_tool("validate-public-key", "--trusted-public-key", weak)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"weak Ed25519 key", rejected.stderr)

        self.private_key.chmod(0o640)
        rejected = self.run_tool("public-key", "--private-key", str(self.private_key))
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"permissions", rejected.stderr)

    @unittest.skipUnless(os.geteuid() == 0, "ownership check requires root")
    def test_private_key_requires_effective_user_ownership(self) -> None:
        os.chown(self.private_key, 65534, 65534)
        try:
            rejected = self.run_tool("public-key", "--private-key", str(self.private_key))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn(b"effective user", rejected.stderr)
        finally:
            os.chown(self.private_key, 0, 0)


if __name__ == "__main__":
    unittest.main()
