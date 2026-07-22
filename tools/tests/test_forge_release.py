from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
TOOL = REPOSITORY / "tools" / "forge-release.py"
PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")


class ForgeReleaseToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.private_key = self.directory / "release-key.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(self.private_key),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.private_key.chmod(0o600)
        self.artifact = self.directory / "cybex-forge-x86_64-linux"
        self.artifact.write_bytes(b"deterministic Forge artifact\0\xff\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

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
            "--published-at",
            "2026-07-23T12:00:00Z",
        ]

    def test_manifest_is_deterministic_complete_and_independently_verifiable(self) -> None:
        first = self.directory / "first.json"
        second = self.directory / "second.json"
        first_result = self.run_tool(*self.manifest_arguments(first))
        second_result = self.run_tool(*self.manifest_arguments(second))
        self.assertEqual(first_result.returncode, 0, first_result.stderr.decode())
        self.assertEqual(second_result.returncode, 0, second_result.stderr.decode())
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o644)
        self.assertEqual(list(self.directory.glob(".first.json.*.tmp")), [])

        manifest = json.loads(first.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], "cybex.forge.release.v1")
        self.assertEqual(manifest["version"], "0.1.1")
        self.assertEqual(manifest["published_at"], "2026-07-23T12:00:00Z")
        self.assertEqual(
            manifest["artifact"]["sha256"], hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        )
        signature = base64.b64decode(manifest["signature"], validate=True)
        self.assertEqual(len(signature), 64)
        message = (
            f'{manifest["version"]}\n'
            f'{manifest["artifact"]["sha256"]}\n'
            f'{manifest["artifact"]["url"]}\n'
        ).encode()

        public_key = self.directory / "public.pem"
        signature_path = self.directory / "signature.bin"
        message_path = self.directory / "message.bin"
        signature_path.write_bytes(signature)
        message_path.write_bytes(message)
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        verified = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key),
                "-rawin",
                "-sigfile",
                str(signature_path),
                "-in",
                str(message_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr.decode())
        message_path.write_bytes(message + b"modified")
        modified = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key),
                "-rawin",
                "-sigfile",
                str(signature_path),
                "-in",
                str(message_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(modified.returncode, 0)

    def test_public_key_is_canonical_raw_standard_base64(self) -> None:
        result = self.run_tool("public-key", "--private-key", str(self.private_key))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        encoded = result.stdout.decode().strip()
        raw = base64.b64decode(encoded, validate=True)
        self.assertEqual(len(raw), 32)
        self.assertEqual(base64.b64encode(raw).decode(), encoded)

        der = subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.private_key),
                "-pubout",
                "-outform",
                "DER",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
        self.assertEqual(der, PUBLIC_DER_PREFIX + raw)

    def test_rejects_noncanonical_versions_urls_and_timestamps(self) -> None:
        cases = {
            "leading v": ("--version", "v0.1.1"),
            "numeric leading zero": ("--version", "0.01.1"),
            "credentialed URL": (
                "--artifact-url",
                "https://user:password@releases.example.test/artifact",
            ),
            "URL fragment": (
                "--notes-url",
                "https://releases.example.test/notes#fragment",
            ),
            "non-UTC timestamp": ("--published-at", "2026-07-23T12:00:00+00:00"),
            "invalid date": ("--published-at", "2026-02-30T12:00:00Z"),
        }
        for label, (option, replacement) in cases.items():
            with self.subTest(label=label):
                arguments = self.manifest_arguments(self.directory / f"{label}.json")
                arguments[arguments.index(option) + 1] = replacement
                result = self.run_tool(*arguments)
                self.assertEqual(result.returncode, 2)

    def test_private_key_permissions_are_fail_closed(self) -> None:
        self.private_key.chmod(0o640)
        result = self.run_tool("public-key", "--private-key", str(self.private_key))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"permissions", result.stderr)

    def test_private_key_details_are_not_reported_and_existing_output_survives(self) -> None:
        invalid_key = self.directory / "do-not-report-this-name.pem"
        private_marker = b"PRIVATE_KEY_MATERIAL_MUST_NOT_APPEAR"
        invalid_key.write_bytes(private_marker)
        invalid_key.chmod(0o600)
        output = self.directory / "existing.json"
        original = b"existing manifest remains intact\n"
        output.write_bytes(original)
        arguments = self.manifest_arguments(output)
        arguments[arguments.index("--private-key") + 1] = str(invalid_key)
        result = self.run_tool(*arguments)
        self.assertEqual(result.returncode, 2)
        combined = result.stdout + result.stderr
        self.assertNotIn(str(invalid_key).encode(), combined)
        self.assertNotIn(private_marker, combined)
        self.assertEqual(output.read_bytes(), original)

    def test_refuses_symlink_inputs_and_protected_output_paths(self) -> None:
        artifact_link = self.directory / "artifact-link"
        artifact_link.symlink_to(self.artifact)
        output = self.directory / "manifest.json"
        arguments = self.manifest_arguments(output)
        arguments[arguments.index("--artifact") + 1] = str(artifact_link)
        self.assertEqual(self.run_tool(*arguments).returncode, 2)

        arguments = self.manifest_arguments(self.artifact)
        result = self.run_tool(*arguments)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"must not overwrite the artifact", result.stderr)


if __name__ == "__main__":
    unittest.main()
