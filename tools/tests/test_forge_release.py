from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
TOOL = REPOSITORY / "tools" / "forge-release.py"
WEAK_PUBLIC_KEYS = REPOSITORY / "trust" / "ed25519-weak-public-keys.txt"
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
        self.installer_iso = (
            self.directory / "cybex-forge-appliance-0.1.1-x86_64-linux.iso"
        )
        self.installer_iso.write_bytes(b"CYBEX FORGE ISO\0" + bytes(range(64)))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_tool(
        self, *arguments: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
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
        self.assertNotIn("installer_iso", manifest)
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

    def test_optional_installer_iso_is_domain_separated_and_deterministic(self) -> None:
        first = self.directory / "installer-first.json"
        second = self.directory / "installer-second.json"
        arguments = [
            *self.manifest_arguments(first),
            "--installer-iso",
            str(self.installer_iso),
            "--installer-iso-url",
            "https://releases.example.test/v0.1.1/cybex-forge-appliance-0.1.1-x86_64-linux.iso",
        ]
        first_result = self.run_tool(*arguments)
        arguments[arguments.index(str(first))] = str(second)
        second_result = self.run_tool(*arguments)
        self.assertEqual(first_result.returncode, 0, first_result.stderr.decode())
        self.assertEqual(second_result.returncode, 0, second_result.stderr.decode())
        self.assertEqual(first.read_bytes(), second.read_bytes())

        manifest = json.loads(first.read_text(encoding="utf-8"))
        installer = manifest["installer_iso"]
        self.assertEqual(installer["architecture"], "x86_64-linux")
        self.assertEqual(installer["size_bytes"], self.installer_iso.stat().st_size)
        self.assertEqual(
            installer["sha256"], hashlib.sha256(self.installer_iso.read_bytes()).hexdigest()
        )
        signature = base64.b64decode(installer["signature"], validate=True)
        message = (
            "CYBEX-FORGE-INSTALLER-ISO-V1\n"
            f'{manifest["version"]}\n'
            f'{installer["architecture"]}\n'
            f'{installer["size_bytes"]}\n'
            f'{installer["sha256"]}\n'
            f'{installer["url"]}\n'
        ).encode()
        public_key = self.directory / "installer-public.pem"
        signature_path = self.directory / "installer-signature.bin"
        message_path = self.directory / "installer-message.bin"
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

        def verify() -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
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

        self.assertEqual(verify().returncode, 0)
        legacy_message = (
            f'{manifest["version"]}\n{installer["sha256"]}\n{installer["url"]}\n'
        ).encode()
        message_path.write_bytes(legacy_message)
        self.assertNotEqual(verify().returncode, 0)
        message_path.write_bytes(message.replace(b"x86_64-linux", b"aarch64-linux"))
        self.assertNotEqual(verify().returncode, 0)

    def test_verify_accepts_exact_candidate_and_rejects_tampered_iso(self) -> None:
        manifest = self.directory / "cybex-forge-release.json"
        arguments = [
            *self.manifest_arguments(manifest),
            "--installer-iso",
            str(self.installer_iso),
            "--installer-iso-url",
            "https://releases.example.test/v0.1.1/cybex-forge-appliance-0.1.1-x86_64-linux.iso",
        ]
        signed = self.run_tool(*arguments)
        self.assertEqual(signed.returncode, 0, signed.stderr.decode())
        public_key = self.run_tool(
            "public-key", "--private-key", str(self.private_key)
        )
        self.assertEqual(public_key.returncode, 0, public_key.stderr.decode())
        trusted = public_key.stdout.decode().strip()
        verify_arguments = [
            "verify",
            "--manifest",
            str(manifest),
            "--artifact",
            str(self.artifact),
            "--installer-iso",
            str(self.installer_iso),
            "--trusted-public-key",
            trusted,
        ]
        verified = self.run_tool(*verify_arguments)
        self.assertEqual(verified.returncode, 0, verified.stderr.decode())
        self.assertIn(b"version=0.1.1", verified.stdout)
        self.assertNotIn(trusted.encode(), verified.stdout)

        verify_arguments[-1] = WEAK_PUBLIC_KEYS.read_text(
            encoding="ascii"
        ).splitlines()[0]
        weak_rejected = self.run_tool(*verify_arguments)
        self.assertEqual(weak_rejected.returncode, 2)
        self.assertIn(b"weak Ed25519 key", weak_rejected.stderr)
        verify_arguments[-1] = trusted

        self.installer_iso.write_bytes(self.installer_iso.read_bytes() + b"tampered")
        rejected = self.run_tool(*verify_arguments)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"SHA-256 does not match", rejected.stderr)

    def test_verify_qualification_binds_exact_candidate_sources_and_cleanup(self) -> None:
        public_key = self.run_tool(
            "public-key", "--private-key", str(self.private_key)
        )
        self.assertEqual(public_key.returncode, 0, public_key.stderr.decode())
        trusted = public_key.stdout.decode().strip()
        run_id = "forge-release-123-1"
        forge_revision = "a" * 40
        manage_revision = "b" * 40
        evidence_path = self.directory / f"{run_id}-evidence.json"
        output = self.directory / "cybex-forge-appliance-qualification.json"
        evidence = {
            "schema": "cybex.incus.public-evidence.v1",
            "generated_at": "2026-07-31T12:00:00+00:00",
            "selector": {"run_id": run_id, "run_prefix": None},
            "runs": [
                {
                    "run_id": run_id,
                    "ok": True,
                    "excluded_json_files": 0,
                    "artifacts": [
                        {
                            "artifact": "forge-appliance-release-smoke.json",
                            "completed": True,
                            "schema": "cybex.incus.forge-appliance-release-smoke.v1",
                            "run_id": run_id,
                            "status": "succeeded",
                            "ok": True,
                            "cleanup_ok": True,
                            "private_state_cleanup_ok": True,
                            "check_counts": {
                                "total": 8,
                                "failed": 0,
                                "skipped": 0,
                            },
                            "passed_checks": [
                                "exact_signed_descriptor",
                                "release_binary_identity",
                                "guided_ready_marker",
                                "embedded_media_version",
                                "embedded_release_binary_version",
                                "embedded_release_binary_sha256",
                                "embedded_production_trust",
                                "guided_installer_service",
                            ],
                            "component_source_identity": {
                                "forge_checkout": {
                                    "revision": forge_revision,
                                    "dirty": False,
                                },
                                "manage_checkout": {
                                    "revision": manage_revision,
                                    "dirty": False,
                                },
                            },
                            "release": {
                                "version": "0.1.1",
                                "architecture": "x86_64-linux",
                                "binary_sha256": hashlib.sha256(
                                    self.artifact.read_bytes()
                                ).hexdigest(),
                                "iso_sha256": hashlib.sha256(
                                    self.installer_iso.read_bytes()
                                ).hexdigest(),
                                "iso_size_bytes": self.installer_iso.stat().st_size,
                                "public_key_sha256": hashlib.sha256(
                                    base64.b64decode(trusted, validate=True)
                                ).hexdigest(),
                                "exact_supplied_artifacts": True,
                                "synthetic_successors_created": False,
                            },
                        }
                    ],
                }
            ],
            "ok": True,
        }
        evidence_path.write_text(
            json.dumps(evidence, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        arguments = [
            "verify-qualification",
            "--evidence",
            str(evidence_path),
            "--artifact",
            str(self.artifact),
            "--installer-iso",
            str(self.installer_iso),
            "--trusted-public-key",
            trusted,
            "--version",
            "0.1.1",
            "--forge-source-revision",
            forge_revision,
            "--manage-source-revision",
            manage_revision,
            "--run-id",
            run_id,
            "--output",
            str(output),
        ]
        verified = self.run_tool(*arguments)
        self.assertEqual(verified.returncode, 0, verified.stderr.decode())
        qualification = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(
            set(qualification),
            {"schema", "run_id", "source", "release", "passed_checks", "cleanup"},
        )
        self.assertEqual(
            qualification["schema"], "cybex.forge.appliance-qualification.v1"
        )
        self.assertEqual(qualification["run_id"], run_id)
        self.assertEqual(qualification["source"]["forge_revision"], forge_revision)
        self.assertEqual(qualification["source"]["manage_revision"], manage_revision)
        self.assertEqual(qualification["cleanup"], {"disposable_vm": True, "private_state": True})
        self.assertEqual(len(qualification["passed_checks"]), 8)
        self.assertNotIn("generated_at", qualification)

        proof = evidence["runs"][0]["artifacts"][0]
        for field, value in (
            ("cleanup_ok", False),
            ("private_state_cleanup_ok", False),
        ):
            with self.subTest(field=field):
                output.unlink(missing_ok=True)
                proof[field] = value
                evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
                rejected = self.run_tool(*arguments)
                self.assertEqual(rejected.returncode, 2)
                self.assertIn(field.encode(), rejected.stderr)
                proof[field] = True

        output.unlink(missing_ok=True)
        proof["passed_checks"] = proof["passed_checks"][:-1]
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        rejected = self.run_tool(*arguments)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"required passed checks", rejected.stderr)
        proof["passed_checks"].append("guided_installer_service")

        output.unlink(missing_ok=True)
        evidence["SECRET_SENTINEL"] = "must-never-enter-a-release-asset"
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        rejected = self.run_tool(*arguments)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"exact expected set", rejected.stderr)
        self.assertFalse(output.exists())
        del evidence["SECRET_SENTINEL"]

        output.unlink(missing_ok=True)
        proof["release"]["iso_sha256"] = "0" * 64
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        rejected = self.run_tool(*arguments)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"iso_sha256", rejected.stderr)

    def test_installer_iso_options_are_all_or_none_and_fail_closed(self) -> None:
        base = self.manifest_arguments(self.directory / "installer-invalid.json")
        cases = [
            ["--installer-iso", str(self.installer_iso)],
            [
                "--installer-iso-url",
                "https://releases.example.test/v0.1.1/cybex-forge-appliance-0.1.1-x86_64-linux.iso",
            ],
            ["--installer-iso-architecture", "x86_64-linux"],
            [
                "--installer-iso",
                str(self.installer_iso),
                "--installer-iso-url",
                "https://releases.example.test/v0.1.1/not-an-iso.img",
            ],
        ]
        for extra in cases:
            with self.subTest(extra=extra):
                self.assertEqual(self.run_tool(*base, *extra).returncode, 2)

        link_directory = self.directory / "links"
        link_directory.mkdir()
        iso_link = link_directory / "cybex-forge-appliance-0.1.1-x86_64-linux.iso"
        iso_link.symlink_to(self.installer_iso)
        linked = [
            *base,
            "--installer-iso",
            str(iso_link),
            "--installer-iso-url",
            "https://releases.example.test/v0.1.1/cybex-forge-appliance-0.1.1-x86_64-linux.iso",
        ]
        self.assertEqual(self.run_tool(*linked).returncode, 2)

        overwrite = self.manifest_arguments(self.installer_iso)
        overwrite.extend(
            [
                "--installer-iso",
                str(self.installer_iso),
                "--installer-iso-url",
                "https://releases.example.test/v0.1.1/cybex-forge-appliance-0.1.1-x86_64-linux.iso",
            ]
        )
        result = self.run_tool(*overwrite)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"must not overwrite the installer ISO artifact", result.stderr)

    def test_installer_iso_name_and_size_contract_is_fail_closed(self) -> None:
        output = self.directory / "installer-contract.json"
        canonical_url = (
            "https://releases.example.test/v0.1.1/"
            "cybex-forge-appliance-0.1.1-x86_64-linux.iso"
        )

        wrong_name = self.directory / "cybex-forge-appliance-latest-x86_64-linux.iso"
        wrong_name.write_bytes(self.installer_iso.read_bytes())
        wrong_local = self.run_tool(
            *self.manifest_arguments(output),
            "--installer-iso",
            str(wrong_name),
            "--installer-iso-url",
            canonical_url,
        )
        self.assertEqual(wrong_local.returncode, 2)
        self.assertIn(b"must be named", wrong_local.stderr)

        wrong_url = self.run_tool(
            *self.manifest_arguments(output),
            "--installer-iso",
            str(self.installer_iso),
            "--installer-iso-url",
            "https://releases.example.test/v0.1.1/cybex-forge-appliance-latest.iso",
        )
        self.assertEqual(wrong_url.returncode, 2)
        self.assertIn(b"path must end", wrong_url.stderr)

        original = self.installer_iso.read_bytes()
        self.installer_iso.write_bytes(b"")
        empty = self.run_tool(
            *self.manifest_arguments(output),
            "--installer-iso",
            str(self.installer_iso),
            "--installer-iso-url",
            canonical_url,
        )
        self.assertEqual(empty.returncode, 2)
        self.assertIn(b"must not be empty", empty.stderr)

        with self.installer_iso.open("wb") as oversized:
            oversized.truncate(16 * 1024 * 1024 * 1024 + 1)
        too_large = self.run_tool(
            *self.manifest_arguments(output),
            "--installer-iso",
            str(self.installer_iso),
            "--installer-iso-url",
            canonical_url,
        )
        self.assertEqual(too_large.returncode, 2)
        self.assertIn(b"size limit", too_large.stderr)
        self.installer_iso.write_bytes(original)

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

    def test_all_fourteen_dalek_accepted_weak_public_key_encodings_are_rejected(self) -> None:
        weak_keys = WEAK_PUBLIC_KEYS.read_text(encoding="ascii").splitlines()
        self.assertEqual(len(weak_keys), 14)
        self.assertEqual(len(set(weak_keys)), 14)
        decoded = [base64.b64decode(value, validate=True) for value in weak_keys]
        self.assertTrue(all(len(value) == 32 for value in decoded))

        strong = self.run_tool(
            "public-key", "--private-key", str(self.private_key)
        )
        self.assertEqual(strong.returncode, 0, strong.stderr.decode())
        accepted = self.run_tool(
            "validate-public-key",
            "--trusted-public-key",
            strong.stdout.decode().strip(),
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())

        for trusted in weak_keys:
            with self.subTest(trusted=trusted):
                rejected = self.run_tool(
                    "validate-public-key", "--trusted-public-key", trusted
                )
                self.assertEqual(rejected.returncode, 2)
                self.assertIn(b"weak Ed25519 key", rejected.stderr)

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

    def test_private_key_requires_single_link_and_effective_user_ownership(self) -> None:
        hardlink = self.directory / "release-key-hardlink.pem"
        hardlink.hardlink_to(self.private_key)
        result = self.run_tool("public-key", "--private-key", str(self.private_key))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"exactly one hard link", result.stderr)
        hardlink.unlink()

        if os.geteuid() == 0:
            os.chown(self.private_key, 65534, 65534)
            try:
                result = self.run_tool("public-key", "--private-key", str(self.private_key))
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"effective user", result.stderr)
            finally:
                os.chown(self.private_key, 0, 0)

    def test_private_key_must_remain_stable_after_openssl_consumes_the_fd(self) -> None:
        real_openssl = shutil.which("openssl")
        self.assertIsNotNone(real_openssl)
        wrapper_dir = self.directory / "openssl-wrapper"
        wrapper_dir.mkdir()
        wrapper = wrapper_dir / "openssl"
        wrapper.write_text(
            "#!/bin/sh\n"
            f"'{real_openssl}' \"$@\"\n"
            "status=$?\n"
            "printf x >> \"$CYBEX_TEST_PRIVATE_KEY\"\n"
            "exit \"$status\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = f"{wrapper_dir}:{environment['PATH']}"
        environment["CYBEX_TEST_PRIVATE_KEY"] = str(self.private_key)

        result = self.run_tool(
            "public-key", "--private-key", str(self.private_key), env=environment
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn(b"changed while OpenSSL was using it", result.stderr)

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
