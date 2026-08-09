from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
TOOL = REPOSITORY / "tools" / "pulse-release.py"
WEAK_PUBLIC_KEYS = REPOSITORY / "trust" / "ed25519-weak-public-keys.txt"


class PulseReleaseToolTests(unittest.TestCase):
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
        self.artifact = self.directory / "cybex-pulse-x86_64-linux"
        self.artifact.write_bytes(b"deterministic Pulse artifact\0\xff\n")
        self.template = self.directory / (
            "cybex-pulse-appliance-template-0.1.1-x86_64-linux.iso"
        )
        self.personalization_offset = 4096
        media = bytearray(b"Cybex Ubuntu template\n" * 900)
        media[
            self.personalization_offset : self.personalization_offset + 8192
        ] = bytes(8192)
        self.template.write_bytes(media)
        self.provisioning_key = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
        self.compatibility = self.directory / "compatibility.json"
        self.compatibility.write_bytes(
            (REPOSITORY / "protocol" / "compatibility.json").read_bytes()
        )

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
            "https://releases.example.test/v0.1.1/cybex-pulse-x86_64-linux",
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
            "cybex-pulse-appliance-template-0.1.1-x86_64-linux.iso",
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

    def network_package_arguments(self) -> tuple[list[str], Path]:
        snapshot = self.directory / (
            "cybex-pulse-appliance-packages-0.1.1-x86_64-linux.tar.zst"
        )
        snapshot.write_bytes(b"deterministic package snapshot\0\xff\n")
        versions = {
            "cybex-pulse": "0.1.1",
            "cybex-pulse-bootstrap": "0.1.1",
            "cybex-pulse-appliance": "0.1.1",
            "linux-generic": "6.17.0.1.1",
            "linux-firmware": "20260715.git123-0ubuntu1",
            "nix-bin": "2.30.1+dfsg-1",
        }
        metadata = self.directory / "package-snapshot.json"
        metadata.write_text(
            json.dumps(
                {
                    "schema": "cybex.pulse.appliance-package-snapshot.v1",
                    "release_id": "0.1.1",
                    "ubuntu_snapshot_id": "20260804T000000Z",
                    "filename": snapshot.name,
                    "sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                    "size_bytes": snapshot.stat().st_size,
                    "required_package_versions": versions,
                    "expected_kernel": versions["linux-generic"],
                    "minimum_protocol": 4,
                    "minimum_state_schema": 1,
                    "rollback_compatible": True,
                }
            ),
            encoding="utf-8",
        )
        return (
            [
                "--installer-iso-template-package-delivery",
                "network-snapshot-v1",
                "--appliance-package-snapshot",
                str(snapshot),
                "--appliance-package-snapshot-metadata",
                str(metadata),
                "--appliance-package-snapshot-url",
                "https://releases.example.test/v0.1.1/" + snapshot.name,
            ],
            snapshot,
        )

    def workstation_arguments(self) -> tuple[list[str], Path, Path]:
        runtime_version = "2.3.4"
        manage_revision = "a" * 40
        nixpkgs_revision = "b" * 40
        source_date_epoch = 1_770_000_000
        tree = self.directory / "workstation-tree"
        tree.mkdir()
        component_bodies = {
            "bzImage": b"deterministic kernel\0\xff\n",
            "initrd": b"deterministic bootstrap initrd\0\xff\n",
            "nix-store.squashfs": b"deterministic immutable store\0\xff\n",
        }
        components: dict[str, dict[str, object]] = {}
        for name, body in component_bodies.items():
            path = tree / name
            path.write_bytes(body)
            components[name] = {
                "sha256": hashlib.sha256(body).hexdigest(),
                "size_bytes": len(body),
            }
        manifest = {
            "schema": "cybex.pulse.workstation-netboot-manifest.v1",
            "runtime_version": runtime_version,
            "architecture": "x86_64-linux",
            "format": "split-squashfs-v1",
            "required_pulse_protocol": 4,
            "manage_source_revision": manage_revision,
            "nixpkgs_revision": nixpkgs_revision,
            "source_date_epoch": source_date_epoch,
            "toplevel": "/nix/store/00000000000000000000000000000000-cybex-runtime",
            "kernel_cmdline_template": "init=/init cybex.squashfs={squashfs_url}",
            "components": components,
            "provenance": {"builder": "test"},
        }
        manifest_path = tree / "manifest.json"
        manifest_path.write_text(
            json.dumps(
                manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            + "\n",
            encoding="utf-8",
        )
        tar_path = self.directory / "workstation.tar"
        with tarfile.open(tar_path, "w", format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted(["manifest.json", *component_bodies]):
                body = (tree / name).read_bytes()
                entry = tarfile.TarInfo(name)
                entry.size = len(body)
                entry.mode = 0o644
                entry.uid = 0
                entry.gid = 0
                entry.mtime = source_date_epoch
                archive.addfile(entry, io.BytesIO(body))
        bundle = self.directory / (
            f"cybex-workstation-netboot-{runtime_version}-{manage_revision[:12]}-"
            "x86_64-linux.tar.zst"
        )
        subprocess.run(
            [
                "zstd",
                "--quiet",
                "--force",
                "--threads=1",
                "--no-dictID",
                str(tar_path),
                "-o",
                str(bundle),
            ],
            check=True,
        )
        return (
            [
                "--workstation-netboot-bundle",
                str(bundle),
                "--workstation-netboot-tree",
                str(tree),
                "--workstation-netboot-url",
                "https://releases.example.test/v0.1.1/" + bundle.name,
                "--workstation-netboot-runtime-version",
                runtime_version,
                "--workstation-netboot-manage-revision",
                manage_revision,
                "--workstation-netboot-nixpkgs-revision",
                nixpkgs_revision,
            ],
            bundle,
            tree,
        )

    def compatibility_arguments(
        self, output: Path, manifest: Path, *, command: str = "compatibility"
    ) -> list[str]:
        arguments = [
            command,
            "--manifest",
            str(manifest),
            "--manifest-url",
            "https://releases.example.test/v0.1.1/cybex-pulse-release.json",
            "--compatibility",
            str(self.compatibility),
        ]
        if command == "compatibility":
            arguments.extend(
                [
                    "--private-key",
                    str(self.private_key),
                    "--output",
                    str(output),
                ]
            )
        else:
            arguments.extend(
                [
                    "--asset",
                    str(output),
                    "--trusted-public-key",
                    self.public_key(),
                ]
            )
        return arguments

    def write_canonical_json(self, path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )

    def test_component_compatibility_is_semantic_not_byte_or_revision_equality(self) -> None:
        pulse = json.loads(self.compatibility.read_text(encoding="utf-8"))
        manage = json.loads(self.compatibility.read_text(encoding="utf-8"))
        pulse["pulse"]["maximum_manage_protocol"] = 5
        manage["protocol_version"] = 5
        manage["manage"]["maximum_pulse_protocol"] = 5
        manage["pulse"]["maximum_manage_protocol"] = 5
        manage["workstation_runtime"]["resolution_states"].append("future_resolution")
        pulse_path = self.directory / "pulse-compatibility.json"
        manage_path = self.directory / "manage-compatibility.json"
        self.write_canonical_json(pulse_path, pulse)
        self.write_canonical_json(manage_path, manage)

        compatible = self.run_tool(
            "verify-component-compatibility",
            "--pulse-compatibility",
            str(pulse_path),
            "--manage-compatibility",
            str(manage_path),
        )
        self.assertEqual(compatible.returncode, 0, compatible.stderr.decode())
        self.assertIn(b"pulse_protocol=4 manage_protocol=5", compatible.stdout)

        manage["manage"] = {
            "minimum_pulse_protocol": 5,
            "maximum_pulse_protocol": 5,
        }
        self.write_canonical_json(manage_path, manage)
        rejected_protocol = self.run_tool(
            "verify-component-compatibility",
            "--pulse-compatibility",
            str(pulse_path),
            "--manage-compatibility",
            str(manage_path),
        )
        self.assertEqual(rejected_protocol.returncode, 2)
        self.assertIn(b"does not accept selected Pulse protocol 4", rejected_protocol.stderr)

        manage["manage"]["minimum_pulse_protocol"] = 4
        manage["workstation_runtime"]["compatibility_epoch"] += 1
        self.write_canonical_json(manage_path, manage)
        rejected_runtime = self.run_tool(
            "verify-component-compatibility",
            "--pulse-compatibility",
            str(pulse_path),
            "--manage-compatibility",
            str(manage_path),
        )
        self.assertEqual(rejected_runtime.returncode, 2)
        self.assertIn(b"runtime compatibility tuples do not match", rejected_runtime.stderr)

        workflow = (REPOSITORY / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("verify-component-compatibility", workflow)
        self.assertNotIn("cmp --silent protocol/compatibility.json", workflow)

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
        self.assertNotIn("package_delivery", descriptor)
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

    def test_network_package_delivery_is_signed_and_requires_its_snapshot(self) -> None:
        output = self.directory / "network-release.json"
        package_arguments, snapshot = self.network_package_arguments()
        signed = self.run_tool(
            *self.manifest_arguments(output),
            *package_arguments,
        )
        self.assertEqual(signed.returncode, 0, signed.stderr.decode())

        manifest = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["installer_iso_template_v2"]["package_delivery"],
            "network-snapshot-v1",
        )
        self.assertIn("appliance_release_v1", manifest)

        verified = self.run_tool(
            *self.verify_arguments(output),
            "--appliance-package-snapshot",
            str(snapshot),
        )
        self.assertEqual(verified.returncode, 0, verified.stderr.decode())

        missing_snapshot = self.run_tool(
            *self.manifest_arguments(self.directory / "missing-snapshot.json"),
            "--installer-iso-template-package-delivery",
            "network-snapshot-v1",
        )
        self.assertEqual(missing_snapshot.returncode, 2)
        self.assertIn(b"require an appliance package snapshot", missing_snapshot.stderr)

        with snapshot.open("r+b") as oversized_snapshot:
            oversized_snapshot.truncate(4 * 1024 * 1024 * 1024 + 1)
        oversized = self.run_tool(
            *self.manifest_arguments(self.directory / "oversized-snapshot.json"),
            *package_arguments,
        )
        self.assertEqual(oversized.returncode, 2)
        self.assertIn(b"exceeds the 4294967296-byte size limit", oversized.stderr)

    def test_release_compatibility_is_deterministic_canonical_and_verifiable(self) -> None:
        manifest_path = self.directory / "release.json"
        signed = self.run_tool(*self.manifest_arguments(manifest_path))
        self.assertEqual(signed.returncode, 0, signed.stderr.decode())
        original_manifest = manifest_path.read_bytes()
        first = self.directory / "first-compatibility.json"
        second = self.directory / "second-compatibility.json"

        one = self.run_tool(*self.compatibility_arguments(first, manifest_path))
        two = self.run_tool(*self.compatibility_arguments(second, manifest_path))
        self.assertEqual(one.returncode, 0, one.stderr.decode())
        self.assertEqual(two.returncode, 0, two.stderr.decode())
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(manifest_path.read_bytes(), original_manifest)

        asset = json.loads(first.read_text(encoding="utf-8"))
        contract = json.loads(self.compatibility.read_text(encoding="utf-8"))
        self.assertEqual(
            set(asset),
            {
                "schema",
                "pulse_release_version",
                "release_manifest",
                "compatibility",
                "compatibility_sha256",
                "artifacts",
                "public_key",
                "signature",
            },
        )
        self.assertEqual(asset["schema"], "cybex.pulse.release-compatibility.v1")
        self.assertEqual(asset["pulse_release_version"], "0.1.1")
        self.assertEqual(asset["compatibility"], contract)
        canonical_contract = (
            json.dumps(
                contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            + "\n"
        ).encode()
        self.assertEqual(
            asset["compatibility_sha256"],
            hashlib.sha256(canonical_contract).hexdigest(),
        )
        self.assertEqual(
            asset["release_manifest"],
            {
                "url": "https://releases.example.test/v0.1.1/"
                "cybex-pulse-release.json",
                "sha256": hashlib.sha256(original_manifest).hexdigest(),
            },
        )
        manifest = json.loads(original_manifest)
        self.assertNotIn("release_compatibility", manifest)
        self.assertEqual(
            asset["artifacts"]["pulse_binary"], manifest["artifact"]
        )
        self.assertEqual(
            asset["artifacts"]["appliance_iso_template"],
            {
                "url": manifest["installer_iso_template_v2"]["url"],
                "sha256": manifest["installer_iso_template_v2"]["template_sha256"],
                "size_bytes": manifest["installer_iso_template_v2"]["size_bytes"],
            },
        )
        self.assertIsNone(asset["artifacts"]["appliance_package_snapshot"])
        self.assertIsNone(asset["artifacts"]["workstation_runtime"])
        self.assertEqual(asset["public_key"], self.public_key())
        self.assertEqual(len(base64.b64decode(asset["signature"], validate=True)), 64)
        self.assertEqual(
            first.read_bytes(),
            (
                json.dumps(
                    asset,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                + "\n"
            ).encode(),
        )
        release_tool = runpy.run_path(str(TOOL))
        unsigned_asset = dict(asset)
        compatibility_signature = base64.b64decode(
            unsigned_asset.pop("signature"), validate=True
        )
        canonical_unsigned_asset = release_tool["_canonical_json_body"](
            unsigned_asset
        )
        public_der = release_tool["ED25519_PUBLIC_DER_PREFIX"] + base64.b64decode(
            asset["public_key"], validate=True
        )
        release_tool["_self_verify"](
            public_der,
            compatibility_signature,
            b"CYBEX-PULSE-RELEASE-COMPATIBILITY-V1\n"
            + canonical_unsigned_asset,
        )
        with self.assertRaises(release_tool["ReleaseError"]):
            release_tool["_self_verify"](
                public_der, compatibility_signature, canonical_unsigned_asset
            )

        verified = self.run_tool(
            *self.compatibility_arguments(
                first, manifest_path, command="verify-compatibility"
            )
        )
        self.assertEqual(verified.returncode, 0, verified.stderr.decode())
        self.assertIn(asset["compatibility_sha256"].encode(), verified.stdout)

    @unittest.skipUnless(shutil.which("zstd"), "zstd is required")
    def test_release_compatibility_binds_every_published_artifact_identity(self) -> None:
        manifest_path = self.directory / "complete-release.json"
        package_arguments, _snapshot = self.network_package_arguments()
        workstation_arguments, _bundle, _tree = self.workstation_arguments()
        signed = self.run_tool(
            *self.manifest_arguments(manifest_path),
            *package_arguments,
            *workstation_arguments,
        )
        self.assertEqual(signed.returncode, 0, signed.stderr.decode())
        output = self.directory / "complete-compatibility.json"
        generated = self.run_tool(
            *self.compatibility_arguments(output, manifest_path)
        )
        self.assertEqual(generated.returncode, 0, generated.stderr.decode())

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        asset = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(asset["artifacts"]["pulse_binary"], manifest["artifact"])
        self.assertEqual(
            asset["artifacts"]["appliance_package_snapshot"],
            manifest["appliance_release_v1"]["cybex_repository_snapshot"],
        )
        expected_runtime = dict(manifest["workstation_netboot"])
        expected_runtime.pop("signature")
        self.assertEqual(
            asset["artifacts"]["workstation_runtime"], expected_runtime
        )
        self.assertEqual(
            asset["artifacts"]["workstation_runtime"]["components"],
            manifest["workstation_netboot"]["components"],
        )
        verified = self.run_tool(
            *self.compatibility_arguments(
                output, manifest_path, command="verify-compatibility"
            )
        )
        self.assertEqual(verified.returncode, 0, verified.stderr.decode())

    def test_release_compatibility_verification_fails_closed_on_tampering(self) -> None:
        manifest_path = self.directory / "release.json"
        output = self.directory / "compatibility-asset.json"
        signed = self.run_tool(*self.manifest_arguments(manifest_path))
        self.assertEqual(signed.returncode, 0, signed.stderr.decode())
        generated = self.run_tool(
            *self.compatibility_arguments(output, manifest_path)
        )
        self.assertEqual(generated.returncode, 0, generated.stderr.decode())
        original_asset = json.loads(output.read_text(encoding="utf-8"))

        noncanonical = self.directory / "noncanonical.json"
        noncanonical.write_text(json.dumps(original_asset, indent=2) + "\n")
        rejected = self.run_tool(
            *self.compatibility_arguments(
                noncanonical, manifest_path, command="verify-compatibility"
            )
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"canonical compact sorted JSON", rejected.stderr)

        unknown = self.directory / "unknown-field.json"
        unknown_value = dict(original_asset)
        unknown_value["unexpected"] = True
        self.write_canonical_json(unknown, unknown_value)
        rejected = self.run_tool(
            *self.compatibility_arguments(
                unknown, manifest_path, command="verify-compatibility"
            )
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"exact expected set", rejected.stderr)

        bad_signature = self.directory / "bad-signature.json"
        bad_signature_value = dict(original_asset)
        signature = bytearray(base64.b64decode(bad_signature_value["signature"]))
        signature[0] ^= 1
        bad_signature_value["signature"] = base64.b64encode(signature).decode()
        self.write_canonical_json(bad_signature, bad_signature_value)
        rejected = self.run_tool(
            *self.compatibility_arguments(
                bad_signature, manifest_path, command="verify-compatibility"
            )
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"self-verify", rejected.stderr)

        weak_key = self.directory / "weak-key.json"
        weak_key_value = dict(original_asset)
        weak_key_value["public_key"] = WEAK_PUBLIC_KEYS.read_text(
            encoding="ascii"
        ).splitlines()[0]
        self.write_canonical_json(weak_key, weak_key_value)
        rejected = self.run_tool(
            *self.compatibility_arguments(
                weak_key, manifest_path, command="verify-compatibility"
            )
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"weak Ed25519 key", rejected.stderr)

        changed_contract = self.directory / "changed-compatibility.json"
        contract = json.loads(self.compatibility.read_text(encoding="utf-8"))
        contract["workstation_runtime"]["import_states"].append("future_state")
        self.write_canonical_json(changed_contract, contract)
        arguments = self.compatibility_arguments(
            output, manifest_path, command="verify-compatibility"
        )
        arguments[arguments.index("--compatibility") + 1] = str(changed_contract)
        rejected = self.run_tool(*arguments)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"does not exactly match", rejected.stderr)

        arguments = self.compatibility_arguments(
            output, manifest_path, command="verify-compatibility"
        )
        arguments[arguments.index("--manifest-url") + 1] = (
            "https://releases.example.test/v0.1.2/cybex-pulse-release.json"
        )
        rejected = self.run_tool(*arguments)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"does not exactly match", rejected.stderr)

        changed_manifest = self.directory / "changed-release.json"
        changed_manifest.write_bytes(manifest_path.read_bytes() + b"\n")
        arguments = self.compatibility_arguments(
            output, changed_manifest, command="verify-compatibility"
        )
        rejected = self.run_tool(*arguments)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"does not exactly match", rejected.stderr)

    def test_release_compatibility_generation_rejects_unsigned_or_unknown_inputs(self) -> None:
        manifest_path = self.directory / "release.json"
        signed = self.run_tool(*self.manifest_arguments(manifest_path))
        self.assertEqual(signed.returncode, 0, signed.stderr.decode())

        tampered_manifest = self.directory / "tampered-release.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        signature = bytearray(base64.b64decode(manifest["signature"]))
        signature[-1] ^= 1
        manifest["signature"] = base64.b64encode(signature).decode()
        tampered_manifest.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
        rejected = self.run_tool(
            *self.compatibility_arguments(
                self.directory / "tampered-output.json", tampered_manifest
            )
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"self-verify", rejected.stderr)

        unknown_contract = self.directory / "unknown-contract.json"
        contract = json.loads(self.compatibility.read_text(encoding="utf-8"))
        contract["future"] = {}
        self.write_canonical_json(unknown_contract, contract)
        arguments = self.compatibility_arguments(
            self.directory / "unknown-output.json", manifest_path
        )
        arguments[arguments.index("--compatibility") + 1] = str(unknown_contract)
        rejected = self.run_tool(*arguments)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"exact expected set", rejected.stderr)

    def test_release_successor_requires_signed_strict_semver_progression(self) -> None:
        manifest_path = self.directory / "release.json"
        signed = self.run_tool(*self.manifest_arguments(manifest_path))
        self.assertEqual(signed.returncode, 0, signed.stderr.decode())
        previous = self.directory / "previous-compatibility.json"
        generated = self.run_tool(
            *self.compatibility_arguments(previous, manifest_path)
        )
        self.assertEqual(generated.returncode, 0, generated.stderr.decode())

        release_tool = runpy.run_path(str(TOOL))
        previous_asset = json.loads(previous.read_text(encoding="utf-8"))

        def signed_version(version: str, output: Path) -> Path:
            payload = dict(previous_asset)
            payload.pop("signature")
            payload["pulse_release_version"] = version
            message = release_tool["_release_compatibility_message"](payload)
            private_fd = os.open(self.private_key, os.O_RDONLY)
            try:
                signature = release_tool["_sign"](private_fd, message)
            finally:
                os.close(private_fd)
            self.write_canonical_json(
                output,
                {
                    **payload,
                    "signature": base64.b64encode(signature).decode("ascii"),
                },
            )
            return output

        successor = signed_version(
            "0.1.2", self.directory / "successor-compatibility.json"
        )
        accepted = self.run_tool(
            "verify-successor",
            "--previous-compatibility",
            str(previous),
            "--current-compatibility",
            str(successor),
            "--trusted-public-key",
            self.public_key(),
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())

        for version in ("0.1.1", "0.1.0"):
            rejected_asset = signed_version(
                version,
                self.directory / f"rejected-{version}-compatibility.json",
            )
            rejected = self.run_tool(
                "verify-successor",
                "--previous-compatibility",
                str(previous),
                "--current-compatibility",
                str(rejected_asset),
                "--trusted-public-key",
                self.public_key(),
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn(b"greater SemVer precedence", rejected.stderr)

        compare = release_tool["_compare_semver"]
        ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ]
        for previous_version, current_version in zip(ordered, ordered[1:]):
            self.assertLess(compare(previous_version, current_version), 0)
            self.assertGreater(compare(current_version, previous_version), 0)
        self.assertEqual(compare("1.0.0+build.1", "1.0.0+build.2"), 0)

        workflow = (REPOSITORY / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("group: pulse-release-publish", workflow)
        predecessor_check = workflow.rfind("verify-successor")
        immutable_publish = workflow.rfind(
            'gh release edit "$GITHUB_REF_NAME" --draft=false'
        )
        self.assertGreater(predecessor_check, 0)
        self.assertLess(predecessor_check, immutable_publish)

    @unittest.skipUnless(shutil.which("zstd"), "zstd is required")
    def test_runtime_epoch_change_requires_a_new_signed_bundle_identity(self) -> None:
        previous_manifest = self.directory / "previous-release.json"
        workstation_arguments, bundle, tree = self.workstation_arguments()
        signed = self.run_tool(
            *self.manifest_arguments(previous_manifest),
            *workstation_arguments,
        )
        self.assertEqual(signed.returncode, 0, signed.stderr.decode())
        previous_asset = self.directory / "previous-compatibility.json"
        generated = self.run_tool(
            *self.compatibility_arguments(previous_asset, previous_manifest)
        )
        self.assertEqual(generated.returncode, 0, generated.stderr.decode())

        next_contract = json.loads(self.compatibility.read_text(encoding="utf-8"))
        next_contract["workstation_runtime"]["compatibility_epoch"] += 1
        next_contract_path = self.directory / "next-compatibility-contract.json"
        self.write_canonical_json(next_contract_path, next_contract)

        def next_compatibility_arguments(output: Path, manifest: Path) -> list[str]:
            arguments = self.compatibility_arguments(output, manifest)
            arguments[arguments.index("--compatibility") + 1] = str(
                next_contract_path
            )
            arguments.extend(
                ["--previous-compatibility", str(previous_asset)]
            )
            return arguments

        rejected = self.run_tool(
            *next_compatibility_arguments(
                self.directory / "relabelled-runtime.json", previous_manifest
            )
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(
            b"bundle SHA-256 must change when its compatibility epoch changes",
            rejected.stderr,
        )

        manifest = json.loads((tree / "manifest.json").read_text(encoding="utf-8"))
        replacement_kernel = b"different epoch-two kernel bytes\n"
        (tree / "bzImage").write_bytes(replacement_kernel)
        manifest["components"]["bzImage"] = {
            "sha256": hashlib.sha256(replacement_kernel).hexdigest(),
            "size_bytes": len(replacement_kernel),
        }
        self.write_canonical_json(tree / "manifest.json", manifest)
        tar_path = self.directory / "next-workstation.tar"
        with tarfile.open(tar_path, "w", format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted(
                ["manifest.json", "bzImage", "initrd", "nix-store.squashfs"]
            ):
                body = (tree / name).read_bytes()
                entry = tarfile.TarInfo(name)
                entry.size = len(body)
                entry.mode = 0o644
                entry.uid = 0
                entry.gid = 0
                entry.mtime = manifest["source_date_epoch"]
                archive.addfile(entry, io.BytesIO(body))
        subprocess.run(
            [
                "zstd",
                "--quiet",
                "--force",
                "--threads=1",
                "--no-dictID",
                str(tar_path),
                "-o",
                str(bundle),
            ],
            check=True,
        )
        current_manifest = self.directory / "current-release.json"
        signed = self.run_tool(
            *self.manifest_arguments(current_manifest),
            *workstation_arguments,
        )
        self.assertEqual(signed.returncode, 0, signed.stderr.decode())
        accepted = self.run_tool(
            *next_compatibility_arguments(
                self.directory / "rotated-runtime.json", current_manifest
            )
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())

        workflow = (REPOSITORY / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("--previous-compatibility", workflow)

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

    @unittest.skipUnless(shutil.which("zstd"), "zstd is required")
    def test_workstation_archive_requires_strict_ustar_headers(self) -> None:
        release_tool = runpy.run_path(str(TOOL))
        verify_ustar = release_tool["_verify_workstation_netboot_ustar"]
        release_error = release_tool["ReleaseError"]

        def archive(name: str, archive_format: int) -> Path:
            tar_path = self.directory / f"{name}.tar"
            with tarfile.open(tar_path, "w", format=archive_format) as output:
                entry = tarfile.TarInfo("manifest.json")
                entry.size = len(b"{}\n")
                entry.mode = 0o644
                output.addfile(entry, io.BytesIO(b"{}\n"))
            compressed = self.directory / f"{name}.tar.zst"
            subprocess.run(
                ["zstd", "--quiet", "--force", str(tar_path), "-o", str(compressed)],
                check=True,
            )
            return compressed

        verify_ustar(archive("strict", tarfile.USTAR_FORMAT))
        with self.assertRaises(release_error):
            verify_ustar(archive("gnu", tarfile.GNU_FORMAT))

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
