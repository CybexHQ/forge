from __future__ import annotations

import argparse
from email.message import Message
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import runpy


REPOSITORY = Path(__file__).resolve().parents[2]
GATE = (
    REPOSITORY
    / "ubuntu-appliance"
    / "qualification"
    / "legacy-bridge-gate.py"
)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


class LegacyBridgeGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.packages = self.root / "packages"
        self.packages.mkdir()
        (self.packages / "cybex-james_2_all.deb").write_bytes(
            b"!<arch>\nexact candidate bytes"
        )
        for name, body in (
            ("Packages", b"Package: cybex-james\nVersion: 2\n"),
            ("Packages.gz", b"deterministic gzip fixture"),
            ("Release", b"Suite: resolute\n"),
        ):
            (self.packages / name).write_bytes(body)
        checksum_names = [
            "cybex-james_2_all.deb",
            "Packages",
            "Packages.gz",
            "Release",
        ]
        (self.packages / "SHA256SUMS").write_text(
            "".join(
                f"{digest((self.packages / name).read_bytes())}  {name}\n"
                for name in checksum_names
            ),
            encoding="ascii",
        )
        (self.packages / "UBUNTU-SNAPSHOT-ID").write_text(
            "20260813T120000Z\n", encoding="ascii"
        )
        self.snapshot_bundle = self.write(
            "cybex-james-appliance-packages-0.2.1-dev.13-x86_64-linux.tar.zst",
            b"exact deterministic package snapshot bundle fixture",
        )
        snapshot_body = self.snapshot_bundle.read_bytes()
        self.snapshot_metadata = self.write(
            "snapshot-metadata.json",
            canonical(
                {
                    "schema": "cybex.james.appliance-package-snapshot.v1",
                    "release_id": "0.2.1-dev.13",
                    "ubuntu_snapshot_id": "20260813T120000Z",
                    "manage_origin": "https://manage.example.test",
                    "manage_source_revision": "1" * 40,
                    "manage_source_sha256": "2" * 64,
                    "manage_source_size_bytes": 1,
                    "filename": self.snapshot_bundle.name,
                    "sha256": digest(snapshot_body),
                    "size_bytes": len(snapshot_body),
                    "required_package_versions": {"cybex-james": "2"},
                    "expected_kernel": "7.0.0-1",
                    "minimum_protocol": 4,
                    "minimum_state_schema": 2,
                    "rollback_compatible": True,
                }
            ),
        )
        self.release = canonical(
            {
                "schema": "cybex.james.appliance-release.v1",
                "release_id": "0.2.1-dev.11",
                "ubuntu_snapshot_id": "20260811T120000Z",
            }
        )
        self.state = canonical(
            {
                "schema": "cybex.james.installed-appliance.v1",
                "release": "0.2.1-dev.11",
                "base_os": "ubuntu",
                "base_os_version": "26.04",
                "root_generation": "0",
                "at_rest_protection": "none",
            }
        )
        self.status = b"Package: cybex-james\nStatus: install ok installed\nVersion: 1\n"
        self.qualification = canonical(
            {
                "schema": "cybex.james.ubuntu-appliance-qualification.v1",
                "ok": True,
                "release_version": "0.2.1-dev.11",
                "ubuntu_snapshot_id": "20260811T120000Z",
                "root_generation": "0",
                "secure_boot": True,
                "final_state": "ready",
            }
        )
        self.identity = {
            "schema": "cybex.james.published-appliance-predecessor.v1",
            "github_release_id": 111,
            "tag_name": "v0.2.1-dev.11",
            "release_id": "0.2.1-dev.11",
            "ubuntu_snapshot_id": "20260811T120000Z",
            "update_contract": "legacy_all_debs",
            "release_compatibility_sha256": "3" * 64,
            "release_manifest_sha256": "4" * 64,
            "package_snapshot_sha256": "5" * 64,
            "package_snapshot_size_bytes": 123,
            "appliance_updater_sha256": "6" * 64,
            "packaged_release_sha256": digest(self.release),
        }
        self.policy = {
            "schema": "cybex.james.legacy-update-bridge-policy.v1",
            "predecessor_update_contract": "legacy_all_debs",
            "predecessor": {
                "release_id": "0.2.1-dev.11",
                "ubuntu_snapshot_id": "20260811T120000Z",
                "installed_release_sha256": digest(self.release),
                "installed_state_sha256": digest(self.state),
                "dpkg_status_sha256": digest(self.status),
                "qualification_evidence_sha256": digest(self.qualification),
                "published_identity_sha256": digest(canonical(self.identity)),
            },
            "candidate": {
                "release_id": "0.2.1-dev.13",
                "ubuntu_snapshot_id": "20260813T120000Z",
            },
            "allowed_upgrades": [
                {"package": "cybex-james", "from": "1", "to": "2"}
            ],
            "allowed_additions": [],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, body: bytes) -> Path:
        path = self.root / name
        path.write_bytes(body)
        return path

    def package_set_sha256(self) -> str:
        package = self.packages / "cybex-james_2_all.deb"
        body = package.read_bytes()
        line = f"{digest(body)} {len(body)} {package.name}\n".encode("ascii")
        return digest(line)

    def evidence(
        self,
        *,
        upgrades: list[dict[str, str]] | None = None,
        additions: list[dict[str, str]] | None = None,
        removals: list[dict[str, str]] | None = None,
        predecessor_release: str | None = None,
        policy: dict[str, object] | None = None,
        identity: dict[str, object] | None = None,
    ) -> bytes:
        selected_identity = identity or self.identity
        selected_policy = json.loads(canonical(policy or self.policy))
        selected_policy["predecessor"]["published_identity_sha256"] = digest(
            canonical(selected_identity)
        )
        policy_body = canonical(selected_policy)
        value = {
            "schema": "cybex.james.legacy-update-bridge-evidence.v1",
            "ok": True,
            "predecessor_release_id": predecessor_release
            or selected_policy["predecessor"]["release_id"],
            "predecessor_ubuntu_snapshot_id": selected_policy["predecessor"][
                "ubuntu_snapshot_id"
            ],
            "candidate_release_id": selected_policy["candidate"]["release_id"],
            "candidate_ubuntu_snapshot_id": selected_policy["candidate"][
                "ubuntu_snapshot_id"
            ],
            "policy_sha256": digest(policy_body),
            "candidate_package_set_sha256": self.package_set_sha256(),
            "candidate_package_count": 1,
            "installed_release_sha256": digest(self.release),
            "installed_state_sha256": digest(self.state),
            "dpkg_status_sha256": digest(self.status),
            "qualification_evidence_sha256": digest(self.qualification),
            "published_identity_sha256": digest(canonical(selected_identity)),
            "command_contract": (
                "apt-get --simulate --no-download --yes install "
                "/run/cybex-update-packages/*.deb"
            ),
            "apt_version": "apt 3.1.6 (amd64)",
            "upgrades": upgrades
            if upgrades is not None
            else selected_policy["allowed_upgrades"],
            "additions": additions
            if additions is not None
            else selected_policy["allowed_additions"],
            "removals": removals if removals is not None else [],
        }
        return canonical(value)

    def verify(
        self,
        evidence_body: bytes,
        *,
        governed_sha256: str | None = None,
        policy: dict[str, object] | None = None,
        identity: dict[str, object] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        selected_identity = identity or self.identity
        selected_policy = json.loads(canonical(policy or self.policy))
        selected_policy["predecessor"]["published_identity_sha256"] = digest(
            canonical(selected_identity)
        )
        policy_path = self.write("policy.json", canonical(selected_policy))
        identity_path = self.write("predecessor-identity.json", canonical(selected_identity))
        evidence_path = self.write("evidence.json", evidence_body)
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(GATE),
                "verify",
                "--packages-dir",
                str(self.packages),
                "--snapshot-bundle",
                str(self.snapshot_bundle),
                "--snapshot-metadata",
                str(self.snapshot_metadata),
                "--policy",
                str(policy_path),
                "--policy-sha256",
                digest(canonical(selected_policy)),
                "--predecessor-identity",
                str(identity_path),
                "--evidence",
                str(evidence_path),
                "--evidence-sha256",
                governed_sha256 or digest(evidence_body),
                "--candidate-release",
                "0.2.1-dev.13",
                "--candidate-snapshot",
                "20260813T120000Z",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def test_exact_governed_monotone_plan_passes(self) -> None:
        result = self.verify(self.evidence())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("zero downgrades/removals", result.stdout)

    def test_downgrade_is_rejected_by_executable_solver_parser(self) -> None:
        namespace = runpy.run_path(str(GATE), run_name="legacy_bridge_gate")
        with self.assertRaisesRegex(namespace["GateError"], "planned a downgrade"):
            namespace["parse_solver_plan"](
                "Inst bind9-host [2] (1 Ubuntu:26.04 [amd64])\n"
                "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
                Path("/usr/bin/dpkg"),
            )

    def test_verify_rejects_descending_governed_version_transition(self) -> None:
        policy = json.loads(canonical(self.policy))
        policy["allowed_upgrades"] = [
            {
                "package": "cybex-james",
                "from": "0.2.1-dev.12-1",
                "to": "0.2.1-1",
            }
        ]
        body = self.evidence(policy=policy)
        result = self.verify(body, policy=policy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-upgrade version transition", result.stderr)

    def test_policy_cannot_misselect_signed_predecessor_contract(self) -> None:
        identity = json.loads(canonical(self.identity))
        identity["update_contract"] = "selective_roots_v2"
        body = self.evidence(identity=identity)
        result = self.verify(body, identity=identity)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("update contract was misselected", result.stderr)

    def test_packaged_updater_identity_derives_legacy_contract(self) -> None:
        namespace = runpy.run_path(str(GATE), run_name="legacy_bridge_gate")
        repository = self.root / "predecessor-packages"
        package_root = self.root / "appliance-package"
        updater = (
            package_root
            / "usr/lib/cybex-james/cybex-james-appliance-update"
        )
        packaged_release = package_root / "usr/share/cybex-james/appliance-release.json"
        (package_root / "DEBIAN").mkdir(parents=True)
        updater.parent.mkdir(parents=True)
        packaged_release.parent.mkdir(parents=True)
        package_root.chmod(0o755)
        (package_root / "DEBIAN").chmod(0o755)
        (package_root / "usr").chmod(0o755)
        (package_root / "usr/lib").chmod(0o755)
        (package_root / "usr/lib/cybex-james").chmod(0o755)
        (package_root / "DEBIAN/control").write_text(
            "Package: cybex-james-appliance\n"
            "Version: 1-1\n"
            "Architecture: amd64\n"
            "Maintainer: Cybex <support@cybex.net>\n"
            "Description: test fixture\n",
            encoding="ascii",
        )
        updater.write_bytes(
            b"#!/usr/bin/env bash\n"
            b"chroot \"$candidate_path\" /bin/sh -c "
            b"'apt-get --no-download --yes install "
            b"/run/cybex-update-packages/*.deb'\n"
        )
        updater.chmod(0o755)
        packaged_release.write_bytes(self.release)
        repository.mkdir()
        package = repository / "cybex-james-appliance_1-1_amd64.deb"
        subprocess.run(
            ["dpkg-deb", "--root-owner-group", "--build", str(package_root), str(package)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        contract, updater_sha256, release_sha256 = namespace[
            "packaged_updater_identity"
        ](
            repository,
            expected_release="0.2.1-dev.11",
            expected_snapshot="20260811T120000Z",
        )
        self.assertEqual(contract, "legacy_all_debs")
        self.assertEqual(updater_sha256, digest(updater.read_bytes()))
        self.assertEqual(release_sha256, digest(self.release))

    def test_removal_is_rejected(self) -> None:
        body = self.evidence(
            removals=[{"package": "apparmor", "version": "5.0.2"}]
        )
        result = self.verify(body)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("planned package removals", result.stderr)

    def test_unallowlisted_upgrade_and_addition_are_rejected(self) -> None:
        cases = (
            self.evidence(
                upgrades=[{"package": "systemd", "from": "1", "to": "2"}]
            ),
            self.evidence(additions=[{"package": "new-dependency", "version": "1"}]),
        )
        for body in cases:
            with self.subTest(body=body):
                result = self.verify(body)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("allowlist", result.stderr)

    def test_weak_or_missing_predecessor_provenance_is_rejected(self) -> None:
        weak = json.loads(canonical(self.policy))
        del weak["predecessor"]["qualification_evidence_sha256"]
        result = self.verify(self.evidence(), policy=weak)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fields are invalid", result.stderr)

        replay = self.evidence()
        result = self.verify(replay, governed_sha256="0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("governed SHA-256", result.stderr)

    def test_installed_release_must_match_signed_packaged_predecessor(self) -> None:
        identity = json.loads(canonical(self.identity))
        identity["packaged_release_sha256"] = "9" * 64
        body = self.evidence(identity=identity)
        result = self.verify(body, identity=identity)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not the signed predecessor package", result.stderr)

    def test_wrong_predecessor_release_replay_is_rejected(self) -> None:
        result = self.verify(
            self.evidence(predecessor_release="0.2.1-dev.10")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("predecessor_release_id", result.stderr)

    def test_candidate_byte_drift_is_rejected(self) -> None:
        evidence = self.evidence()
        with (self.packages / "cybex-james_2_all.deb").open("ab") as package:
            package.write(b"drift")
        result = self.verify(evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed its internal SHA-256", result.stderr)

    def test_post_solver_rehash_rejects_candidate_mutation(self) -> None:
        namespace = runpy.run_path(str(GATE), run_name="legacy_bridge_gate")
        packages, package_set_sha256 = namespace["candidate_packages"](
            self.packages
        )
        names = [package.name for package in packages]
        with (self.packages / "cybex-james_2_all.deb").open("ab") as package:
            package.write(b"mutated during solver")
        with self.assertRaisesRegex(
            namespace["GateError"], "package bytes changed during the APT solver run"
        ):
            namespace["require_unchanged_package_set"](
                self.packages, names, package_set_sha256
            )

    def test_snapshot_must_move_forward(self) -> None:
        policy = json.loads(canonical(self.policy))
        policy["candidate"]["ubuntu_snapshot_id"] = "20260811T120000Z"
        result = self.verify(self.evidence(), policy=policy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be newer", result.stderr)

    def test_capture_source_hard_codes_the_real_legacy_wildcard_paths(self) -> None:
        source = GATE.read_text(encoding="utf-8")
        self.assertIn('CANDIDATE_PACKAGES_PATH = Path("/run/cybex-update-packages")', source)
        self.assertIn('APT_GET_PATH = Path("/usr/bin/apt-get")', source)
        self.assertIn('DPKG_STATUS_PATH = Path("/var/lib/dpkg/status")', source)
        self.assertIn(
            'INSTALLED_STATE_PATH = Path("/var/lib/cybex-james/control/appliance-release.json")',
            source,
        )
        self.assertIn(
            'exec /usr/bin/apt-get --simulate --no-download --yes install', source
        )
        self.assertNotIn('capture_parser.add_argument("--packages-dir"', source)
        self.assertNotIn('capture_parser.add_argument("--apt-get"', source)
        self.assertNotIn('capture_parser.add_argument("--dpkg-status"', source)
        self.assertNotIn('capture_parser.add_argument("--installed-state"', source)
        self.assertGreaterEqual(
            source.count("require_read_only_candidate_mount(packages_dir)"), 2
        )

    def test_capture_cli_rejects_misleading_predecessor_path_overrides(self) -> None:
        policy = self.write("capture-policy.json", canonical(self.policy))
        identity = self.write("capture-predecessor.json", canonical(self.identity))
        qualification = self.write(
            "predecessor-qualification.json", self.qualification
        )
        dpkg_status = self.write("dpkg-status", self.status)
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(GATE),
                "capture",
                "--policy",
                str(policy),
                "--policy-sha256",
                digest(canonical(self.policy)),
                "--predecessor-identity",
                str(identity),
                "--qualification-evidence",
                str(qualification),
                "--dpkg-status",
                str(dpkg_status),
                "--output",
                str(self.root / "capture.json"),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments: --dpkg-status", result.stderr)

    def test_publish_recheck_rejects_concurrent_predecessor_drift(self) -> None:
        manifest = {
            "schema": "cybex.james.release.v1",
            "version": "0.2.1-dev.11",
            "artifact": {
                "url": (
                    "https://github.example/CybexHQ/forge/releases/download/"
                    "v0.2.1-dev.11/cybex-james-x86_64-linux"
                ),
                "sha256": "7" * 64,
            },
            "appliance_release_v1": {
                "release_id": "0.2.1-dev.11",
                "ubuntu_snapshot_id": "20260811T120000Z",
                "cybex_repository_snapshot": {
                    "url": (
                        "https://github.example/CybexHQ/forge/releases/download/"
                        "v0.2.1-dev.11/cybex-james-appliance-packages-"
                        "0.2.1-dev.11-x86_64-linux.tar.zst"
                    ),
                    "sha256": "5" * 64,
                    "size_bytes": 123,
                },
            },
        }
        manifest_body = canonical(manifest)
        compatibility = {
            "schema": "cybex.james.release-compatibility.v1",
            "james_release_version": "0.2.1-dev.11",
            "release_manifest": {
                "url": (
                    "https://github.example/CybexHQ/forge/releases/download/"
                    "v0.2.1-dev.11/cybex-james-release.json"
                ),
                "sha256": digest(manifest_body),
            },
            "compatibility": {},
        }
        compatibility_body = canonical(compatibility)
        identity = json.loads(canonical(self.identity))
        identity["release_compatibility_sha256"] = digest(compatibility_body)
        identity["release_manifest_sha256"] = digest(manifest_body)
        compatibility_path = self.write("published-compatibility.json", compatibility_body)
        manifest_path = self.write("published-manifest.json", manifest_body)
        identity_path = self.write("qualified-predecessor.json", canonical(identity))
        verifier = self.write("fake-release-verifier.py", b"raise SystemExit(0)\n")
        command = [
            sys.executable,
            "-B",
            str(GATE),
            "recheck-predecessor",
            "--qualified-identity",
            str(identity_path),
            "--compatibility",
            str(compatibility_path),
            "--manifest",
            str(manifest_path),
            "--trusted-public-key",
            "test-public-key",
            "--release-verifier",
            str(verifier),
            "--github-release-id",
            "222",
            "--tag-name",
            "v0.2.1-dev.11",
            "--package-snapshot-sha256",
            "5" * 64,
            "--package-snapshot-size",
            "123",
        ]
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("changed after qualification", result.stderr)

        package_drift_command = list(command)
        package_drift_command[package_drift_command.index("222")] = "111"
        package_drift_command[package_drift_command.index("5" * 64)] = "8" * 64
        result = subprocess.run(
            package_drift_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("package bytes changed after qualification", result.stderr)

    def test_publish_recheck_accepts_the_exact_qualified_predecessor(self) -> None:
        manifest = {
            "schema": "cybex.james.release.v1",
            "version": "0.2.1-dev.11",
            "artifact": {
                "url": (
                    "https://github.example/CybexHQ/forge/releases/download/"
                    "v0.2.1-dev.11/cybex-james-x86_64-linux"
                ),
                "sha256": "7" * 64,
            },
            "appliance_release_v1": {
                "release_id": "0.2.1-dev.11",
                "ubuntu_snapshot_id": "20260811T120000Z",
                "cybex_repository_snapshot": {
                    "url": (
                        "https://github.example/CybexHQ/forge/releases/download/"
                        "v0.2.1-dev.11/cybex-james-appliance-packages-"
                        "0.2.1-dev.11-x86_64-linux.tar.zst"
                    ),
                    "sha256": "5" * 64,
                    "size_bytes": 123,
                },
            },
        }
        manifest_body = canonical(manifest)
        compatibility = {
            "schema": "cybex.james.release-compatibility.v1",
            "james_release_version": "0.2.1-dev.11",
            "release_manifest": {
                "url": (
                    "https://github.example/CybexHQ/forge/releases/download/"
                    "v0.2.1-dev.11/cybex-james-release.json"
                ),
                "sha256": digest(manifest_body),
            },
            "compatibility": {},
        }
        compatibility_body = canonical(compatibility)
        identity = json.loads(canonical(self.identity))
        identity["release_compatibility_sha256"] = digest(compatibility_body)
        identity["release_manifest_sha256"] = digest(manifest_body)
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(GATE),
                "recheck-predecessor",
                "--qualified-identity",
                str(self.write("exact-predecessor.json", canonical(identity))),
                "--compatibility",
                str(self.write("exact-compatibility.json", compatibility_body)),
                "--manifest",
                str(self.write("exact-manifest.json", manifest_body)),
                "--trusted-public-key",
                "test-public-key",
                "--release-verifier",
                str(self.write("exact-verifier.py", b"raise SystemExit(0)\n")),
                "--github-release-id",
                "111",
                "--tag-name",
                "v0.2.1-dev.11",
                "--package-snapshot-sha256",
                "5" * 64,
                "--package-snapshot-size",
                "123",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unchanged signed predecessor", result.stdout)

    def test_workflow_blocks_signing_on_governed_exact_candidate_gate(self) -> None:
        workflow = (REPOSITORY / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        gate = workflow.index("Require a monotone legacy-update bridge before signing")
        predecessor = workflow.index(
            "Resolve and authenticate latest published predecessor"
        )
        signing = workflow.index("Sign and self-verify release manifests")
        self.assertLess(predecessor, gate)
        self.assertLess(gate, signing)
        self.assertIn("CYBEX_JAMES_LEGACY_BRIDGE_POLICY_SHA256", workflow)
        self.assertIn("CYBEX_JAMES_LEGACY_BRIDGE_EVIDENCE_SHA256", workflow)
        self.assertIn("--snapshot-bundle", workflow[gate:signing])
        self.assertIn("--snapshot-metadata", workflow[gate:signing])
        self.assertIn("--predecessor-identity", workflow[gate:signing])
        self.assertNotIn("CYBEX_JAMES_PREDECESSOR_UPDATE_CONTRACT", workflow)
        self.assertIn("identify-predecessor", workflow[predecessor:gate])
        self.assertIn(
            "steps.published-predecessor.outputs.update_contract == 'legacy_all_debs'",
            workflow,
        )
        self.assertIn("has_predecessor: ${{ steps.published-predecessor.outputs.exists }}", workflow)
        self.assertIn("printf 'exists=false\\n' >> \"$GITHUB_OUTPUT\"", workflow)
        self.assertIn(
            "if: needs.release_build.outputs.has_predecessor == 'true'",
            workflow,
        )
        self.assertIn("test -z \"$previous\"", workflow)
        self.assertIn("test ! -e dist/cybex-james-build-predecessor.json", workflow)
        publish = workflow.index("release_publish:")
        recheck = workflow.index("recheck-predecessor", publish)
        publish_release = workflow.index(
            'gh release edit "$GITHUB_REF_NAME" --draft=false', publish
        )
        self.assertLess(recheck, publish_release)
        self.assertIn("--package-snapshot-sha256", workflow[recheck:publish_release])
        self.assertIn("--package-snapshot-size", workflow[recheck:publish_release])
        self.assertIn("group: james-release-publish", workflow[publish:recheck])
        self.assertIn("cybex-james-qualified-predecessor.json", workflow)
        qualification = workflow.index(
            "Exercise real installed predecessor to exact candidate update"
        )
        upload = workflow.index("Upload bounded qualification evidence", qualification)
        qualification_body = workflow[qualification:upload]
        self.assertIn("case \"$CYBEX_JAMES_PUBLISHED_PREDECESSOR_UPDATE_CONTRACT\"", qualification_body)
        legacy = qualification_body.index("legacy_all_debs)")
        selective = qualification_body.index("selective_roots_v2)")
        self.assertLess(legacy, selective)
        self.assertIn("$signed_package_url", qualification_body[legacy:selective])
        self.assertIn(
            'qualification_package_transport_url="$signed_package_url"',
            qualification_body[legacy:selective],
        )
        self.assertIn(
            "--qualification-package-transport-url",
            qualification_body[selective:],
        )
        self.assertIn("cybex-james-ubuntu-update-qualification.json", workflow)
        self.assertIn("cybex.james.ubuntu-appliance-update-qualification.v1", workflow)
        self.assertIn(".workstation_runtime_operational' \"$evidence\"", workflow)
        self.assertIn(".workstation_runtime_converged' \"$evidence\"", workflow)
        self.assertIn(".builtin_blueprints_deliverable' \"$evidence\"", workflow)

    def test_real_n_to_n_plus_one_harness_requires_activation_and_health(self) -> None:
        harness = (
            REPOSITORY
            / "ubuntu-appliance/qualification/run-update-lifecycle.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'api POST "/v1/james/nodes/$server_device_id/qualification-updates"',
            harness,
        )
        self.assertIn("predecessor_evidence_sha256", harness)
        self.assertIn("candidate_manifest_sha256", harness)
        self.assertIn("reboot_observed:$reboot_observed", harness)
        self.assertIn("release_activated:true", harness)
        self.assertIn("appliance_projection_healthy:true", harness)
        self.assertIn("cybex.james.ubuntu-appliance-update-qualification.v1", harness)


class LocalPublishedPredecessorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "published"
        self.artifacts.mkdir(mode=0o755)
        self.stage_state = self.root / "private-stage-state"
        self.stage_state.mkdir(mode=0o700)
        self.served_prefix = "https://dev.example.test/james-dev-artifacts"
        self.verifier = self.root / "release-verifier.py"
        self.verifier.write_bytes(b"raise SystemExit(0)\n")
        self.namespace = runpy.run_path(str(GATE), run_name="legacy_bridge_gate")
        self.real_stream_https_artifact = self.namespace[
            "stream_https_artifact"
        ]
        self.write_release(
            "0.2.1-dev.11", "20260804T000000Z", selective=False
        )
        self.write_release(
            "0.2.1-dev.12", "20260805T000000Z", selective=True
        )
        staged = self.artifacts / "0.2.1-dev.13"
        staged.mkdir(mode=0o755)
        staged_package = (
            staged
            / "cybex-james-appliance-packages-0.2.1-dev.13-x86_64-linux.tar.zst"
        )
        staged_package.write_bytes(b"unpublished candidate package only")
        staged_package.chmod(0o444)
        staged.chmod(0o555)
        self.write_stage_journal(
            "0.2.1-dev.13", staged_package, owner="acceptance-dev13"
        )

        def exact_local_stream(
            url: str,
            *,
            expected_sha256: str,
            expected_size: int,
            label: str,
        ) -> None:
            del label
            prefix = f"{self.served_prefix}/"
            self.assertTrue(url.startswith(prefix))
            relative = url.removeprefix(prefix)
            self.assertNotIn("..", relative.split("/"))
            body = (self.artifacts / relative).read_bytes()
            self.assertEqual(len(body), expected_size)
            self.assertEqual(digest(body), expected_sha256)

        self.namespace["build_local_predecessor_identity"].__globals__[
            "stream_https_artifact"
        ] = exact_local_stream

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_release(
        self, version: str, snapshot_id: str, *, selective: bool
    ) -> Path:
        directory = self.artifacts / version
        directory.mkdir(mode=0o755)
        package_root = self.root / f"package-root-{version}"
        repository = self.root / f"repository-{version}"
        package_root.mkdir()
        repository.mkdir()
        updater = package_root / "usr/lib/cybex-james/cybex-james-appliance-update"
        packaged_release = package_root / "usr/share/cybex-james/appliance-release.json"
        control = package_root / "DEBIAN/control"
        updater.parent.mkdir(parents=True)
        packaged_release.parent.mkdir(parents=True)
        control.parent.mkdir(parents=True)
        control.parent.chmod(0o755)
        control.write_text(
            "Package: cybex-james-appliance\n"
            f"Version: {version}-1\n"
            "Architecture: amd64\n"
            "Maintainer: Cybex <support@cybex.net>\n"
            "Description: local predecessor fixture\n",
            encoding="ascii",
        )
        if selective:
            updater.write_bytes(
                b"#!/usr/bin/env bash\n"
                b"# cybex.james.verified-appliance-update.v1\n"
                b"package_targets=(cybex-james cybex-james-bootstrap "
                b"cybex-james-appliance)\n"
                b"# --no-remove --no-allow-downgrades "
                b"--no-allow-change-held-packages\n"
            )
        else:
            updater.write_bytes(
                b"#!/usr/bin/env bash\n"
                b"chroot \"$candidate_path\" /bin/sh -c "
                b"'apt-get --no-download --yes install "
                b"/run/cybex-update-packages/*.deb'\n"
            )
        updater.chmod(0o755)
        packaged_release.write_bytes(
            canonical(
                {
                    "schema": "cybex.james.appliance-release.v1",
                    "release_id": version,
                    "ubuntu_snapshot_id": snapshot_id,
                }
            )
        )
        deb = repository / f"cybex-james-appliance_{version}-1_amd64.deb"
        subprocess.run(
            [
                "dpkg-deb",
                "--root-owner-group",
                "--build",
                str(package_root),
                str(deb),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        for name, body in (
            ("Packages", b"Package: cybex-james-appliance\n"),
            ("Packages.gz", b"deterministic gzip fixture\n"),
            ("Release", b"Suite: resolute\n"),
        ):
            (repository / name).write_bytes(body)
        governed = [deb.name, "Packages", "Packages.gz", "Release"]
        (repository / "SHA256SUMS").write_text(
            "".join(
                f"{digest((repository / name).read_bytes())}  {name}\n"
                for name in governed
            ),
            encoding="ascii",
        )
        (repository / "UBUNTU-SNAPSHOT-ID").write_text(
            f"{snapshot_id}\n", encoding="ascii"
        )
        package_name = (
            f"cybex-james-appliance-packages-{version}-x86_64-linux.tar.zst"
        )
        package_snapshot = directory / package_name
        subprocess.run(
            [
                "tar",
                "--zstd",
                "--format=ustar",
                "-cf",
                str(package_snapshot),
                "-C",
                str(repository),
                ".",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        binary = directory / "cybex-james-x86_64-linux"
        template_name = (
            f"cybex-james-appliance-template-{version}-x86_64-linux.iso"
        )
        template = directory / template_name
        netboot_name = (
            f"cybex-workstation-netboot-1.0.{version.rsplit('.', 1)[-1]}-"
            f"{digest(version.encode())[:12]}-x86_64-linux.tar.zst"
        )
        netboot = directory / netboot_name
        binary.write_bytes(f"james binary {version}\n".encode())
        template.write_bytes(f"installer template {version}\n".encode())
        netboot.write_bytes(f"netboot bundle {version}\n".encode())
        artifact_url = lambda name: f"{self.served_prefix}/{version}/{name}"
        manifest = {
            "schema": "cybex.james.release.v1",
            "version": version,
            "release_url": "https://dev.example.test/james",
            "notes_url": "https://dev.example.test/james",
            "published_at": "2026-08-12T00:00:00Z",
            "artifact": {
                "url": artifact_url(binary.name),
                "sha256": digest(binary.read_bytes()),
            },
            "signature": "fixture",
            "installer_iso_template_v2": {
                "version": version,
                "url": artifact_url(template.name),
                "template_sha256": digest(template.read_bytes()),
                "size_bytes": template.stat().st_size,
            },
            "appliance_release_v1": {
                "schema": "cybex.james.appliance-release.v1",
                "release_id": version,
                "ubuntu_snapshot_id": snapshot_id,
                "cybex_repository_snapshot": {
                    "url": artifact_url(package_snapshot.name),
                    "sha256": digest(package_snapshot.read_bytes()),
                    "size_bytes": package_snapshot.stat().st_size,
                },
            },
            "workstation_netboot": {
                "url": artifact_url(netboot.name),
                "sha256": digest(netboot.read_bytes()),
                "size_bytes": netboot.stat().st_size,
            },
        }
        manifest_path = directory / "cybex-james-release.json"
        manifest_path.write_bytes(canonical(manifest))
        compatibility = {
            "schema": "cybex.james.release-compatibility.v1",
            "james_release_version": version,
            "release_manifest": {
                "url": artifact_url(manifest_path.name),
                "sha256": digest(manifest_path.read_bytes()),
            },
            "compatibility": {},
        }
        compatibility_path = directory / "cybex-james-release-compatibility.json"
        compatibility_path.write_bytes(canonical(compatibility))
        checksum_order = [
            binary.name,
            template.name,
            package_snapshot.name,
            netboot.name,
            manifest_path.name,
            compatibility_path.name,
        ]
        (directory / "SHA256SUMS").write_text(
            "".join(
                f"{digest((directory / name).read_bytes())} *{name}\n"
                for name in checksum_order
            ),
            encoding="ascii",
        )
        for path in directory.iterdir():
            path.chmod(0o555 if path == binary else 0o444)
        directory.chmod(0o555)
        return directory

    def write_stage_journal(
        self, release_id: str, package: Path, *, owner: str
    ) -> Path:
        url = f"{self.served_prefix}/{release_id}/{package.name}"
        journal = {
            "schema": "cybex.james.canonical-package-stage.v1",
            "owner": owner,
            "manifest_sha256": "a" * 64,
            "release_id": release_id,
            "url": url,
            "filename": package.name,
            "sha256": digest(package.read_bytes()),
            "size_bytes": package.stat().st_size,
            "directory_created": True,
            "directory_original_mode": 0o555,
        }
        path = self.stage_state / f"{digest(url.encode('ascii'))}.json"
        path.write_bytes(canonical(journal))
        path.chmod(0o600)
        return path

    def arguments(self, *, output: str = "local-identity.json") -> argparse.Namespace:
        return argparse.Namespace(
            artifact_root=self.artifacts,
            staging_state_dir=self.stage_state,
            served_prefix=self.served_prefix,
            trusted_public_key="fixture-public-key",
            release_verifier=self.verifier,
            output=self.root / output,
        )

    def identify(self) -> tuple[dict[str, object], Path]:
        arguments = self.arguments()
        self.namespace["identify_local_predecessor"](arguments)
        return json.loads(arguments.output.read_bytes()), arguments.output

    def test_identifies_highest_exact_seven_file_local_release(self) -> None:
        identity, identity_path = self.identify()
        self.assertEqual(
            identity["schema"],
            "cybex.james.local-published-appliance-predecessor.v1",
        )
        self.assertEqual(identity["release_id"], "0.2.1-dev.12")
        self.assertEqual(identity["ubuntu_snapshot_id"], "20260805T000000Z")
        self.assertEqual(identity["update_contract"], "selective_roots_v2")
        self.assertEqual(identity["published_release_count"], 2)
        self.assertRegex(identity["release_set_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(identity["release_index_sha256"], r"^[0-9a-f]{64}$")
        value, body = self.namespace["load_predecessor_identity"](identity_path)
        self.assertEqual(value["release_id"], "0.2.1-dev.12")
        self.assertEqual(body, canonical(identity))

    def test_exact_local_recheck_passes_then_rejects_a_new_highest_release(self) -> None:
        identity, identity_path = self.identify()
        arguments = self.arguments(output="unused.json")
        arguments.qualified_identity = identity_path
        self.namespace["recheck_local_predecessor"](arguments)
        self.write_release(
            "0.2.1-dev.14", "20260806T000000Z", selective=True
        )
        with self.assertRaisesRegex(
            self.namespace["GateError"], "changed after qualification"
        ):
            self.namespace["recheck_local_predecessor"](arguments)
        self.assertEqual(identity["release_id"], "0.2.1-dev.12")

    def test_higher_malformed_semver_entry_is_never_silently_skipped(self) -> None:
        hostile = self.artifacts / "0.2.1-dev.99"
        hostile.mkdir(mode=0o755)
        (hostile / "partial-release").write_bytes(b"attacker-controlled")
        with self.assertRaisesRegex(
            self.namespace["GateError"], "higher local SemVer entry"
        ):
            self.namespace["build_local_predecessor_identity"](self.arguments())

    def test_higher_package_stage_requires_exact_private_journal(self) -> None:
        staged = self.artifacts / "0.2.1-dev.13"
        arguments = self.arguments()
        arguments.staging_state_dir = None
        with self.assertRaisesRegex(
            self.namespace["GateError"], "private staging journal"
        ):
            self.namespace["build_local_predecessor_identity"](arguments)

        journal = next(self.stage_state.glob("*.json"))
        journal.chmod(0o600)
        value = json.loads(journal.read_bytes())
        value["sha256"] = "0" * 64
        journal.write_bytes(canonical(value))
        journal.chmod(0o600)
        with self.assertRaisesRegex(
            self.namespace["GateError"], "does not bind the exact package stage"
        ):
            self.namespace["build_local_predecessor_identity"](self.arguments())
        self.assertEqual(set(path.name for path in staged.iterdir()), {
            "cybex-james-appliance-packages-0.2.1-dev.13-x86_64-linux.tar.zst"
        })

    def test_lower_excluded_semver_metadata_is_bound_by_recheck(self) -> None:
        legacy = self.artifacts / "0.2.1-dev.10"
        legacy.mkdir(mode=0o755)
        old = legacy / "historical-build.txt"
        old.write_bytes(b"historical")
        identity, identity_path = self.identify()
        arguments = self.arguments(output="unused.json")
        arguments.qualified_identity = identity_path
        old.write_bytes(b"changed historical metadata")
        with self.assertRaisesRegex(
            self.namespace["GateError"], "changed after qualification"
        ):
            self.namespace["recheck_local_predecessor"](arguments)

    def test_local_release_rejects_extra_files_and_noncanonical_urls(self) -> None:
        selected = self.artifacts / "0.2.1-dev.12"
        selected.chmod(0o755)
        extra = selected / "unpublished.json"
        extra.write_bytes(b"{}\n")
        extra.chmod(0o444)
        selected.chmod(0o555)
        with self.assertRaisesRegex(
            self.namespace["GateError"], "higher local SemVer entry"
        ):
            self.namespace["build_local_predecessor_identity"](self.arguments())
        selected.chmod(0o755)
        extra.unlink()
        manifest_path = selected / "cybex-james-release.json"
        manifest_path.chmod(0o644)
        manifest = json.loads(manifest_path.read_bytes())
        manifest["artifact"]["url"] = (
            "https://other.example.test/james-dev-artifacts/0.2.1-dev.12/"
            "cybex-james-x86_64-linux"
        )
        manifest_path.write_bytes(canonical(manifest))
        manifest_path.chmod(0o444)
        compatibility_path = selected / "cybex-james-release-compatibility.json"
        compatibility_path.chmod(0o644)
        compatibility = json.loads(compatibility_path.read_bytes())
        compatibility["release_manifest"]["sha256"] = digest(
            manifest_path.read_bytes()
        )
        compatibility_path.write_bytes(canonical(compatibility))
        compatibility_path.chmod(0o444)
        checksum_path = selected / "SHA256SUMS"
        checksum_path.chmod(0o644)
        lines = checksum_path.read_text(encoding="ascii").splitlines()
        lines[-2] = f"{digest(manifest_path.read_bytes())} *cybex-james-release.json"
        lines[-1] = (
            f"{digest(compatibility_path.read_bytes())} "
            "*cybex-james-release-compatibility.json"
        )
        checksum_path.write_text("\n".join(lines) + "\n", encoding="ascii")
        checksum_path.chmod(0o444)
        selected.chmod(0o555)
        with self.assertRaisesRegex(
            self.namespace["GateError"], "exact canonical local release URL"
        ):
            self.namespace["build_local_predecessor_identity"](self.arguments())

    def test_https_stream_rejects_redirects_and_content_encoding(self) -> None:
        body = b"exact HTTPS response bytes"

        class Response:
            def __init__(
                self,
                status: int,
                *,
                encoding: str | None = None,
                location: str | None = None,
                content_range: str | None = None,
            ) -> None:
                self.status = status
                self.headers = Message()
                self.headers["Content-Length"] = str(len(body))
                if encoding is not None:
                    self.headers["Content-Encoding"] = encoding
                if location is not None:
                    self.headers["Location"] = location
                if content_range is not None:
                    self.headers["Content-Range"] = content_range
                self._read = False

            def read(self, _size: int) -> bytes:
                if self._read:
                    return b""
                self._read = True
                return body

        class Connection:
            def __init__(self, response: Response) -> None:
                self.response = response
                self.headers: dict[str, str] = {}

            def request(
                self,
                _method: str,
                _path: str,
                *,
                body: object,
                headers: dict[str, str],
            ) -> None:
                self.assert_no_body = body
                self.headers = headers

            def getresponse(self) -> Response:
                return self.response

            def close(self) -> None:
                pass

        def factory(response: Response):
            connection = Connection(response)

            def create(*_args: object, **_kwargs: object) -> Connection:
                return connection

            return connection, create

        success_connection, success_factory = factory(Response(200))
        self.real_stream_https_artifact(
            "https://dev.example.test/exact",
            expected_sha256=digest(body),
            expected_size=len(body),
            label="fixture artifact",
            connection_factory=success_factory,
        )
        self.assertEqual(success_connection.headers["Accept-Encoding"], "identity")
        for response, message in (
            (Response(302), "exact 200"),
            (Response(200, location="https://dev.example.test/other"), "redirect"),
            (Response(200, encoding="gzip"), "content encoding"),
            (
                Response(
                    200,
                    content_range=f"bytes 0-{len(body) - 1}/{len(body)}",
                ),
                "partial",
            ),
        ):
            _connection, create = factory(response)
            with self.assertRaisesRegex(self.namespace["GateError"], message):
                self.real_stream_https_artifact(
                    "https://dev.example.test/exact",
                    expected_sha256=digest(body),
                    expected_size=len(body),
                    label="fixture artifact",
                    connection_factory=create,
                )

        _connection, create = factory(Response(200))
        with self.assertRaisesRegex(
            self.namespace["GateError"], "immutable release set"
        ):
            self.real_stream_https_artifact(
                "https://dev.example.test/exact",
                expected_sha256="0" * 64,
                expected_size=len(body),
                label="fixture artifact",
                connection_factory=create,
            )

    def test_production_workflow_is_byte_identical(self) -> None:
        workflow = (REPOSITORY / ".github/workflows/release.yml").read_bytes()
        self.assertEqual(
            digest(workflow),
            "1aa7d7a10656ed66c6cb0a61f4bcfeb0efe19ed68c3afa5f70e57cab67796831",
        )


if __name__ == "__main__":
    unittest.main()
