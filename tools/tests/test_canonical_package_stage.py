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
STAGER = (
    REPOSITORY
    / "ubuntu-appliance"
    / "qualification"
    / "stage-canonical-package.py"
)
WORKFLOW = REPOSITORY / ".github" / "workflows" / "release.yml"
APPLIANCE_README = REPOSITORY / "ubuntu-appliance" / "README.md"


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


class CanonicalPackageStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "public"
        self.state = self.root / "private"
        self.source = self.root / "source"
        self.artifacts.mkdir(mode=0o755)
        self.state.mkdir(mode=0o700)
        self.source.mkdir(mode=0o700)
        self.version = "0.2.1-dev.13"
        self.filename = (
            f"cybex-james-appliance-packages-{self.version}-x86_64-linux.tar.zst"
        )
        self.package = self.source / self.filename
        self.package.write_bytes(b"exact signed candidate package snapshot\0\xff")
        url = f"https://dev.example.test/james-dev-artifacts/{self.version}/{self.filename}"
        self.manifest = self.source / "cybex-james-release.json"
        self.manifest.write_bytes(
            canonical(
                {
                    "schema": "cybex.james.release.v1",
                    "version": self.version,
                    "appliance_release_v1": {
                        "schema": "cybex.james.appliance-release.v1",
                        "release_id": self.version,
                        "ubuntu_snapshot_id": "20260812T000000Z",
                        "cybex_repository_snapshot": {
                            "url": url,
                            "sha256": digest(self.package.read_bytes()),
                            "size_bytes": self.package.stat().st_size,
                        },
                        "required_package_versions": {},
                        "expected_kernel": "7.0.0-test",
                        "minimum_protocol": 4,
                        "minimum_state_schema": 2,
                        "rollback_compatible": True,
                        "release_notes": "https://dev.example.test/releases/test",
                        "signature": base64.b64encode(bytes(range(64))).decode("ascii"),
                    },
                }
            )
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def command(
        self, action: str, *, owner: str = "acceptance-run-13"
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            sys.executable,
            "-B",
            str(STAGER),
            action,
            "--manifest",
            str(self.manifest),
            "--artifact-root",
            str(self.artifacts),
            "--served-prefix",
            "https://dev.example.test/james-dev-artifacts",
            "--state-dir",
            str(self.state),
            "--owner",
            owner,
        ]
        if action == "stage":
            arguments.extend(["--package-snapshot", str(self.package)])
        return subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    @property
    def target_directory(self) -> Path:
        return self.artifacts / self.version

    @property
    def target(self) -> Path:
        return self.target_directory / self.filename

    @property
    def private_package_temp(self) -> Path:
        manifest = json.loads(self.manifest.read_bytes())
        url = manifest["appliance_release_v1"]["cybex_repository_snapshot"]["url"]
        key = hashlib.sha256(url.encode("ascii")).hexdigest()
        return self.state / f".{key}.json.package.tmp"

    def test_stage_verify_and_cleanup_are_exact_and_idempotent(self) -> None:
        for _attempt in range(2):
            result = self.command("stage")
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), self.package.read_bytes())
        self.assertEqual(os.stat(self.target).st_mode & 0o777, 0o444)
        self.assertEqual(os.stat(self.target_directory).st_mode & 0o777, 0o555)
        self.assertEqual([path.name for path in self.target_directory.iterdir()], [self.filename])
        verified = self.command("verify")
        self.assertEqual(verified.returncode, 0, verified.stderr)

        cleaned = self.command("cleanup")
        self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
        self.assertFalse(self.target_directory.exists())
        cleaned_again = self.command("cleanup")
        self.assertEqual(cleaned_again.returncode, 0, cleaned_again.stderr)

    def test_stage_cleans_a_safe_partial_left_by_an_interrupted_copy(self) -> None:
        self.private_package_temp.write_bytes(b"interrupted private copy")
        self.private_package_temp.chmod(0o400)
        staged = self.command("stage")
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertFalse(self.private_package_temp.exists())
        self.assertEqual(self.target.read_bytes(), self.package.read_bytes())

    def test_does_not_publish_manifest_or_compatibility(self) -> None:
        result = self.command("stage")
        self.assertEqual(result.returncode, 0, result.stderr)
        exposed = [
            str(path.relative_to(self.artifacts))
            for path in self.artifacts.rglob("*")
            if path.is_file()
        ]
        self.assertEqual(exposed, [f"{self.version}/{self.filename}"])

    def test_mismatch_is_rejected_before_exposure(self) -> None:
        value = json.loads(self.manifest.read_bytes())
        value["appliance_release_v1"]["cybex_repository_snapshot"]["sha256"] = "0" * 64
        self.manifest.write_bytes(canonical(value))
        result = self.command("stage")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match its signed descriptor", result.stderr)
        self.assertFalse(self.target_directory.exists())

    def test_existing_different_bytes_are_never_overwritten(self) -> None:
        self.target_directory.mkdir(mode=0o755)
        self.target.write_bytes(b"unrelated existing bytes")
        self.target.chmod(0o444)
        result = self.command("stage")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to adopt an unowned", result.stderr)
        self.assertEqual(self.target.read_bytes(), b"unrelated existing bytes")

    def test_cleanup_requires_the_exact_owner(self) -> None:
        staged = self.command("stage")
        self.assertEqual(staged.returncode, 0, staged.stderr)
        rejected = self.command("cleanup", owner="somebody-else")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("does not match this request", rejected.stderr)
        self.assertTrue(self.target.exists())

    def test_cleanup_never_removes_unowned_existing_package(self) -> None:
        self.target_directory.mkdir(mode=0o755)
        self.target.write_bytes(self.package.read_bytes())
        self.target.chmod(0o444)
        rejected = self.command("cleanup")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("unowned canonical package", rejected.stderr)
        self.assertTrue(self.target.exists())

    def test_cleanup_never_removes_a_package_after_release_promotion(self) -> None:
        staged = self.command("stage")
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.target_directory.chmod(0o700)
        (self.target_directory / "cybex-james-release.json").write_bytes(
            self.manifest.read_bytes()
        )
        self.target_directory.chmod(0o555)
        rejected = self.command("cleanup")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("release directory changed", rejected.stderr)
        self.assertTrue(self.target.exists())

    def test_existing_empty_release_directory_is_preserved(self) -> None:
        self.target_directory.mkdir(mode=0o755)
        original_mode = os.stat(self.target_directory).st_mode & 0o777
        staged = self.command("stage")
        self.assertEqual(staged.returncode, 0, staged.stderr)
        cleaned = self.command("cleanup")
        self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
        self.assertTrue(self.target_directory.is_dir())
        self.assertEqual(
            os.stat(self.target_directory).st_mode & 0o777, original_mode
        )

    def test_private_state_cannot_be_inside_the_served_tree(self) -> None:
        nested_state = self.artifacts / "state"
        nested_state.mkdir(mode=0o700)
        arguments = [
            sys.executable,
            "-B",
            str(STAGER),
            "stage",
            "--manifest",
            str(self.manifest),
            "--package-snapshot",
            str(self.package),
            "--artifact-root",
            str(self.artifacts),
            "--served-prefix",
            "https://dev.example.test/james-dev-artifacts",
            "--state-dir",
            str(nested_state),
            "--owner",
            "acceptance-run-13",
        ]
        rejected = subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("outside the served artifact tree", rejected.stderr)

    def test_staging_lock_cannot_be_a_symlink(self) -> None:
        manifest = json.loads(self.manifest.read_bytes())
        url = manifest["appliance_release_v1"]["cybex_repository_snapshot"]["url"]
        key = hashlib.sha256(url.encode("ascii")).hexdigest()
        unrelated = self.root / "unrelated-lock-target"
        unrelated.write_bytes(b"do not touch")
        (self.state / f"{key}.lock").symlink_to(unrelated)
        rejected = self.command("stage")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("securely open the staging lock", rejected.stderr)
        self.assertEqual(unrelated.read_bytes(), b"do not touch")

    def test_url_must_map_to_the_exact_served_release_path(self) -> None:
        value = json.loads(self.manifest.read_bytes())
        value["appliance_release_v1"]["cybex_repository_snapshot"]["url"] = (
            f"https://dev.example.test/not-served/{self.version}/{self.filename}"
        )
        self.manifest.write_bytes(canonical(value))
        result = self.command("stage")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not map exactly", result.stderr)

    def test_production_legacy_branch_remains_fail_closed_on_canonical_https(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        legacy_branch = workflow[
            workflow.index("legacy_all_debs)") : workflow.index("selective_roots_v2)")
        ]
        self.assertIn("signed_package_url", legacy_branch)
        self.assertIn("--proto '=https'", legacy_branch)
        self.assertIn("qualification_package_transport_url=\"$signed_package_url\"", legacy_branch)
        self.assertNotIn("serve-package-snapshot.py", legacy_branch)
        self.assertNotIn("gh release create", legacy_branch)

    def test_documentation_calls_out_the_github_immutable_release_blocker(self) -> None:
        documentation = APPLIANCE_README.read_text(encoding="utf-8")
        self.assertIn("stage-canonical-package.py stage", documentation)
        self.assertIn("repository immutable-release policy", documentation)
        self.assertIn("fails its canonical", documentation)
        self.assertIn("download\npreflight", documentation)


if __name__ == "__main__":
    unittest.main()
