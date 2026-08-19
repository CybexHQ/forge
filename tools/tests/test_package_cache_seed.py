from __future__ import annotations

import hashlib
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
EXTRACT_SEED = (
    REPOSITORY / "ubuntu-appliance" / "extract-package-cache-seed.py"
)
SNAPSHOT_ID = "20260805T000000Z"


@unittest.skipUnless(shutil.which("zstd") and shutil.which("dpkg-deb"), "zstd and dpkg-deb are required")
class PackageCacheSeedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.output = self.directory / "output"
        self.output.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build_deb(
        self,
        package_name: str,
        filename: str,
        architecture: str = "amd64",
    ) -> Path:
        root = self.directory / f"root-{filename}"
        control = root / "DEBIAN" / "control"
        control.parent.mkdir(parents=True)
        root.chmod(0o755)
        control.parent.chmod(0o755)
        control.write_text(
            "\n".join(
                [
                    f"Package: {package_name}",
                    "Version: 1.0-1",
                    f"Architecture: {architecture}",
                    "Maintainer: Cybex Test <test@invalid.example>",
                    "Description: package cache seed test fixture",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        package = self.directory / filename
        result = subprocess.run(
            ["dpkg-deb", "--root-owner-group", "--build", str(root), str(package)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            self.fail(result.stderr.decode("utf-8", errors="replace"))
        return package

    def write_snapshot(
        self,
        packages: list[Path],
        *,
        marker: str = SNAPSHOT_ID,
        extra_members: list[tuple[tarfile.TarInfo, bytes]] | None = None,
    ) -> Path:
        archive_path = self.directory / f"snapshot-{len(list(self.directory.glob('*.zst')))}.tar"
        with tarfile.open(archive_path, "w", format=tarfile.USTAR_FORMAT) as archive:
            marker_body = f"{marker}\n".encode("ascii")
            marker_entry = tarfile.TarInfo("./UBUNTU-SNAPSHOT-ID")
            marker_entry.mode = 0o644
            marker_entry.size = len(marker_body)
            archive.addfile(marker_entry, io.BytesIO(marker_body))
            for package in packages:
                archive.add(package, arcname=f"./{package.name}", recursive=False)
            for member, body in extra_members or []:
                archive.addfile(member, io.BytesIO(body) if member.isreg() else None)
        snapshot = archive_path.with_suffix(".tar.zst")
        subprocess.run(
            ["zstd", "-q", "-f", str(archive_path), "-o", str(snapshot)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=True,
        )
        return snapshot

    def write_raw_snapshot(self, body: bytes) -> Path:
        archive_path = self.directory / f"raw-{len(list(self.directory.glob('*.zst')))}.tar"
        archive_path.write_bytes(body)
        snapshot = archive_path.with_suffix(".tar.zst")
        subprocess.run(
            ["zstd", "-q", "-f", str(archive_path), "-o", str(snapshot)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=True,
        )
        return snapshot

    def write_plan(self, packages: list[Path]) -> Path:
        plan = self.directory / "apt-print-uris"
        records = []
        for package in packages:
            digest = hashlib.sha256(package.read_bytes()).hexdigest()
            records.append(
                "'https://snapshot.ubuntu.com/ubuntu/"
                f"{SNAPSHOT_ID}/pool/main/t/test/{package.name}' "
                f"{package.name} {package.stat().st_size} SHA256:{digest}"
            )
        plan.write_text("APT resolver heading\n" + "\n".join(records) + "\n", encoding="utf-8")
        return plan

    def run_extract(
        self,
        snapshot: Path,
        plan: Path,
        *,
        expected_snapshot_id: str = SNAPSHOT_ID,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(EXTRACT_SEED),
                "--snapshot",
                str(snapshot),
                "--expected-ubuntu-snapshot-id",
                expected_snapshot_id,
                "--apt-print-uris",
                str(plan),
                "--output",
                str(self.output),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_extracts_only_current_ubuntu_closure_and_never_old_james_packages(self) -> None:
        selected = self.build_deb("curl", "curl_1.0-1_amd64.deb")
        unused = self.build_deb("obsolete-package", "obsolete-package_1.0-1_amd64.deb")
        james = self.build_deb("cybex-james-old", "cybex-james-old_1.0-1_amd64.deb")
        snapshot = self.write_snapshot([selected, unused, james])
        result = self.run_extract(snapshot, self.write_plan([selected, james]))

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual([path.name for path in self.output.iterdir()], [selected.name])
        self.assertEqual((self.output / selected.name).read_bytes(), selected.read_bytes())
        self.assertIn(b"seeded 1 validated Ubuntu package", result.stdout)

    def test_snapshot_id_mismatch_fails_and_cleans_partial_packages(self) -> None:
        selected = self.build_deb("curl", "curl_1.0-1_amd64.deb")
        snapshot = self.write_snapshot([selected], marker="20260804T000000Z")
        result = self.run_extract(snapshot, self.write_plan([selected]))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"UBUNTU-SNAPSHOT-ID does not match", result.stderr)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_selected_deb_remains_opaque_until_apt_authenticates_it(self) -> None:
        malformed = self.directory / "curl_1.0-1_amd64.deb"
        malformed.write_bytes(b"not a Debian package")
        snapshot = self.write_snapshot([malformed])
        result = self.run_extract(snapshot, self.write_plan([malformed]))

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.output / malformed.name).read_bytes(), malformed.read_bytes())
        self.assertNotIn(b"dpkg", result.stderr)

    def test_same_size_candidate_with_wrong_strong_hash_is_not_seeded(self) -> None:
        authentic = self.build_deb("curl", "curl_1.0-1_amd64.deb")
        plan = self.write_plan([authentic])
        authentic.write_bytes(b"x" * authentic.stat().st_size)
        snapshot = self.write_snapshot([authentic])

        result = self.run_extract(snapshot, plan)

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"seeded 0 validated Ubuntu package", result.stdout)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_plan_requires_sha256_from_the_exact_snapshot(self) -> None:
        selected = self.build_deb("curl", "curl_1.0-1_amd64.deb")
        snapshot = self.write_snapshot([selected])
        plan = self.write_plan([selected])
        plan.write_text(
            plan.read_text(encoding="utf-8").replace("SHA256:", "MD5Sum:"),
            encoding="utf-8",
        )

        weak = self.run_extract(snapshot, plan)
        self.assertNotEqual(weak.returncode, 0)
        self.assertIn(b"lacks a strong SHA256 digest", weak.stderr)

        exact_plan = self.write_plan([selected])
        exact_plan.write_text(
            exact_plan.read_text(encoding="utf-8").replace(
                SNAPSHOT_ID, "20260804T000000Z"
            ),
            encoding="utf-8",
        )
        wrong_snapshot = self.run_extract(snapshot, exact_plan)
        self.assertNotEqual(wrong_snapshot.returncode, 0)
        self.assertIn(b"unexpected package URI", wrong_snapshot.stderr)

    def test_unsafe_deb_archive_members_fail_without_partial_output(self) -> None:
        selected = self.build_deb("curl", "curl_1.0-1_amd64.deb")
        plan = self.write_plan([selected])

        unsafe_members: list[tuple[tarfile.TarInfo, bytes]] = []
        symlink = tarfile.TarInfo(f"./{selected.name}")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "elsewhere"
        unsafe_members.append((symlink, b""))

        nested = tarfile.TarInfo(f"./nested/{selected.name}")
        nested.size = len(b"invalid")
        unsafe_members.append((nested, b"invalid"))

        for member, body in unsafe_members:
            with self.subTest(member=member.name, type=member.type):
                snapshot = self.write_snapshot([], extra_members=[(member, body)])
                result = self.run_extract(snapshot, plan)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(list(self.output.iterdir()), [])

    def test_rejects_large_tar_extensions_before_reading_their_payload(self) -> None:
        selected = self.build_deb("curl", "curl_1.0-1_amd64.deb")
        plan = self.write_plan([selected])

        for extension_type in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME):
            with self.subTest(extension_type=extension_type):
                extension = tarfile.TarInfo("./untrusted-extension")
                extension.type = extension_type
                extension.size = 4 * 1024 * 1024 * 1024
                snapshot = self.write_raw_snapshot(
                    extension.tobuf(format=tarfile.USTAR_FORMAT)
                )

                result = self.run_extract(snapshot, plan)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"unsupported archive member type", result.stderr)
                self.assertEqual(list(self.output.iterdir()), [])

    def test_nonempty_output_is_never_overwritten(self) -> None:
        selected = self.build_deb("curl", "curl_1.0-1_amd64.deb")
        snapshot = self.write_snapshot([selected])
        sentinel = self.output / selected.name
        sentinel.write_bytes(b"preserve me")

        result = self.run_extract(snapshot, self.write_plan([selected]))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"output directory must be empty", result.stderr)
        self.assertEqual(sentinel.read_bytes(), b"preserve me")


if __name__ == "__main__":
    unittest.main()
