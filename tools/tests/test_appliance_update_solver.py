from pathlib import Path
import os
import pwd
import shutil
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
UPDATER = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "usr"
    / "lib"
    / "cybex-james"
    / "cybex-james-appliance-update"
)
APPLIANCE_SOURCE = REPOSITORY / "src" / "appliance.rs"


def _build_package(
    root: Path,
    package: str,
    version: str,
    *,
    depends: str | None = None,
    conflicts: str | None = None,
) -> Path:
    package_root = root / f"build-{package}-{version}"
    control = package_root / "DEBIAN" / "control"
    control.parent.mkdir(parents=True)
    control.parent.chmod(0o755)
    fields = [
        f"Package: {package}",
        f"Version: {version}",
        "Section: misc",
        "Priority: optional",
        "Architecture: all",
        "Maintainer: Cybex test <test@invalid>",
    ]
    if depends is not None:
        fields.append(f"Depends: {depends}")
    if conflicts is not None:
        fields.append(f"Conflicts: {conflicts}")
    fields.append("Description: disposable selective-update solver fixture")
    control.write_text("\n".join(fields) + "\n", encoding="utf-8")
    payload = package_root / "usr" / "share" / package / "fixture"
    payload.parent.mkdir(parents=True)
    payload.write_text(f"{package} {version}\n", encoding="utf-8")
    output = root / "repo" / f"{package}_{version}_all.deb"
    output.parent.mkdir(exist_ok=True)
    built = subprocess.run(
        ["dpkg-deb", "--root-owner-group", "--build", package_root, output],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if built.returncode != 0:
        raise AssertionError(built.stdout + built.stderr)
    return output


def _installed_stanza(package: str, version: str, *, held: bool = False) -> str:
    wanted = "hold" if held else "install"
    return "\n".join(
        [
            f"Package: {package}",
            f"Status: {wanted} ok installed",
            "Priority: optional",
            "Section: misc",
            "Installed-Size: 1",
            "Maintainer: Cybex test <test@invalid>",
            "Architecture: all",
            f"Version: {version}",
            "Description: disposable installed fixture",
            "",
        ]
    )


def _prepare_apt_root(
    root: Path, installed_status: str, *, transport: str = "file"
) -> tuple[list[str], Path]:
    repository = root / "repo"
    packages = subprocess.run(
        ["dpkg-scanpackages", "--multiversion", ".", "/dev/null"],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        text=True,
    ).stdout
    (repository / "Packages").write_text(packages, encoding="utf-8")

    apt_root = root / "apt-root"
    source_parts = apt_root / "etc" / "apt" / "sources.list.d"
    preferences = apt_root / "etc" / "apt" / "preferences.d"
    lists = apt_root / "var" / "lib" / "apt" / "lists"
    archives = apt_root / "var" / "cache" / "apt" / "archives"
    status = apt_root / "var" / "lib" / "dpkg" / "status"
    log = apt_root / "var" / "log" / "apt"
    for directory in (
        source_parts,
        preferences,
        lists / "partial",
        archives / "partial",
        status.parent,
        log,
    ):
        directory.mkdir(parents=True, exist_ok=True)
    source_list = apt_root / "etc" / "apt" / "sources.list"
    repository_uri = repository.as_uri().replace("file:", f"{transport}:", 1)
    source_list.write_text(
        f"deb [trusted=yes] {repository_uri} ./\n", encoding="utf-8"
    )
    status.write_text(installed_status, encoding="utf-8")
    current_user = pwd.getpwuid(os.getuid()).pw_name
    options = [
        "-o",
        f"Dir={apt_root}",
        "-o",
        f"Dir::Etc::sourcelist={source_list}",
        "-o",
        f"Dir::Etc::sourceparts={source_parts}",
        "-o",
        f"Dir::State::status={status}",
        "-o",
        f"Dir::State::lists={lists}",
        "-o",
        f"Dir::Cache::archives={archives}",
        "-o",
        f"Dir::Log={log}",
        "-o",
        "APT::Architecture=amd64",
        "-o",
        f"APT::Sandbox::User={current_user}",
        "-o",
        "Acquire::Languages=none",
        "-o",
        "APT::Install-Recommends=false",
        "-o",
        "APT::Install-Suggests=false",
    ]
    updated = subprocess.run(
        ["apt-get", *options, "update"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if updated.returncode != 0:
        raise AssertionError(updated.stdout + updated.stderr)
    return options, archives


def _run_apt(options: list[str], *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["apt-get", *options, *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


class ApplianceUpdateSolverContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.updater = UPDATER.read_text(encoding="utf-8")
        self.appliance = APPLIANCE_SOURCE.read_text(encoding="utf-8")

    def test_verified_marker_exposes_only_the_three_signed_cybex_roots(self) -> None:
        constant = self.appliance.index("const APPLIANCE_UPDATE_ROOT_PACKAGES")
        constant_end = self.appliance.index("];", constant) + 2
        contract = self.appliance[constant:constant_end]
        for package in (
            "cybex-james",
            "cybex-james-appliance",
            "cybex-james-bootstrap",
        ):
            self.assertEqual(contract.count(f'"{package}"'), 1)
        for installer_anchor in (
            "linux-generic",
            "linux-firmware",
            "nix-bin",
            "python3",
        ):
            self.assertNotIn(f'"{installer_anchor}"', contract)
        self.assertIn(
            ".required_package_versions\n                .get(package)", self.appliance
        )
        self.assertIn(
            '"update_package_versions":update_package_versions', self.appliance
        )

    def test_solver_uses_only_the_isolated_verified_file_repository(self) -> None:
        self.assertIn(
            "URIs: copy:///run/cybex-update-packages", self.updater
        )
        self.assertIn(
            'test -x "$candidate_path/usr/lib/apt/methods/copy"', self.updater
        )
        for option in (
            "Dir::Etc::sourcelist=/run/cybex-update-apt/cybex-update.sources",
            "Dir::Etc::sourceparts=-",
            "Dir::State::lists=/run/cybex-update-apt/lists",
            "Dir::Cache::archives=/run/cybex-update-apt/archives",
        ):
            self.assertIn(option, self.updater)
        self.assertNotIn(
            "install /run/cybex-update-packages/*.deb", self.updater
        )
        self.assertIn(
            'mount -o remount,bind,ro "$candidate_path/run/cybex-update-packages"',
            self.updater,
        )

    def test_simulation_and_apply_share_fail_closed_solver_options(self) -> None:
        simulation = self.updater.index("--simulate --assume-yes")
        apply = self.updater.index("DEBIAN_FRONTEND=noninteractive", simulation)
        verification = self.updater.index(
            "verify_no_package_regression", apply
        )
        self.assertLess(simulation, apply)
        self.assertLess(apply, verification)
        self.assertGreaterEqual(self.updater.count('"${apt_safety_options[@]}"'), 2)
        for option in (
            "--no-remove",
            "--no-allow-downgrades",
            "--no-allow-change-held-packages",
            "--no-install-recommends",
        ):
            self.assertIn(option, self.updater)
        self.assertIn('install "${package_targets[@]}"', self.updater)
        self.assertIn(
            'chroot "$candidate_path" dpkg --compare-versions',
            self.updater,
        )
        self.assertIn("capture_held_packages", self.updater)
        self.assertIn('cmp --silent -- "$held_before" "$held_after"', self.updater)

    def test_failure_evidence_is_bounded_and_reports_stable_codes(self) -> None:
        self.assertIn("(ulimit -f 4096;", self.updater)
        self.assertIn("tail -c 8192", self.updater)
        self.assertIn("failure_reason=package_plan_unsafe", self.updater)
        self.assertIn("failure_reason=package_apply_failed", self.updater)
        self.assertIn("failure_reason=package_state_unsafe", self.updater)
        self.assertIn("failure_stage=candidate_cleanup", self.updater)
        self.assertIn("candidate_created=false", self.updater)
        status = self.updater.index(
            'write_status failed "$failure_stage" 0 "$candidate" "" "$failure_reason"'
        )
        diagnostic = self.updater.index("write_bounded_package_diagnostic")
        self.assertLess(diagnostic, status)

    @unittest.skipUnless(
        shutil.which("apt-get")
        and shutil.which("dpkg-deb")
        and shutil.which("dpkg-scanpackages"),
        "apt-get, dpkg-deb, and dpkg-scanpackages are required",
    )
    def test_real_apt_rejects_hostile_removal_and_downgrade_plans(self) -> None:
        safety = (
            "--no-remove",
            "--no-allow-downgrades",
            "--no-allow-change-held-packages",
            "--no-install-recommends",
        )
        with tempfile.TemporaryDirectory() as temporary:
            removal_root = Path(temporary) / "removal"
            _build_package(
                removal_root,
                "cybex-test-root",
                "2",
                conflicts="cybex-test-victim",
            )
            removal_options, _archives = _prepare_apt_root(
                removal_root,
                _installed_stanza("cybex-test-victim", "1"),
            )
            hostile_removal = _run_apt(
                removal_options,
                "--simulate",
                "install",
                "cybex-test-root=2",
            )
            self.assertEqual(
                hostile_removal.returncode,
                0,
                hostile_removal.stdout + hostile_removal.stderr,
            )
            self.assertIn("Remv cybex-test-victim", hostile_removal.stdout)
            rejected_removal = _run_apt(
                removal_options,
                "--simulate",
                "--assume-yes",
                *safety,
                "install",
                "cybex-test-root=2",
            )
            self.assertNotEqual(rejected_removal.returncode, 0)

            downgrade_root = Path(temporary) / "downgrade"
            _build_package(downgrade_root, "cybex-test-root", "2")
            downgrade_options, _archives = _prepare_apt_root(
                downgrade_root,
                _installed_stanza("cybex-test-root", "3"),
            )
            hostile_downgrade = _run_apt(
                downgrade_options,
                "--simulate",
                "--allow-downgrades",
                "install",
                "cybex-test-root=2",
            )
            self.assertEqual(
                hostile_downgrade.returncode,
                0,
                hostile_downgrade.stdout + hostile_downgrade.stderr,
            )
            self.assertIn("Inst cybex-test-root [3] (2", hostile_downgrade.stdout)
            rejected_downgrade = _run_apt(
                downgrade_options,
                "--simulate",
                "--assume-yes",
                *safety,
                "install",
                "cybex-test-root=2",
            )
            self.assertNotEqual(rejected_downgrade.returncode, 0)

    @unittest.skipUnless(
        shutil.which("apt-get")
        and shutil.which("dpkg-deb")
        and shutil.which("dpkg-scanpackages")
        and Path("/usr/lib/apt/methods/copy").is_file(),
        "apt-get, its copy method, dpkg-deb, and dpkg-scanpackages are required",
    )
    def test_real_apt_stages_exact_local_bytes_before_no_download_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = _build_package(root, "cybex-test-root", "2")
            options, archives = _prepare_apt_root(root, "", transport="copy")
            staged = _run_apt(
                options,
                "--yes",
                "--download-only",
                "--no-remove",
                "--no-allow-downgrades",
                "--no-allow-change-held-packages",
                "--no-install-recommends",
                "install",
                "cybex-test-root=2",
            )
            self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)
            staged_packages = list(archives.glob("cybex-test-root_2_all.deb"))
            self.assertEqual(
                len(staged_packages),
                1,
                f"{staged.stdout}{staged.stderr}\narchives={list(archives.iterdir())}",
            )
            self.assertEqual(staged_packages[0].read_bytes(), package.read_bytes())
            repository_offline = root / "repo-unmounted"
            (root / "repo").rename(repository_offline)
            cached_only = _run_apt(
                options,
                "--yes",
                "--download-only",
                "--no-download",
                "--no-remove",
                "--no-allow-downgrades",
                "--no-allow-change-held-packages",
                "--no-install-recommends",
                "install",
                "cybex-test-root=2",
            )
            self.assertEqual(
                cached_only.returncode,
                0,
                cached_only.stdout + cached_only.stderr,
            )

        staging = self.updater.index("--yes --download-only")
        unmount = self.updater.index(
            'umount "$candidate_path/run/cybex-update-packages"', staging
        )
        no_download = self.updater.index("--yes --no-download", unmount)
        self.assertLess(staging, unmount)
        self.assertLess(unmount, no_download)


if __name__ == "__main__":
    unittest.main()
