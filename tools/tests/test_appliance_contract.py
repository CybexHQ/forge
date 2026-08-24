from pathlib import Path
import hashlib
import json
import os
import grp
import pwd
import runpy
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import urlopen


REPOSITORY = Path(__file__).resolve().parents[2]
FIRST_BOOT = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "usr"
    / "lib"
    / "cybex-james"
    / "cybex-james-first-boot"
)
SERVICE = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "etc"
    / "systemd"
    / "system"
    / "cybex-james.service"
)
FIRST_BOOT_SERVICE = SERVICE.with_name("cybex-james-first-boot.service")
PHYSICAL_CONSOLE_SERVICE = SERVICE.with_name("getty@tty1.service")
NETWORK_RUNTIME_SERVICE = SERVICE.with_name("cybex-james-network-runtime.service")
NETWORK_RUNTIME_TIMER = SERVICE.with_name("cybex-james-network-runtime.timer")
NETWORK_RUNTIME = FIRST_BOOT.with_name("cybex-james-network-runtime")
PHYSICAL_CONSOLE = FIRST_BOOT.with_name("cybex-james-console")
STATE_LAYOUT = FIRST_BOOT.with_name("cybex-james-state-layout")
IPXE_AUTOEXEC = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "usr"
    / "share"
    / "cybex-james"
    / "autoexec.ipxe"
)
PXE_MENU_BACKGROUND = REPOSITORY / "assets" / "pxe-menu.png"
PXE_NGINX_SITE = (
    REPOSITORY
    / "ubuntu-appliance/rootfs/etc/nginx/sites-available/cybex-james"
)
APPLIANCE_UPDATE = FIRST_BOOT.with_name("cybex-james-appliance-update")
GENERATION_COMMIT = FIRST_BOOT.with_name("cybex-james-generation-commit")
POSTINST = REPOSITORY / "ubuntu-appliance" / "package" / "cybex-james-appliance.postinst"
QUALIFICATION_LIFECYCLE = (
    REPOSITORY / "ubuntu-appliance" / "qualification" / "run-lifecycle.sh"
)
VERIFY_PERSONALIZED_MEDIA = QUALIFICATION_LIFECYCLE.with_name(
    "verify-personalized-media.py"
)
NETWORK_CHANGE = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "usr"
    / "lib"
    / "cybex-james"
    / "cybex-james-network-change"
)
NETPLAN_APPLY = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "usr"
    / "lib"
    / "cybex-james"
    / "cybex-james-netplan-apply"
)
NETPLAN_ACTIVATE = NETPLAN_APPLY.with_name("cybex-james-netplan-activate")
BUILD_TEMPLATE = REPOSITORY / "ubuntu-appliance" / "build-template.sh"
AUTOINSTALL_USER_DATA = REPOSITORY / "ubuntu-appliance" / "nocloud" / "user-data"
GRUB_THEME = REPOSITORY / "ubuntu-appliance" / "grub-theme" / "theme.txt"
BUILD_PACKAGE_SNAPSHOT = (
    REPOSITORY / "ubuntu-appliance" / "build-package-snapshot.sh"
)
BUILD_OFFLINE_REPOSITORY = (
    REPOSITORY / "ubuntu-appliance" / "build-offline-repo.sh"
)
EXTRACT_PACKAGE_CACHE_SEED = (
    REPOSITORY / "ubuntu-appliance" / "extract-package-cache-seed.py"
)
SNAPSHOT_RELEASE_DATE = (
    REPOSITORY / "ubuntu-appliance" / "snapshot-release-date.py"
)
BUILD_PACKAGES = REPOSITORY / "ubuntu-appliance" / "build-packages.sh"
BUILD_MANAGE_SOURCE_ARCHIVE = (
    REPOSITORY / "ubuntu-appliance" / "build-manage-source-archive.sh"
)
MANAGE_INSTALLER_REQUIRED_PATHS = (
    "agent/cybex-agent/Cargo.toml",
    "agent/cybex-agent/Cargo.lock",
    "agent/cybex-agent/src/hardware_inventory.rs",
    "agent/cybex-agent/src/installer_boot.rs",
    "agent/cybex-agent/src/lib.rs",
    "agent/cybex-agent/src/main.rs",
    "agent/cybex-agent/src/managed_wifi.rs",
    "deploy/nixos/cybex-agent-module.nix",
    "deploy/nixos/cybex-apply-blueprint.sh",
    "deploy/nixos/cybex-authd-packages.nix",
    "deploy/nixos/cybex-authd.nix",
    "deploy/nixos/cybex-blueprints.nix",
    "deploy/nixos/cybex-himmelblau-packages.nix",
    "deploy/nixos/cybex-himmelblau.nix",
    "deploy/nixos/cybex-ldap.nix",
)
RELEASE_WORKFLOW = REPOSITORY / ".github" / "workflows" / "release.yml"
RUST_BUILD_SCRIPT = REPOSITORY / "build.rs"
PACKAGE_SERVER = (
    REPOSITORY
    / "ubuntu-appliance"
    / "qualification"
    / "serve-package-snapshot.py"
)


def create_manage_source_fixture(root: Path) -> tuple[Path, str]:
    source = root / "manage-source"
    (source / "agent/cybex-agent").mkdir(parents=True)
    (source / "deploy/nixos").mkdir(parents=True)
    (source / "agent/cybex-agent/Cargo.toml").write_text(
        "[package]\nname = \"cybex-agent\"\nversion = \"1.0.14\"\n",
        encoding="utf-8",
    )
    (source / "agent/cybex-agent/Cargo.lock").write_text(
        "# deterministic fixture\nversion = 3\n",
        encoding="utf-8",
    )
    (source / "agent/cybex-agent/src").mkdir()
    agent_sources = {
        "hardware_inventory.rs": "pub fn collect() {}\n",
        "installer_boot.rs": "pub fn prepare() {}\n",
        "lib.rs": "mod hardware_inventory;\nmod installer_boot;\nmod managed_wifi;\n",
        "main.rs": "fn main() {}\n",
        "managed_wifi.rs": "pub fn reconcile() {}\n",
    }
    for name, body in agent_sources.items():
        (source / "agent/cybex-agent/src" / name).write_text(body, encoding="utf-8")
    installer_sources = {
        "cybex-agent-module.nix": (
            "{ ... }: { helper = builtins.readFile ./cybex-apply-blueprint.sh; }\n"
        ),
        "cybex-apply-blueprint.sh": "#!/usr/bin/env bash\nexit 0\n",
        "cybex-authd-packages.nix": "{ pkgs, ... }: { }\n",
        "cybex-authd.nix": (
            "{ ... }: let packages = import ./cybex-authd-packages.nix { }; in { }\n"
        ),
        "cybex-blueprints.nix": (
            "{ ... }: { imports = [ ./cybex-authd.nix ./cybex-ldap.nix "
            "./cybex-himmelblau.nix ]; }\n"
        ),
        "cybex-himmelblau-packages.nix": "{ pkgs, ... }: { }\n",
        "cybex-himmelblau.nix": (
            "{ ... }: let packages = import ./cybex-himmelblau-packages.nix { }; "
            "in { }\n"
        ),
        "cybex-ldap.nix": "{ ... }: { }\n",
    }
    for name, body in installer_sources.items():
        (source / "deploy/nixos" / name).write_text(body, encoding="utf-8")
    (source / "deploy/nixos/cybex-apply-blueprint.sh").chmod(0o755)
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.name", "Cybex test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "test@cybex.invalid"],
        check=True,
    )
    # Prove the archive helper does not inherit a repository-local tar umask.
    subprocess.run(
        ["git", "-C", str(source), "config", "tar.umask", "0077"],
        check=True,
    )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_AUTHOR_DATE": "2026-08-05T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-08-05T00:00:00Z",
        }
    )
    subprocess.run(
        ["git", "-C", str(source), "commit", "-q", "-m", "fixture"],
        env=environment,
        check=True,
    )
    revision = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    return source, revision


class ApplianceFirstBootContractTests(unittest.TestCase):
    def test_snapshot_release_date_is_fixed_and_validated(self) -> None:
        result = subprocess.run(
            [sys.executable, "-B", str(SNAPSHOT_RELEASE_DATE), "20260805T000000Z"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Wed, 05 Aug 2026 00:00:00 +0000\n")

        epoch = subprocess.run(
            [
                sys.executable,
                "-B",
                str(SNAPSHOT_RELEASE_DATE),
                "--epoch",
                "20260805T000000Z",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        self.assertEqual(epoch.returncode, 0, epoch.stderr)
        self.assertEqual(epoch.stdout, "1785888000\n")

        invalid = subprocess.run(
            [sys.executable, "-B", str(SNAPSHOT_RELEASE_DATE), "20260230T000000Z"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("not a real UTC timestamp", invalid.stderr)

    @unittest.skipUnless(shutil.which("apt-ftparchive"), "apt-ftparchive is required")
    def test_fixed_snapshot_date_makes_release_index_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "Packages").write_text("", encoding="utf-8")
            command = [
                "apt-ftparchive",
                "-o",
                "APT::FTPArchive::Release::Date=Wed, 05 Aug 2026 00:00:00 +0000",
                "release",
                ".",
            ]
            first = subprocess.run(
                command,
                cwd=directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout
            second = subprocess.run(
                command,
                cwd=directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout

        self.assertEqual(first, second)
        self.assertIn(b"Date: Wed, 05 Aug 2026 00:00:00 +0000\n", first)

    @unittest.skipUnless(
        shutil.which("dpkg-deb")
        and shutil.which("git")
        and shutil.which("jq")
        and shutil.which("zstd"),
        "dpkg-deb, git, jq, and zstd are required",
    )
    def test_local_cybex_packages_are_byte_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            james = directory / "cybex-james"
            bootstrap = directory / "cybex-james-bootstrap"
            james.write_bytes(b"deterministic James fixture\n")
            bootstrap.write_bytes(b"deterministic bootstrap fixture\n")
            james.chmod(0o755)
            bootstrap.chmod(0o755)
            first = directory / "first"
            second = directory / "second"
            first.mkdir()
            second.mkdir()
            manage_source, manage_revision = create_manage_source_fixture(directory)
            arguments = [
                "--james-binary",
                str(james),
                "--bootstrap-binary",
                str(bootstrap),
                "--version",
                "1.2.3",
                "--ubuntu-snapshot-id",
                "20260805T000000Z",
                "--manage-source-dir",
                str(manage_source),
                "--manage-source-revision",
                manage_revision,
                "--release-public-key",
                "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
                "--provisioning-public-key",
                "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
            ]
            for output in (first, second):
                result = subprocess.run(
                    [str(BUILD_PACKAGES), "--output", str(output), *arguments],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                time.sleep(1.05)

            first_packages = sorted(first.glob("*.deb"))
            second_packages = sorted(second.glob("*.deb"))
            self.assertEqual(
                [package.name for package in first_packages],
                [package.name for package in second_packages],
            )
            self.assertEqual(
                [package.read_bytes() for package in first_packages],
                [package.read_bytes() for package in second_packages],
            )

            appliance = next(
                package
                for package in first_packages
                if package.name.startswith("cybex-james-appliance_")
            )
            james_package = next(
                package
                for package in first_packages
                if package.name.startswith("cybex-james_")
            )
            james_data_root = directory / "james-data"
            subprocess.run(
                ["dpkg-deb", "--extract", str(james_package), str(james_data_root)],
                check=True,
            )
            packaged_source_dir = (
                james_data_root / "usr/share/cybex-james/manage-source"
            )
            packaged_archive = packaged_source_dir / f"{manage_revision}.tar"
            packaged_metadata_path = packaged_source_dir / f"{manage_revision}.json"
            packaged_metadata = json.loads(
                packaged_metadata_path.read_text(encoding="utf-8")
            )
            self.assertEqual(packaged_source_dir.stat().st_mode & 0o777, 0o755)
            self.assertEqual(packaged_archive.stat().st_mode & 0o777, 0o444)
            self.assertEqual(packaged_metadata_path.stat().st_mode & 0o777, 0o444)
            self.assertEqual(packaged_metadata["revision"], manage_revision)
            self.assertEqual(packaged_metadata["filename"], packaged_archive.name)
            self.assertEqual(packaged_metadata["size_bytes"], packaged_archive.stat().st_size)
            self.assertEqual(
                packaged_metadata["sha256"],
                hashlib.sha256(packaged_archive.read_bytes()).hexdigest(),
            )
            with packaged_archive.open("rb") as archive_file:
                embedded_revision = subprocess.run(
                    ["git", "get-tar-commit-id"],
                    stdin=archive_file,
                    stdout=subprocess.PIPE,
                    text=True,
                    check=True,
                ).stdout.strip()
            self.assertEqual(embedded_revision, manage_revision)
            with tarfile.open(packaged_archive, mode="r:") as source_archive:
                source_members = {member.name: member for member in source_archive}
            for required in MANAGE_INSTALLER_REQUIRED_PATHS:
                self.assertIn(required, source_members)
                self.assertTrue(source_members[required].isreg())
                expected_mode = (
                    0o755
                    if required == "deploy/nixos/cybex-apply-blueprint.sh"
                    else 0o644
                )
                self.assertEqual(source_members[required].mode, expected_mode)
            self.assertTrue(
                all(not member.issym() and not member.islnk() for member in source_members.values())
            )

            outer_tar = directory / "package-snapshot.tar"
            with tarfile.open(outer_tar, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                member = tarfile.TarInfo(james_package.name)
                member.size = james_package.stat().st_size
                member.mode = 0o644
                member.uid = 0
                member.gid = 0
                member.mtime = 0
                with james_package.open("rb") as package_file:
                    archive.addfile(member, package_file)
            snapshot = directory / "package-snapshot.tar.zst"
            subprocess.run(
                [
                    "zstd",
                    "-19",
                    "--threads=1",
                    "--no-progress",
                    "--no-dictID",
                    "-o",
                    str(snapshot),
                    str(outer_tar),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            release_tool = runpy.run_path(str(REPOSITORY / "tools/james-release.py"))
            inspected = release_tool["_inspect_packaged_manage_source"](
                snapshot, "1.2.3"
            )
            self.assertEqual(inspected["revision"], manage_revision)
            self.assertEqual(inspected["sha256"], packaged_metadata["sha256"])
            self.assertEqual(inspected["size_bytes"], packaged_metadata["size_bytes"])
            trailing_archive = directory / "manage-source-trailing.tar"
            shutil.copyfile(packaged_archive, trailing_archive)
            with trailing_archive.open("ab") as archive_file:
                archive_file.write(bytes(20 * 512))
            with self.assertRaises(release_tool["ReleaseError"]):
                release_tool["_verify_manage_source_git_archive"](
                    trailing_archive, manage_revision
                )
            truncated_archive = directory / "manage-source-truncated.tar"
            shutil.copyfile(packaged_archive, truncated_archive)
            with truncated_archive.open("r+b") as archive_file:
                archive_file.truncate(packaged_archive.stat().st_size - 512)
            with self.assertRaises(release_tool["ReleaseError"]):
                release_tool["_verify_manage_source_git_archive"](
                    truncated_archive, manage_revision
                )

            data_root = directory / "appliance-data"
            control_root = directory / "appliance-control"
            subprocess.run(
                ["dpkg-deb", "--extract", str(appliance), str(data_root)],
                check=True,
            )
            subprocess.run(
                ["dpkg-deb", "--control", str(appliance), str(control_root)],
                check=True,
            )
            packaged_first_boot = (
                data_root
                / "usr/lib/cybex-james/cybex-james-first-boot"
            ).read_text(encoding="utf-8")
            packaged_netplan_activate = (
                data_root
                / "usr/lib/cybex-james/cybex-james-netplan-activate"
            )
            packaged_physical_console = (
                data_root / "usr/lib/cybex-james/cybex-james-console"
            )
            packaged_physical_console_service = (
                data_root / "etc/systemd/system/getty@tty1.service"
            )
            packaged_ipxe_autoexec = (
                data_root / "usr/share/cybex-james/autoexec.ipxe"
            )
            packaged_pxe_menu_background = (
                data_root
                / "usr/share/cybex-james/assets/pxe-menu.png"
            )
            packaged_pxe_nginx_site = (
                data_root / "etc/nginx/sites-available/cybex-james"
            )
            packaged_postinst = (control_root / "postinst").read_text(
                encoding="utf-8"
            )
            for packaged_script in (packaged_first_boot, packaged_postinst):
                self.assertIn(
                    "install -d -m 0755 -o root -g root "
                    "/var/cache/cybex-james/tftp",
                    packaged_script,
                )
            self.assertIn(
                'install -m 0644 -o root -g root "$source"',
                packaged_first_boot,
            )
            self.assertEqual(
                (
                    data_root
                    / "usr/lib/cybex-james/cybex-james-first-boot"
                ).stat().st_mode
                & 0o777,
                0o755,
            )
            self.assertEqual(
                (control_root / "postinst").stat().st_mode & 0o777,
                0o755,
            )
            self.assertEqual(packaged_netplan_activate.stat().st_mode & 0o777, 0o755)
            self.assertEqual(packaged_physical_console.stat().st_mode & 0o777, 0o755)
            self.assertEqual(
                packaged_physical_console_service.stat().st_mode & 0o777, 0o644
            )
            self.assertEqual(
                packaged_physical_console.read_bytes(), PHYSICAL_CONSOLE.read_bytes()
            )
            self.assertEqual(
                packaged_physical_console_service.read_bytes(),
                PHYSICAL_CONSOLE_SERVICE.read_bytes(),
            )
            self.assertEqual(packaged_ipxe_autoexec.stat().st_mode & 0o777, 0o644)
            self.assertEqual(packaged_ipxe_autoexec.read_bytes(), IPXE_AUTOEXEC.read_bytes())
            self.assertEqual(
                packaged_pxe_menu_background.stat().st_mode & 0o777,
                0o644,
            )
            self.assertEqual(
                packaged_pxe_menu_background.read_bytes(),
                PXE_MENU_BACKGROUND.read_bytes(),
            )
            self.assertEqual(
                packaged_pxe_nginx_site.read_bytes(),
                PXE_NGINX_SITE.read_bytes(),
            )
            pxe_nginx = packaged_pxe_nginx_site.read_text(encoding="utf-8")
            self.assertIn(
                "location = /files/assets/pxe-menu.png {",
                pxe_nginx,
            )
            self.assertIn(
                "alias /usr/share/cybex-james/assets/pxe-menu.png;",
                pxe_nginx,
            )
            self.assertIn(
                'location ~ "^/manage-source/(?<source_file>[0-9a-f]{40}\\.(?:tar|json))$" {',
                pxe_nginx,
            )
            self.assertIn(
                "alias /usr/share/cybex-james/manage-source/$source_file;",
                pxe_nginx,
            )
            self.assertIn("limit_except GET { deny all; }", pxe_nginx)
            self.assertNotIn(
                "location /manage-source/",
                pxe_nginx,
            )
            self.assertNotIn(
                "alias /usr/share/cybex-james/manage-source/;",
                pxe_nginx,
            )
            self.assertIn(
                "10-netplan-cybex-james.network",
                packaged_netplan_activate.read_text(encoding="utf-8"),
            )

    @unittest.skipUnless(
        shutil.which("git") and shutil.which("jq"),
        "git and jq are required",
    )
    def test_manage_source_archive_requires_a_clean_regular_git_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, revision = create_manage_source_fixture(root)
            dirty = source / "untracked"
            dirty.write_text("not in the exact commit\n", encoding="utf-8")
            rejected = subprocess.run(
                [
                    str(BUILD_MANAGE_SOURCE_ARCHIVE),
                    "--source-dir",
                    str(source),
                    "--revision",
                    revision,
                    "--output-dir",
                    str(root / "dirty-output"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("must be exact and clean", rejected.stderr)
            dirty.unlink()

            linked = source / "linked-source"
            linked.symlink_to("agent/cybex-agent/Cargo.toml")
            subprocess.run(
                ["git", "-C", str(source), "add", "linked-source"], check=True
            )
            subprocess.run(
                ["git", "-C", str(source), "commit", "-q", "-m", "linked fixture"],
                check=True,
            )
            linked_revision = subprocess.run(
                ["git", "-C", str(source), "rev-parse", "HEAD"],
                stdout=subprocess.PIPE,
                text=True,
                check=True,
            ).stdout.strip()
            rejected = subprocess.run(
                [
                    str(BUILD_MANAGE_SOURCE_ARCHIVE),
                    "--source-dir",
                    str(source),
                    "--revision",
                    linked_revision,
                    "--output-dir",
                    str(root / "linked-output"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("symlink, submodule, or unsupported", rejected.stderr)

    @unittest.skipUnless(
        shutil.which("git") and shutil.which("jq"),
        "git and jq are required",
    )
    def test_manage_source_contract_rejects_a_partial_installer_source_archive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release_tool = runpy.run_path(str(REPOSITORY / "tools/james-release.py"))
            self.assertEqual(
                release_tool["MANAGE_SOURCE_INSTALLER_REQUIRED_PATHS"],
                frozenset(MANAGE_INSTALLER_REQUIRED_PATHS),
            )
            omitted_paths = (
                "agent/cybex-agent/src/managed_wifi.rs",
                "deploy/nixos/cybex-himmelblau-packages.nix",
            )
            for case_index, omitted_path in enumerate(omitted_paths):
                source, revision = create_manage_source_fixture(
                    root / f"case-{case_index}"
                )
                partial_archive = root / f"partial-manage-source-{case_index}.tar"
                partial_paths = [
                    path
                    for path in MANAGE_INSTALLER_REQUIRED_PATHS
                    if path != omitted_path
                ]
                subprocess.run(
                    [
                        "git",
                        "-c",
                        "tar.umask=0022",
                        "-C",
                        str(source),
                        "archive",
                        "--format=tar",
                        f"--output={partial_archive}",
                        revision,
                        "--",
                        *partial_paths,
                    ],
                    check=True,
                )

                with self.assertRaisesRegex(
                    release_tool["ReleaseError"],
                    "omits a required installer source path",
                ):
                    release_tool["_verify_manage_source_git_archive"](
                        partial_archive, revision
                    )

                (source / omitted_path).unlink()
                subprocess.run(
                    ["git", "-C", str(source), "add", "-u", "--", omitted_path],
                    check=True,
                )
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(source),
                        "commit",
                        "-q",
                        "-m",
                        "partial fixture",
                    ],
                    check=True,
                )
                partial_revision = subprocess.run(
                    ["git", "-C", str(source), "rev-parse", "HEAD"],
                    stdout=subprocess.PIPE,
                    text=True,
                    check=True,
                ).stdout.strip()
                rejected = subprocess.run(
                    [
                        str(BUILD_MANAGE_SOURCE_ARCHIVE),
                        "--source-dir",
                        str(source),
                        "--revision",
                        partial_revision,
                        "--output-dir",
                        str(root / f"partial-output-{case_index}"),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(f"omits required path {omitted_path}", rejected.stderr)

    def test_qualification_package_server_exposes_only_the_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            snapshot = directory / "cybex-james-appliance-packages-1.2.3-x86_64-linux.tar.zst"
            snapshot.write_bytes(b"exact unpublished qualification snapshot\0\xff")
            port_file = directory / "port"
            server = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(PACKAGE_SERVER),
                    "--bind",
                    "127.0.0.1",
                    "--file",
                    str(snapshot),
                    "--port-file",
                    str(port_file),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            try:
                for _attempt in range(100):
                    if port_file.exists():
                        break
                    if server.poll() is not None:
                        self.fail(server.stderr.read().decode())
                    time.sleep(0.01)
                port = int(port_file.read_text(encoding="ascii"))
                origin = f"http://127.0.0.1:{port}"
                with urlopen(f"{origin}/{snapshot.name}", timeout=2) as response:
                    self.assertEqual(response.read(), snapshot.read_bytes())
                with self.assertRaises(HTTPError) as failure:
                    urlopen(f"{origin}/not-the-snapshot", timeout=2)
                self.assertEqual(failure.exception.code, 404)
            finally:
                server.terminate()
                server.wait(timeout=2)
                if server.stderr is not None:
                    server.stderr.close()

    def test_thin_iso_and_package_snapshot_are_built_separately(self) -> None:
        template = BUILD_TEMPLATE.read_text(encoding="utf-8")
        self.assertNotIn("build-offline-repo.sh", template)
        self.assertNotIn("$iso_tree/cybex/apt", template)
        self.assertIn('$iso_tree/cybex/release-public-key', template)
        self.assertIn("network-snapshot-v1", template)
        self.assertIn('rm -rf -- "$iso_tree/pool" "$iso_tree/dists"', template)
        self.assertIn("casper/ubuntu-server-minimal.squashfs", template)
        self.assertIn('live_busybox="$live_root/usr/bin/busybox"', template)
        self.assertIn('"$live_busybox" --list | grep -Fx arping', template)
        self.assertIn("unsquashfs", template)
        self.assertIn("casper/install-sources.yaml", template)
        self.assertIn(
            "casper/ubuntu-server-minimal.ubuntu-server.squashfs", template
        )
        self.assertIn(
            "casper/ubuntu-server-minimal.ubuntu-server.installer.squashfs",
            template,
        )
        self.assertIn("thin installer ISO retained a target package repository", template)
        self.assertIn("hidden_efi_image_sha256", template)
        self.assertIn(
            "remastered ISO changed the hidden UEFI El Torito image bytes",
            template,
        )
        self.assertIn('"$bootstrap_binary" required-manage-origin', template)
        self.assertIn('--expected-manage-origin', template)
        self.assertIn('cmp "$bootstrap_binary" "$embedded_bootstrap"', template)
        self.assertIn('Boot Cybex James Setup', template)
        self.assertIn('set theme=/boot/grub/themes/cybex-james/theme.txt', template)
        self.assertIn('assets/pxe-menu.png', template)
        self.assertTrue(GRUB_THEME.is_file())

        console_arguments = "console=ttyS0,115200n8 console=tty0"
        self.assertIn(console_arguments, template)
        self.assertNotIn("console=tty0 console=ttyS0,115200n8", template)
        user_data = AUTOINSTALL_USER_DATA.read_text(encoding="utf-8")
        self.assertIn("/dev/tty0 /dev/ttyS0", user_data)

        snapshot = BUILD_PACKAGE_SNAPSHOT.read_text(encoding="utf-8")
        self.assertIn("build-offline-repo.sh", snapshot)
        self.assertIn("cybex.james.appliance-package-snapshot.v1", snapshot)
        self.assertIn("--expected-manage-origin", snapshot)
        self.assertIn('"$bootstrap_binary" required-manage-origin', snapshot)
        self.assertIn("build-manage-source-archive.sh", snapshot)
        self.assertIn("manage_source_revision", snapshot)

        package_builder = BUILD_PACKAGES.read_text(encoding="utf-8")
        self.assertIn("build-manage-source-archive.sh", package_builder)
        self.assertIn("usr/share/cybex-james/manage-source", package_builder)
        self.assertIn("iputils-arping", package_builder)
        offline_builder = BUILD_OFFLINE_REPOSITORY.read_text(encoding="utf-8")
        self.assertIn("iputils-arping", offline_builder)
        source_builder = BUILD_MANAGE_SOURCE_ARCHIVE.read_text(encoding="utf-8")
        self.assertIn("git -c tar.umask=0022", source_builder)
        self.assertIn("git get-tar-commit-id", source_builder)
        self.assertIn("cybex.james.manage-source.v1", source_builder)

        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        snapshot_build = workflow.index("build-package-snapshot.sh")
        template_build = workflow.index("build-template.sh")
        self.assertLess(snapshot_build, template_build)
        self.assertIn(
            '--installer-iso-template-package-delivery "$package_delivery"',
            workflow,
        )
        self.assertIn(
            'CYBEX_JAMES_BUILD_MANAGE_ORIGIN="$CYBEX_JAMES_BUILD_MANAGE_ORIGIN"',
            workflow,
        )
        self.assertIn(
            '--expected-manage-origin "$CYBEX_JAMES_BUILD_MANAGE_ORIGIN"',
            workflow,
        )
        self.assertIn("--manage-source-dir manage-source", workflow)
        self.assertIn("--manage-source-revision", workflow)
        self.assertGreaterEqual(
            workflow.count(
                '--expected-manage-origin "$CYBEX_JAMES_BUILD_MANAGE_ORIGIN"'
            ),
            5,
        )
        self.assertEqual(
            workflow.count("--appliance-package-snapshot-metadata"),
            1,
        )
        self.assertIn(
            '"$RUNNER_TEMP/cybex-james-appliance-packages-metadata.json"',
            workflow,
        )
        self.assertIn('--installer-iso-template-metadata', workflow)
        self.assertNotIn(
            'CYBEX_JAMES_BUILD_MANAGE_ORIGIN="$("$RUNNER_TEMP/cybex-james-bootstrap"',
            workflow,
        )
        self.assertNotIn(
            "ubuntu-appliance/rootfs/usr/lib/cybex-james/*", workflow
        )
        self.assertIn("python3 -m py_compile", workflow)
        self.assertIn("squashfs-tools", workflow)
        self.assertIn(
            "cargo:rerun-if-env-changed=CYBEX_JAMES_BUILD_MANAGE_ORIGIN",
            RUST_BUILD_SCRIPT.read_text(encoding="utf-8"),
        )

        provisioning_inventory = (
            REPOSITORY / "src" / "provisioning" / "inventory.rs"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'const LIVE_INSTALLER_BUSYBOX: &str = "/usr/bin/busybox";',
            provisioning_inventory,
        )
        self.assertGreaterEqual(
            provisioning_inventory.count("bounded_live_arping_success("), 3
        )
        self.assertNotIn(
            'bounded_command_success(\n                "arping",',
            provisioning_inventory,
        )

    def test_template_rejects_a_production_bootstrap_for_an_explicit_dev_origin(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            bootstrap = root / "cybex-james-bootstrap"
            bootstrap.write_text(
                "#!/bin/sh\n"
                "test \"${1:-}\" = required-manage-origin || exit 2\n"
                "printf '%s\\n' https://manage.cybex.net\n",
                encoding="utf-8",
            )
            bootstrap.chmod(0o755)
            stubs = root / "stubs"
            stubs.mkdir()
            for command in (
                "curl",
                "gpgv",
                "jq",
                "sha256sum",
                "stat",
                "xorriso",
                "sed",
                "cmp",
                "awk",
            ):
                stub = stubs / command
                stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                stub.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = f"{stubs}:{environment['PATH']}"
            rejected = subprocess.run(
                [
                    str(BUILD_TEMPLATE),
                    "--output-dir",
                    str(output),
                    "--bootstrap-binary",
                    str(bootstrap),
                    "--version",
                    "0.2.1-dev.6",
                    "--ubuntu-snapshot-id",
                    "20260805T000000Z",
                    "--expected-manage-origin",
                    "https://dev.manage.example.test",
                    "--release-public-key",
                    "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
                    "--provisioning-public-key",
                    "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(
                "bootstrap requires https://manage.cybex.net",
                rejected.stderr,
            )
            self.assertIn(
                "explicit expected Management origin is https://dev.manage.example.test",
                rejected.stderr,
            )

    def test_package_snapshot_rejects_a_mismatched_installed_bootstrap_origin(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            manage_source, manage_revision = create_manage_source_fixture(root)
            james = root / "cybex-james"
            james.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            james.chmod(0o755)
            bootstrap = root / "cybex-james-bootstrap"
            bootstrap.write_text(
                "#!/bin/sh\n"
                "test \"${1:-}\" = required-manage-origin || exit 2\n"
                "printf '%s\\n' https://manage.cybex.net\n",
                encoding="utf-8",
            )
            bootstrap.chmod(0o755)
            stubs = root / "stubs"
            stubs.mkdir()
            for command in (
                "apt-ftparchive",
                "apt-get",
                "awk",
                "dpkg-deb",
                "dpkg-scanpackages",
                "gzip",
                "jq",
                "sha256sum",
                "sort",
                "stat",
                "tar",
                "zstd",
            ):
                stub = stubs / command
                stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                stub.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = f"{stubs}:{environment['PATH']}"
            rejected = subprocess.run(
                [
                    str(BUILD_PACKAGE_SNAPSHOT),
                    "--output-dir",
                    str(output),
                    "--james-binary",
                    str(james),
                    "--bootstrap-binary",
                    str(bootstrap),
                    "--version",
                    "0.2.1-dev.6",
                    "--ubuntu-snapshot-id",
                    "20260805T000000Z",
                    "--manage-source-dir",
                    str(manage_source),
                    "--manage-source-revision",
                    manage_revision,
                    "--expected-manage-origin",
                    "https://dev.manage.example.test",
                    "--release-public-key",
                    "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
                    "--provisioning-public-key",
                    "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(
                "package bootstrap requires https://manage.cybex.net",
                rejected.stderr,
            )
            self.assertIn(
                "explicit expected Management origin is https://dev.manage.example.test",
                rejected.stderr,
            )

    def test_previous_package_snapshot_is_only_an_explicit_authenticated_cache_seed(self) -> None:
        snapshot_builder = BUILD_PACKAGE_SNAPSHOT.read_text(encoding="utf-8")
        offline_builder = BUILD_OFFLINE_REPOSITORY.read_text(encoding="utf-8")
        extractor = EXTRACT_PACKAGE_CACHE_SEED.read_text(encoding="utf-8")

        self.assertIn("--previous-package-snapshot", snapshot_builder)
        self.assertIn(
            'previous_snapshot_arguments=(--previous-package-snapshot "$previous_package_snapshot")',
            snapshot_builder,
        )
        self.assertIn("--previous-package-snapshot", offline_builder)
        self.assertNotIn("CYBEX_JAMES_PREVIOUS_PACKAGE_SNAPSHOT", snapshot_builder)
        self.assertNotIn("CYBEX_JAMES_PREVIOUS_PACKAGE_SNAPSHOT", offline_builder)

        update = offline_builder.index('apt-get "${apt_options[@]}" update')
        plan = offline_builder.index("--print-uris")
        extract = offline_builder.index("extract-package-cache-seed.py")
        authenticated_download = offline_builder.index(
            'apt-get "${apt_options[@]}" --yes --download-only --no-install-recommends install'
        )
        self.assertLess(update, plan)
        self.assertLess(plan, extract)
        self.assertLess(extract, authenticated_download)
        self.assertIn('ln -- "$package" "$destination"', offline_builder)
        self.assertIn("Acquire::ForceHash=sha256", offline_builder)
        self.assertIn("snapshot-release-date.py", offline_builder)
        self.assertIn("APT::FTPArchive::Release::Date", offline_builder)

        self.assertIn("MAX_SNAPSHOT_BYTES", extractor)
        self.assertIn("MAX_ARCHIVE_DECOMPRESSED_BYTES", extractor)
        self.assertIn("hashlib.sha256", extractor)
        self.assertIn("APT_SHA256_RE", extractor)
        self.assertIn("parse_ustar_header", extractor)
        self.assertNotIn("tarfile.open", extractor)
        self.assertNotIn("dpkg-deb", extractor)
        self.assertIn('snapshot_marker != expected_marker', extractor)
        self.assertIn('package.name.lower().startswith("cybex-james")', extractor)
        self.assertLess(
            authenticated_download,
            offline_builder.index('architecture="$(dpkg-deb -f "$package" Architecture)"'),
        )

    def test_nix_store_directories_are_checked_individually(self) -> None:
        script = FIRST_BOOT.read_text(encoding="utf-8")
        self.assertIn("test -d /nix/store\n", script)
        self.assertIn("test -d /nix/var/nix/db\n", script)
        self.assertNotIn("test -d /nix/store /nix/var/nix/db", script)

    def test_service_can_read_config_only_after_first_boot_succeeds(self) -> None:
        script = FIRST_BOOT.read_text(encoding="utf-8")
        self.assertIn(
            "chown root:cybex-james /etc/cybex-james/config.toml\n"
            "chmod 0640 /etc/cybex-james/config.toml\n",
            script,
        )

        service = SERVICE.read_text(encoding="utf-8")
        self.assertIn(
            "Requires=cybex-james-first-boot.service "
            "cybex-james-network-runtime.service\n",
            service,
        )
        self.assertIn("cybex-james-network-runtime.service", service)
        self.assertIn("nginx.service tftpd-hpa.service", service)
        self.assertIn(
            "Wants=network-online.target nginx.service tftpd-hpa.service", service
        )
        self.assertNotIn("Requires=nginx.service", service)

    def test_physical_console_is_status_only_and_preserves_recovery_paths(self) -> None:
        console = PHYSICAL_CONSOLE.read_text(encoding="utf-8")
        service = PHYSICAL_CONSOLE_SERVICE.read_text(encoding="utf-8")

        self.assertEqual(PHYSICAL_CONSOLE.stat().st_mode & 0o777, 0o755)
        self.assertEqual(PHYSICAL_CONSOLE_SERVICE.stat().st_mode & 0o777, 0o644)
        self.assertIn("ExecStart=/usr/lib/cybex-james/cybex-james-console", service)
        self.assertIn("Type=idle", service)
        self.assertIn("TTYPath=/dev/tty1", service)
        self.assertIn("Conflicts=rescue.service", service)
        self.assertIn("StandardError=journal", service)
        self.assertNotIn("agetty", service)
        self.assertNotIn("serial-getty", service)
        self.assertNotIn("/bin/login", service)

        self.assertIn("CYBEX JAMES", console)
        self.assertIn("Managed by Cybex Manage", console)
        self.assertIn("Starting", console)
        self.assertIn("Ready", console)
        self.assertIn("Attention needed", console)
        self.assertIn("Check Cybex Manage for status and next steps.", console)
        self.assertIn("cybex_fresh=1", console)
        self.assertIn(".display_name | strings", console)
        self.assertIn("root:cybex-james:640:1", console)
        self.assertNotIn("device_id", console)
        self.assertNotIn("journalctl", console)
        self.assertNotIn("login:", console)

        probe = subprocess.run(
            [
                "bash",
                "-c",
                f"""
source {shlex.quote(str(PHYSICAL_CONSOLE))}
unit_failed() {{ return 1; }}
unit_active() {{ return 0; }}
fresh_health_ready() {{ return 0; }}
update_appliance_state
printf '%s:%s\\n' "$appliance_state" "$non_ready_checks"
fresh_health_ready() {{ return 1; }}
for ((attempt = 0; attempt < attention_after_checks; attempt++)); do
  update_appliance_state
done
printf '%s:%s\\n' "$appliance_state" "$non_ready_checks"
unit_failed() {{ [[ "$1" = cybex-james.service ]]; }}
update_appliance_state
printf '%s:%s\\n' "$appliance_state" "$non_ready_checks"
""",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertEqual(
            probe.stdout.splitlines(),
            ["ready:0", "attention:6", "attention:6"],
        )

        postinst = POSTINST.read_text(encoding="utf-8")
        self.assertIn("getty@tty1.service", postinst)
        self.assertNotIn("serial-getty", postinst)

    def test_service_nix_client_state_is_private_without_weakening_control(self) -> None:
        service = SERVICE.read_text(encoding="utf-8")
        expected_environment = {
            "HOME": "/var/cache/cybex-james/agent/home",
            "XDG_CACHE_HOME": "/var/cache/cybex-james/agent/cache",
            "XDG_CONFIG_HOME": "/var/cache/cybex-james/agent/config",
            "XDG_STATE_HOME": "/var/cache/cybex-james/agent/state",
            "TMPDIR": "/var/cache/cybex-james/agent/tmp",
            "NIX_USER_CONF_FILES": "/dev/null",
        }
        for name, value in expected_environment.items():
            self.assertIn(f"Environment={name}={value}\n", service)
        self.assertIn("ProtectHome=true\n", service)
        self.assertIn(
            "ReadWritePaths=/var/lib/cybex-james /var/cache/cybex-james\n",
            service,
        )

        for script_path in (POSTINST, FIRST_BOOT):
            script = script_path.read_text(encoding="utf-8")
            self.assertIn(
                "install -d -m 0750 -o root -g cybex-james \"$agent_cache\"",
                script,
            )
            self.assertIn("for private in home cache config state tmp; do", script)
            self.assertIn(
                "install -d -m 0700 -o cybex-james -g cybex-james \"$path\"",
                script,
            )
            self.assertIn("! -L \"$agent_cache\"", script)
            self.assertIn("! -L \"$path\"", script)

        first_boot = FIRST_BOOT.read_text(encoding="utf-8")
        self.assertIn(
            "test \"$(stat -c '%U:%G:%a' \"$agent_cache\")\" = "
            "root:cybex-james:750",
            first_boot,
        )
        self.assertIn(
            "test \"$(stat -c '%U:%G:%a' \"$control_dir\")\" = "
            "root:cybex-james:750",
            first_boot,
        )

    def test_first_boot_does_not_wait_for_units_ordered_after_it(self) -> None:
        script = FIRST_BOOT.read_text(encoding="utf-8")
        self.assertNotIn("systemctl enable --now", script)
        self.assertIn(
            "systemctl enable nix-daemon nginx tftpd-hpa "
            "cybex-james-firewall ssh\n",
            script,
        )

    def test_qualification_cold_starts_a_stalled_installed_disk_once(self) -> None:
        script = QUALIFICATION_LIFECYCLE.read_text(encoding="utf-8")
        self.assertIn("validate-manage-origin", script)
        self.assertIn(".installer_iso_template_v2.manage_origin", script)
        verifier = VERIFY_PERSONALIZED_MEDIA.read_text(encoding="utf-8")
        self.assertIn(
            'value.get("manage_origin") != descriptor.get("manage_origin")',
            verifier,
        )
        self.assertIn(
            'installer) boot_arguments=(-boot "once=d,menu=off")', script
        )
        self.assertIn(
            'installed) boot_arguments=(-boot "order=c,menu=off")', script
        )
        self.assertIn("qemu_restart_count=0\n", script)
        self.assertIn("qemu_restart_count=1\n", script)
        self.assertIn("cold_restart_deadline=$((SECONDS + 300))\n", script)
        self.assertIn("-m 32768", script)

    def test_qualification_makes_the_personalized_iso_private_and_writable(self) -> None:
        script = QUALIFICATION_LIFECYCLE.read_text(encoding="utf-8")
        copy = script.index('cp --reflink=auto -- "$template" "$personalized"')
        private_copy = script.index('chmod 0600 "$personalized"', copy)
        personalize = script.index(
            'dd if="$envelope" of="$personalized" bs=1 seek="$personalization_offset"',
            private_copy,
        )
        self.assertLess(copy, private_copy)
        self.assertLess(private_copy, personalize)

    def test_qualification_proves_greenfield_runtime_and_builtin_delivery(self) -> None:
        script = QUALIFICATION_LIFECYCLE.read_text(encoding="utf-8")
        self.assertIn(".source_builds_allowed' \"$delivery_policy\"", script)
        for slug in (
            "standard_taskbar_workstation",
            "dock_workstation",
            "hyprland_developer",
        ):
            self.assertIn(slug, script)
        self.assertIn(".package_ref? // empty", script)
        self.assertIn('index("deno") != null', script)
        self.assertIn('index("nodejs") == null', script)
        self.assertIn(
            'api GET "/v1/james/nodes/$device_id/workstation-netboot"', script
        )
        self.assertIn('"$(jq -er \'.operational\' "$runtime_status")" = true', script)
        self.assertIn('"$(jq -er \'.converged\' "$runtime_status")" = true', script)
        self.assertIn(
            'api GET "/v1/james/nodes/$device_id/build/jobs?limit=200&offset=0"',
            script,
        )
        self.assertIn("source_build_candidates:.cache_metadata.source_build_candidates", script)
        self.assertIn("builtin_blueprints_qualified_on_new_james:true", script)

    def test_root_network_helper_shares_handshake_files_with_james(self) -> None:
        change_script = NETWORK_CHANGE.read_text(encoding="utf-8")
        self.assertIn('temporary="$(mktemp "$status_dir/.appliance-network-change-status.XXXXXX")"', change_script)
        self.assertIn('chown root:cybex-james "$temporary"\n', change_script)
        self.assertIn('chmod 0640 "$temporary"\n', change_script)

        apply_script = NETPLAN_APPLY.read_text(encoding="utf-8")
        self.assertIn("rollback() {\n  trap - ERR\n", apply_script)
        self.assertIn("exit 70", apply_script)
        self.assertIn("candidate_activation) exit 71", apply_script)
        self.assertIn("acknowledgement) exit 72", apply_script)
        self.assertIn('rm -f "$pending" "$backup"', apply_script)
        self.assertIn('test "$(tr -d \'\\n\' < "$pending")" = "$candidate_sha"', apply_script)
        self.assertIn('cmp --silent -- "$active" "$backup"', apply_script)
        backup_commit = apply_script.index('mv -f "$backup_temporary" "$backup"')
        self.assertIn('pending_temporary="$(mktemp "$control_dir/.netplan-pending.XXXXXX")"', apply_script)
        self.assertIn('sync -f "$pending_temporary"\n', apply_script)
        pending_commit = apply_script.index('mv -f "$pending_temporary" "$pending"')
        candidate_replace = apply_script.index('replace_active "$candidate"')
        self.assertLess(backup_commit, pending_commit)
        self.assertLess(pending_commit, candidate_replace)
        commit = apply_script.index('approved_temporary="$(mktemp "$control_dir/.netplan-approved.XXXXXX")"')
        approved_sync = apply_script.index('sync -f "$approved_temporary"', commit)
        approved_rename = apply_script.index(
            'mv -f "$approved_temporary" "$control_dir/netplan-approved.json"',
            approved_sync,
        )
        marker = apply_script.index('"$fallback_marker"', commit)
        directory_sync = apply_script.index('sync -f "$control_dir"', marker)
        self.assertLess(commit, marker)
        self.assertLess(approved_sync, approved_rename)
        self.assertLess(approved_rename, marker)
        self.assertLess(marker, directory_sync)
        self.assertNotIn('"$ack_file"', apply_script[commit:])
        terminal_fence = change_script.index(
            "A crash after the root-owned terminal status commit"
        )
        terminal_cleanup = change_script.index('rm -f "$request" "$ack"', terminal_fence)
        self.assertLess(terminal_fence, terminal_cleanup)
        recovery = change_script.index(
            "verify-appliance-network-change-recovery"
        )
        recovery_compare = change_script.index(
            'cmp --silent -- "$candidate" "$control_dir/netplan-approved.json"',
            recovery,
        )
        recovery_status = change_script.index(
            "write_status acknowledged recovered_commit", recovery_compare
        )
        recovery_cleanup = change_script.index(
            'rm -f "$request" "$ack" "$candidate"', recovery_status
        )
        self.assertLess(recovery_compare, recovery_status)
        self.assertLess(recovery_status, recovery_cleanup)
        success_status = change_script.index("write_status acknowledged committed")
        success_cleanup = change_script.index(
            'rm -f "$request" "$ack" "$candidate"', success_status
        )
        success_sync = change_script.index(
            'sync -f "$state_dir/inbox"', success_cleanup
        )
        self.assertLess(success_status, success_cleanup)
        self.assertLess(success_cleanup, success_sync)
        self.assertIn(
            "write_status failed rollback \"$candidate_sha256\" "
            "network_rollback_failed",
            change_script,
        )
        self.assertIn(
            "write_status rolled_back rollback \"$candidate_sha256\" "
            "candidate_activation_failed",
            change_script,
        )

        guard = FIRST_BOOT.with_name("cybex-james-network-guard").read_text(
            encoding="utf-8"
        )
        self.assertIn('cybex.james.network-fallback.v1', guard)
        self.assertIn('approved_sha256="$(sha256sum "$approved"', guard)
        self.assertNotIn('origin=https://manage.cybex.net', guard)
        self.assertIn('required-manage-origin', guard)
        self.assertIn('"$control_dir/netplan-before-change.yaml"', guard)
        fallback_health = guard.rindex('timeout 60 curl --fail')
        fallback_cleanup = guard.index(
            'rm -f "$control_dir/netplan-pending.sha256"', fallback_health
        )
        self.assertLess(fallback_health, fallback_cleanup)
        self.assertNotIn(
            '"$control_dir/network-fallback-active"', guard[fallback_cleanup:]
        )

        activation = NETPLAN_ACTIVATE.read_text(encoding="utf-8")
        self.assertIn("umask 0027\n    netplan generate\n    netplan apply", activation)
        self.assertIn("root:systemd-network:640:1", activation)
        self.assertIn("10-netplan-cybex-james.network", activation)
        self.assertNotIn("systemd-escape", activation)
        self.assertIn('generated_files=("$runtime_dir"/10-netplan-*.network)', activation)
        self.assertIn("networkctl --no-pager status", activation)
        self.assertIn('if [[ "$selected" = "$expected" ]]', activation)
        self.assertNotIn("netplan generate\n", guard)
        self.assertNotIn("netplan apply\n", guard)
        self.assertNotIn("netplan generate\n", apply_script)
        self.assertNotIn("netplan apply\n", apply_script)
        self.assertNotIn("netplan generate\n", FIRST_BOOT.read_text(encoding="utf-8"))

    @unittest.skipUnless(
        shutil.which("jq"),
        "jq is required",
    )
    def test_netplan_activation_preserves_readability_and_rejects_dracut(self) -> None:
        source = NETPLAN_ACTIVATE.read_text(encoding="utf-8")
        owner = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            active = root / "90-cybex-james.yaml"
            runtime = root / "network"
            fake_bin = root / "bin"
            calls = root / "netplan-calls"
            runtime.mkdir()
            fake_bin.mkdir()
            expected = runtime / "10-netplan-cybex-james.network"
            extra = runtime / "10-netplan-enp5s0.network"

            adapted = source.replace(
                "active=/etc/netplan/90-cybex-james.yaml",
                f"active={shlex.quote(str(active))}",
            ).replace(
                "runtime_dir=/run/systemd/network",
                f"runtime_dir={shlex.quote(str(runtime))}",
            ).replace(
                "root:root:600:1", f"{owner}:{group}:600:1"
            ).replace(
                "root:systemd-network:640:1", f"{owner}:{group}:640:1"
            ).replace("seq 1 60", "seq 1 1").replace("sleep 0.5", ":")
            executable = root / "activate"
            executable.write_text(adapted, encoding="utf-8")
            executable.chmod(0o755)

            netplan = fake_bin / "netplan"
            netplan.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"printf '%s %s\\n' \"$(umask)\" \"$1\" >> {shlex.quote(str(calls))}\n"
                f"printf '[Match]\\nName=enp5s0\\n' > {shlex.quote(str(expected))}\n"
                f"printf '[Match]\\nName=enp5s0\\n' > {shlex.quote(str(extra))}\n",
                encoding="utf-8",
            )
            netplan.chmod(0o755)
            networkctl = fake_bin / "networkctl"
            networkctl.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                "printf '       Network File: %s\\n' \"$NETWORK_SELECTION\"\n",
                encoding="utf-8",
            )
            networkctl.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

            for dhcp4 in (True, False):
                with self.subTest(dhcp4=dhcp4):
                    active.write_text(
                        json.dumps(
                            {
                                "network": {
                                    "version": 2,
                                    "renderer": "networkd",
                                    "ethernets": {
                                        "cybex-james": {
                                            "set-name": "enp5s0",
                                            "dhcp4": dhcp4,
                                        }
                                    },
                                }
                            }
                        ),
                        encoding="utf-8",
                    )
                    active.chmod(0o600)
                    calls.unlink(missing_ok=True)
                    expected.unlink(missing_ok=True)
                    environment["NETWORK_SELECTION"] = str(expected)
                    result = subprocess.run(
                        [str(executable)],
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        calls.read_text(encoding="utf-8"),
                        "0027 generate\n0027 apply\n",
                    )
                    self.assertEqual(expected.stat().st_mode & 0o777, 0o640)
                    self.assertEqual(extra.stat().st_mode & 0o777, 0o640)

            extra.chmod(0o600)
            environment["NETWORK_SELECTION"] = str(expected)
            result = subprocess.run(
                [str(executable)],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe permissions", result.stderr)
            self.assertIn(extra.name, result.stderr)
            extra.chmod(0o640)

            environment["NETWORK_SELECTION"] = str(
                runtime / "zzzz-dracut-cmdline.network"
            )
            result = subprocess.run(
                [str(executable)],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("zzzz-dracut-cmdline.network", result.stderr)

    def test_bridge_state_boundary_and_package_staging_are_fail_closed(self) -> None:
        postinst = POSTINST.read_text(encoding="utf-8")
        harden_parent = postinst.index('chown root:cybex-james "$james_root"')
        inspect_child = postinst.index('for protected in "$james_root/control" "$james_root/status"')
        create_child = postinst.index('mkdir "$protected"', inspect_child)
        self.assertLess(harden_parent, inspect_child)
        self.assertLess(inspect_child, create_child)
        self.assertIn('[ -d "$protected" ] && [ ! -L "$protected" ] || exit 1', postinst)

        layout = STATE_LAYOUT.read_text(encoding="utf-8")
        self.assertIn('CONTROL = ROOT / "control"', layout)
        self.assertIn('STATUS = ROOT / "status"', layout)
        self.assertIn('INBOX = STATE / "inbox"', layout)
        self.assertNotIn('"appliance-update-status.json"', layout)
        self.assertNotIn('"appliance-network-change-status.json"', layout)
        manage = (REPOSITORY / "src/manage.rs").read_text(encoding="utf-8")
        self.assertIn(
            '"/var/lib/cybex-james/status/reliability-state.json"', manage
        )
        self.assertNotIn(
            '"/var/lib/cybex-james/reliability-state.json"', manage
        )
        first_boot = FIRST_BOOT.read_text(encoding="utf-8")
        self.assertNotIn('chown -R cybex-james:cybex-james /var/lib/cybex-james/state', first_boot)

        service = FIRST_BOOT_SERVICE.read_text(encoding="utf-8")
        self.assertIn("TimeoutStartSec=4h", service)
        self.assertIn("up to 16 GiB", service)
        self.assertIn("verify-appliance-candidate-update", first_boot)

        updater = APPLIANCE_UPDATE.read_text(encoding="utf-8")
        package_plan = updater.index("failure_stage=package_plan")
        package_apply = updater.index(
            "DEBIAN_FRONTEND=noninteractive", package_plan
        )
        package_verification = updater.index(
            "failure_stage=package_verification", package_apply
        )
        cleanup_call = updater.index("cleanup_update_staging", package_verification)
        seal = updater.index('candidate_control="$candidate_path/var/lib/cybex-james/control"')
        self.assertLess(package_plan, package_apply)
        self.assertLess(package_apply, package_verification)
        self.assertLess(package_verification, cleanup_call)
        self.assertLess(cleanup_call, seal)
        self.assertNotIn(
            "install /run/cybex-update-packages/*.deb", updater
        )
        self.assertIn(
            'install "${package_targets[@]}"', updater
        )
        self.assertGreaterEqual(updater.count('"${apt_safety_options[@]}"'), 2)
        self.assertIn("--no-remove", updater)
        self.assertIn("--no-allow-downgrades", updater)
        self.assertIn("--no-allow-change-held-packages", updater)
        self.assertIn("verify_no_package_regression", updater)
        self.assertIn("failure_reason=package_plan_unsafe", updater)
        self.assertIn('rm -rf --one-file-system -- "$staging"', updater)
        self.assertIn('sync -f "$candidate_staging_control"', updater)
        self.assertIn("trap cleanup EXIT", updater)
        failure = updater.index("fail_update()")
        self.assertIn("remove_terminal_bundle", updater[failure:])
        failed_request = updater.index("mv -f \"$request\"", failure)
        failed_sync = updater.index('sync -f "$state_dir/inbox"', failed_request)
        failed_bundle = updater.index("remove_terminal_bundle", failed_sync)
        self.assertLess(failed_request, failed_sync)
        self.assertLess(failed_sync, failed_bundle)

        source_seal = updater.index('write_pending_seal "$control_dir"')
        candidate_seal = updater.index('write_pending_seal "$candidate_control"')
        arm_candidate = updater.index('grub-reboot "cybex-james-generation-$candidate"')
        self.assertLess(source_seal, candidate_seal)
        self.assertLess(candidate_seal, arm_candidate)
        self.assertIn(
            'test ! -e "$pending_seal" && test ! -L "$pending_seal"', updater
        )
        self.assertIn('candidate_created=false', updater)
        orphan_check = updater.index(
            'if [[ -e "$source_clear_intent" || -L "$source_clear_intent" ]]'
        )
        orphan_terminal = updater.index(
            'test "$(jq -er \'.status\' "$status")" = succeeded', orphan_check
        )
        orphan_generation = updater.index(
            'test "$(cat "$control_dir/root-generation")" =', orphan_terminal
        )
        orphan_unlink = updater.index('rm -f "$source_clear_intent"', orphan_generation)
        orphan_sync = updater.index('sync -f "$control_dir"', orphan_unlink)
        pending_absent = updater.index(
            'test ! -e "$pending_seal" && test ! -L "$pending_seal"',
            orphan_sync,
        )
        self.assertLess(orphan_terminal, orphan_generation)
        self.assertLess(orphan_generation, orphan_unlink)
        self.assertLess(orphan_unlink, orphan_sync)
        self.assertLess(orphan_sync, pending_absent)
        snapshot = updater.index('btrfs subvolume snapshot / "$candidate_path"')
        created = updater.index('candidate_created=true', snapshot)
        guarded_delete = updater.index('if [[ "$candidate_created" = true ]]')
        self.assertLess(snapshot, created)
        self.assertLess(guarded_delete, snapshot)
        delete_candidate = updater.index("delete_candidate_generation()")
        delete_retry = updater.index("for deletion_attempt in 1 2", delete_candidate)
        delete_success = updater.index("candidate_created=false", delete_retry)
        cleanup_failure = updater.index("failure_stage=candidate_cleanup", delete_success)
        self.assertLess(delete_candidate, delete_retry)
        self.assertLess(delete_retry, delete_success)
        self.assertLess(delete_success, cleanup_failure)
        self.assertIn('candidate="$((maximum_generation + 1))"', updater)

        fallback = first_boot.index('write_update_status rolled_back boot_fallback')
        remove_candidate = first_boot.index('delete_root_generation "$pending"', fallback)
        clear_handoff = first_boot.index('rm -f "$request" "$pending_seal"', fallback)
        self.assertLess(fallback, remove_candidate)
        self.assertLess(remove_candidate, clear_handoff)
        fallback_sync = first_boot.index('sync -f "$inbox_dir"', clear_handoff)
        fallback_bundle = first_boot.index("remove_terminal_bundle", fallback_sync)
        self.assertLess(clear_handoff, fallback_sync)
        self.assertLess(fallback_sync, fallback_bundle)
        self.assertIn("cleanup_orphan_update_bundles", layout)
        self.assertIn("with os.scandir(fd) as entries", layout)
        self.assertNotIn('entries=("$directory"/*)', first_boot)

        commit = GENERATION_COMMIT.read_text(encoding="utf-8")
        self.assertNotIn("appliance-updates/", commit)
        rollback = commit.index("rollback()")
        self.assertIn(
            'set_shared_grub_default "$source_generation"',
            commit[rollback:],
        )
        verify_source = commit.index("with_source_control verify")
        clear_source = commit.index("with_source_control clear")
        resume_trap = commit.index("trap resume_candidate ERR", verify_source)
        source_compare = commit.index('cmp --silent -- "$pending_file" "$source_seal"')
        source_terminal = commit.index(
            'source_status_file="$source_status/appliance-update-status.json"',
            source_compare,
        )
        source_unlink = commit.index('rm -f "$source_seal"')
        candidate_cleanup = commit.index(
            'rm -f "$pending_file"'
        )
        pending_cleanup_sync = commit.index('sync -f "$control_dir"', candidate_cleanup)
        intent_cleanup = commit.index('rm -f "$source_clear_intent"', pending_cleanup_sync)
        self.assertLess(source_compare, source_unlink)
        self.assertLess(source_terminal, source_unlink)
        self.assertIn('sync -f "$source_status"', commit[source_terminal:source_unlink])
        self.assertLess(verify_source, clear_source)
        self.assertLess(resume_trap, clear_source)
        self.assertLess(clear_source, candidate_cleanup)
        self.assertLess(candidate_cleanup, pending_cleanup_sync)
        self.assertLess(pending_cleanup_sync, intent_cleanup)
        self.assertIn('sync -f "$source_control"', commit[source_unlink:])
        self.assertIn(
            'cmp --silent -- "$pending_file" "$source_clear_intent"', commit
        )
        self.assertIn(
            '[[ "$generation" = "$pending" || "$generation" = "$source_generation" ]]',
            commit,
        )
        success = commit.index("write_status succeeded committed")
        success_request = commit.index('rm -f "$request"', success)
        success_sync = commit.index('sync -f "$state_dir/inbox"', success_request)
        success_bundle = commit.index(
            'rm -f -- "$bundle_dir/$attempt_id.tar.zst"', success_sync
        )
        self.assertLess(success_request, success_sync)
        self.assertLess(success_sync, success_bundle)
        self.assertIn(
            'rm -f -- "$bundle_dir/$attempt_id.tar.zst"', commit[success:]
        )
        self.assertIn('sync -f "$bundle_dir"', commit[success:])
        self.assertIn("old nonterminal update forever", first_boot)
        self.assertIn(
            '[[ "$(jq -er \'.status\' "$status_file")" = succeeded ]]',
            first_boot,
        )

    def test_orphan_cleanup_is_bounded_and_preserves_active_bundle(self) -> None:
        with mock.patch(
            "pwd.getpwnam", return_value=SimpleNamespace(pw_uid=os.getuid())
        ), mock.patch(
            "grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())
        ):
            namespace = runpy.run_path(str(STATE_LAYOUT))
        cleanup = namespace["cleanup_orphan_update_bundles"]

        with tempfile.TemporaryDirectory() as temporary:
            inbox = Path(temporary) / "inbox"
            bundles = inbox / "appliance-update-bundles"
            bundles.mkdir(parents=True, mode=0o700)
            bundles.chmod(0o700)
            attempt_id = "11111111-2222-4333-8444-555555555555"
            active = bundles / f"{attempt_id}.tar.zst"
            active.write_bytes(b"active signed archive")
            for index in range(100):
                (bundles / f"orphan-{index:03}.part").write_bytes(b"orphan")
            request = inbox / "appliance-update-request.json"
            request.write_text(
                json.dumps(
                    {
                        "schema": "cybex.james.appliance-update-request.v1",
                        "attempt_id": attempt_id,
                        "bundle_path": str(active),
                    }
                ),
                encoding="utf-8",
            )

            removed, inspected = cleanup(bundles, request)
            self.assertLessEqual(inspected, 65)
            self.assertLessEqual(removed, 65)
            self.assertTrue(active.is_file())
            self.assertGreater(len(list(bundles.iterdir())), 1)

            request.write_text("[]\n", encoding="utf-8")
            _removed, inspected = cleanup(bundles, request)
            self.assertLessEqual(inspected, 65)

    def test_tftp_assets_and_runtime_address_are_fail_closed(self) -> None:
        first_boot = FIRST_BOOT.read_text(encoding="utf-8")
        self.assertIn("stage_ipxe /usr/lib/ipxe/snponly.efi snponly.efi", first_boot)
        self.assertIn("stage_ipxe /usr/lib/ipxe/ipxe-amd64.efi ipxe.efi", first_boot)
        self.assertIn(
            "stage_ipxe_script /usr/share/cybex-james/autoexec.ipxe autoexec.ipxe",
            first_boot,
        )
        self.assertIn('install -d -m 0755 -o root -g root /var/cache/cybex-james/tftp', first_boot)
        self.assertIn('install -m 0644 -o root -g root "$source"', first_boot)
        self.assertNotIn('install -m 0640 -o root -g tftp "$source"', first_boot)
        self.assertIn("! -L /var/cache/cybex-james/tftp", first_boot)
        self.assertIn('TFTP_USERNAME="tftp"', first_boot)
        self.assertIn('TFTP_DIRECTORY="/var/cache/cybex-james/tftp"', first_boot)
        self.assertIn('TFTP_OPTIONS="--secure"', first_boot)
        self.assertNotIn('TFTP_USERNAME="cybex-james"', first_boot)
        self.assertLess(
            first_boot.index("cybex-james-network-guard"),
            first_boot.index("cybex-james-network-runtime"),
        )
        self.assertLess(
            first_boot.index("cybex-james-network-runtime"),
            first_boot.index("validate-appliance-config"),
        )

        runtime = NETWORK_RUNTIME.read_text(encoding="utf-8")
        self.assertIn("reconcile-network-runtime", runtime)
        self.assertIn("systemctl --no-block try-restart", runtime)
        service = NETWORK_RUNTIME_SERVICE.read_text(encoding="utf-8")
        self.assertEqual(NETWORK_RUNTIME_SERVICE.stat().st_mode & 0o777, 0o644)
        self.assertIn("After=network-online.target", service)
        self.assertIn("Before=cybex-james.service", service)
        timer = NETWORK_RUNTIME_TIMER.read_text(encoding="utf-8")
        self.assertEqual(NETWORK_RUNTIME_TIMER.stat().st_mode & 0o777, 0o644)
        self.assertEqual(NETWORK_RUNTIME.stat().st_mode & 0o777, 0o755)
        self.assertIn("OnUnitActiveSec=1min", timer)
        self.assertIn("Persistent=true", timer)
        postinst = POSTINST.read_text(encoding="utf-8")
        self.assertIn("cybex-james-network-runtime.timer", postinst)
        self.assertIn("install -d -m 0755 -o root -g root /var/cache/cybex-james/tftp", postinst)
        self.assertIn("! -L /var/cache/cybex-james/tftp", postinst)
        readiness = (REPOSITORY / "src/readiness.rs").read_text(encoding="utf-8")
        self.assertIn("read_safe_public_tftp_bootloader", readiness)
        self.assertIn("read_safe_public_tftp_ipxe_chain_script", readiness)
        self.assertIn("tftp_ipxe_chain_script", readiness)
        self.assertIn("metadata.permissions().mode() & 0o777 != 0o644", readiness)

        autoexec = IPXE_AUTOEXEC.read_text(encoding="utf-8")
        self.assertTrue(autoexec.startswith("#!ipxe\n"))
        self.assertEqual(autoexec.count("dhcp net0 ||"), 2)
        self.assertEqual(
            autoexec.count(
                "chain --autofree http://${next-server}/boot/${net0/mac:hexhyp}"
            ),
            2,
        )
        self.assertEqual(autoexec.count("set cybex-local-handoff 0"), 2)
        self.assertEqual(
            autoexec.count(
                "iseq ${cybex-local-handoff} 1 && goto cybex_local_handoff"
            ),
            2,
        )
        self.assertIn(":cybex_local_handoff\nexit 1", autoexec)
        self.assertIn("isset ${next-server}", autoexec)
        self.assertIn("isset ${net0/mac}", autoexec)
        self.assertNotIn("organization", autoexec)
        self.assertNotIn("token", autoexec)


if __name__ == "__main__":
    unittest.main()
