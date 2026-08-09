from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen


REPOSITORY = Path(__file__).resolve().parents[2]
FIRST_BOOT = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "usr"
    / "lib"
    / "cybex-forge"
    / "cybex-forge-first-boot"
)
SERVICE = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "etc"
    / "systemd"
    / "system"
    / "cybex-forge.service"
)
QUALIFICATION_LIFECYCLE = (
    REPOSITORY / "ubuntu-appliance" / "qualification" / "run-lifecycle.sh"
)
NETWORK_CHANGE = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "usr"
    / "lib"
    / "cybex-forge"
    / "cybex-forge-network-change"
)
NETPLAN_APPLY = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "usr"
    / "lib"
    / "cybex-forge"
    / "cybex-forge-netplan-apply"
)
BUILD_TEMPLATE = REPOSITORY / "ubuntu-appliance" / "build-template.sh"
BUILD_PACKAGE_SNAPSHOT = (
    REPOSITORY / "ubuntu-appliance" / "build-package-snapshot.sh"
)
RELEASE_WORKFLOW = REPOSITORY / ".github" / "workflows" / "release.yml"
PACKAGE_SERVER = (
    REPOSITORY
    / "ubuntu-appliance"
    / "qualification"
    / "serve-package-snapshot.py"
)


class ApplianceFirstBootContractTests(unittest.TestCase):
    def test_qualification_package_server_exposes_only_the_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            snapshot = directory / "cybex-forge-appliance-packages-1.2.3-x86_64-linux.tar.zst"
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

        snapshot = BUILD_PACKAGE_SNAPSHOT.read_text(encoding="utf-8")
        self.assertIn("build-offline-repo.sh", snapshot)
        self.assertIn("cybex.forge.appliance-package-snapshot.v1", snapshot)

        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        snapshot_build = workflow.index("build-package-snapshot.sh")
        template_build = workflow.index("build-template.sh")
        self.assertLess(snapshot_build, template_build)
        self.assertIn(
            '--installer-iso-template-package-delivery "$package_delivery"',
            workflow,
        )

    def test_nix_store_directories_are_checked_individually(self) -> None:
        script = FIRST_BOOT.read_text(encoding="utf-8")
        self.assertIn("test -d /nix/store\n", script)
        self.assertIn("test -d /nix/var/nix/db\n", script)
        self.assertNotIn("test -d /nix/store /nix/var/nix/db", script)

    def test_service_can_read_config_only_after_first_boot_succeeds(self) -> None:
        script = FIRST_BOOT.read_text(encoding="utf-8")
        self.assertIn(
            "chown root:cybex-forge /etc/cybex-forge/config.toml\n"
            "chmod 0640 /etc/cybex-forge/config.toml\n",
            script,
        )

        service = SERVICE.read_text(encoding="utf-8")
        self.assertIn("Requires=cybex-forge-first-boot.service\n", service)
        self.assertIn("After=network-online.target nix-daemon.service "
                      "cybex-forge-first-boot.service\n", service)

    def test_first_boot_does_not_wait_for_units_ordered_after_it(self) -> None:
        script = FIRST_BOOT.read_text(encoding="utf-8")
        self.assertNotIn("systemctl enable --now", script)
        self.assertIn(
            "systemctl enable nix-daemon nginx tftpd-hpa "
            "cybex-forge-firewall ssh\n",
            script,
        )

    def test_qualification_cold_starts_a_stalled_installed_disk_once(self) -> None:
        script = QUALIFICATION_LIFECYCLE.read_text(encoding="utf-8")
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

    def test_root_network_helper_shares_handshake_files_with_forge(self) -> None:
        change_script = NETWORK_CHANGE.read_text(encoding="utf-8")
        self.assertIn('chown root:cybex-forge "$status.tmp"\n', change_script)
        self.assertIn('chmod 0640 "$status.tmp"\n', change_script)

        apply_script = NETPLAN_APPLY.read_text(encoding="utf-8")
        self.assertIn('chown root:cybex-forge "$pending"\n', apply_script)
        self.assertIn('chmod 0640 "$pending"\n', apply_script)


if __name__ == "__main__":
    unittest.main()
