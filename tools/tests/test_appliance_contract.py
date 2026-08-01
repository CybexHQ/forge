from __future__ import annotations

from pathlib import Path
import json
import os
import shutil
import shlex
import subprocess
import tempfile
import unittest
import uuid


REPOSITORY = Path(__file__).resolve().parents[2]
APPLIANCE = REPOSITORY / "appliance"
SHELL_FILES = (
    APPLIANCE / "cybex-forge-appliance-install",
    APPLIANCE / "cybex-forge-appliance-rescue",
    APPLIANCE / "cybex-forge-appliance-entrypoint",
    APPLIANCE / "cybex-forge-appliance-check",
    REPOSITORY / "install" / "proxmox-host-lxc.sh",
    REPOSITORY / "install" / "cybex-forge-lxc-install.sh",
)


class ApplianceContractTests(unittest.TestCase):
    def test_all_install_and_recovery_shell_is_syntactically_valid(self) -> None:
        result = subprocess.run(
            ["bash", "-n", *(str(path) for path in SHELL_FILES)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_seed_answers_are_data_only_and_fail_closed(self) -> None:
        installer = SHELL_FILES[0].read_text(encoding="utf-8")
        entrypoint = SHELL_FILES[2].read_text(encoding="utf-8")
        appliance_readme = (APPLIANCE / "README.md").read_text(encoding="utf-8")
        self.assertIn('*) die "answers file contains unsupported key: $key"', installer)
        self.assertIn('die "answers file repeats MODE"', installer)
        self.assertIn("[[:cntrl:]]", installer)
        self.assertNotIn("eval ", installer)
        self.assertNotIn("source \"$answers_file\"", installer)
        self.assertIn('SEED_LABEL="CYBEX_FORGE_SEED"', entrypoint)
        self.assertIn('--answers-file "$SEED_MOUNT/answers" --yes --poweroff', entrypoint)
        self.assertIn("cybex-forge-secure-input snapshot", installer)
        self.assertIn('answers_file="/proc/self/fd/$answers_input_fd"', installer)
        self.assertIn('enrollment_code_file="$snapshot"', installer)
        self.assertNotIn("enrollment_input_fd", installer)
        self.assertIn("discard_enrollment_code_snapshot", installer)
        self.assertIn("refresh_enrollment_code_snapshot", installer)
        self.assertIn("cybex-forge-secure-input erase-if-same", installer)
        self.assertNotIn("shred -u", installer)
        self.assertIn(
            "-R -uid 0 -gid 0 -file-mode 0600 -dir-mode 0700",
            appliance_readme,
        )

    def test_destructive_and_recovery_boundaries_are_explicit(self) -> None:
        installer = SHELL_FILES[0].read_text(encoding="utf-8")
        for contract in (
            "MINIMUM_DISK_BYTES=$((128 * 1024 * 1024 * 1024))",
            'lsblk -dn -o TYPE -- "$disk"',
            'lsblk -dn -o RM -- "$disk"',
            "target disk contains active swap",
            "target disk has active device-mapper or RAID holders",
            "verify_appliance_identity",
            '"schema":"cybex.forge.appliance.install.v1"',
            "appliance recovery config",
            "validate-appliance-media",
            "Type the full device path to continue",
            "This reformats EFI/root",
            "update=media-rebase-pending-ack",
        ):
            self.assertIn(contract, installer)
        recovery_branch = installer.split("case \"$mode\" in", 1)[1]
        self.assertIn(
            "recovery) wait_for_partitions; verify_layout; verify_appliance_identity; check_filesystems; prepare_recovery_root",
            recovery_branch,
        )

    def test_proxmox_path_never_forwards_the_code_as_guest_argv(self) -> None:
        host = SHELL_FILES[4].read_text(encoding="utf-8")
        guest = SHELL_FILES[5].read_text(encoding="utf-8")
        self.assertIn('unset CYBEX_FORGE_AUTH_CODE', host)
        self.assertIn('unset CYBEX_FORGE_AUTH_CODE', guest)
        self.assertIn('--auth-code-file "$guest_auth_code_file"', host)
        self.assertNotIn('--auth-code "$auth_code"', host)
        self.assertIn('secure_remove_local_auth_code "$auth_code_file"', host)
        self.assertIn("secure_remove_guest_auth_code", host)
        self.assertIn('forge_install_code_file = "$bootstrap_auth_code_file"', guest)
        self.assertNotIn('forge_install_code = "$auth_code"', guest)
        self.assertIn("one-time credential was not scrubbed", guest)

    def test_proxmox_path_enforces_the_appliance_memory_minimum(self) -> None:
        host = SHELL_FILES[4].read_text(encoding="utf-8")
        self.assertIn(
            'validate_int_range "--proxmox-memory-mb" "$memory_mb" 16384 1048576',
            host,
        )
        self.assertNotIn("memory is below the 16384 MiB minimum", host)

    def test_proxmox_auth_code_paths_have_a_protected_parent_race_boundary(self) -> None:
        host = SHELL_FILES[4].read_text(encoding="utf-8")
        guest = SHELL_FILES[5].read_text(encoding="utf-8")
        for script in (host, guest):
            parent_check = script.split(
                "validate_root_protected_auth_code_parent()", 1
            )[1].split("validate_auth_code_file()", 1)[0]
            self.assertIn('canonical="$(realpath -e -- "$parent")"', parent_check)
            self.assertIn('[ -L "$current" ]', parent_check)
            self.assertIn('owner="$(stat -c \'%u\' -- "$current")"', parent_check)
            self.assertIn('mode_value=$((8#$mode))', parent_check)
            self.assertIn("mode_value & 0022", parent_check)
            self.assertIn("entirely root-owned", parent_check)

        host_validator = host.split("validate_auth_code_file()", 1)[1].split(
            "secure_remove_local_auth_code()", 1
        )[0]
        self.assertLess(
            host_validator.index("validate_root_protected_auth_code_parent"),
            host_validator.index('[ ! -L "$path" ]'),
        )
        host_stage = host.split("stage_enrollment_code()", 1)[1].split(
            "run_lxc_installer()", 1
        )[0]
        self.assertLess(
            host_stage.index('validate_auth_code_file "$auth_code_file"'),
            host_stage.index('pct push "$vmid" "$auth_code_file"'),
        )
        self.assertLess(
            host_stage.index('pct push "$vmid" "$auth_code_file"'),
            host_stage.index('secure_remove_local_auth_code "$auth_code_file"'),
        )

        guest_prepare = guest.split("prepare_auth_code_source()", 1)[1].split(
            "validate_listen_addr()", 1
        )[0]
        self.assertLess(
            guest_prepare.index("validate_root_protected_auth_code_parent"),
            guest_prepare.index('validate_auth_code_file "$auth_code_file"'),
        )
        guest_stage = guest.split("install_enrollment_code()", 1)[1].split(
            "install_theme_assets()", 1
        )[0]
        ordered = (
            "validate_root_protected_auth_code_parent",
            'validate_auth_code_file "$source"',
            "bootstrap_auth_code_pending=1",
            'persist_bootstrap_auth_code_identity "$bootstrap_auth_code_identity"',
            '"$source" "$bootstrap_auth_code_staged_file"',
            'identity "$bootstrap_auth_code_staged_file" 512 secret',
            'mv -T -- "$bootstrap_auth_code_staged_file" "$bootstrap_auth_code_file"',
            'identity "$bootstrap_auth_code_file" 512 secret',
            'shred -u -n 1 -z -- "$source"',
        )
        positions = [guest_stage.index(fragment) for fragment in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn(
            'bootstrap_auth_code_staged_file="/var/lib/cybex-forge/bootstrap/.enrollment-code.staged"',
            guest,
        )
        self.assertIn(
            'bootstrap_auth_code_identity_file="/var/lib/cybex-forge-bootstrap.identity"',
            guest,
        )
        self.assertIn(
            'guest_bootstrap_auth_code_staged_file="/var/lib/cybex-forge/bootstrap/.enrollment-code.staged"',
            host,
        )
        self.assertIn(
            'guest_bootstrap_auth_code_identity_file="/var/lib/cybex-forge-bootstrap.identity"',
            host,
        )

    @unittest.skipUnless(shutil.which("cc"), "a C compiler is not installed")
    def test_proxmox_cleanup_erases_prebind_stage_and_renamed_tomb(self) -> None:
        """Exercise both crash windows through the host's guest cleanup program."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            helper = root / "cybex-forge-secure-input"
            compile_result = subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(APPLIANCE / "cybex-forge-secure-input.c"),
                    "-o",
                    str(helper),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr.decode())

            runuser = root / "runuser"
            runuser.write_text(
                "#!/bin/sh\n"
                "test \"$1\" = -u || exit 97\n"
                "shift 2\n"
                "test \"$1\" = -- || exit 97\n"
                "shift\n"
                "exec \"$@\"\n",
                encoding="ascii",
            )
            runuser.chmod(0o755)

            host = SHELL_FILES[4].read_text(encoding="utf-8")
            cleanup = (
                "secure_remove_guest_bootstrap_auth_code()"
                + host.split("secure_remove_guest_bootstrap_auth_code()", 1)[1].split(
                    "validate_staged_guest_auth_code()", 1
                )[0]
            )
            cleanup = cleanup.replace(
                "helper=/usr/local/libexec/cybex-forge-secure-input",
                f"helper={shlex.quote(str(helper))}",
            )
            source = root / "enrollment-code"
            tomb = root / ".enrollment-code.consumed"
            staged = root / ".enrollment-code.staged"
            identity_file = root / "cybex-forge-bootstrap.identity"
            probe = (
                "set -euo pipefail\n"
                + "pct() {\n"
                + "  test \"$1\" = exec; shift\n"
                + "  test \"$1\" = \"$vmid\"; shift\n"
                + "  test \"$1\" = --; shift\n"
                + "  \"$@\"\n"
                + "}\n"
                + f"vmid=901\n"
                + f"guest_bootstrap_auth_code_file={shlex.quote(str(source))}\n"
                + f"guest_bootstrap_auth_code_tomb={shlex.quote(str(tomb))}\n"
                + f"guest_bootstrap_auth_code_staged_file={shlex.quote(str(staged))}\n"
                + f"guest_bootstrap_auth_code_identity_file={shlex.quote(str(identity_file))}\n"
                + cleanup
                + "\n"
                # Failure injected immediately after secret materialization,
                # before the installer can bind an inode identity.
                + f"printf '%s\\n' prebind-secret-must-disappear-123 > {shlex.quote(str(staged))}\n"
                + f"chmod 0600 {shlex.quote(str(staged))}\n"
                + f"printf '%s\\n' pending > {shlex.quote(str(identity_file))}\n"
                + f"chmod 0600 {shlex.quote(str(identity_file))}\n"
                + "secure_remove_guest_bootstrap_auth_code\n"
                + f"test ! -e {shlex.quote(str(staged))}\n"
                + f"test ! -e {shlex.quote(str(identity_file))}\n"
                # A reboot/kill after publication or Rust's consumption rename
                # leaves only the durable pre-rename identity and tomb path.
                + f"printf '%s\\n' renamed-secret-must-disappear-456 > {shlex.quote(str(source))}\n"
                + f"chmod 0600 {shlex.quote(str(source))}\n"
                + f"identity=$({shlex.quote(str(helper))} identity {shlex.quote(str(source))} 512 secret)\n"
                + f"printf '%s\\n' \"$identity\" > {shlex.quote(str(identity_file))}\n"
                + f"chmod 0600 {shlex.quote(str(identity_file))}\n"
                + f"mv -T {shlex.quote(str(source))} {shlex.quote(str(tomb))}\n"
                + "secure_remove_guest_bootstrap_auth_code\n"
                + f"test ! -e {shlex.quote(str(tomb))}\n"
                + f"test ! -e {shlex.quote(str(identity_file))}\n"
            )
            environment = dict(os.environ)
            environment["PATH"] = f"{root}:{environment['PATH']}"
            result = subprocess.run(
                ["bash", "-c", probe, "bootstrap-cleanup-failure-probe"],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertFalse(source.exists())
            self.assertFalse(tomb.exists())
            self.assertFalse(staged.exists())
            self.assertFalse(identity_file.exists())

    def test_recovery_rebases_only_exact_update_control_files_and_queues_evidence(self) -> None:
        installer = SHELL_FILES[0].read_text(encoding="utf-8")
        rescue = SHELL_FILES[1].read_text(encoding="utf-8")
        for path in (
            "$updates_dir/request.json",
            "$updates_dir/status.json",
            "$releases_dir/apply-state.json",
            "$releases_dir/apply.lock",
        ):
            self.assertIn(path, installer)
        self.assertIn("cybex.forge.media-rebase.v1", installer)
        self.assertIn('"media_sequence":$media_sequence', installer)
        self.assertIn("advance_media_sequence", installer)
        self.assertIn("media-rebase-events", installer)
        self.assertIn("appliance/update-history/$event_id", installer)
        self.assertIn("media-rebase-transaction.json", installer)
        self.assertIn("reconcile-appliance", installer)
        self.assertIn('[ "$event_count" -lt 16 ]', installer)
        self.assertIn("media-rebase queue is full", installer)
        reset = installer.split("reset_managed_update_control_state()", 1)[1].split(
            "install_system()", 1
        )[0]
        self.assertNotIn("rm -rf", reset)
        journal_publish = reset.index('mv -- "$journal_tmp" "$journal"')
        reconcile = reset.index('chroot "$TARGET_MOUNT"')
        self.assertLess(journal_publish, reconcile)
        self.assertNotIn('remove_exact_update_control_file "$request_path"', reset)
        self.assertIn(
            'exec cybex-forge-appliance-install --mode repair --disk "$disk" --yes',
            rescue,
        )
        self.assertNotIn('install -m 0755 -o root -g root "$package_path/bin/cybex-forge"', rescue)

    def test_appliance_enrollment_requires_https_and_transition_config_is_secret_free(self) -> None:
        installer = SHELL_FILES[0].read_text(encoding="utf-8")
        host = SHELL_FILES[4].read_text(encoding="utf-8")
        guest = SHELL_FILES[5].read_text(encoding="utf-8")
        self.assertIn("API_URL must use HTTPS", installer)
        self.assertIn("--allow-insecure-manage-http", host)
        self.assertIn("--allow-insecure-manage-http", guest)
        self.assertNotIn('forge_install_code = "$auth_code"', installer)

    def test_nix_expression_is_pinned_and_excludes_local_secrets(self) -> None:
        expression = (APPLIANCE / "default.nix").read_text(encoding="utf-8")
        module = (APPLIANCE / "module.nix").read_text(encoding="utf-8")
        iso = (APPLIANCE / "iso.nix").read_text(encoding="utf-8")
        installer = (APPLIANCE / "cybex-forge-appliance-install").read_text(
            encoding="utf-8"
        )
        self.assertIn("74cc63f702f7d60a557e152a57b40fb1fd0f72ac", expression)
        self.assertIn("102brk31m46v3p5n630zdl230ni0hjxrigc6n601k10rds8dqyfi", expression)
        self.assertIn('lib.hasPrefix ".env" name', expression)
        self.assertIn('name == "__pycache__"', expression)
        self.assertIn('lib.hasSuffix ".pyc" name', expression)
        self.assertIn("pkgs.pkgsStatic.rustPlatform.buildRustPackage", expression)
        self.assertIn("ed25519-weak-public-keys.txt", expression)
        self.assertIn("trustedKeyIsStrong", expression)
        self.assertIn("appliance requires canonical Base64 for a non-weak", expression)
        self.assertIn(
            'image.baseName = lib.mkForce "cybex-forge-appliance-${version}-x86_64-linux"',
            iso,
        )
        self.assertIn('virtualisation.incus.agent.enable = true', module)
        self.assertIn('virtualisation.incus.agent.enable = true', iso)
        self.assertIn('"console=ttyS0,115200n8"', module)
        forge_path = module.split("forgePath = with pkgs; [", 1)[1].split("];", 1)[0]
        self.assertRegex(forge_path, r"\bnix\b")
        for boot_module in (
            "9p",
            "9pnet",
            "9pnet_virtio",
            "nf_tables",
            "nft_chain_nat",
            "nft_ct",
            "nft_fib_inet",
            "nft_reject_inet",
            "nls_ascii",
            "nls_cp437",
            "nls_iso8859-1",
            "vfat",
            "virtio_console",
            "virtio_net",
            "xt_pkttype",
        ):
            self.assertIn(f'"{boot_module}"', module)
        self.assertIn("cybex-forge-boot-diagnostics", module)
        self.assertIn('wantedBy = [ "emergency.target" ];', module)
        self.assertIn('TTYPath = "/dev/ttyS0";', module)
        self.assertIn("CYBEX_FORGE_BOOT_DIAGNOSTIC status=storage-failure", module)
        self.assertIn("/bin/dmesg --level=err,warn", module)
        self.assertIn("/bin/fsck.vfat -n", module)
        self.assertIn("systemd.services.firewall.onFailure", module)
        self.assertIn("cybex-forge-firewall-diagnostics.service", module)
        self.assertIn("CYBEX_FORGE_NETWORK_DIAGNOSTIC status=firewall-failure", module)
        self.assertIn("CYBEX_FORGE_NETWORK_DIAGNOSTIC status=interface-snapshot", module)
        self.assertIn('OnBootSec = "45s";', module)
        self.assertNotIn("system.activationScripts.cybexForgeMutableRuntime", module)
        self.assertIn("systemd.services.cybex-forge-mutable-runtime", module)
        self.assertIn('requiredBy = [ "multi-user.target" ];', module)
        self.assertIn('after = [ "local-fs.target" ];', module)
        self.assertIn('requires = [ "local-fs.target" ];', module)
        self.assertIn('"cybex-forge.service"', module)
        self.assertIn(
            'chmod 0644 "$TARGET_MOUNT/etc/nginx/sites-available/cybex-forge"',
            installer,
        )
        self.assertIn(
            'chmod 0644 "$TARGET_MOUNT/etc/default/tftpd-hpa"', installer
        )
        diagnostic = module.split(
            "systemd.services.cybex-forge-boot-diagnostics", 1
        )[1].split("users.groups.cybex-forge", 1)[0]
        self.assertNotIn("config.toml", diagnostic)
        self.assertNotIn("enrollment", diagnostic.lower())
        self.assertIn('systemd.services."getty@tty1".enable = false', iso)
        self.assertIn('systemd.services."autovt@tty1".enable = false', iso)
        self.assertIn('ExecStartPre = "${pkgs.kbd}/bin/chvt 1";', iso)
        self.assertIn(
            "gptfdisk iproute2 nix nixos-install-tools openssh parted systemd util-linux",
            iso,
        )
        self.assertIn(
            'conflicts = [ "getty@tty1.service" "autovt@tty1.service" ];',
            iso,
        )
        self.assertIn('marker guided ready "mode=interactive"', installer)
        self.assertIn('size = 8192', module)
        self.assertIn('options = "--delete-older-than 7d"', module)
        self.assertIn("${pkgs.ipxe.src}", module)
        self.assertIn('CYBEX_FORGE_REQUIRE_PINNED_IPXE_SOURCE = "1"', module)
        self.assertIn('trusted-users = [ "root" ]', module)
        self.assertIn('allowed-users = [ "root" "cybex-forge" ]', module)
        self.assertIn("CAP_SYS_CHROOT", module)
        self.assertIn('[ "AF_INET" "AF_INET6" "AF_UNIX" ]', module)
        self.assertIn('services.timesyncd.enable = true', module)
        self.assertIn('"time-sync.target"', module)
        self.assertIn("cybex-forge-appliance-reconcile", module)
        self.assertIn("binary-recovery.json", module)
        reconcile = module.split(
            "systemd.services.cybex-forge-appliance-reconcile", 1
        )[1].split("systemd.services.cybex-forge =", 1)[0]
        self.assertIn(
            'ExecStart = "/usr/local/bin/cybex-forge --config '
            '/etc/cybex-forge/config.toml reconcile-appliance";',
            reconcile,
        )
        self.assertNotIn('${forgePackage}/bin/cybex-forge --config', reconcile)

    def test_production_tag_release_is_governed_signed_and_attested(self) -> None:
        workflow = (REPOSITORY / ".github" / "workflows" / "appliance.yml").read_text(
            encoding="utf-8"
        )
        rust_gate = workflow.split("\n  rust-release:\n", 1)[1].split(
            "\n  nix:\n", 1
        )[0]
        build = workflow.split("\n  release_build:\n", 1)[1].split(
            "\n  release_artifact_smoke:\n", 1
        )[0]
        smoke = workflow.split("\n  release_artifact_smoke:\n", 1)[1].split(
            "\n  release_publish:\n", 1
        )[0]
        publish = workflow.split("\n  release_publish:\n", 1)[1]

        self.assertIn("if: startsWith(github.ref, 'refs/tags/v')", rust_gate)
        self.assertIn(
            "dtolnay/rust-toolchain@8641a17e25bf5b40c118d48fe0f81e8655731839",
            rust_gate,
        )
        self.assertIn("toolchain: 1.85.0", rust_gate)
        self.assertIn("cargo fmt --all --check", rust_gate)
        self.assertIn("cargo test --locked", rust_gate)
        self.assertIn("cargo clippy --all-targets --all-features -- -D warnings", rust_gate)

        self.assertIn(
            "needs: [contracts, rust-release, nix, appliance-incus]", build
        )
        self.assertIn("environment: production-release", build)
        self.assertIn("CYBEX_FORGE_RELEASE_PRIVATE_KEY_B64", build)
        self.assertIn("CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY", build)
        self.assertIn("tools/forge-release.py validate-public-key", build)
        self.assertIn("tools/forge-release.py manifest", build)
        self.assertIn(
            'test "$derived_public_key" = "$CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY"',
            build,
        )
        self.assertIn("Upload the one release candidate artifact", build)
        self.assertIn("compression-level: 0", build)
        self.assertIn("Select the build-once candidate artifact", build)
        self.assertIn("actions/runs/$GITHUB_RUN_ID/artifacts?name=", build)
        self.assertIn("steps.release-candidate.outputs.reuse != 'true'", build)
        self.assertIn("Bind candidate artifact identity and provenance", build)
        self.assertIn("retention-days: 30", build)
        self.assertIn("artifact_id: ${{ steps.release-artifact.outputs.artifact_id }}", build)
        self.assertIn(
            'if [ "$GITHUB_RUN_ATTEMPT" -ne 1 ]; then',
            build,
        )
        self.assertIn("refusing to rebuild or re-sign it", build)
        self.assertIn(
            "CYBEX_FORGE_RELEASE_ARTIFACT: cybex-forge-release-candidate-${{ github.run_id }}",
            build,
        )
        self.assertNotIn("${{ github.run_attempt }}", build)
        self.assertIn("cd dist", build)
        self.assertIn("cybex-forge-release.json > SHA256SUMS", build)
        self.assertNotIn("dist/cybex-forge-release.json > dist/SHA256SUMS", build)
        self.assertNotIn("actions/attest@", build)
        self.assertNotIn("gh release create", build)
        self.assertNotIn("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", build)
        self.assertEqual(workflow.count("Upload the one release candidate artifact"), 1)

        self.assertIn("needs: release_build", smoke)
        self.assertIn("environment: forge-appliance-qualification", smoke)
        self.assertIn("actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093", smoke)
        self.assertIn("forge-appliance-release-smoke", smoke)
        self.assertIn("artifact-ids: ${{ env.CYBEX_FORGE_RELEASE_ARTIFACT_ID }}", smoke)
        self.assertIn("Validate original candidate artifact provenance", smoke)
        self.assertIn(
            'git -C .cybex-forge merge-base --is-ancestor', smoke
        )
        self.assertIn(
            'git -C .cybex-manage merge-base --is-ancestor', smoke
        )
        self.assertIn("id: upload-release-evidence", smoke)
        self.assertIn('--expected-forge-source-revision "$GITHUB_SHA"', smoke)
        self.assertIn(
            '--expected-manage-source-revision "$CYBEX_E2E_MANAGE_REF"', smoke
        )
        self.assertIn("if: always()", smoke)
        self.assertIn("Always remove exact release-smoke resources", smoke)
        self.assertLess(
            smoke.index("chmod 0444"),
            smoke.index("labctl.py forge-appliance-release-smoke"),
        )
        self.assertNotIn("CYBEX_FORGE_RELEASE_PRIVATE_KEY_B64", smoke)
        self.assertNotIn("tools/forge-release.py manifest", smoke)
        self.assertNotIn("path: dist/", smoke)
        self.assertIn(
            "path: .cybex-manage/var/testbench/incus-public/", smoke
        )

        self.assertIn("needs: [release_build, release_artifact_smoke]", publish)
        self.assertIn("tools/forge-release.py verify", publish)
        self.assertIn("tools/forge-release.py verify-qualification", publish)
        self.assertIn("cybex-forge-appliance-qualification.json", publish)
        self.assertIn("length == 5", publish)
        self.assertIn("Validate candidate and qualification artifact provenance", publish)
        self.assertIn("artifact-ids: ${{ env.CYBEX_FORGE_RELEASE_EVIDENCE_ARTIFACT_ID }}", publish)
        self.assertIn(
            "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26", publish
        )
        self.assertNotIn("CYBEX_FORGE_RELEASE_PRIVATE_KEY_B64", publish)
        ordered = (
            'gh release create "$GITHUB_REF_NAME"',
            'gh release upload "$GITHUB_REF_NAME"',
            "remote_assets_match",
            'gh release edit "$GITHUB_REF_NAME" --draft=false',
        )
        positions = [publish.index(fragment) for fragment in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("--draft --verify-tag", publish)
        self.assertIn("for _attempt in $(seq 1 20)", publish)
        self.assertIn("repos/$GITHUB_REPOSITORY/commits/$GITHUB_REF_NAME", publish)
        self.assertIn('test "${remote_tag_commit,,}" = "${GITHUB_SHA,,}"', publish)
        self.assertIn('--target "$GITHUB_SHA"', publish)
        self.assertIn("--method DELETE", publish)
        self.assertIn('gh release verify "$GITHUB_REF_NAME"', publish)
        self.assertIn('gh release verify-asset "$GITHUB_REF_NAME" "$path"', publish)
        stale_draft = publish.split(
            "- name: Remove only a stale draft for this exact tag", 1
        )[1].split("- name: Create draft and attach exact assets", 1)[0]
        self.assertIn('repos/$GITHUB_REPOSITORY/releases/tags/$GITHUB_REF_NAME', stale_draft)
        self.assertIn(".tag_name", stale_draft)
        self.assertIn(".draft", stale_draft)
        self.assertIn(".immutable", stale_draft)
        self.assertIn("Cybex-Release-Workflow:", stale_draft)
        self.assertIn("Cybex-Candidate-Artifact-ID:", stale_draft)
        self.assertIn("Cybex-Candidate-Artifact-SHA256:", stale_draft)
        self.assertIn("expected_body=", stale_draft)
        self.assertIn(".body //", stale_draft)
        self.assertIn(".name //", stale_draft)
        self.assertIn("length <= 5", stale_draft)
        self.assertIn("map(.name) | unique | length", stale_draft)
        self.assertIn("all(.[].name;", stale_draft)
        self.assertNotIn("grep -Fqx", stale_draft)
        self.assertNotIn("--generate-notes", publish)
        self.assertGreaterEqual(
            workflow.count("(cd dist && sha256sum --check --strict SHA256SUMS)"),
            2,
        )
        self.assertNotIn(".target_commitish", publish)

        self.assertIn("CYBEX_FORGE_RELEASE_POLICY_TOKEN", build)
        immutable_check = build.split(
            "- name: Require repository immutable-release policy", 1
        )[1].split("- name: Build exact binary and installer ISO", 1)[0]
        self.assertIn("gh api --method GET", immutable_check)
        self.assertIn("repos/$GITHUB_REPOSITORY/immutable-releases", immutable_check)
        self.assertIn('"$immutable_enabled" != "true"', immutable_check)
        for mutating_method in ("--method PUT", "--method PATCH", "--method DELETE"):
            self.assertNotIn(mutating_method, immutable_check)

    def test_forge_ci_requires_exact_cross_repo_incus_lifecycle_before_release(self) -> None:
        caller = (REPOSITORY / ".github" / "workflows" / "appliance.yml").read_text(
            encoding="utf-8"
        )
        workflow = (
            REPOSITORY / ".github" / "workflows" / "appliance-incus.yml"
        ).read_text(encoding="utf-8")
        caller_job = caller.split("\n  appliance-incus:\n", 1)[1].split(
            "\n  release_build:\n", 1
        )[0]
        self.assertIn("uses: ./.github/workflows/appliance-incus.yml", caller)
        self.assertIn("if: github.event_name == 'push'", caller)
        self.assertNotIn("secrets:", caller_job)
        self.assertIn(
            "needs: [contracts, rust-release, nix, appliance-incus]", caller
        )
        self.assertIn("workflow_call:", workflow)
        self.assertIn("runs-on: [self-hosted, cybex-proxmox]", workflow)
        self.assertIn("environment: forge-appliance-qualification", workflow)
        self.assertIn("CYBEX_E2E_MANAGE_REF", workflow)
        self.assertIn(
            "CYBEX_E2E_EXPECTED_MANAGE_SOURCE_REVISION: ${{ vars.CYBEX_E2E_MANAGE_REF }}",
            workflow,
        )
        job_environment = workflow.split("    env:\n", 1)[1].split("    steps:\n", 1)[0]
        self.assertNotIn("CYBEX_API_TOKEN:", job_environment)
        self.assertIn("secrets.CYBEX_MANAGE_REPO_TOKEN || github.token", workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn("path: .cybex-forge", workflow)
        self.assertIn("path: .cybex-manage", workflow)
        self.assertNotIn(".cybex-forge/.cybex-manage", workflow)
        self.assertIn(
            "CYBEX_FORGE_SOURCE_DIR: ${{ github.workspace }}/.cybex-forge", workflow
        )
        self.assertIn("forge-appliance-forge-${{ github.run_id }}", workflow)
        self.assertIn("if: github.event_name == 'push'", workflow)
        self.assertNotIn("head.repo.full_name", workflow)
        governed_source = workflow.split(
            "- name: Validate governed Forge event source", 1
        )[1].split("- name: Validate coordinated Manage ref", 1)[0]
        self.assertIn("refs/heads/main|refs/tags/v*", governed_source)
        self.assertIn(
            "git show-ref --verify --quiet refs/remotes/origin/main",
            governed_source,
        )
        self.assertIn(
            'git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main',
            governed_source,
        )
        self.assertIn(
            'git merge-base --is-ancestor "${CYBEX_E2E_MANAGE_REF,,}" refs/remotes/origin/main',
            workflow,
        )
        self.assertLess(
            workflow.index("Validate governed Forge event source"),
            workflow.index("Checkout exact Manage controller"),
        )
        self.assertIn("status --porcelain", workflow)
        self.assertIn("timeout --signal=INT --kill-after=120s 300m", workflow)
        self.assertIn("if: failure() || cancelled()", workflow)
        ordered_steps = (
            "Validate appliance controller contracts",
            "Validate exact Manage and web builds",
            "Prepare Incus lab",
            "Qualify signed Forge appliance",
            "Recover exact interrupted appliance run",
            "Summarize appliance evidence",
            "Export bounded public evidence",
        )
        positions = [workflow.index(step) for step in ordered_steps]
        self.assertEqual(positions, sorted(positions))

    def test_install_state_replacement_is_atomic_and_ordered(self) -> None:
        installer = SHELL_FILES[0].read_text(encoding="utf-8")
        writer = installer.split("write_install_state()", 1)[1].split(
            "install_system()", 1
        )[0]
        self.assertNotIn(
            'cat > "$TARGET_MOUNT/var/lib/cybex-forge/appliance/install-state.json"',
            installer,
        )
        ordered = (
            'temporary="$(mktemp "$state_dir/.install-state.XXXXXX")"',
            '> "$temporary"',
            'chown root:root "$temporary"',
            'chmod 0600 "$temporary"',
            'sync -f "$temporary"',
            'mv -T -- "$temporary" "$state_path"',
            'sync -f "$state_dir"',
        )
        positions = [writer.index(contract) for contract in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("refusing to overwrite unsafe appliance install-state path", writer)
        postcheck = writer.index("refusing to replace unsafe appliance install-state path")
        self.assertGreater(postcheck, writer.index('sync -f "$temporary"'))
        self.assertLess(postcheck, writer.index('mv -T -- "$temporary" "$state_path"'))
        install_system = installer.split("install_system()", 1)[1].split(
            "confirm_destructive_install()", 1
        )[0]
        self.assertLess(
            install_system.index('write_install_state "$version"'),
            install_system.index('reset_managed_update_control_state "$version"'),
        )

    def test_install_enrollment_credential_is_a_last_step_transaction(self) -> None:
        installer = SHELL_FILES[0].read_text(encoding="utf-8")
        initial_config = installer.split("write_initial_config()", 1)[1].split(
            "commit_install_enrollment_code()", 1
        )[0]
        self.assertNotIn("refresh_enrollment_code_snapshot", initial_config)
        self.assertNotIn("erase-if-same", initial_config)
        self.assertNotIn(
            'install -m 0600 -o "$FORGE_UID" -g "$FORGE_GID"',
            initial_config,
        )

        transaction = installer.split("commit_install_enrollment_code()", 1)[1].split(
            "restore_or_backup_config()", 1
        )[0]
        ordered = (
            "enrollment_target_cleanup_armed=1",
            "refresh_enrollment_code_snapshot",
            "run_as_target_forge bash -ceu",
            'enrollment_target_staged_identity="$(run_as_target_forge',
            "discard_enrollment_code_snapshot",
            "enrollment_stage_checkpoint",
            "run_as_target_forge mv -T --no-clobber",
            'run_as_target_forge sync -f "$target_parent"',
            'enrollment_target_staged_path=""',
            'enrollment_target_identity="$(run_as_target_forge',
            "enrollment_commit_checkpoint",
            "enrollment_target_committed=1",
            "enrollment_target_cleanup_armed=0",
            "cybex-forge-secure-input erase-if-same",
            '"$enrollment_code_source" "$enrollment_source_identity"',
        )
        positions = [transaction.index(contract) for contract in ordered]
        self.assertEqual(positions, sorted(positions))

        install_system = installer.split("install_system()", 1)[1].split(
            "confirm_destructive_install()", 1
        )[0]
        finalization = (
            "write_runtime_files",
            "restore_or_backup_config",
            "validate_target_config",
            'write_install_state "$version"',
            'reset_managed_update_control_state "$version"',
            "sync",
            "commit_install_enrollment_code",
        )
        positions = [install_system.index(contract) for contract in finalization]
        self.assertEqual(positions, sorted(positions))

        exit_handler = installer.split("on_exit()", 1)[1].split(
            "trap on_exit EXIT", 1
        )[0]
        self.assertLess(
            exit_handler.index("scrub_uncommitted_enrollment_target"),
            exit_handler.index("cleanup_mounts"),
        )

    def test_appliance_config_is_validated_without_output_before_mutation(self) -> None:
        installer = SHELL_FILES[0].read_text(encoding="utf-8")
        validator = installer.split("validate_config_file()", 1)[1].split(
            "remove_config_validation_candidate()", 1
        )[0]
        self.assertIn('"$validator" --config "$config_path" validate-appliance-config', validator)
        self.assertIn(">/dev/null 2>/dev/null", validator)
        self.assertNotIn("print-config", validator)

        preflight = installer.split("validate_initial_config_preflight()", 1)[1].split(
            "write_initial_config()", 1
        )[0]
        self.assertLess(
            preflight.index('render_initial_config "$config_validation_candidate"'),
            preflight.index('validate_config_file "$config_validation_candidate" preflight'),
        )
        install_system = installer.split("install_system()", 1)[1].split(
            "confirm_destructive_install()", 1
        )[0]
        self.assertLess(
            install_system.index("restore_or_backup_config"),
            install_system.index("validate_target_config"),
        )
        self.assertLess(
            install_system.index("validate_target_config"),
            install_system.index("commit_install_enrollment_code"),
        )
        main = installer.split("main() {", 1)[1]
        self.assertLess(
            main.index("validate_initial_config_preflight"),
            main.index("partition_new_disk"),
        )

        identity = installer.split("verify_appliance_identity()", 1)[1].split(
            "validate_published_enrollment_code()", 1
        )[0]
        self.assertLess(
            identity.index('validate_config_file "$state_probe/appliance/config.toml"'),
            identity.index("validate-appliance-media"),
        )
        recovery = installer.split("prepare_recovery_root()", 1)[1].split(
            "mount_target()", 1
        )[0]
        self.assertLess(
            recovery.index("validate_config_file"), recovery.index("wipefs --all --force")
        )

    def test_completed_install_is_refused_before_repartition(self) -> None:
        installer = SHELL_FILES[0].read_text(encoding="utf-8")
        guard = installer.split("refuse_committed_appliance_reinstall()", 1)[1].split(
            "check_filesystems()", 1
        )[0]
        self.assertIn("a completed Forge appliance install is already present", guard)
        self.assertIn("ro,noload,nosuid,nodev,noexec", guard)
        main = installer.split("main() {", 1)[1]
        self.assertLess(
            main.index("refuse_committed_appliance_reinstall"),
            main.index("partition_new_disk"),
        )

    def test_config_validation_failure_is_pre_destructive_and_secret_silent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            validator = root / "forge-validator"
            validator.write_text(
                """#!/usr/bin/env python3
import pathlib
import sys

if len(sys.argv) != 4 or sys.argv[1] != "--config" or sys.argv[3] != "validate-appliance-config":
    raise SystemExit(90)
raw = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
if "99999" in raw or "SECRET_SENTINEL" in raw:
    print(raw)
    print(raw, file=sys.stderr)
    raise SystemExit(41)
""",
                encoding="utf-8",
            )
            validator.chmod(0o755)
            trust = root / "update-trusted-public-key"
            trust.write_text(
                "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n",
                encoding="ascii",
            )
            target = root / "target"
            target_config = target / "etc/cybex-forge/config.toml"
            target_config.parent.mkdir(parents=True)

            installer = SHELL_FILES[0].read_text(encoding="utf-8")
            definitions = installer.split("main() {", 1)[0]
            definitions = definitions.replace(
                'TARGET_MOUNT="/mnt"', f"TARGET_MOUNT={shlex.quote(str(target))}", 1
            )
            definitions = definitions.replace(
                "exec 9>/run/cybex-forge-appliance-install.lock",
                f'exec 9>{shlex.quote(str(root / "installer.lock"))}',
            )
            definitions = definitions.replace(
                "/etc/cybex-forge-appliance/update-trusted-public-key",
                str(trust),
            )
            definitions = definitions.replace(
                "/run/cybex-forge-config.XXXXXX",
                str(root / "cybex-forge-config.XXXXXX"),
            )
            definitions = definitions.replace(
                "/run/cybex-forge-config.??????)",
                f"{root}/cybex-forge-config.??????)",
            )
            definitions = definitions.replace("sync -f /run", f"sync -f {root}")
            definitions = definitions.replace(
                '"0:600:1"', f'"{os.getuid()}:600:1"'
            )
            definitions = definitions.replace(
                "0:640:1:*)", f"{os.getuid()}:640:1:*)"
            )
            common = (
                definitions
                + "\ncompleted=1\n"
                + "FORGE_UID=$(id -u)\n"
                + "FORGE_GID=$(id -g)\n"
                + "mode=install\n"
                + f"embedded_forge_binary() {{ printf '%s\\n' {shlex.quote(str(validator))}; }}\n"
                + 'organization_id="550e8400-e29b-41d4-a716-446655440000"\n'
            )

            destructive = root / "destructive-step"
            published = root / "credential-published"
            invalid_preflight = (
                common
                + 'api_url="https://manage.example:99999"\n'
                + 'public_base_url="http://forge.example"\n'
                + 'validate_url "API_URL" "$api_url"\n'
                + "validate_initial_config_preflight\n"
                + f"touch {shlex.quote(str(destructive))} {shlex.quote(str(published))}\n"
            )
            invalid = subprocess.run(
                ["bash", "-c", invalid_preflight, "invalid-config-preflight-probe"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn(b"generated appliance configuration is invalid", invalid.stderr)
            self.assertFalse(destructive.exists())
            self.assertFalse(published.exists())
            self.assertFalse(list(root.glob("cybex-forge-config.*")))

            secret = "SECRET_SENTINEL-must-never-reach-output"
            target_config.write_text(
                f'[manage]\nforge_install_code = "{secret}"\n', encoding="utf-8"
            )
            target_config.chmod(0o640)
            invalid_target = subprocess.run(
                [
                    "bash",
                    "-c",
                    common + "validate_target_config\n",
                    "invalid-target-config-probe",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(invalid_target.returncode, 0)
            self.assertNotIn(secret.encode(), invalid_target.stdout + invalid_target.stderr)
            self.assertIn(b"target appliance configuration is invalid", invalid_target.stderr)

            normal = subprocess.run(
                [
                    "bash",
                    "-c",
                    common
                    + 'api_url="https://manage.example:443"\n'
                    + 'public_base_url="http://forge.example"\n'
                    + f"render_initial_config {shlex.quote(str(target_config))}\n"
                    + f"chmod 0640 {shlex.quote(str(target_config))}\n"
                    + "validate_target_config\n",
                    "valid-target-config-probe",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(normal.returncode, 0, normal.stderr.decode())
            self.assertIn(
                'forge_install_code_file = "/var/lib/cybex-forge/bootstrap/enrollment-code"',
                target_config.read_text(encoding="utf-8"),
            )

    @unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is not installed")
    def test_recovery_admission_rejects_noncanonical_identity_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            validator = root / "forge-validator"
            validator.write_text(
                """#!/usr/bin/env python3
import pathlib
import sys

raw = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
if "FORGE_CONFIG_SECRET_SENTINEL" in raw:
    print(raw)
    print(raw, file=sys.stderr)
    raise SystemExit(41)
""",
                encoding="utf-8",
            )
            validator.chmod(0o755)

            installer = SHELL_FILES[0].read_text(encoding="utf-8")
            definitions = installer.split("validate_media_rebase_queue_room()", 1)[0]
            definitions = definitions.replace(
                "exec 9>/run/cybex-forge-appliance-install.lock",
                f'exec 9>{shlex.quote(str(root / "installer.lock"))}',
            )
            uid = os.getuid()
            definitions = definitions.replace("0:600:1:*", f"{uid}:600:1:*")
            definitions = definitions.replace("0:644:1:*", f"{uid}:644:1:*")
            definitions = definitions.replace('"0:700"', f'"{uid}:700"')

            def create_fixture(name: str) -> tuple[Path, Path]:
                fixture = root / name
                state = fixture / "state"
                metadata = state / "appliance"
                ssh = metadata / "ssh"
                ssh.mkdir(parents=True, mode=0o700)
                metadata.chmod(0o700)
                (metadata / "install-state.json").write_text(
                    '{"schema":"cybex.forge.appliance.install.v1",'
                    '"version":"0.1.2","mode":"install","status":"installed"}\n',
                    encoding="ascii",
                )
                (metadata / "config.toml").write_text(
                    '[manage]\napi_url = "https://manage.example"\n',
                    encoding="ascii",
                )
                (metadata / "machine-id").write_text(
                    "0123456789abcdef0123456789abcdef\n", encoding="ascii"
                )
                (metadata / "media-sequence").write_text("1\n", encoding="ascii")
                for protected in (
                    metadata / "install-state.json",
                    metadata / "config.toml",
                    metadata / "machine-id",
                    metadata / "media-sequence",
                ):
                    protected.chmod(0o600)
                subprocess.run(
                    [
                        "ssh-keygen",
                        "-q",
                        "-t",
                        "ed25519",
                        "-N",
                        "",
                        "-C",
                        "forge-host",
                        "-f",
                        str(ssh / "ssh_host_ed25519_key"),
                    ],
                    check=True,
                )
                (ssh / "ssh_host_ed25519_key").chmod(0o600)
                (ssh / "ssh_host_ed25519_key.pub").chmod(0o644)
                operator = fixture / "operator-key"
                subprocess.run(
                    [
                        "ssh-keygen",
                        "-q",
                        "-t",
                        "ed25519",
                        "-N",
                        "",
                        "-C",
                        "operator-café",
                        "-f",
                        str(operator),
                    ],
                    check=True,
                )
                authorized = metadata / "root-authorized_keys"
                authorized.write_bytes((fixture / "operator-key.pub").read_bytes())
                authorized.chmod(0o600)
                mutation = fixture / "destructive-step"
                return state, mutation

            def admit(state: Path, mutation: Path) -> subprocess.CompletedProcess[bytes]:
                probe = (
                    definitions
                    + "\ncompleted=1\n"
                    + f"FORGE_UID={uid}\n"
                    + f"FORGE_GID={os.getgid()}\n"
                    + "validate_config_file() {\n"
                    + f"  {shlex.quote(str(validator))} --config \"$1\" "
                    + "validate-appliance-config >/dev/null 2>/dev/null\n"
                    + "}\n"
                    + f"validate_appliance_metadata_dir {shlex.quote(str(state))}\n"
                    + "read_canonical_install_state_version "
                    + f"{shlex.quote(str(state / 'appliance/install-state.json'))} "
                    + ">/dev/null || die \"CYBEX_STATE identity schema is invalid\"\n"
                    + "validate_config_file "
                    + f"{shlex.quote(str(state / 'appliance/config.toml'))} identity-admission "
                    + "|| die \"CYBEX_STATE appliance recovery config is invalid\"\n"
                    + f"touch {shlex.quote(str(mutation))}\n"
                )
                return subprocess.run(
                    ["bash", "-c", probe, "recovery-admission-probe"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

            valid_state, valid_mutation = create_fixture("valid-utf8-comment")
            valid = admit(valid_state, valid_mutation)
            self.assertEqual(valid.returncode, 0, valid.stderr.decode())
            self.assertTrue(valid_mutation.exists())

            cases: list[tuple[str, callable]] = [
                (
                    "install-state-trailing-record",
                    lambda metadata: (metadata / "install-state.json").write_text(
                        '{"schema":"cybex.forge.appliance.install.v1",'
                        '"version":"0.1.2","mode":"install","status":"installed"}\n'
                        "trailing-record\n",
                        encoding="ascii",
                    ),
                ),
                (
                    "machine-id-trailing-record",
                    lambda metadata: (metadata / "machine-id").write_text(
                        "0123456789abcdef0123456789abcdef\ntrailing-record\n",
                        encoding="ascii",
                    ),
                ),
                (
                    "machine-id-all-zero",
                    lambda metadata: (metadata / "machine-id").write_text(
                        "00000000000000000000000000000000\n", encoding="ascii"
                    ),
                ),
                (
                    "mismatched-host-key",
                    lambda metadata: (metadata / "ssh/ssh_host_ed25519_key.pub").write_bytes(
                        (metadata.parent.parent / "operator-key.pub").read_bytes()
                    ),
                ),
                (
                    "authorized-key-multiple-records",
                    lambda metadata: (metadata / "root-authorized_keys").write_bytes(
                        (metadata / "root-authorized_keys").read_bytes() * 2
                    ),
                ),
                (
                    "semantic-config-secret",
                    lambda metadata: (metadata / "config.toml").write_text(
                        '[manage]\nforge_install_code = "FORGE_CONFIG_SECRET_SENTINEL"\n',
                        encoding="ascii",
                    ),
                ),
            ]

            for name, mutate in cases:
                state, mutation = create_fixture(name)
                mutate(state / "appliance")
                result = admit(state, mutation)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertFalse(mutation.exists(), name)
                self.assertNotIn(
                    b"FORGE_CONFIG_SECRET_SENTINEL",
                    result.stdout + result.stderr,
                    name,
                )

            rsa_state, rsa_mutation = create_fixture("non-ed25519-host-key")
            rsa_ssh = rsa_state / "appliance/ssh"
            (rsa_ssh / "ssh_host_ed25519_key").unlink()
            (rsa_ssh / "ssh_host_ed25519_key.pub").unlink()
            subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "rsa",
                    "-b",
                    "2048",
                    "-N",
                    "",
                    "-C",
                    "wrong-host-type",
                    "-f",
                    str(rsa_ssh / "ssh_host_ed25519_key"),
                ],
                check=True,
            )
            (rsa_ssh / "ssh_host_ed25519_key").chmod(0o600)
            (rsa_ssh / "ssh_host_ed25519_key.pub").chmod(0o644)
            rsa_result = admit(rsa_state, rsa_mutation)
            self.assertNotEqual(rsa_result.returncode, 0)
            self.assertFalse(rsa_mutation.exists())

    def test_identity_admission_mounts_cannot_replay_ext4_journals(self) -> None:
        installer = SHELL_FILES[0].read_text(encoding="utf-8")
        rescue = SHELL_FILES[1].read_text(encoding="utf-8")
        safe_options = "ro,noload,nosuid,nodev,noexec"
        for script in (installer, rescue):
            readonly_mounts = [
                line.strip()
                for line in script.splitlines()
                if line.strip().startswith("mount -o ro,")
            ]
            self.assertTrue(readonly_mounts)
            for mount in readonly_mounts:
                self.assertIn(safe_options, mount)

        identity = installer.split("verify_appliance_identity()", 1)[1].split(
            "check_filesystems()", 1
        )[0]
        self.assertLess(
            identity.index('mount -o ro,noload,nosuid,nodev,noexec "$(partition_path 3)"'),
            identity.index("validate-appliance-media"),
        )
        self.assertLess(
            identity.index('validate_config_file "$state_probe/appliance/config.toml"'),
            identity.index("validate-appliance-media"),
        )
        installer_main = installer.split("main() {", 1)[1]
        for branch in (
            "repair) wait_for_partitions; verify_layout; verify_appliance_identity; check_filesystems ;;",
            "recovery) wait_for_partitions; verify_layout; verify_appliance_identity; check_filesystems; prepare_recovery_root ;;",
        ):
            self.assertIn(branch, installer_main)

        rescue_identity = rescue.split("verify_identity()", 1)[1].split(
            "cleanup()", 1
        )[0]
        rescue_admission = (
            'mount -o ro,noload,nosuid,nodev,noexec "$(partition_path 3)"',
            'validate_protected_identity_file "$install_state"',
            'validate_protected_identity_file "$config_backup"',
            'read_canonical_install_state_version "$install_state"',
            'cybex-forge --config "$config_backup" validate-appliance-config',
            'media_version="$(< /etc/cybex-forge-appliance/version)"',
            "validate-appliance-media",
        )
        positions = [rescue_identity.index(contract) for contract in rescue_admission]
        self.assertEqual(positions, sorted(positions))
        self.assertGreater(rescue_identity.rindex('umount "$probe"'), positions[-1])
        rescue_cleanup = rescue.split("cleanup()", 1)[1].split(
            "trap cleanup EXIT", 1
        )[0]
        self.assertIn('if [ "$identity_probe_mounted" -eq 1 ]', rescue_cleanup)
        self.assertIn('umount "$IDENTITY_PROBE"', rescue_cleanup)
        rescue_file_validator = rescue.split(
            "validate_protected_identity_file()", 1
        )[1].split("read_canonical_install_state_version()", 1)[0]
        self.assertIn('[ -L "$path" ]', rescue_file_validator)
        self.assertIn("0:600:1:*", rescue_file_validator)
        rescue_main = rescue.split('[ "$(id -u)" -eq 0 ]', 1)[1]
        self.assertLess(rescue_main.index("verify_identity"), rescue_main.index("case \"$command_name\" in\n  mount)"))

    def test_repair_uses_protected_config_and_older_media_stops_before_mutation(self) -> None:
        installer = SHELL_FILES[0].read_text(encoding="utf-8")
        restore = installer.split("restore_or_backup_config()", 1)[1].split(
            "write_runtime_files()", 1
        )[0]
        self.assertIn('validate_protected_recovery_file "$backup"', restore)
        self.assertIn('install -m 0640 -o root -g "$FORGE_GID" "$backup" "$config"', restore)
        self.assertNotIn("repair requires an existing Forge config", restore)

        identity = installer.split("verify_appliance_identity()", 1)[1].split(
            "check_filesystems()", 1
        )[0]
        self.assertIn("validate-appliance-media", identity)
        repair_flow = installer.split('case "$mode" in', 1)[1]
        self.assertLess(
            repair_flow.index("verify_appliance_identity"),
            repair_flow.index("check_filesystems"),
        )

    def test_appliance_service_hardening_and_identity_are_declarative(self) -> None:
        module = (APPLIANCE / "module.nix").read_text(encoding="utf-8")
        installer = SHELL_FILES[0].read_text(encoding="utf-8")
        for contract in (
            'Slice = "cybex-forge-control.slice"',
            'CapabilityBoundingSet = ""',
            'AmbientCapabilities = ""',
            "PrivateDevices = true",
            "ProtectClock = true",
            "ProtectControlGroups = true",
            "ProtectHostname = true",
            "ProtectKernelLogs = true",
            "ProtectKernelModules = true",
            "ProtectKernelTunables = true",
            "RemoveIPC = true",
            "MemoryDenyWriteExecute = true",
            'RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ]',
        ):
            self.assertIn(contract, module)
        self.assertIn("/var/lib/cybex-forge/appliance/machine-id", module)
        self.assertIn("/var/lib/cybex-forge/appliance/media-sequence", module)
        self.assertGreaterEqual(module.count("exact_single_line"), 4)
        self.assertIn('exact_single_line "$machine_id_backup"', module)
        self.assertIn('exact_single_line "$media_sequence"', module)
        self.assertIn('exact_single_line "$authorized_key_backup"', module)
        self.assertIn("00000000000000000000000000000000", module)
        self.assertIn('[ "$(stat -c %s "$media_sequence")" -le 20 ]', module)
        self.assertIn("ssh_host_ed25519_key", module)
        self.assertIn("root-authorized_keys", installer)
        self.assertIn('chmod 0600 "$ssh_private"', installer)
        self.assertIn('chmod 0644 "$ssh_public"', installer)
        self.assertIn("ensure_target_init()", installer)
        self.assertIn("local init_target=/nix/var/nix/profiles/system/init", installer)
        self.assertIn('NIXOS_INSTALL_BOOTLOADER=1 nixos-install', installer)
        self.assertLess(
            installer.index('NIXOS_INSTALL_BOOTLOADER=1 nixos-install'),
            installer.index('  ensure_target_init\n'),
        )
        self.assertIn("minimum_memory_bytes = 16106127360", installer)

    def test_appliance_public_edge_is_read_only_and_bounded(self) -> None:
        installer = SHELL_FILES[0].read_text(encoding="utf-8")
        for contract in (
            "if ($request_method !~ ^(GET|HEAD)$)",
            "client_max_body_size 1k",
            "client_header_timeout 5s",
            "proxy_connect_timeout 2s",
            "proxy_buffering off",
            "location = /login { return 404; }",
            "location /api/ { return 404; }",
            "autoindex off",
        ):
            self.assertIn(contract, installer)
        self.assertIn("listen 80 default_server", installer)
        self.assertNotIn("listen [::]:80", installer)

    @unittest.skipUnless(shutil.which("cc"), "a C compiler is not installed")
    def test_enrollment_secret_descriptor_is_not_inherited_by_children(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = root / "cybex-forge-secure-input"
            compile_result = subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(APPLIANCE / "cybex-forge-secure-input.c"),
                    "-o",
                    str(helper),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr.decode())

            source = root / "enrollment-code"
            source.write_text("secret-not-for-installer-children-123", encoding="ascii")
            source.chmod(0o600)
            installer = SHELL_FILES[0].read_text(encoding="utf-8")
            definitions = installer.split("main() {", 1)[0]
            definitions = definitions.replace(
                "exec 9>/run/cybex-forge-appliance-install.lock",
                f'exec 9>{shlex.quote(str(root / "installer.lock"))}',
            )
            definitions = definitions.replace(
                "/run/cybex-forge-input.XXXXXX",
                str(root / "cybex-forge-input.XXXXXX"),
            )
            probe = (
                definitions
                + "\ntrap - EXIT\n"
                + f"enrollment_code_file={shlex.quote(str(source))}\n"
                + "bind_enrollment_code_file\n"
                + "snapshot_path=\"$enrollment_code_file\"\n"
                + "SECRET_SOURCE=\"$enrollment_code_source\" "
                + "SECRET_SNAPSHOT=\"$snapshot_path\" bash -c '"
                + "for descriptor in /proc/self/fd/*; do "
                + "target=$(readlink \"$descriptor\" 2>/dev/null || true); "
                + "case \"$target\" in "
                + "\"$SECRET_SOURCE\"|\"$SECRET_SNAPSHOT\"|\"$SECRET_SNAPSHOT (deleted)\") exit 91 ;; "
                + "esac; done'\n"
                + "discard_enrollment_code_snapshot\n"
                + "test ! -e \"$snapshot_path\"\n"
            )
            environment = dict(os.environ)
            environment["PATH"] = f"{root}:{environment['PATH']}"
            result = subprocess.run(
                ["bash", "-c", probe, "secret-inheritance-probe"],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(
                source.read_text(encoding="ascii"),
                "secret-not-for-installer-children-123",
            )

    @unittest.skipUnless(shutil.which("cc"), "a C compiler is not installed")
    def test_install_enrollment_publication_fault_scrubs_target_and_retries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = root / "cybex-forge-secure-input"
            compile_result = subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(APPLIANCE / "cybex-forge-secure-input.c"),
                    "-o",
                    str(helper),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr.decode())

            target = root / "target"
            bootstrap = target / "var/lib/cybex-forge/bootstrap"
            appliance_state = target / "var/lib/cybex-forge/appliance"
            bootstrap.mkdir(parents=True, mode=0o700)
            appliance_state.mkdir(mode=0o700)
            bootstrap.chmod(0o700)
            appliance_state.chmod(0o700)
            source_parent = root / "source"
            source_parent.mkdir(mode=0o700)
            source = source_parent / "enrollment-code"
            sentinel = "transactional-enrollment-secret-123"
            source.write_text(sentinel, encoding="ascii")
            source.chmod(0o600)

            installer = SHELL_FILES[0].read_text(encoding="utf-8")
            definitions = installer.split("main() {", 1)[0]
            definitions = definitions.replace(
                'TARGET_MOUNT="/mnt"',
                f"TARGET_MOUNT={shlex.quote(str(target))}",
                1,
            )
            definitions = definitions.replace(
                "exec 9>/run/cybex-forge-appliance-install.lock",
                f'exec 9>{shlex.quote(str(root / "installer.lock"))}',
            )
            definitions = definitions.replace(
                "/run/cybex-forge-input.XXXXXX",
                str(root / "cybex-forge-input.XXXXXX"),
            )
            definitions = definitions.replace(
                "/run/cybex-forge-input.*)",
                f"{root}/cybex-forge-input.*)",
            )
            definitions = definitions.replace(
                '= "0:700" ]; then',
                f'= "{os.getuid()}:700" ]; then',
                1,
            )
            common_probe = (
                definitions
                + "\ncompleted=1\n"
                + "FORGE_UID=$(id -u)\n"
                + "FORGE_GID=$(id -g)\n"
                + "mode=install\n"
                + "validate_secret_file() { :; }\n"
                + f"enrollment_code_file={shlex.quote(str(source))}\n"
                + "bind_enrollment_code_file\n"
                + "discard_enrollment_code_snapshot\n"
            )
            environment = dict(os.environ)
            environment["PATH"] = f"{root}:{environment['PATH']}"

            staged_failure = subprocess.run(
                [
                    "bash",
                    "-c",
                    common_probe
                    + "enrollment_stage_checkpoint() { return 72; }\n"
                    + "commit_install_enrollment_code\n",
                    "enrollment-staging-fault-probe",
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(
                staged_failure.returncode, 72, staged_failure.stderr.decode()
            )
            self.assertEqual(source.read_text(encoding="ascii"), sentinel)
            self.assertFalse((bootstrap / "enrollment-code").exists())
            self.assertFalse((bootstrap / ".enrollment-code.staged").exists())

            failed = subprocess.run(
                [
                    "bash",
                    "-c",
                    common_probe
                    + "enrollment_commit_checkpoint() { return 73; }\n"
                    + "commit_install_enrollment_code\n",
                    "enrollment-publication-fault-probe",
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(failed.returncode, 73, failed.stderr.decode())
            self.assertEqual(source.read_text(encoding="ascii"), sentinel)
            self.assertFalse((bootstrap / "enrollment-code").exists())
            self.assertFalse((bootstrap / ".enrollment-code.staged").exists())
            self.assertFalse((appliance_state / ".enrollment-code.staged").exists())
            self.assertFalse(list(root.glob("cybex-forge-input.*")))

            retried = subprocess.run(
                [
                    "bash",
                    "-c",
                    common_probe + "commit_install_enrollment_code\n",
                    "enrollment-publication-retry-probe",
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(retried.returncode, 0, retried.stderr.decode())
            self.assertFalse(source.exists())
            installed = bootstrap / "enrollment-code"
            self.assertEqual(installed.read_text(encoding="ascii"), sentinel)
            self.assertEqual(installed.stat().st_mode & 0o777, 0o600)
            self.assertFalse((bootstrap / ".enrollment-code.staged").exists())
            self.assertFalse((appliance_state / ".enrollment-code.staged").exists())
            self.assertFalse(list(root.glob("cybex-forge-input.*")))

    def test_consumed_source_boundary_refuses_to_overwrite_committed_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bootstrap = root / "bootstrap"
            bootstrap.mkdir(mode=0o700)
            code = bootstrap / "enrollment-code"
            sentinel = "committed-target-secret-123456"
            code.write_text(sentinel, encoding="ascii")
            code.chmod(0o600)
            mutation = root / "repartitioned"

            installer = SHELL_FILES[0].read_text(encoding="utf-8")
            definitions = installer.split("main() {", 1)[0]
            definitions = definitions.replace(
                "exec 9>/run/cybex-forge-appliance-install.lock",
                f'exec 9>{shlex.quote(str(root / "installer.lock"))}',
            )
            probe = (
                definitions
                + "\ncompleted=1\n"
                + "FORGE_UID=$(id -u)\n"
                + "FORGE_GID=$(id -g)\n"
                + f"if validate_published_enrollment_code {shlex.quote(str(code))}; then\n"
                + '  die "a completed Forge appliance install is already present; boot it"\n'
                + "fi\n"
                + f"touch {shlex.quote(str(mutation))}\n"
            )
            result = subprocess.run(
                ["bash", "-c", probe, "committed-install-rerun-probe"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(mutation.exists())
            self.assertEqual(code.read_text(encoding="ascii"), sentinel)
            self.assertNotIn(sentinel.encode("ascii"), result.stdout + result.stderr)
            for path in root.rglob("*"):
                if path.is_file() and path != code:
                    self.assertNotIn(sentinel.encode("ascii"), path.read_bytes())

    @unittest.skipUnless(shutil.which("cc"), "a C compiler is not installed")
    def test_secure_input_rejects_links_and_never_erases_a_swapped_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = root / "secure-input"
            compile_result = subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(APPLIANCE / "cybex-forge-secure-input.c"),
                    "-o",
                    str(helper),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr.decode())
            helper_source = (APPLIANCE / "cybex-forge-secure-input.c").read_text(
                encoding="utf-8"
            )
            self.assertIn("open_protected_parent", helper_source)
            self.assertIn("openat(directory, source_name", helper_source)
            self.assertIn("fstatat(directory, source_name", helper_source)
            self.assertIn("unlinkat(directory, source_name, 0)", helper_source)
            self.assertNotIn("unlink(source)", helper_source)

            source = root / "enrollment-code"
            source.write_text("a" * 32, encoding="ascii")
            source.chmod(0o600)
            snapshot = root / "snapshot"
            captured = subprocess.run(
                [str(helper), "snapshot", str(source), str(snapshot), "512", "secret"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(captured.returncode, 0, captured.stderr.decode())
            self.assertEqual(snapshot.read_text(encoding="ascii"), "a" * 32)
            identity = captured.stdout.decode().strip()
            self.assertEqual(len(identity.split(":")), 7)

            original = root / "original-code"
            source.rename(original)
            source.write_text("replacement-must-survive", encoding="ascii")
            source.chmod(0o600)
            erased = subprocess.run(
                [str(helper), "erase-if-same", str(source), identity],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(erased.returncode, 0)
            self.assertEqual(source.read_text(encoding="ascii"), "replacement-must-survive")
            self.assertEqual(original.read_text(encoding="ascii"), "a" * 32)

            symlink = root / "code-link"
            symlink.symlink_to(original)
            linked = subprocess.run(
                [
                    str(helper),
                    "snapshot",
                    str(symlink),
                    str(root / "linked-snapshot"),
                    "512",
                    "secret",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(linked.returncode, 0)

            hardlink = root / "code-hardlink"
            hardlink.hardlink_to(original)
            hardlinked = subprocess.run(
                [
                    str(helper),
                    "snapshot",
                    str(original),
                    str(root / "hardlink-snapshot"),
                    "512",
                    "secret",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(hardlinked.returncode, 0)

            unsafe_parent = root / "unsafe-parent"
            unsafe_parent.mkdir(mode=0o700)
            unsafe_source = unsafe_parent / "enrollment-code"
            unsafe_source.write_text("b" * 32, encoding="ascii")
            unsafe_source.chmod(0o600)
            unsafe_parent.chmod(0o777)
            unsafe_snapshot = subprocess.run(
                [
                    str(helper),
                    "snapshot",
                    str(unsafe_source),
                    str(root / "unsafe-parent-snapshot"),
                    "512",
                    "secret",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(unsafe_snapshot.returncode, 0)
            self.assertEqual(unsafe_source.read_text(encoding="ascii"), "b" * 32)

            guarded_parent = root / "guarded-parent"
            guarded_parent.mkdir(mode=0o700)
            guarded_source = guarded_parent / "enrollment-code"
            guarded_source.write_text("c" * 32, encoding="ascii")
            guarded_source.chmod(0o600)
            guarded_snapshot = root / "guarded-snapshot"
            guarded = subprocess.run(
                [
                    str(helper),
                    "snapshot",
                    str(guarded_source),
                    str(guarded_snapshot),
                    "512",
                    "secret",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(guarded.returncode, 0, guarded.stderr.decode())
            guarded_parent.chmod(0o777)
            refused_erase = subprocess.run(
                [
                    str(helper),
                    "erase-if-same",
                    str(guarded_source),
                    guarded.stdout.decode().strip(),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(refused_erase.returncode, 0)
            self.assertEqual(guarded_source.read_text(encoding="ascii"), "c" * 32)

            erasable_parent = root / "erasable-parent"
            erasable_parent.mkdir(mode=0o700)
            erasable_source = erasable_parent / "enrollment-code"
            erasable_source.write_text("d" * 32, encoding="ascii")
            erasable_source.chmod(0o600)
            erasable_snapshot = root / "erasable-snapshot"
            erasable_identity = subprocess.run(
                [
                    str(helper),
                    "snapshot",
                    str(erasable_source),
                    str(erasable_snapshot),
                    "512",
                    "secret",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(
                erasable_identity.returncode, 0, erasable_identity.stderr.decode()
            )
            erased_exact = subprocess.run(
                [
                    str(helper),
                    "erase-if-same",
                    str(erasable_source),
                    erasable_identity.stdout.decode().strip(),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(erased_exact.returncode, 0, erased_exact.stderr.decode())
            self.assertFalse(erasable_source.exists())

    def test_generated_interactive_secret_is_removed_without_a_bound_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installer = SHELL_FILES[0].read_text(encoding="utf-8")
            definitions = installer.split("main() {", 1)[0]
            definitions = definitions.replace(
                "exec 9>/run/cybex-forge-appliance-install.lock",
                f'exec 9>{shlex.quote(str(root / "installer.lock"))}',
            )
            definitions = definitions.replace(
                "/run/cybex-forge-input.XXXXXX",
                str(root / "cybex-forge-input.XXXXXX"),
            )
            definitions = definitions.replace(
                "/run/cybex-forge-input.*)",
                f"{root}/cybex-forge-input.*)",
            )
            definitions = definitions.replace(
                '= "0:700" ]; then',
                f'= "{os.getuid()}:700" ]; then',
                1,
            )
            probe = (
                definitions
                + "\ncompleted=1\n"
                + "ensure_secure_input_dir\n"
                + 'enrollment_code_file="$secure_input_dir/enrollment-source"\n'
                + 'printf "%s\\n" "secret-created-before-bind-123" > "$enrollment_code_file"\n'
                + "generated_secret_file=1\n"
                + "enrollment_code_source=\"$enrollment_code_file\"\n"
                + "enrollment_source_identity=\"\"\n"
                + "exit 73\n"
            )
            result = subprocess.run(
                ["bash", "-c", probe, "generated-secret-cleanup-probe"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 73, result.stderr.decode())
            self.assertFalse(list(root.glob("cybex-forge-input.*")))
            self.assertNotIn(
                b"secret-created-before-bind-123",
                b"".join(
                    path.read_bytes() for path in root.iterdir() if path.is_file()
                ),
            )

    def test_full_media_rebase_queue_fails_closed_before_repair_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary)
            queue = state_root / "updates" / "media-rebase-events"
            queue.mkdir(parents=True, mode=0o700)
            queue.chmod(0o700)
            for index in range(16):
                event_id = str(uuid.UUID(int=index + 1, version=4))
                event = queue / f"{event_id}.json"
                event.write_text(
                    json.dumps(
                        {
                            "schema": "cybex.forge.media-rebase.v1",
                            "event_id": event_id,
                            "media_sequence": index + 1,
                        },
                        separators=(",", ":"),
                    ),
                    encoding="utf-8",
                )
                event.chmod(0o600)

            installer = SHELL_FILES[0].read_text(encoding="utf-8")
            definitions = installer.split("main() {", 1)[0]
            definitions = definitions.replace(
                "exec 9>/run/cybex-forge-appliance-install.lock",
                f'exec 9>"{state_root / "installer.lock"}"',
            )
            probe = (
                definitions
                + "\nFORGE_UID=$(id -u)\n"
                + f"validate_media_rebase_queue_room {shlex.quote(str(state_root))}\n"
                + "printf 'unexpected-repair-work\\n'\n"
            )
            result = subprocess.run(
                ["bash", "-c", probe, "queue-probe"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"media-rebase queue is full", result.stderr)
            self.assertNotIn(b"unexpected-repair-work", result.stdout)

    @unittest.skipUnless(shutil.which("nix-instantiate"), "Nix is not installed")
    def test_nix_files_parse(self) -> None:
        for path in ("default.nix", "module.nix", "iso.nix"):
            result = subprocess.run(
                ["nix-instantiate", "--parse", str(APPLIANCE / path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    @unittest.skipUnless(shutil.which("nix-instantiate"), "Nix is not installed")
    def test_nix_appliance_rejects_all_shared_weak_update_keys(self) -> None:
        expression = APPLIANCE / "default.nix"
        weak_keys = (
            REPOSITORY / "trust" / "ed25519-weak-public-keys.txt"
        ).read_text(encoding="ascii").splitlines()
        self.assertEqual(len(weak_keys), 14)
        for trusted in weak_keys:
            with self.subTest(trusted=trusted):
                result = subprocess.run(
                    [
                        "nix-instantiate",
                        "--eval",
                        "--strict",
                        str(expression),
                        "-A",
                        "installerIso.name",
                        "--argstr",
                        "updateTrustedPublicKey",
                        trusted,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"non-weak raw 32-byte Ed25519", result.stderr)

        noncanonical_padding = subprocess.run(
            [
                "nix-instantiate",
                "--eval",
                "--strict",
                str(expression),
                "-A",
                "installerIso.name",
                "--argstr",
                "updateTrustedPublicKey",
                "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURp=",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(noncanonical_padding.returncode, 0)
        self.assertIn(b"canonical Base64", noncanonical_padding.stderr)


if __name__ == "__main__":
    unittest.main()
