# Cybex Forge

Cybex Forge is the local companion appliance for [Cybex](https://cybex.net).
It runs inside customer infrastructure and provides local services that Cybex
Manage can orchestrate without moving customer-specific heavy work into the
SaaS control plane.

## Capabilities

Cybex Forge currently provides four managed local capabilities:

- Forge Boot (`boot_v1`): serves PXE/iPXE boot flows, installer ISOs, boot
  profiles, known clients, boot assets, and boot events.
- Forge Build (`builder_v1`): runs local Nix builds that Cybex Manage queues
  for configured and allowed targets.
- Forge Cache (`cache_v1`): publishes successful build outputs through a signed
  local Nix binary cache and reports cache metadata back to Cybex Manage.
- Forge updater (`updater_v1`): applies Manage-approved release updates locally
  with artifact verification, service restart, health check, and rollback.

Cybex Forge is not a standalone infrastructure management product. It is
designed to work only with the Cybex commercial SaaS platform, including Cybex
Manage at [manage.cybex.net](https://manage.cybex.net). Profiles, device
enrollment, runtime settings, desired Build jobs, artifact metadata, and
reporting are controlled by Cybex Manage.

## Installation

Installation is currently supported only through the Proxmox installer generated
inside Cybex Manage:

1. Sign in to [manage.cybex.net](https://manage.cybex.net).
2. Open the Forge installer flow.
3. Choose the Proxmox installer.
4. Run the generated command on your Proxmox host.

The installer creates and configures the Cybex Forge service, installs the
local Nix toolchain used by Forge Build/Cache and installer ISO builds, grants
the service account Nix daemon access, auto-detects the LXC LAN address for the
initial Boot URL, enrolls it with Cybex Manage, and keeps the local Forge node
managed by Cybex.
The installer uses Debian's Nix package to bootstrap `/nix/var/nix/profiles/default/bin/nix`
to a current Nix release, and Forge Build uses that profile binary for managed
flake builds.

Proxmox LXC is fine for Forge Boot and small Build/Cache deployments when the
LXC has enough CPU, memory, disk, and Nix privileges for the configured targets.
Serious NixOS closure/image building may need larger LXC resources, a VM, or
dedicated hardware. The default installer creates a narrow generated Desktop
Experience closure target in `[[build.targets]]`; add further targets
deliberately instead of using a broad build allowlist. For generated Desktop
Experience closure jobs, pin the target `flake` to the same nixpkgs revision
used by the installer media when you need strict reproducibility, and keep
`attr` at the generated
`packages.<system>.desktop-experience` output. Manual standalone installation is
not currently supported.

## Managed Updates

Managed installs enable `[update]` by default. Cybex Manage discovers the latest
release manifest, shows an `Update available` badge for adopted Forge nodes that
advertise `updater_v1`, and sends the selected update through the signed managed
config endpoint. Forge stores the request, reports progress back to Manage, and
the root `cybex-forge-runtime-apply.timer` performs the privileged apply.

The release manifest asset is JSON:

```json
{
  "schema": "cybex.forge.release.v1",
  "version": "v0.1.0",
  "release_url": "https://github.com/CybexHQ/forge/releases/tag/v0.1.0",
  "notes_url": "https://github.com/CybexHQ/forge/releases/tag/v0.1.0",
  "published_at": "2026-07-06T00:00:00Z",
  "artifact": {
    "url": "https://github.com/CybexHQ/forge/releases/download/v0.1.0/cybex-forge-x86_64-linux",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "signature": ""
}
```

Forge downloads to `update.work_dir`, enforces `max_artifact_size_bytes`,
verifies the SHA-256, optionally verifies an Ed25519 signature when
`trusted_public_key` is configured, stages the binary under `releases_dir`, smoke
tests it with `--config <config_path> print-config`, atomically replaces
`binary_path`, restarts `service_name`, and waits for `health_url`. Leave
`health_url` empty in config to derive it from `server.listen_addr`; managed
config rendering keeps it aligned with Manage-owned listener changes. On restart
or health failure, Forge restores the previous binary and reports `rolled_back`.

When signing is enabled, sign this exact message:

```text
version + "\n" + sha256 + "\n" + artifact_url + "\n"
```

## Source And License

The source code is published as source-available for transparency,
auditability, and trust.

Cybex is a commercial SaaS product. This repository is not licensed under MIT or
another permissive open-source license. Use, modification, and deployment are
limited to Cybex-connected installations under the terms in [LICENSE](LICENSE).
