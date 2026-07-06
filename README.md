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
- Forge installer ISO builds (`installer_iso_builder_v1`): builds organization
  enrollment installer ISOs locally and serves them from Forge public files.

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
local Nix toolchain used by Forge Build/Cache, grants the service account Nix
daemon access, auto-detects the LXC LAN address for the initial Boot URL,
enrolls it with Cybex Manage, and keeps the local Forge node managed by Cybex.

Proxmox LXC is fine for Forge Boot and small Build/Cache deployments when the
LXC has enough CPU, memory, disk, and Nix privileges for the configured targets.
Serious NixOS closure/image building may need larger LXC resources, a VM, or
dedicated hardware. Build targets are disabled until configured in
`[[build.targets]]`; the default installer creates the worker and cache
directories but no broad build allowlist. For generated Desktop Experience
closure jobs, pin the target `flake` to the same nixpkgs revision used by the
installer media, and keep `attr` at the generated
`packages.<system>.desktop-experience` output. Manual standalone installation is
not currently supported.

## Source And License

The source code is published as source-available for transparency,
auditability, and trust.

Cybex is a commercial SaaS product. This repository is not licensed under MIT or
another permissive open-source license. Use, modification, and deployment are
limited to Cybex-connected installations under the terms in [LICENSE](LICENSE).
