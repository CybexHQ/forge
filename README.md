# Cybex Forge

Cybex Forge is the local companion appliance for [Cybex](https://cybex.net).
It runs inside customer infrastructure and provides local services that Cybex
Manage can orchestrate without moving customer-specific heavy work into the
SaaS control plane.

Cybex Forge ships Forge Boot, Forge Build, and Forge Cache for managed local
infrastructure:

- `boot_v1`: PXE/iPXE provisioning, Boot profiles, clients, events, ISO sync,
  and netboot asset generation.
- `builder_v1`: local Nix Build execution for Manage-queued jobs that match the
  configured artifact type, target, system, flake, and attribute allowlist.
- `cache_v1`: signed local Nix binary cache export under `/cache/`, including
  generated signing keys, validated `nix-cache-info`, signed `.narinfo`
  metadata, retention, and Manage reporting.

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

The old `install/cybex-boot-lxc-install.sh` entry point is kept as a wrapper for
previously generated commands. When the Forge installer is rerun inside an old
`cybex-boot` LXC, it disables the old units and copies legacy state, SQLite, and
boot asset files into Forge-owned paths only when the new targets are empty.

The installer creates and configures the Cybex Forge service, installs the
local Nix toolchain used by Forge Build/Cache, grants the service account Nix
daemon access, enrolls it with Cybex Manage, and keeps the local Forge node
managed by Cybex.

Proxmox LXC is fine for Forge Boot and small Build/Cache deployments when the
LXC has enough CPU, memory, disk, and Nix privileges for the configured targets.
Serious NixOS closure/image building may need larger LXC resources, a VM, or
dedicated hardware. Build targets are disabled until configured in
`[[build.targets]]`; the default installer creates the worker and cache
directories but no broad build allowlist. Manual standalone installation is not
currently supported.

## Source And License

The source code is published as source-available for transparency,
auditability, and trust.

Cybex is a commercial SaaS product. This repository is not licensed under MIT or
another permissive open-source license. Use, modification, and deployment are
limited to Cybex-connected installations under the terms in [LICENSE](LICENSE).
