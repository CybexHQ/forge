# Cybex Boot

Cybex Boot is the local PXE/iPXE boot component for [Cybex](https://cybex.net).
It runs on your infrastructure and serves boot scripts and boot assets for
machines managed through Cybex.

Cybex Boot is not a standalone PXE management product. It is designed to work
only with the Cybex commercial SaaS platform, including Cybex Manage at
[manage.cybex.net](https://manage.cybex.net). Profiles, device enrollment,
runtime settings, and reporting are controlled by Cybex Manage.

## Installation

Installation is currently supported only through the Proxmox installer generated
inside Cybex Manage:

1. Sign in to [manage.cybex.net](https://manage.cybex.net).
2. Open the Forge/Boot installer flow.
3. Choose the Proxmox installer.
4. Run the generated command on your Proxmox host.

The installer creates and configures the Cybex Boot service, enrolls it with
Cybex Manage, and keeps the local boot server managed by Cybex.

Manual standalone installation is not currently supported.

## Source And License

The source code is published as source-available for transparency,
auditability, and trust.

Cybex is a commercial SaaS product. This repository is not licensed under MIT or
another permissive open-source license. Use, modification, and deployment are
limited to Cybex-connected installations under the terms in [LICENSE](LICENSE).
