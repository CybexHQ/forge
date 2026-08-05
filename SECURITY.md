# Security

## Supported platform

Only the Ubuntu 26.04 Forge appliance installed from a personalized Cybex
Manage provisioning V2 ISO is supported. Legacy NixOS appliance and
Proxmox/LXC deployments receive no security updates and must be replaced.

## Trust boundaries

- The offline ISO template and release descriptors are signed by the Forge
  release key.
- The fixed personalization slot contains a bounded, signed, single-use V2
  provisioning envelope.
- Provisioning activates the reserved device identity before the installed
  service starts; the service does not accept install codes or pairing codes.
- Agent requests are signed by the activated device key.
- Appliance package updates and network changes are signed, journaled, and
  fail closed.
- SSH access uses the configured SSH CA and the exact reserved device ID as the
  principal.
- Workstation netboot bundles are immutable and signature-verified before
  publication.

The bootstrap validates envelope canonicalization, signatures, session state,
target-disk identity, and network plan before destructive installation. It
does not write the target disk before approval.

Secrets must not be stored in repository files, command lines, logs, release
manifests, or qualification evidence. Production signing keys and provisioning
credentials are supplied through protected deployment facilities.

## Reporting vulnerabilities

Report suspected vulnerabilities privately to the Cybex security contact. Do
not include production credentials or personal data. Include the affected
release, reproduction conditions, and whether Secure Boot, provisioning,
updates, network changes, or netboot publication are involved.
