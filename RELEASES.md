# Release Notes

Use one section per production tag.

## v0.1.0

Status: public-source ready; production tag pending.

Release checklist:

- CI is green for formatting, tests, clippy, installer script syntax,
  shellcheck, and dependency audit.
- The tag exists on the remote Forge repository.
- The Cybex Manage deployment that generated production commands is configured
  with `CYBEX_FORGE_INSTALL_REF=v0.1.0` or the selected production tag.
- A disposable Proxmox host/LXC install has verified that the generated command
  clones Forge into `/root/forge`, builds and starts Cybex Forge, submits the
  one-time enrollment, and appears as pending `cybex-forge` in Manage.
- The pending enrollment has been adopted and Boot health, nginx, TFTP,
  runtime apply services, and installer ISO/source serving have been verified.
- Install output has been captured with one-time auth codes and other secrets
  redacted.
