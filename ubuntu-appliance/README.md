# Ubuntu Forge appliance

This directory builds the provisionable Ubuntu 26.04 LTS Forge appliance and
contains its installed package payload, systemd services, update/network
helpers, and release qualification harness. This is the sole supported Forge
appliance and installation implementation.

## Build inputs and outputs

`base-iso.json` pins the generally available Ubuntu Server ISO by canonical
HTTPS URL, filename, byte length, SHA-256, and Canonical checksum/signature
URLs. `build-template.sh` downloads those inputs, verifies the signed
`SHA256SUMS` with `/usr/share/keyrings/ubuntu-archive-keyring.gpg`, verifies the
exact ISO bytes, extracts it, and preserves every EFI binary byte-for-byte.
Canonical's signed shim, GRUB, kernel, and modules therefore remain the Secure
Boot chain; no MOK enrollment is required.

The build adds only:

- unattended NoCloud/Autoinstall configuration;
- `cybex-forge-bootstrap` and accepted online provisioning public keys;
- a fixed zero-filled 8192-byte `/CYBEX_PROVISIONING.BIN` slot;
- an offline APT repository built by `build-offline-repo.sh`;
- the installed appliance package and hardening/runtime helpers.

Typical invocation:

```bash
ubuntu-appliance/build-template.sh \
  --output-dir dist \
  --forge-binary target/x86_64-unknown-linux-gnu/release/cybex-forge \
  --bootstrap-binary target/x86_64-unknown-linux-gnu/release/cybex-forge-bootstrap \
  --version 1.2.3 \
  --ubuntu-snapshot-id 20260804T000000Z \
  --release-public-key "$CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY" \
  --provisioning-public-key "$CYBEX_FORGE_PROVISIONING_PUBLIC_KEY"
```

Provisioning keys must be canonical standard-Base64 raw Ed25519 public keys,
unique, and supplied in sorted order. The release key is the offline update
trust root. Private signing keys are never inputs to this build.

Outputs are created once and never overwritten:

- `cybex-forge-appliance-template-<version>-x86_64-linux.iso`
- matching template metadata with the exact slot offset/size/digests
- `cybex-forge-appliance-packages-<version>-x86_64-linux.tar.zst`
- matching package-snapshot metadata

Release automation signs the v2 installer descriptor and package descriptor,
qualifies these exact bytes, and publishes the same candidate. Rebuilding after
qualification is forbidden.

## Offline repository

`build-packages.sh` produces `cybex-forge`, `cybex-forge-bootstrap`, and
`cybex-forge-appliance` Debian packages. The appliance dependency closure
includes systemd, nginx, TFTP/iPXE, OpenSSH, nftables, Netplan, Btrfs/watchdog,
Nix, `linux-generic`, `linux-firmware`, `intel-microcode`, and
`amd64-microcode`. It installs the pinned Forge release public key and all
root-owned helpers. `build-offline-repo.sh` resolves and downloads the exact
Ubuntu snapshot dependency closure and emits deterministic APT metadata.
Independent `apt-daily`, `apt-daily-upgrade`, and `unattended-upgrades` units
are masked by package installation.

## Provisioning bootstrap

The NoCloud seed has no interactive sections. Its early command runs:

```text
cybex-forge-bootstrap prepare
```

The Rust bootstrap verifies canonical envelope padding/body/signature and the
fixed production `https://manage.cybex.net` origin, derives a provisioning-only
key from the 256-bit media secret, claims the session with exact-body proof,
and uploads bounded inventory. It blocks until Management returns a valid plan.
Before partitioning it re-collects inventory, checks Secure Boot/UEFI/wired
Ethernet and exact disk geometry/stable identity. A static plan is exercised
with the candidate source address in an isolated policy-routing table: duplicate
address detection, gateway ARP, every approved DNS resolver, and TLS to the
signed Management origin must all succeed. The temporary address, rule, and
routes are removed on every exit path.

The accepted destructive event precedes the first disk command. Partition 3
(`CYBEX_STATE`) is then created first; a random permanent Ed25519 key is written
and fsynced there, and the Management identity transition requires both
temporary and permanent signatures. The rest of the GPT is created
idempotently. Subiquity re-reads the generated `/autoinstall.yaml`, installs
only from the offline repository, and late commands materialize the exact
device identity/config, Netplan, SSH CA/principal, management firewall CIDRs,
and release state into `/target`.

Durable state records the session, signed plan, online Management public key,
permanent key, event sequence, identity activation, and install completion.
Booting the same media after a pre-completion power interruption validates and
resumes exact geometry/events. A completed marker sets the installed Ubuntu
UEFI entry as `BootNext` and reboots rather than replaying installation.

## Installed services

- `cybex-forge.service`: unprivileged Forge service
- `cybex-forge-first-boot.service`: network guard, first permanent-key report,
  and readiness transition
- `cybex-forge-firewall.service`: management-CIDR SSH nftables boundary
- `cybex-forge-appliance-update.timer/service`: maintenance-window root
  generation updater
- `cybex-forge-generation-commit.service`: candidate health/commit or rollback
- `cybex-forge-network-change.path/service`: signed two-phase Netplan changes

`cybex-support` has a locked password. SSH disables password/keyboard/root
login, permits only that user and the exact device principal, and trusts active
plus next Cybex CA public keys. Forwarding works only when the short-lived user
certificate explicitly contains its permission extension. nftables drops SSH
from outside the plan's management CIDRs.

`/nix` is an executable `nodev,nosuid` bind mount backed by
`CYBEX_CACHE`. Installer-seeded Nix content is copied there before the
bind is activated; first boot verifies the mount identity/options and initializes
the store before `nix-daemon`. The store remains root-owned while
`cybex-forge` receives daemon access through `nix-users`.

## Root generations and package updates

The Forge service accepts only a Management request whose
`cybex.forge.appliance-release.v1` validates against the installed offline
release key. It downloads the exact archive without redirects. Root then runs
`cybex-forge verify-appliance-update` against the original descriptor/archive,
checks safe archive entries/checksum coverage/Packages versions, and builds a
writable Btrfs generation. Installation uses only that extracted repository.
The candidate must pass package, signed-kernel, systemd, Nix, release, and
boot-file validation before one-shot GRUB selection.

On candidate boot, `cybex-forge-generation-commit` checks Forge, Nix, nginx,
TFTP, disk, and network. Success sets the default generation and retains two
prior known-good generations. Failure records bounded rollback evidence and
leaves the prior default in force. A hardware watchdog protects a candidate
that never reaches the commit service.

## Qualification

`.github/workflows/release.yml` builds a single candidate. Before publication,
the self-hosted qualification job runs
`ubuntu-appliance/qualification/run-lifecycle.sh` against those exact bytes.
The harness verifies personalization, boots with OVMF Secure Boot, proves the
disk prefix is unchanged before approval, claims and approves through
Management, installs, rotates identity, reboots with media still attached,
requires a healthy permanent-key appliance projection, completes a two-phase
DHCP network change, verifies an exact-principal/non-forwarding SSH
certificate, and captures bounded redacted evidence. Browser tests separately
cover range requests across both slot boundaries; Rust/shell tests cover update
state, generation commit/rollback, and network rollback helpers. Publication
downloads the qualified artifact by ID/digest and fails if it is missing,
expired, changed, or rebuilt.

Production qualification must also cover the documented VM controller matrix
and representative Dell, HP, Lenovo, Intel/AMD, Ethernet, SATA/NVMe/VMD, and
firmware generations before the release is promoted.
