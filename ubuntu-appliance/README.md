# Ubuntu James appliance

This directory builds the provisionable Ubuntu 26.04 LTS James thin USB
installer, its separately delivered package snapshot, the installed appliance
payload, and the release qualification harness. This is the sole supported
James appliance and installation implementation.

## Build inputs and outputs

`base-iso.json` pins a dated Ubuntu 26.04 Server image that passed Canonical's
automated image tests by canonical HTTPS URL, filename, byte length, SHA-256,
and Canonical checksum/signature URLs. Dated URLs keep the build reproducible;
the moving `current` alias is never consumed. `build-template.sh` downloads those inputs, verifies the signed
`SHA256SUMS` with `/usr/share/keyrings/ubuntu-archive-keyring.gpg`, verifies the
exact ISO bytes, extracts it, and preserves every EFI binary byte-for-byte.
Canonical's signed shim, GRUB, kernel, and modules therefore remain the Secure
Boot chain; no MOK enrollment is required.

The ISO build adds only:

- unattended NoCloud/Autoinstall configuration;
- `cybex-james-bootstrap`, accepted online provisioning public keys, and the
  offline James release trust key;
- the Cybex-branded GRUB boot screen used by the former USB installer, with a
  single **Boot Cybex James Setup** action;
- a fixed zero-filled 8192-byte `/CYBEX_PROVISIONING.BIN` slot.

Static-network safety checks run before the target package snapshot is
installed. The bootstrap therefore uses the `arping` applet at the pinned live
installer's absolute `/usr/bin/busybox` path. The template build extracts that
exact authenticated live root and rejects the ISO if either BusyBox or its
`arping` applet is absent. The installed appliance continues to receive
`iputils-arping` through the signed package closure.

The package dependency closure is built and published as a separate signed
release asset. It is intentionally not embedded at `/cybex/apt`, keeping the
hybrid ISO suitable for USB installation while avoiding a second copy of the
kernel, firmware, and appliance runtime packages. The ISO builder also removes
Ubuntu's `/pool` and `/dists` target-package trees, including the large
proprietary GPU driver pool. It retains `/casper` in full, including the live
installer kernel, initrd, hardware modules, firmware, and minimal server
SquashFS, so boot-time hardware support remains the stock signed Ubuntu set.
The pinned base currently remasters to approximately 1.65 GB (1.54 GiB).

Typical invocation:

```bash
ubuntu-appliance/build-package-snapshot.sh \
  --output-dir dist \
  --james-binary target/x86_64-unknown-linux-gnu/release/cybex-james \
  --bootstrap-binary target/x86_64-unknown-linux-gnu/release/cybex-james-bootstrap \
  --version 1.2.3 \
  --ubuntu-snapshot-id 20260804T000000Z \
  --manage-source-dir "$CYBEX_JAMES_MANAGE_SOURCE_DIR" \
  --manage-source-revision "$CYBEX_JAMES_MANAGE_SOURCE_REVISION" \
  --expected-manage-origin "$CYBEX_JAMES_BUILD_MANAGE_ORIGIN" \
  --release-public-key "$CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY" \
  --provisioning-public-key "$CYBEX_JAMES_PROVISIONING_PUBLIC_KEY"

ubuntu-appliance/build-template.sh \
  --output-dir dist \
  --bootstrap-binary target/x86_64-unknown-linux-gnu/release/cybex-james-bootstrap \
  --version 1.2.3 \
  --ubuntu-snapshot-id 20260804T000000Z \
  --expected-manage-origin "$CYBEX_JAMES_BUILD_MANAGE_ORIGIN" \
  --release-public-key "$CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY" \
  --provisioning-public-key "$CYBEX_JAMES_PROVISIONING_PUBLIC_KEY"
```

For a follow-up release on the exact same Ubuntu snapshot, the previous
package snapshot may be supplied only as an explicit download-cache seed:

```bash
ubuntu-appliance/build-package-snapshot.sh \
  --output-dir dist \
  --james-binary target/x86_64-unknown-linux-gnu/release/cybex-james \
  --bootstrap-binary target/x86_64-unknown-linux-gnu/release/cybex-james-bootstrap \
  --version 1.2.4 \
  --ubuntu-snapshot-id 20260804T000000Z \
  --manage-source-dir "$CYBEX_JAMES_MANAGE_SOURCE_DIR" \
  --manage-source-revision "$CYBEX_JAMES_MANAGE_SOURCE_REVISION" \
  --expected-manage-origin "$CYBEX_JAMES_BUILD_MANAGE_ORIGIN" \
  --release-public-key "$CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY" \
  --provisioning-public-key "$CYBEX_JAMES_PROVISIONING_PUBLIC_KEY" \
  --previous-package-snapshot dist/cybex-james-appliance-packages-1.2.3-x86_64-linux.tar.zst
```

The flag is optional and is never inferred from an environment variable or
from `dist`. A supplied snapshot with a different `UBUNTU-SNAPSHOT-ID` is a
hard error; omit the flag when moving to another Ubuntu snapshot.

Provisioning keys must be canonical standard-Base64 raw Ed25519 public keys,
unique, and supplied in sorted order. The release key is the offline update
trust root. Private signing keys are never inputs to this build.
The package snapshot and installer template must receive the exact same sorted
governed provisioning-key set; a key-set mismatch makes legacy state promotion
fail closed.
The package builder also compares the bootstrap binary's compiled Management
origin with the independently supplied expected origin and records it in its
bounded build metadata. Manifest signing requires that metadata and accepts it
only when its origin matches the signed installer-template origin. This binds
the bootstrap installed from the authenticated package archive without adding
the private build metadata to the public release asset set.

The Manage source arguments must identify an exact clean checkout at the
signed workstation runtime's 40-hex `manage_source_revision`. The package
builder creates a deterministic Git tar archive with a fixed archive umask and
embeds it in `cybex-james` at
`/usr/share/cybex-james/manage-source/<revision>.tar`. Adjacent canonical JSON
binds its revision, filename, byte length, and SHA-256. The directory is
root-owned mode `0755`; both files are root-owned mode `0444`. Package-snapshot
metadata records the same identity, manifest signing rejects a revision that
differs from the workstation descriptor, and independent release verification
opens the signed snapshot and Debian package to repeat that check. This keeps
installer-target builds offline and adds no public release artifact.

Both builders create their outputs once and never overwrite an existing
candidate:

- `cybex-james-appliance-template-<version>-x86_64-linux.iso`
- matching template metadata with the exact slot offset/size/digests and
  `package_delivery: network-snapshot-v1` plus the explicit canonical
  `manage_origin`
- `cybex-james-appliance-packages-<version>-x86_64-linux.tar.zst`
- matching package-snapshot metadata

Release automation signs the v2 installer descriptor and package descriptor,
qualifies these exact bytes, and publishes the same candidate. Rebuilding after
qualification is forbidden.

## Network-delivered package snapshot

`build-packages.sh` produces `cybex-james`, `cybex-james-bootstrap`, and
`cybex-james-appliance` Debian packages. The appliance dependency closure
includes systemd, nginx, TFTP/iPXE, OpenSSH, nftables, Netplan, Btrfs/watchdog,
Nix, `linux-generic`, `linux-firmware`, `intel-microcode`, and
`amd64-microcode`. The snapshot also carries `grub-efi-amd64`, Canonical's
signed GRUB and shim packages, and `secureboot-db`; the target therefore does
not depend on Ubuntu's removed media pool to create its signed UEFI boot chain.
The pinned Subiquity/Curtin runtime bind-mounts `/run` into the chrootable
target, so the authenticated repository staged beneath
`/run/cybex-appliance-repo/packages` is available to Curtin's UEFI curthooks
before late commands run.
It installs the pinned James release public key and all root-owned helpers.
`build-offline-repo.sh` resolves and downloads the exact
Ubuntu snapshot dependency closure and emits deterministic APT metadata;
`build-package-snapshot.sh` archives that repository and emits the bounded
metadata consumed by release signing. Independent `apt-daily`,
`apt-daily-upgrade`, and `unattended-upgrades` units are masked by package
installation.

Before admitting a signed workstation runtime or starting any installer-target
build, James securely reopens the revision-scoped Manage archive and metadata,
rejects links or unsafe ownership/modes/link counts, and verifies the declared
size and SHA-256. Installer flakes use only the resulting local
`tarball+file:///usr/share/cybex-james/manage-source/<revision>.tar` input; no
GitHub availability or credential is part of device preparation.

The optional previous-snapshot seed is an optimization, not a trust root or an
offline mode. After authenticating the current snapshot indexes, APT first
projects the exact current dependency filenames. The seed reader securely
opens a bounded regular archive, requires the exact snapshot marker, and
extracts only unique top-level regular `.deb` members selected by that current
plan. APT is forced to project the strong SHA256 from those authenticated
indexes; every candidate must match that exact digest and size before import.
Names beginning with `cybex-james` are always discarded so each release uses
the newly built James packages. No Debian or inner archive parser sees bytes
before this strong identity check. Verified candidates are imported with
no-overwrite semantics into a fresh APT archive cache, APT fetches every
missing package, and only afterward does the builder inspect package structure
and architecture. Local package archive timestamps and repository indexes are
regenerated from the signed Ubuntu snapshot timestamp, so seeded and unseeded
builds emit the same package snapshot bytes.

## Provisioning bootstrap

The NoCloud seed has no interactive sections. Its early command runs:

```text
cybex-james-bootstrap prepare
```

The Rust bootstrap verifies canonical envelope padding/body/signature and the
fixed production `https://manage.cybex.net` origin, derives a provisioning-only
key from the 256-bit media secret, claims the session with exact-body proof,
and uploads bounded inventory. It blocks until Management returns a valid plan
containing the release-signed appliance package snapshot. The bootstrap
authenticates that descriptor with `/cdrom/cybex/release-public-key`, downloads
the exact snapshot, and validates its size, digest, archive, repository, and
required package versions before installation can be accepted. A failed or
interrupted fetch leaves the target disk untouched. Hardware, network, media,
and package failures before the destructive event are reported with bounded
public-safe codes and messages while the full local error stays in the
bootstrap journal. The live environment keeps polling after the failure so
Management can reopen the same session for review and issue a superseding
plan; if it was powered off, an administrator can restart the same ISO after
choosing the safe retry.

Official bootstrap binaries keep that production origin compiled in. A
development-only appliance may be pinned to another canonical HTTPS origin at
compile time with `CYBEX_JAMES_BUILD_MANAGE_ORIGIN`; that binary and ISO must
use separate development provisioning and release trust keys. The template
builder requires the independently governed `--expected-manage-origin`, asks
the bootstrap binary for its compiled origin, and re-opens the completed ISO to
prove it embedded those exact bootstrap bytes. Release manifest generation
requires the same explicit expected origin and the template build metadata;
verification requires the expected origin again. None of these gates derives
the expectation from the bootstrap or from release artifact URLs.

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
only from the authenticated downloaded repository, and late commands
materialize the exact device identity/config, Netplan, SSH CA/principal,
management firewall CIDRs, and release state into `/target`.

Durable state records the session, signed plan, online Management public key,
permanent key, event sequence, identity activation, and install completion.
Booting the same media after a pre-completion power interruption validates and
resumes exact geometry/events. A completed marker inspects the kernel-provided
UEFI variables directly, sets the active installed Ubuntu or Cybex James entry
as `BootNext`, verifies it, and reboots rather than replaying installation. The
live recovery handoff therefore has no undeclared dependency on `efibootmgr`.

## Installed services

- `cybex-james.service`: unprivileged James service
- `cybex-james-first-boot.service`: network guard, first permanent-key report,
  and readiness transition
- `getty@tty1.service`: status-only physical console for the managed appliance
- `cybex-james-firewall.service`: management-CIDR SSH nftables boundary
- `cybex-james-appliance-update.timer/service`: maintenance-window root
  generation updater
- `cybex-james-generation-commit.service`: candidate health/commit or rollback
- `cybex-james-network-change.path/service`: signed two-phase Netplan changes
- `cybex-james-network-runtime.timer/service`: reconciles the advertised boot
  origin with the committed Netplan interface after DHCP leases or approved
  network changes

The first physical virtual console is an appliance status display, not a local
administration or login screen. It shows only the administrator-assigned James
name when that name is safe for a terminal, a simple Starting, Ready, or
Attention needed state, and directs recovery to Cybex Manage. The tty1-specific
unit yields to system rescue mode; serial-console recovery and the separate
short-lived-certificate SSH support path are unchanged. Normal administration
remains exclusively in Cybex Manage.

First boot stages the package-provided `snponly.efi`, `ipxe-amd64.efi`, and
credential-free `autoexec.ipxe` handoff into the persistent TFTP root as
root-owned, public-readable immutable files. The narrow tree is `0755
root:root` and all three files are `0644 root:root`: this satisfies
`tftpd-hpa`'s public-readability policy without granting either the
unprivileged James process or the dedicated `tftp` account write access. The
handoff uses the DHCP `next-server` and the active NIC's MAC to request the
per-client HTTP boot route. This breaks stock iPXE's otherwise-recursive
chainload without requiring a DHCP server to implement a fragile second-stage
user-class rule. No tenant, credential, configuration, or runtime-generated
material is placed there. `tftpd-hpa` serves only that root, and readiness
refuses success unless both the selected launcher and exact handoff have safe
metadata and are served byte-for-byte over complete TFTP transfers.
Readiness also self-fetches the boot script from the current local IPv4 origin;
public health requests share a bounded single-flight cache rather than starting
unlimited probes.

The James appliance continues to require factory Secure Boot enabled. A
workstation installed through PXE currently requires x86-64 UEFI network boot
with Secure Boot turned off because the package-provided iPXE EFI program and
the NixOS workstation kernel do not yet share a Cybex-governed signing chain.
Do not claim workstation Secure Boot support until that chain is an explicit,
verified release prerequisite.

`cybex-support` has a locked password. SSH disables password/keyboard/root
login, permits only that user and the exact device principal, and trusts active
plus next Cybex CA public keys. Forwarding works only when the short-lived user
certificate explicitly contains its permission extension. nftables drops SSH
from outside the plan's management CIDRs.

`/nix` is an executable `nodev,nosuid` bind mount backed by
`CYBEX_CACHE`. Appliance installation requires a fixed disk of at least
160 GiB; the bootstrap also requires at least 80 GiB for this final shared
partition after the fixed EFI, root, state, and swap partitions. Installer-seeded
Nix content is copied there before the bind is activated; first boot verifies
the mount identity/options and initializes the store before `nix-daemon`.
The store remains root-owned while `cybex-james` receives daemon access through
`nix-users`. Cache retention reacts to both its configured cache-size ceiling
and real filesystem headroom, preserving space for one maximum exact workstation
installer target whenever unprotected artifacts can be reclaimed.

## Root generations and package updates

The James service accepts only a Management request whose
`cybex.james.appliance-release.v1` validates against the installed offline
release key. It downloads the exact archive without redirects. Root then runs
`cybex-james verify-appliance-update` against the original descriptor/archive,
checks safe archive entries/checksum coverage/Packages versions, and builds a
writable Btrfs generation. The repository is shared with fresh installation,
but an installed update does not install its full installer closure. APT sees
only the verified local repository and requests the exact signed versions of
`cybex-james`, `cybex-james-bootstrap`, and `cybex-james-appliance`; only their
needed dependencies may be added or upgraded. The update is rejected before
mutation if APT would remove, downgrade, or change a held package, and the
complete installed package set is compared again after application. APT first
copies that safe solution from the read-only snapshot into the candidate's
private cache; the snapshot is then unmounted and application forbids any
further acquisition. The candidate must then pass package, signed-kernel,
systemd, Nix, release, and boot-file validation before one-shot GRUB selection.

A release that succeeds an appliance still carrying the legacy full-closure
updater is a one-time bridge. Publication qualification must exercise that
predecessor's exact update command against the successor snapshot and prove a
monotone plan with no removals or downgrades. After that bridge, the selective
solver above is the supported N-to-N+1 update contract.

On candidate boot, `cybex-james-generation-commit` checks James, Nix, nginx,
TFTP, disk, and network. Success sets the default generation and retains two
prior known-good generations. Failure records bounded rollback evidence and
leaves the prior default in force. A hardware watchdog protects a candidate
that never reaches the commit service.

## Qualification

`.github/workflows/release.yml` builds a single candidate. Before publication,
the self-hosted qualification job runs
`ubuntu-appliance/qualification/run-lifecycle.sh` against those exact bytes.
The harness submits the release-signed candidate descriptor to Management.
For a selective-root predecessor it serves the exact unpublished package
snapshot on a dynamically allocated port bound only to the qualification
bridge's private IPv4 address and supplies that short-lived transport override
to the signed qualification plan. A frozen legacy predecessor rejects that
additional field, so its one-time bridge instead requires the same package
bytes to be readable at the already-signed canonical HTTPS URL before Manage
delivers the predecessor's canonical three-field request. The harness then
downloads only its signed fixed-size personalization envelope, applies that
envelope to the local build-once template, verifies personalization, boots
with OVMF Secure Boot, proves the
disk prefix is unchanged before approval, claims and approves through
Management, installs, rotates identity, reboots with media still attached,
requires a healthy permanent-key appliance projection, completes a two-phase
DHCP network change, verifies an exact-principal/non-forwarding SSH
certificate, and then proves the greenfield delivery invariant. The new James
must report an operational and converged verified workstation runtime; the
default source-free policy must remain effective; and the exact current
revisions of Standard Taskbar Workstation, Standard Dock Workstation, and
Hyprland Developer must all prepare successfully on that node and be ready on
every required replica. The Hyprland seed must contain Deno rather than Node.js.
A source-policy failure records its bounded offending derivations before the
qualification fails. Publication requires these assertions in the run evidence,
so an official built-in that is incompatible with the current James classifier
cannot first be discovered on a customer installation. The harness then
captures bounded redacted evidence. Browser tests separately
cover range requests across both slot boundaries; Rust/shell tests cover update
state, generation commit/rollback, and network rollback helpers. Publication
downloads the qualified artifact by ID/digest and fails if it is missing,
expired, changed, or rebuilt.

For development releases whose signed package URL is under Manage's configured
`/james-dev-artifacts` tree, first verify the complete candidate with
`tools/james-release.py verify`, then stage only the hash-bound package:

```bash
install -d -m 0700 /absolute/private/cybex-james-stage-state
ubuntu-appliance/qualification/stage-canonical-package.py stage \
  --manifest dist/cybex-james-release.json \
  --package-snapshot dist/cybex-james-appliance-packages-VERSION-x86_64-linux.tar.zst \
  --artifact-root /absolute/served/releases \
  --served-prefix https://manage.example/james-dev-artifacts \
  --state-dir /absolute/private/cybex-james-stage-state \
  --owner acceptance-VERSION
```

`verify` accepts the same arguments except `--package-snapshot`. On a cancelled
or failed qualification, `cleanup` removes only an exact file still bound to
the same manifest digest and owner; it is idempotent and refuses unowned or
changed paths. Keep the package and private ownership journal after a
successful qualification: ordinary release promotion takes over that exact
file when it adds the other verified artifacts. Cleanup also refuses to run
after the release directory has gained any other file, preventing it from
removing a promoted package. The helper never copies the manifest,
compatibility asset, selection pointer, or any other candidate file into the
served tree.

The production workflow's signed URLs are GitHub
`/releases/download/<tag>/...` URLs. A draft release asset is not an anonymous
canonical transport for a frozen appliance, while publishing a package-only
release under repository immutable-release policy would lock that tag before
the other qualified assets can be attached. Therefore the
`legacy_all_debs` production branch deliberately fails its canonical download
preflight unless an authorized immutable package-only transport exists at the
signed URL. Do not work around that gate by publishing the release early,
adding a field the predecessor cannot deserialize, or signing a different
origin: Manage's production importer requires every release artifact to belong
to the same immutable GitHub release. The bounded local staging helper above is
the supported path for this acceptance campaign; general production release
automation remains blocked on an artifact host/publication protocol that can
atomically promote the complete qualified release without changing signed
URLs.

### Local immutable predecessor identity

Development bridge preparation must not describe the predecessor as a fake
GitHub release. `legacy-bridge-gate.py identify-local-predecessor` instead
selects the highest SemVer directory that is an exact immutable seven-file
release beneath the configured artifact root. It requires a mode-`0555`
release directory, the six checksum-listed release artifacts plus
`SHA256SUMS`, exact owner/link/mode/size/digest metadata, verified release and
compatibility signatures, and artifact URLs exactly beneath one canonical
HTTPS served prefix. Every SemVer-named child is classified and its stable
metadata is included in the local index digest, including older mutable build
trees. A malformed or mutable entry newer than the selected release is fatal.
A newer package-only candidate is accepted as staging—not publication—only
when its exact immutable package bytes are bound by the canonical staging
helper's canonical mode-`0600` ownership journal in a private directory outside
the served tree.

```bash
ubuntu-appliance/qualification/legacy-bridge-gate.py \
  identify-local-predecessor \
  --artifact-root /absolute/served/releases \
  --staging-state-dir /absolute/private/cybex-james-stage-state \
  --served-prefix https://manage.example/james-dev-artifacts \
  --trusted-public-key "$CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY" \
  --release-verifier tools/james-release.py \
  --output /absolute/private/local-predecessor.json

ubuntu-appliance/qualification/legacy-bridge-gate.py \
  recheck-local-predecessor \
  --qualified-identity /absolute/private/local-predecessor.json \
  --artifact-root /absolute/served/releases \
  --staging-state-dir /absolute/private/cybex-james-stage-state \
  --served-prefix https://manage.example/james-dev-artifacts \
  --trusted-public-key "$CYBEX_JAMES_UPDATE_TRUSTED_PUBLIC_KEY" \
  --release-verifier tools/james-release.py
```

Identification streams all seven selected files from their exact HTTPS URLs,
requires status 200 without redirects, ranges, or content encoding, and checks
the declared length and SHA-256 while streaming. It extracts the authenticated
package snapshot to derive the updater contract and packaged release identity.
The separate
`cybex.james.local-published-appliance-predecessor.v1` result binds both the
selected seven-file release-set digest and the complete local published-index
digest. Run the recheck after qualification and before using the governed
identity; it repeats the full inspection and fails if the highest release,
index, bytes, signatures, origin, or packaged updater changed. These local
commands do not alter the GitHub production identity commands or release
workflow.

The bridge address is discovered automatically. A runner with more than one
private bridge address can select an address already assigned to that bridge
with `CYBEX_JAMES_QUALIFICATION_PACKAGE_BIND_ADDRESS`; loopback and public
addresses are rejected.

The automated boot entry mirrors Ubuntu to the first serial port so early
installer failures are visible in the protected job, while keeping the
physical display as the primary console. Ubuntu's remove-media prompt and
installer failures therefore remain visible on the attached screen as well as
in serial diagnostics. Qualification stops after five minutes when an approved
candidate has not acknowledged its plan or begun destructive work, and includes
only bounded console and session diagnostics.
The protected VM uses a fixed virtual NIC address and disk serial so retries
represent the same hardware. A failed pre-write qualification is revoked
automatically, releasing its unused reserved device identity.

Production qualification must also cover the documented VM controller matrix
and representative Dell, HP, Lenovo, Intel/AMD, Ethernet, SATA/NVMe/VMD, and
firmware generations before the release is promoted.
