# Cybex Forge appliance

The Forge appliance is a pinned, non-flake NixOS image. It embeds one static
Forge release binary, the matching recovery copy, and the public Ed25519 key
used by the existing managed updater. A production ISO cannot be evaluated
without that public key.

## Build

Use the same canonical standard-Base64 raw 32-byte public key that signs Forge
release manifests:

```bash
RELEASE_PUBLIC_KEY='replace-with-44-character-standard-base64-key'
nix-build --no-out-link appliance/default.nix -A package \
  --argstr updateTrustedPublicKey "$RELEASE_PUBLIC_KEY"
nix-build --no-out-link appliance/default.nix -A installerIso \
  --argstr updateTrustedPublicKey "$RELEASE_PUBLIC_KEY"
```

`package` produces `bin/cybex-forge`. `installerIso` produces
`iso/cybex-forge-appliance-<version>-x86_64-linux.iso`. The expression pins
nixpkgs by revision and content hash and deliberately does not introduce a
flake into this repository.

Evaluation rejects all fourteen byte encodings that Dalek accepts for the
eight small-order Ed25519 points. Forge repeats that weak-key rejection when
parsing deployed update and cache trust.

The manifest signer accepts only that exact versioned ISO basename (locally
and in the final URL), a nonempty regular artifact, and at most 16 GiB. The
signed manifest authenticates the downloaded ISO bytes. This custom NixOS ISO
is not UEFI Secure Boot signed: boot in UEFI mode with firmware Secure Boot
disabled unless a separate, documented Secure Boot signing path is added.

For a release, sign the binary and ISO in one backwards-compatible manifest:

```bash
python3 tools/forge-release.py manifest \
  --artifact result-package/bin/cybex-forge \
  --artifact-url https://releases.example/cybex-forge-0.1.3-x86_64-linux \
  --installer-iso result-iso/iso/cybex-forge-appliance-0.1.3-x86_64-linux.iso \
  --installer-iso-url https://releases.example/cybex-forge-appliance-0.1.3-x86_64-linux.iso \
  --version 0.1.3 --private-key /secure/forge-release-key.pem \
  --release-url https://releases.example/forge/0.1.3 \
  --published-at 2026-07-31T12:00:00Z --output forge-release.json
```

The optional `installer_iso` object is signed with the
`CYBEX-FORGE-INSTALLER-ISO-V1` domain and binds version, architecture, byte
length, SHA-256, and URL. Existing binary-update fields and signatures are
unchanged. The signer requires the private key to be owned by its effective
user, mode 0600 with one link, and unchanged across every OpenSSL operation.

## Guided install

Boot the ISO in UEFI mode. The guided installer starts on tty1 and lists the
detected IPv4 address plus the exact disk model and size before confirmation.
The production minimum is 128 GiB. Install mode rejects removable disks,
mounted descendants, active swap, device-mapper/RAID holders, and anything
other than a whole disk. It requires the operator to type the resolved device
path unless `--yes` is explicitly supplied.

`API_URL` must use HTTPS because initial enrollment carries the one-time code.
`PUBLIC_BASE_URL` may use HTTP because it serves LAN PXE clients and public boot
assets, not the enrollment credential. tty1 has exactly one owner: its getty is
disabled while the guided installer owns the terminal.

The disk layout is:

| Partition | Label | Size | Purpose |
| --- | --- | ---: | --- |
| 1 | `CYBEX_EFI` | 1 GiB | UEFI system partition |
| 2 | `CYBEX_ROOT` | 40 GiB | Replaceable appliance OS |
| 3 | `CYBEX_STATE` | 16 GiB | Identity, database, config backup, updates, 8 GiB swap |
| 4 | `CYBEX_CACHE` | remainder | Build work/output, Organization ISOs, 48 GiB bounded cache |

Allocate at least 16 GiB RAM and 8 GiB swap. Admission uses 15 GiB and 7.5 GiB
operational floors so firmware/kernel and swap metadata reservations do not
make an exactly-sized VM fail its own advertised minimum. The `cybex-forge`
account is an allowed Nix daemon client but is not a trusted Nix user.

The OS store is garbage-collected daily after job-owned roots have been
released; unreferenced paths older than seven days are deleted and store path
optimization is enabled. Recovery metadata and exported artifacts live on the
separate preserved partitions and are not Nix GC roots.

On first installed boot, Forge generates its Ed25519 device identity, submits
the file-backed one-time credential, persists the enrollment response, and
atomically scrubs the credential. The serial/journal marker is:

```text
CYBEX_FORGE_ENROLLMENT pairing_code=... public_key_fingerprint=...
```

Adopt that exact pairing code and fingerprint in Manage. Until adoption, Forge
truthfully remains pending; the installer does not claim enrollment success.
After managed apply, the active config and protected recovery backup omit both
inline enrollment plaintext and the consumed file reference. During the short
first-boot transition, the backup may contain only the fixed safe path
`/var/lib/cybex-forge/bootstrap/enrollment-code`.

The installer publishes that credential only as its final durable action: one
Forge-owned staging file is fsynced, atomically renamed beside the final file,
and the parent directory is fsynced before a writable source is erased. Boot
reconciliation scrubs an interrupted staging file before Forge starts. If
power is lost after final publication (including after the source was erased)
but before the installer prints success, rerunning `install` detects the valid
installed identity and committed credential and refuses to repartition it.
Boot the installed disk to finish first enrollment. A deliberate destructive
reset requires the operator to clear the old disk identity out of band after
independently verifying the target; there is intentionally no installer force
flag that bypasses this boundary.

The appliance enables time synchronization and orders enrollment/runtime
apply after `time-sync.target`. Clock waiting is bounded to 60 seconds so an
already-adopted appliance with no upstream network still starts its cached PXE
service; signed HTTPS calls continue retrying until time and Manage recover.
The public nginx listener is IPv4-only, permits only GET/HEAD, returns 404 for
`/login` and `/api/*`, caps request sizes and timeouts, and streams large
`/files/*` and `/cache/*` responses without proxy buffering.

## Unattended seed media

Create a second ISO with volume label `CYBEX_FORGE_SEED`. Its root must contain
`/answers` and, for install mode only, `/enrollment-code`. The answers parser is
data-only: it rejects unknown/duplicate keys and never sources or evaluates the
file.

Example install answers:

```text
MODE=install
DISK=/dev/sda
API_URL=https://manage.example.com
ORGANIZATION_ID=550e8400-e29b-41d4-a716-446655440000
PUBLIC_BASE_URL=http://10.20.30.40
SSH_AUTHORIZED_KEY=ssh-ed25519 AAAA... disposable-qualification
```

Authoritative seed build (the source directory must contain only these named
files):

```bash
SEED_DIR="$(mktemp -d)"
install -m 0444 answers "$SEED_DIR/answers"
install -m 0400 enrollment-code "$SEED_DIR/enrollment-code"
xorriso -as mkisofs -quiet -R -uid 0 -gid 0 -file-mode 0600 -dir-mode 0700 \
  -V CYBEX_FORGE_SEED \
  -o cybex-forge-seed.iso -graft-points \
  /answers="$SEED_DIR/answers" /enrollment-code="$SEED_DIR/enrollment-code"
```

Presence of exactly one valid seed volume selects unattended mode. Successful
unattended install emits `stage=complete status=success`, then powers off so a
VM harness can detach both ISOs safely. Always detach and securely destroy the
seed ISO before booting the installed disk: it remains an independent sensitive
copy of the one-time code. The installed copy is scrubbed only after first-boot
enrollment succeeds.

The installer snapshots both inputs through an `O_NOFOLLOW` descriptor after
checking owner, mode, link count, size, inode, and stable metadata. Public
answers are parsed through a protected `/proc/self/fd` handle. The enrollment
snapshot is instead closed and removed before disk checks or `nixos-install`,
so installer children inherit no readable credential descriptor. The exact
same source identity is re-snapshotted only for the intended protected staging
operation and immediately removed. A writable credential source is
overwritten/unlinked only when all bound identity and timestamp fields still
match; seed media is explicitly read-only and remains the harness's disposal
responsibility.

## Repair, recovery, and rescue

`repair` checks all filesystems and reinstalls the embedded NixOS closure
without formatting. `recovery` proves the GPT and `CYBEX_STATE` appliance
identity, checks only the preserved state/cache filesystems, then reformats EFI
and root. Both preserve the managed state, device signing key, cache signing
key, cache, Organization ISOs, and build artifacts. Any identity mismatch
fails closed. Both modes restore the validated root-owned recovery config from
`CYBEX_STATE`; repair never promotes a mutable or corrupt root config into the
protected copy. The protected installed base version is parsed as canonical
SemVer and replacement media older than that version is rejected before fsck,
formatting, updater-control deletion, or any other disk mutation.

The appliance-specific config validator runs before privileged runtime writes,
on every boot before recovery reconciliation, during identity admission, and
again immediately before a recovery wipe. It requires managed mode with an
HTTPS Manage URL, enabled updates with a strong Ed25519 trust key, the fixed
local service/binary/config/health endpoints, fixed private state and cache-key
paths, and public/build/cache data below the preserved `/srv/cybex-forge`
mount. A semantically valid generic Forge config that would move appliance
state onto the replaceable root filesystem is therefore rejected.

Recovery also preserves `/var/lib/cybex-forge/appliance/machine-id`, the
state-backed Ed25519 SSH host key under
`/var/lib/cybex-forge/appliance/ssh/`, and the optional operator key at
`/var/lib/cybex-forge/appliance/root-authorized_keys`. The installer restores
the machine ID and root authorized key; sshd reads its host key directly from
the preserved state partition. `recovery` requires the same typed resolved-disk
confirmation as install unless `--yes` is explicit, while accurately stating
that only EFI/root are reformatted.

```bash
cybex-forge-appliance-install --mode repair --disk /dev/sda --yes
cybex-forge-appliance-install --mode recovery --disk /dev/sda --yes
cybex-forge-appliance-rescue check /dev/sda
cybex-forge-appliance-rescue restore-binary /dev/sda
```

The rescue `restore-binary` command delegates to the same governed `repair`
flow, rather than copying a binary behind the updater's durable state.
Operators must first verify the ISO through the signed release manifest. Managed updates
accept only a canonical SemVer newer than the running binary and require the
candidate's exact `cybex-forge <version>` identity, so an intentional rollback
belongs in this governed ISO recovery path.

Repair/recovery archive the prior exact updater control files under
`/var/lib/cybex-forge/appliance/update-history/<event-id>/`, remove only
`request.json`, `status.json`, `apply-state.json`, and `apply.lock`, and queue a
durable `cybex.forge.media-rebase.v1` event under
`/var/lib/cybex-forge/updates/media-rebase-events/`. The signed Forge report
replays up to 16 ordered events until Manage acknowledges their exact IDs.
Each event carries a positive `media_sequence` allocated by atomically
advancing the root-owned
`/var/lib/cybex-forge/appliance/media-sequence`; sequence, not the potentially
incorrect hardware clock, defines order. Gaps are safe and duplicate sequences
fail closed. Before changing a disk, repair/recovery validates the protected
queue and requires fewer than 16 pending events. If it is full, boot normally
and let Manage acknowledge the pending evidence before retrying offline media.
Only then can Manage re-offer a newer signed executable. This makes the UI
reconcile to the embedded idle/base version without discarding terminal update
history or mistaking recovery for an ordinary rollback.

The complete event is first committed and fsynced as the root-owned
`/var/lib/cybex-forge/appliance/media-rebase-transaction.json`. Only the
boot-time appliance reconciler may then delete the four controls, atomically
publish the event without replacement, and clear the journal. The same oneshot
runs before Forge on every boot, so power loss after any deletion or after
event publication is idempotently replayed. A pending journal blocks another
offline repair/recovery until the installed appliance has booted and completed
reconciliation.

If activation finds the mutable live Forge binary missing, non-regular,
non-executable, or incorrectly protected, it durably journals that fact before
atomically restoring the embedded binary. The pre-Forge reconciler replaces
any stale terminal success with an explicit `appliance_binary_recovery`
projection containing the restored executable's actual version. Terminal
success is never short-circuited unless both the live version and signed
artifact SHA-256 still match the exact request.

## Qualification contract

The live and installed systems enable the Incus guest agent and serial console
at `ttyS0,115200n8`. Stable installer markers use
`CYBEX_FORGE_INSTALLER stage=<stage> status=<status>`. Installed evidence is
`/var/lib/cybex-forge/appliance/install-state.json`; the recovery config is
`/var/lib/cybex-forge/appliance/config.toml`. Qualification must use disposable
VMs and verify install, credential scrub, enrollment/adoption, signed upgrade,
interrupted-upgrade rollback, repair, recovery, identity continuity, PXE HTTP,
and TFTP before a release is published.

Production CI has two intentionally different VM proofs. The exact-source
lifecycle above uses an ephemeral release key and synthetic successor versions
to exercise the destructive journey. After the production build is signed
once, a separate read-only smoke downloads and boots those exact ISO bytes and
checks the embedded version, production public key, binary identity, and guided
installer service. It creates no successor and returns no release asset from
the self-hosted runner; the publisher downloads the original build artifact
again. Older-media ordering, both media-rebase interruption boundaries,
corrupt-root-config protection, and missing-live-binary boot recovery are
fault-injected by the Rust and shell/C contract suites. They are not labelled
as physical VM observations in the public evidence.

Install, repair, and recovery replace the protected install-state record only
through a root-owned mode-0600 temporary file, file `fsync`, atomic rename, and
parent-directory `fsync`. A symlink or non-regular destination fails closed,
and loss of power before rename leaves the last valid appliance identity
intact.

Install completes with `enrollment=pending-on-first-boot`. Repair and recovery
instead report `enrollment=preserved update=media-rebase-pending-ack`; neither
claims that a preserved, already-adopted identity is pending enrollment.

The appliance pre-seeds writable iPXE source from the pinned nixpkgs closure;
managed apply refuses a network clone if that source is missing. It also keeps
NixOS-declarative systemd/Nix units intact and updates only the active Forge
config and appliance-compatible nginx site. `/usr/local/bin/cybex-forge-check`
is appliance-specific and verifies those NixOS contracts, local health, PXE,
machine identity, SSH host identity, and the enrollment-secret boundary.

The Proxmox LXC path remains supported separately by
`install/proxmox-host-lxc.sh`; it now uses the same protected file-backed
one-time credential lifecycle.
