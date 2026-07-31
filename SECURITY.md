# Security Policy

## Supported Versions

Production deployments should install from a signed or otherwise controlled
release tag such as `v0.1.0`, not from a floating branch.

| Version | Supported |
| ------- | --------- |
| Latest release tag | Yes |
| `main` | Development only |

## Reporting A Vulnerability

Report suspected vulnerabilities privately to the project maintainers before
opening public issues. Include the affected release tag or commit, a concise
reproduction path, and whether the issue can expose credentials, enrollment
codes, managed device identities, or boot artifacts.

Do not include one-time Forge install codes, private keys, database passwords,
API tokens, or other secret material in public reports, logs, examples, or
screenshots.

## Release Gate

Before publishing a production tag, run:

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
bash -n install/proxmox-host-lxc.sh install/cybex-forge-lxc-install.sh appliance/cybex-forge-appliance-*
shellcheck install/proxmox-host-lxc.sh install/cybex-forge-lxc-install.sh appliance/cybex-forge-appliance-*
python3 -B -m unittest discover -s tools/tests -v
nix-instantiate --parse appliance/default.nix
nix-instantiate --parse appliance/module.nix
nix-instantiate --parse appliance/iso.nix
nix-build --no-out-link appliance/default.nix -A package
# Pass the production public release key; never the private signing key.
nix-build --no-out-link appliance/default.nix -A installerIso \
  --argstr updateTrustedPublicKey "$CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY"
cargo tree -i sqlx-mysql
cargo audit --ignore RUSTSEC-2023-0071
cargo package --allow-dirty --no-verify
```

`RUSTSEC-2023-0071` is ignored only because `cargo audit` reports optional
`sqlx-mysql` lockfile metadata even when the active feature tree does not use
the MySQL driver. `cargo tree -i sqlx-mysql` must print `nothing to print`
before that ignore is acceptable.

The tag workflow is separately gated by the protected `production-release`
environment. Configure its approved public trust root variable and matching
base64-encoded private-key secret as documented in `RELEASES.md`; missing,
weak, or mismatched trust inputs must fail the job. Enable repository
immutable releases before tagging and provide the environment's read-only
`CYBEX_FORGE_RELEASE_POLICY_TOKEN` so CI can verify (but never mutate) that
policy through the repository Administration-read API. The private key is
materialized only for the build/sign step, is never passed to Nix, and is
removed before the one release-candidate artifact is uploaded. The self-hosted
exact-artifact smoke receives the public trust root but never references the
production signing key and never uploads release bytes. The publisher
downloads the original build artifact and bounded qualification evidence by
immutable artifact ID, verifies their Actions provenance and digests, verifies
and attests all five release assets, attaches them to an owned draft, checks
the remote digests, and publishes only after the exact smoke succeeds. A pinned
Rust formatting/test/clippy gate is also a direct prerequisite of the tag build.
Only workflow attempt one may build or sign; later attempts reuse the candidate
or fail closed when it is unavailable instead of re-signing. Draft cleanup
requires the exact marker-only body and title and permits only a unique subset
of the five expected asset names. The tag also waits for the self-hosted exact-SHA
Manage/Forge source lifecycle gate; its required variables, API credential,
optional cross-repository read token, and runner labels are listed in
`RELEASES.md`.

Qualification publishing accepts only the closed public-evidence schema and
eight required named release-smoke checks, then emits a newly normalized
allowlisted document. It rejects unknown fields rather than copying arbitrary
runner evidence into a release asset.

Live qualification credentials belong only to the separate protected
`forge-appliance-qualification` environment, whose required reviewers and
deployment policy admit protected `main` and governed `v*` tags. Remove
repository-scoped copies of those secrets. A repository tag ruleset must
restrict creation, update, deletion, and bypass of `v*` tags. Qualification
fetches full Forge and Manage history and requires each selected commit to be
reachable from its repository's `origin/main`; those in-workflow assertions do
not replace the external tag ruleset or environment approval.

Release tooling, appliance evaluation, updater configuration, and binary-cache
trust parsing reject all fourteen Dalek-accepted byte encodings for the eight
small-order Ed25519 points. Runtime signature checks use strict Ed25519
verification.

Then run both the dashboard-generated Proxmox host command and the signed ISO
journey against disposable hosts/VMs using that exact tag. ISO evidence must
cover install, credential scrub, enrollment/adoption, signed forward update,
rollback, repair, recovery, and identity continuity. Verify the signed ISO
before boot, detach and destroy secret-bearing seed media after install, and
capture only redacted evidence.

The disposable ISO lifecycle physically proves hidden credential entry and
scrub, the IPv4 GET/HEAD-only nginx edge, bounded first-boot clock
synchronization, and monotonic media-rebase behavior across a backward guest
clock. Rust unit and shell/C contract suites separately prove O_NOFOLLOW and
stable-inode handling and inject swapped secret paths, a full 16-event queue,
older media, both reconciliation interruption points, corrupt root config, and
missing live executable recovery. Those tests prove
pre-mutation ordering and truthful replay/recovery semantics, but the bounded
public VM evidence must not describe those specific injected faults as
physical observations. The release-candidate smoke has the narrower purpose
of booting the exact production ISO and binding its version, trust root,
signature/digests, and guided service before publication.
