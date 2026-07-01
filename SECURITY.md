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

Do not include one-time Boot install codes, private keys, database passwords,
API tokens, or other secret material in public reports, logs, examples, or
screenshots.

## Release Gate

Before publishing a production tag, run:

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
bash -n install/proxmox-host-lxc.sh install/cybex-boot-lxc-install.sh
shellcheck install/proxmox-host-lxc.sh install/cybex-boot-lxc-install.sh
cargo tree -i sqlx-mysql
cargo audit --ignore RUSTSEC-2023-0071
cargo package --allow-dirty --no-verify
```

`RUSTSEC-2023-0071` is ignored only because `cargo audit` reports optional
`sqlx-mysql` lockfile metadata even when the active feature tree does not use
the MySQL driver. `cargo tree -i sqlx-mysql` must print `nothing to print`
before that ignore is acceptable.

Then run the dashboard-generated Proxmox host command against a disposable
host/LXC using that exact tag and capture redacted install evidence.
