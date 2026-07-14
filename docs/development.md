# Development

## Toolchain

Blindfold is pinned to Rust 1.96.0 with edition 2024, `rustfmt`, and Clippy. Install
`rustup`, then let the repository toolchain file select the compiler.

Install the additional checks with your preferred package manager or:

```sh
cargo install --locked cargo-audit cargo-deny
```

Install Gitleaks from its maintained release packages. CI uses a pinned container image.

## Build and Test

```sh
cargo build --workspace
cargo test --workspace --all-targets --all-features
cargo build --workspace --release
./scripts/manual_guard_smoke.sh
```

## Formatting and Linting

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Apply formatting with:

```sh
cargo fmt --all
```

## Supply Chain

```sh
cargo audit
cargo deny check
```

TypeScript SDK:

```sh
npm --prefix sdk/typescript test
```

Python SDK:

```sh
PYTHONPATH=sdk/python/src python3 -m unittest discover -s sdk/python/tests -v
uv build sdk/python
```

Focused iteration commands:

```sh
cargo test -p blindfold-detectors --all-targets
cargo test -p blindfold-proxy --all-targets
cargo test -p blindfold-vault --all-targets
cargo test -p blindfold-cli --all-targets
```

Use `cargo tree --workspace --depth 2` before adding a dependency. Prefer an established
crate when it replaces substantial security-sensitive parsing, cryptography, filesystem,
or matching code. Keep local code when a dependency would save only a few obvious lines.

`cargo audit` checks the RustSec advisory database. `cargo deny` enforces advisory,
license, source, and duplicate-dependency policy from `deny.toml`. A deny exception must
be narrow, justified in configuration, and linked to a tracking issue before merge.

## Secret Scanning

```sh
gitleaks detect \
  --source . \
  --config .github/gitleaks.toml \
  --redact \
  --no-banner
```

The configuration extends Gitleaks defaults and excludes only `tests/fixtures/`, whose
contents are explicitly fake detector inputs. Findings are redacted in CI.

## Fixtures

All fixture values must:

- live below `tests/fixtures/`;
- include an obvious fake marker in surrounding content;
- use reserved domains, local endpoints, or documentation IP ranges;
- be invalid for the provider they resemble; and
- be listed in `tests/fixtures/README.md`.

Never paste a credential and mutate a few characters. Construct synthetic values from
the provider's public shape. Tests must avoid printing fixture plaintext when an
assertion fails.

## Documentation

Check Markdown links and commands manually when changing docs. Material changes to the
managed boundary, platform support, SafeRefs, vault, or dependency policy require an ADR
under `docs/decisions/`.

Harness adapter manifests are treated as untrusted test data. Current tests must prove
absence of project-directory auto-loading and fail-closed version and capability gates.
Before external execution or native tool hooks can be enabled, tests must additionally
prove explicit installation, hook-result sanitization, and a final provider-proxy check.
A manifest may reference only a contained out-of-process entrypoint. It must never add
an in-process library, shell command, policy implementation, or restoration path.
Hook-result sanitization tests become mandatory before a manifest may declare tool
events.

## Locked Container Boundary

`bf container run` is a separate Docker-only preview. Build its common gateway/agent
image with:

```sh
docker build -f containers/Dockerfile.locked -t blindfold-locked:local .
```

The ordinary CLI suite does not start Docker. It checks fail-closed CLI validation and
the exact Docker argv for the agent, gateway, resource limits, mounts, labels, and
session cleanup. Those tests are necessary but do not establish that a real Docker
Engine produced the documented namespace and mount topology.

The 2026-07-14 macOS/ARM64 implementation run supplied one manual instance of this
evidence: Docker inspection confirmed the mount split and hardening, route inspection
found no IPv4 and only loopback IPv6 routes, direct IP returned `ENETUNREACH`, DNS
returned `EAI_AGAIN`, the gateway path was reachable, and exact cleanup left no labeled
containers or volumes. This must be repeated or automated for release candidates; it is
not a substitute for the platform matrix below.

A change to the locked boundary requires a local-Engine end-to-end test before its OS
control can be reported as verified. That evidence must inspect the running agent
namespace, prove absence of non-loopback IPv4 and IPv6 routes, prove the provider key is
absent from the agent environment and mounts, prove the gateway has no workspace mount,
exercise sanitized request and response traffic against a controlled fake provider, and
verify exact session cleanup. Never use a live provider credential or production data
for this test.

The locked tier deliberately has no package, web, Git, SSH, network MCP, or arbitrary
CONNECT egress. Do not weaken that restriction to make a development smoke test more
convenient. Read [Locked Container Boundary](container-boundary.md),
[ADR 0010](decisions/0010-locked-container-egress-boundary.md), and the
[Adversarial Verification Report](../BLINDFOLD_STRESS_TEST_REPORT.md) before changing
the launcher or image.

## CI Layout

- `quality`: format and Clippy on Linux;
- `test`: workspace tests on Linux and macOS, including static locked-launcher tests;
- `supply-chain`: RustSec and `cargo-deny`;
- `secrets`: redacted Gitleaks scan.

The workflow currently has no live Docker topology job. Therefore it does not yet supply
release evidence for the locked boundary by itself.

## Release Preparation

Follow [release-policy.md](release-policy.md). At minimum:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo build --workspace --release
cargo audit
cargo deny check
gitleaks detect --source . --config .github/gitleaks.toml --redact
```

Release evidence must also cover supported-platform installation, documentation, and
no-raw-fixture leak tests. A release that includes the locked preview must additionally
record the local-Docker topology checks described above on each claimed host platform.
