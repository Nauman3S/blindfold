# Contributing

Blindfold is security infrastructure. Changes should be small enough to review, explicit
about their trust boundary, and backed by tests proportional to their risk.

## Prerequisites

- Rust 1.96.0 with `rustfmt` and `clippy`
- `cargo-audit`
- `cargo-deny`
- Gitleaks
- Node.js 22.6 or newer for the TypeScript SDK
- Python 3.10 or newer and `uv` for Python SDK packaging
- A local Docker Engine for locked-container image builds and end-to-end boundary tests

The pinned Rust toolchain is installed automatically by `rustup` when commands run in the
repository.

## Local Checks

Run before submitting a change:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
npm --prefix sdk/typescript test
PYTHONPATH=sdk/python/src python3 -m unittest discover -s sdk/python/tests -v
uv build sdk/python
./scripts/manual_guard_smoke.sh
cargo audit
cargo deny check
gitleaks detect --source . --config .github/gitleaks.toml --redact
```

See [docs/development.md](docs/development.md) for installation and platform details.
Docker is not required for the ordinary Rust and SDK suites. It is required before a
change to the locked boundary can be represented as end-to-end verified.

## Security Requirements

- Do not put live credentials, private keys, customer data, or production output in the
  repository, issue tracker, CI, examples, or test artifacts.
- Add negative tests for every security-sensitive path. Tests must inspect captured
  stdout, stderr, logs, audit records, temporary artifacts, and fake upstream traffic as
  applicable.
- Never print raw fixture values in a failing assertion. Prefer identifiers and redacted
  fingerprints.
- Security-sensitive malformed or unsupported input must fail closed.
- New agent modes must be noninteractive, have captured output, and prove both traffic
  directions against a fake upstream before becoming supported.
- Changes to `bf container run` must prove that the agent has Docker `network=none`, the
  gateway alone owns external networking and the real credential, the gateway has no
  workspace mount, and cleanup targets only the exact session resources. Docker-argv
  unit tests do not replace a live local-Engine topology test.
- Do not add package, web, Git, SSH, MCP-network, or arbitrary CONNECT egress to the
  locked tier. An opaque outbound channel invalidates its model-only egress claim.
- Harness adapters must use the strict manifest schema, finite lower and upper version
  bounds, exact core-owned capability gates, and fail before proxy startup on a probe
  mismatch.
- Never auto-load adapters or plugin manifests from a project tree. External entrypoints
  must remain explicitly selected, out of process, and contained by their installation
  directory.
- Do not declare tool-request or tool-result events until the corresponding native hook
  is established and its bounded payload is sanitized by core.
- New provider transports require an explicit route/method/media grammar and negative
  tests for opaque, fragmented, and oversized inputs.
- Logging and error changes must be reviewed for accidental payload, header,
  environment, path, or secret disclosure.
- New restoration destinations require a threat-model and policy update.

## Fixtures

Fixtures belong under `tests/fixtures/`, must be obviously fake, and should still match
the structure expected by detectors and parsers. Every fixture directory should explain
why the data cannot be live. Gitleaks ignores only this isolated path; moving a fixture
elsewhere should make secret scanning fail.

Use reserved domains such as `example.com`, documentation IP ranges, non-routable local
services, and explicit markers such as `BLINDFOLD_FAKE_FIXTURE`. Do not derive fixtures
from a real credential.

## Dependencies

Blindfold follows a minimal-dependency policy:

- prefer the standard library and existing workspace dependencies;
- add one focused crate only when it removes meaningful security or maintenance risk;
- avoid overlapping frameworks and convenience-only dependencies;
- disable unused default features;
- document why security-sensitive dependencies are needed; and
- ensure licenses and advisories pass `cargo deny check` and `cargo audit`.

Generated dependency updates should be isolated from behavior changes where practical.

## Architecture Decisions

Material changes to the managed boundary, supported agent grammar, provider protocol,
SafeRef format, vault, platform support, cryptography, serialization, network exposure,
container topology, or dependency strategy require an ADR in `docs/decisions/`.
Supersede prior decisions rather than silently rewriting history. See
[Locked Container Boundary](docs/container-boundary.md) and
[Guarantees](docs/guarantees.md) for the current claim that changes must preserve.

## Pull Requests

Describe:

- the user-visible behavior;
- the protected path and trust-boundary impact;
- failure behavior;
- tests and commands run; and
- documentation or migration impact.

Keep unrelated formatting, generated files, and refactors out of the change.

Contributions are submitted under the Apache License 2.0 unless explicitly stated
otherwise.
