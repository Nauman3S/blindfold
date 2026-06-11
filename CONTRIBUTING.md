# Contributing

Blindfold is security infrastructure. Changes should be small enough to review, explicit
about their trust boundary, and backed by tests proportional to their risk.

## Prerequisites

- Rust 1.96.0 with `rustfmt` and `clippy`
- `cargo-audit`
- `cargo-deny`
- Gitleaks

The pinned Rust toolchain is installed automatically by `rustup` when commands run in the
repository.

## Local Checks

Run before submitting a change:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit
cargo deny check
gitleaks detect --source . --config .github/gitleaks.toml --redact
```

See [docs/development.md](docs/development.md) for installation and platform details.

## Security Requirements

- Do not put live credentials, private keys, customer data, or production output in the
  repository, issue tracker, CI, examples, or test artifacts.
- Add negative tests for every security-sensitive path. Tests must inspect captured
  stdout, stderr, logs, audit records, temporary artifacts, and fake upstream traffic as
  applicable.
- Never print raw fixture values in a failing assertion. Prefer identifiers and redacted
  fingerprints.
- Security-sensitive malformed or unsupported input must fail closed.
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

Material changes to the managed boundary, SafeRef format, vault, platform support,
cryptography, serialization, network exposure, or dependency strategy require an ADR in
`docs/decisions/`. Supersede prior decisions rather than silently rewriting history.

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
