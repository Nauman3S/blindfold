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
cargo test --workspace --all-features
cargo build --workspace --release
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

## CI Layout

- `quality`: format and Clippy on Linux;
- `test`: workspace tests on Linux and macOS;
- `supply-chain`: RustSec and `cargo-deny`;
- `secrets`: redacted Gitleaks scan.

The workflow intentionally avoids service containers, caching layers, and release logic
at Phase 0.

## Release Preparation

Follow [release-policy.md](release-policy.md). At minimum:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
cargo audit
cargo deny check
gitleaks detect --source . --config .github/gitleaks.toml --redact
```

Release evidence must also cover supported-platform installation, documentation, and
no-raw-fixture leak tests once those features exist.
