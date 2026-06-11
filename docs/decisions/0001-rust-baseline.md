# ADR 0001: Rust Baseline and Minimal Dependencies

- Status: Accepted
- Date: 2026-06-11

## Context

Blindfold handles sensitive values in network, storage, parsing, and subprocess paths.
It needs predictable binaries, explicit ownership, strong domain types, and careful
control over serialization and unsafe code.

## Decision

Use Rust 1.96.0, edition 2024, workspace resolver 3, and a pinned minimal toolchain with
Clippy and rustfmt. Forbid unsafe code in workspace-owned crates unless a future ADR
defines a narrowly reviewed exception.

Apply a minimal-dependency policy:

- standard library and existing dependencies first;
- one focused crate per capability where practical;
- no overlapping async, HTTP, CLI, crypto, or serialization stacks without an ADR;
- disable unused default features;
- prefer widely reviewed RustCrypto or platform primitives over custom cryptography;
- keep raw-value types out of generic logging and serialization interfaces; and
- gate dependencies with RustSec and `cargo-deny`.

## Consequences

Edition 2024 and Rust 1.96 provide a modern, fixed language baseline and reproducible
compiler behavior. Contributors need the pinned toolchain. Some older distributions
cannot use their packaged compiler.

Fewer dependencies reduce supply-chain and accidental-logging surface, but targeted
dependencies remain preferable to bespoke cryptography, protocol parsers, or unsafe
platform bindings.
