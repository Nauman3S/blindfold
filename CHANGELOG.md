# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows Semantic Versioning as described in
[docs/release-policy.md](docs/release-policy.md).

## [Unreleased]

### Added

- Zero-persistence wrappers for Claude Code, Codex CLI, and OpenCode.
- `blindfold shell-init` and visible per-invocation wrapper opt-out support.
- Secret detectors, redaction modes, bounded repository scanning, and safe reports.
- Destination-aware policy presets and scoped restoration decisions.
- XChaCha20-Poly1305 local vault with safe audit metadata.
- Sanitized explicit-secret process execution.
- Loopback OpenAI-compatible and Anthropic-compatible application proxy.
- Unified-diff secret scanning.
- MCP stdio JSON-RPC protection preview.
- Dependency-free TypeScript application SDK preview.
- Integrated CLI commands and user-focused README examples.
- Apache License 2.0.
- CI checks for formatting, Clippy, tests, dependency policy, vulnerability auditing,
  and secret scanning.
- Architecture decisions for the Rust baseline, vault direction, SafeRef format, and
  managed support boundary.
- Isolated fake credential fixtures for future security regression tests.

### Fixed

- CLI proxy startup now satisfies the detector's required streaming overlap.

[Unreleased]: https://github.com/Nauman3S/blindfold/compare/HEAD
