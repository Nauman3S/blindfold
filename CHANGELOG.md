# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows Semantic Versioning as described in
[docs/release-policy.md](docs/release-policy.md).

## [Unreleased]

### Added

- Explicit payload-free command/session/request tracing with global `--trace`,
  `trace list|show|tail|export|clear`, and the short `bf` binary alias.
- Closed, bounded, rotating, schema-validated owner-only trace storage.
- Cryptographically randomized operation-local Rust surrogates.
- Complete scan reporting with a distinct incomplete-scan exit code.
- Atomic redacted file output with overwrite protection.
- A task-oriented `USE_CASES.md` beginner guide with copy-paste workflows.
- Zero-persistence wrappers for Claude Code, Codex CLI, and OpenCode.
- Explicit guard-mode spelling with `blindfold run --guard ...`.
- Guard mode starts a CONNECT egress guard and sets proxy environment variables for the
  agent process, blocking direct known LLM provider tunnels for proxy-aware clients.
- Project-scoped egress commands: `blindfold allow domain ...`, `blindfold deny domain ...`,
  and `blindfold status`.
- Guard egress now allows common development registries by default and blocks unknown
  domains unless the project policy allows them.
- OpenRouter routing for OpenCode through Blindfold's OpenAI-compatible proxy path.
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

- Traced agent sessions now explicitly report unmediated direct filesystem access
  instead of implying the whole session is protected.
- Managed coding-agent wrappers no longer inherit the parent secret environment.
- Audit reads reject symlinks, oversized files, malformed records, and free-form fields.
- MCP stdio reads are bounded per message and plaintext credential-named tool arguments
  fail closed.
- Proxy sanitization now covers nested tool payloads and rejects unsupported non-empty
  media types.
- Diff scanning no longer treats a whole line as safe because it contains a SafeRef or
  a placeholder-like substring.
- Vault and audit paths reject symlinked storage targets.
- TypeScript SDK tokens are unpredictable and overlapping values are replaced
  longest-first.
- Contextual detector matches no longer redact only a prefix of punctuation-rich or
  oversized values.
- CLI proxy startup now satisfies the detector's required streaming overlap.

[Unreleased]: https://github.com/Nauman3S/blindfold/compare/HEAD
