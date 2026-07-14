# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses Semantic
Versioning.

## [Unreleased]

### Added

- Secret and supported-PII detectors, bounded repository scanning, and complete-scan
  reporting.
- Placeholder, environment-reference, schema-only, surrogate, blocking, and encrypted
  vault-backed masking operations.
- XChaCha20-Poly1305 local vault with scoped, expiring opaque SafeRefs and safe audit
  metadata.
- Sanitized explicit-secret process execution and a narrow policy-gated bearer HTTP
  broker.
- Loopback OpenAI/Anthropic proxy with bounded JSON, Anthropic response SSE, and OpenAI
  Responses WebSocket handling.
- One constrained runner for Claude print mode, Codex exec/review, and OpenCode run.
- Mandatory proxy-aware egress policy and captured output sanitization for supported
  agent commands.
- Destination policy, generated-diff scanning, MCP stdio transformation, and closed
  payload-free command/session/request tracing.
- Dependency-free Python and TypeScript application SDK previews.
- Rust workspace CI, dependency policy, vulnerability audit, and secret fixture checks.
- ADR 0008 documenting the constrained noninteractive runner.
- Strict, bounded TOML harness-adapter manifests using `serde`, `toml`, and `semver`,
  plus an explicit-directory plugin host with contained-entrypoint validation.
- Embedded Claude, Codex, and OpenCode adapter manifests with fail-closed exact-version
  probes at `bf run` startup; `bf doctor` validates manifests without executing agents.

### Changed

- JSON sanitization now visits every string value instead of a provider-field allowlist.
- HTTP provider forwarding is POST-only; unsupported content types fail closed even for
  empty bodies.
- Anthropic SSE is response-only and route-gated; OpenAI SSE is rejected.
- WebSockets are limited to JSON-object text messages on the OpenAI Responses route.
- Agent execution no longer exposes selectable guard/degraded modes. The managed proxy,
  proxy-aware egress control, clean environment, and captured output are mandatory.
- Interactive/TUI, resume, server, remote, plugin, search, and dangerous permission
  bypass modes fail before the child starts.
- Removed `--guard`, `--no-proxy`, preview `--strict`, `BLINDFOLD_BYPASS`, and generated
  shell wrappers.
- Untested older and future harness versions now fail before proxy or agent startup.
- Unix managed execution now terminates remaining child process-group members so a
  pipe-holding descendant cannot defeat an output or version-probe timeout.

### Fixed

- Managed child output is emitted once after sanitization rather than duplicated.
- Parent secret environment variables are no longer inherited by managed agents.
- Unknown JSON fields, fragmented SSE events, fragmented WebSocket messages, unsupported
  upgrade paths, binary frames, and upstream response headers cannot bypass the proxy
  boundary.
- Agent traces explicitly report unmediated filesystem reads instead of implying
  whole-agent containment.
- Vault, audit, trace, and policy storage reject unsafe symlinked paths and malformed or
  free-form records.
- Diff scanning no longer treats a whole line as safe because it contains a SafeRef or
  placeholder-like substring.

[Unreleased]: https://github.com/Nauman3S/blindfold/compare/HEAD
