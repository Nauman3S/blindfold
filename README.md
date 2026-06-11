# Blindfold

**Let AI agents use secrets without seeing secrets.**

Blindfold is a local-first privacy and secrets boundary for AI coding agents.

```text
Agent can use secrets through approved local operations.
Agent cannot see raw secrets in traffic and tool output managed by Blindfold.
```

The boundary is deliberately specific: Blindfold can protect only integrations, LLM
traffic, files, commands, and tool calls that are routed through a supported Blindfold
component. It is not an operating-system sandbox and cannot protect paths that bypass it.
See [Guarantees](docs/guarantees.md) and the [Threat Model](THREAT_MODEL.md).

> **Project status:** pre-release foundation work. The workspace builds, but the security
> controls and CLI commands described as `v0.1.0` targets are not implemented yet. Do not
> use the current code to protect real secrets.

## Planned v0.1.0 Experience

```sh
blindfold init
blindfold doctor
blindfold run -- claude
```

The first release will target a managed Claude Code workflow with:

- scanning and redaction for supported secret formats;
- SafeRefs that stand in for raw values;
- a local LLM proxy for supported OpenAI-compatible and Anthropic-compatible traffic;
- explicit secret injection into approved child processes;
- sanitized managed output, logs, errors, and audit records; and
- startup diagnostics that identify protected, degraded, and unprotected paths.

These are release targets, not claims about the current skeleton.

## Managed Boundary

For a supported and correctly configured `v0.1.0` path, Blindfold is intended to:

1. inspect managed input before it is sent to an LLM or returned to an agent;
2. replace detected raw values with non-secret references;
3. restore values only into a destination explicitly trusted by policy;
4. avoid intentionally placing raw values in Blindfold logs, errors, audit events, or
   agent-visible managed output; and
5. fail closed when security-sensitive managed input cannot be interpreted safely.

Blindfold does **not** promise to:

- mediate direct provider requests, direct filesystem reads, or commands that bypass it;
- contain a malicious process or a compromised operating system or user account;
- stop an approved child process from intentionally exfiltrating a value it receives;
- detect every unknown, encoded, transformed, or fragmented secret; or
- provide transparent system-wide interception.

Strict sandboxing and direct-egress prevention are future work. Startup output must never
describe those controls as active when they are not.

## Platforms

`v0.1.0` supports:

- macOS on currently supported Apple releases, on Apple silicon and Intel where CI and
  release testing are available; and
- Linux on maintained x86_64 distributions with a usable Secret Service implementation
  for key storage.

Windows is unsupported for `v0.1.0`: there is no release artifact, support commitment, or
security-boundary guarantee for Windows. See [Supported Platforms](docs/platforms.md).

## Development

The repository uses Rust 1.96.0 and edition 2024.

```sh
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Supply-chain and secret checks:

```sh
cargo audit
cargo deny check
gitleaks detect --source . --config .github/gitleaks.toml --redact
```

See [Development](docs/development.md) for prerequisites, fixture rules, and the full
validation sequence.

## Documentation

- [Architecture](docs/architecture.md)
- [Guarantees and limitations](docs/guarantees.md)
- [Threat model](THREAT_MODEL.md)
- [Policy model](docs/policy.md)
- [Claude Code boundary](docs/claude-code.md)
- [Development guide](docs/development.md)
- [Release policy](docs/release-policy.md)
- [Architecture decisions](docs/decisions/README.md)

## Security

Do not open a public issue for a suspected vulnerability or include real credentials in
a report. Use the repository's private vulnerability reporting flow described in
[SECURITY.md](SECURITY.md).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Security-sensitive changes require negative
tests showing that raw fixture values do not reach output or artifacts.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
