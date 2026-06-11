# Blindfold

**Let AI agents use secrets without seeing secrets.**

Blindfold is a local-first security boundary for AI coding workflows. It scans and
redacts secrets, runs commands with selected environment values, proxies supported LLM
traffic, and records safe metadata without intentionally logging raw values.

Blindfold protects only operations routed through Blindfold. It is not an OS sandbox,
network firewall, or guarantee that every unknown secret format will be detected.

## Status

This repository is pre-release software:

- **Implemented:** scanning, redaction, policy evaluation, encrypted local vault,
  sanitized command execution, OpenAI/Anthropic application proxy, diff scanning.
- **Preview:** Claude wrapper, MCP stdio transformer, TypeScript SDK.
- **Not implemented:** OS keychain adapter, transparent network interception, filesystem
  sandbox, MCP network transports, Windows support.

Use fake credentials while evaluating the project.

## Install

Blindfold uses Rust 1.96.0 and edition 2024.

```sh
git clone https://github.com/Nauman3S/blindfold.git
cd blindfold
cargo build --release
export PATH="$PWD/target/release:$PATH"
```

Confirm the binary:

```sh
blindfold --version
blindfold --help
```

## Quick Start

```sh
blindfold init
blindfold doctor
blindfold scan .
blindfold redact .env
```

`scan` exits with code `2` when it finds sensitive content. Findings contain locations
and categories, not matched values.

## Scan Files and Directories

Scan the current project:

```sh
blindfold scan .
```

Scan one file:

```sh
blindfold scan config.json
```

Machine-readable output:

```sh
blindfold scan . --json
```

The scanner ignores common dependency/build directories, does not follow symlinks by
default, skips binary files, and enforces file and total-byte limits.

## Redact Content

Redact a file:

```sh
blindfold redact .env
```

Redact standard input:

```sh
printf 'Authorization: Bearer fake-token-value-1234567890\n' | blindfold redact
```

Available modes:

```sh
blindfold redact .env --mode env-ref
blindfold redact config.json --mode schema-only
blindfold redact config.json --mode placeholder
blindfold redact config.json --mode surrogate
blindfold redact config.json --mode block
```

For a dotenv file, `env-ref` keeps the variable relationship:

```text
OPENAI_API_KEY=${OPENAI_API_KEY}
DATABASE_URL=${DATABASE_URL}
```

`block` returns a failure instead of printing transformed input when sensitive content
is found.

## Run a Command with Secrets

Select each environment value explicitly:

```sh
export DEMO_API_KEY='sk-proj-fake-blindfold-example-1234567890'
blindfold exec --secret DEMO_API_KEY -- sh -c 'test -n "$DEMO_API_KEY"; echo ready'
```

Blindfold:

1. starts the child with a minimal environment;
2. injects only selected secrets;
3. rejects a secret embedded in command arguments;
4. captures stdout and stderr concurrently;
5. redacts injected values from captured output; and
6. preserves the child exit result.

This is not a process sandbox. A hostile child can transform or exfiltrate a secret it
was explicitly given.

## Check Policy Behavior

```sh
blindfold policy check \
  --mode balanced \
  --destination model \
  --sensitivity secret
```

Example result:

```text
action=Block basis=Invariant mode=Balanced destination=ModelProvider sensitivity=Secret
```

Modes are `chill`, `balanced`, `strict`, and `ci`. Destinations include `model`,
`agent`, `tool`, `child`, `file`, `log`, `audit`, `user`, and `trusted-local`.

## Encrypted Local Vault

The current vault uses XChaCha20-Poly1305 with a caller-supplied 32-byte master key.
An OS keychain adapter is not implemented yet.

For local evaluation, create a key without printing it:

```sh
export BLINDFOLD_MASTER_KEY="$(openssl rand -hex 32)"
export DEMO_API_KEY='sk-proj-fake-blindfold-example-1234567890'
```

Store one environment value and receive a SafeRef:

```sh
blindfold vault put-env DEMO_API_KEY --ttl-seconds 3600
```

List metadata only:

```sh
blindfold vault list
```

Clear the current project/session scope:

```sh
blindfold vault clear
```

The key must be supplied again to reopen the vault. Do not put
`BLINDFOLD_MASTER_KEY` in project files or shell history. Production use should wait for
the planned macOS Keychain and Linux Secret Service adapters.

## Audit Events

Vault operations append safe JSON-lines metadata:

```sh
blindfold audit
```

Audit events contain closed action/outcome fields and optional SafeRefs. They do not
contain plaintext vault values.

## LLM Proxy

Run a loopback proxy with an explicit upstream allowlist:

```sh
blindfold proxy \
  --listen 127.0.0.1:8787 \
  --openai-upstream https://api.openai.com/v1 \
  --anthropic-upstream https://api.anthropic.com
```

Provider routes are:

```text
http://127.0.0.1:8787/openai/...
http://127.0.0.1:8787/anthropic/...
```

Example OpenAI-compatible request:

```sh
curl http://127.0.0.1:8787/openai/chat/completions \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"example","messages":[{"role":"user","content":"inspect this text"}]}'
```

The proxy sanitizes supported JSON text fields and SSE data, enforces body/time limits,
rejects proxy loops, and does not perform transparent TLS interception. Authentication
headers are forwarded to the allowlisted upstream and must be managed by the caller.

## Coding Agent Wrappers

Launch an installed coding agent through an ephemeral loopback proxy. Native arguments
go after `--`:

```sh
blindfold run claude -- --model sonnet
blindfold run codex -- review
blindfold run opencode -- run "inspect this project"
```

No persistent Claude, Codex, or OpenCode configuration is changed. Existing agent
authentication continues to work normally.

Keep typing the native command names by activating shell wrappers:

```sh
eval "$(blindfold shell-init zsh)"

claude
codex review
opencode run "fix the tests"
```

Use `bash` instead of `zsh` when appropriate. Opt out for one command:

```sh
bf-off claude
bf-off codex review
bf-off opencode
```

The explicit equivalents are:

```sh
BLINDFOLD_BYPASS=1 codex review
blindfold run codex --no-proxy -- review
```

The wrapper prints protected and unavailable controls before launch. It currently
sanitizes supported provider traffic, but not interactive terminal output, and it cannot
prevent direct filesystem or network bypasses. `--strict` refuses to start while those
controls remain unavailable.

See [Coding agent wrappers](docs/coding-agents.md) for custom gateway examples and
agent-specific routing behavior.

## Scan Generated Diffs

Scan tracked working-tree changes:

```sh
blindfold diff-check
```

Scan staged changes:

```sh
blindfold diff-check --staged
```

Scan a supplied patch without requiring Git:

```sh
blindfold diff-check --patch change.diff --json
```

Reports include safe locations, severity, and remediation without printing the detected
value. Exit code `2` means findings were detected.

## MCP Stdio Preview

Sanitize one newline-delimited JSON-RPC response before returning it to an agent:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"safe output"}]}}' |
  blindfold mcp --direction to-agent --server demo
```

`to-server` mode rejects SafeRefs because the CLI preview does not yet connect the MCP
resolver to a configured vault/policy scope:

```sh
blindfold mcp --direction to-server --server demo < request.jsonl
```

The underlying library supports injected field-level resolver policies. Only
newline-delimited stdio JSON-RPC is in scope; MCP HTTP/network transports are not.

## TypeScript SDK Preview

The dependency-free preview lives in [`sdk/typescript`](sdk/typescript):

```sh
cd sdk/typescript
npm test
```

It tokenizes application text before an LLM call and restores PII only for an
`end_user` destination. Secret restoration to LLM, log, or memory destinations is
always denied.

## Guarantees and Limitations

Within a supported managed path, Blindfold is designed to:

- redact detected raw values before managed LLM or agent output;
- avoid intentionally logging raw values;
- restore vault values only after explicit scope and policy checks;
- fail closed on malformed security-sensitive input; and
- accurately report degraded controls.

Blindfold does not protect:

- direct calls, reads, or commands that bypass it;
- a compromised OS or user account;
- a malicious approved child process;
- every unknown, encrypted, or transformed secret;
- memory scraping or side channels; or
- Windows.

Read [Guarantees](docs/guarantees.md), [Threat Model](THREAT_MODEL.md),
[Coding agent wrappers](docs/coding-agents.md),
[Claude Code limitations](docs/claude-code.md), [MCP preview](docs/mcp.md), and
[SDK preview](docs/sdk.md) before using Blindfold.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo audit
cargo deny check
```

See [Development](docs/development.md), [Architecture](docs/architecture.md), and
[Contributing](CONTRIBUTING.md).

## Security

Do not include real credentials in issues, fixtures, logs, or vulnerability reports.
Follow [SECURITY.md](SECURITY.md) for private reporting.

## License

Apache License 2.0. See [LICENSE](LICENSE).
