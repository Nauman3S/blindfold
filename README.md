# Blindfold

**Let AI agents use secrets without seeing secrets.**

Blindfold is a local-first security boundary for AI coding workflows. It scans and
redacts secrets, runs commands with selected environment values, proxies supported LLM
traffic, and records safe metadata without intentionally logging raw values.

Blindfold protects only operations routed through Blindfold. Native `bf run` is not an
OS sandbox. The preview `bf container run` mode adds an OS-enforced model-only network
boundary, but it is still not a guarantee that every unknown or transformed secret will
be detected.

**New here? Start with [Simple Use Cases](USE_CASES.md).** It explains the common
commands without requiring you to understand the full architecture.

## Status

This repository is pre-release software:

- **Implemented:** scanning, redaction, policy evaluation, encrypted local vault,
  sanitized command execution, one-shot brokered HTTP calls, OpenAI/Anthropic
  application proxy, diff scanning, credential-bearing URL parsing, and automatic
  detection of RFC-valid email addresses and international phone numbers. The strict
  TOML adapter-manifest API, explicit-directory plugin loader, and exact harness
  version probes are also implemented.
- **Preview:** constrained noninteractive Claude, Codex, and OpenCode wrappers; locked
  Docker `network=none` agent runs with a credential-owning Unix-socket gateway; MCP
  stdio transformer; Python and TypeScript SDKs.
- **Not implemented:** OS keychain adapter, a sanitized/staged filesystem workspace,
  broad semantic PII discovery (names, addresses, national IDs), MCP network
  transports, Windows support, external adapter execution, and native harness
  pre/post-tool hook injection.

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
bf --version
blindfold --help
```

`bf` is a short alias for the same CLI.

## Quick Start

```sh
blindfold init
blindfold doctor
blindfold run codex -- exec "summarize this repo"
```

Common tasks and copy-paste examples are in [USE_CASES.md](USE_CASES.md).
`doctor` validates the configuration, installed-command presence, and embedded harness
contracts without executing agent binaries or printing command paths or secrets. Exact
version compatibility is checked at `bf run` startup. Most runtime commands still use
CLI defaults and flags; runtime configuration integration remains preview work.

## Scan Files and Directories

Scan the current working directory:

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
default, skips binary files, and enforces file and total-byte limits. Exit code `2`
means findings were detected. Exit code `3` means the scan was incomplete because of an
I/O error, oversized file, or traversal budget.

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

Write safely to a new file:

```sh
blindfold redact .env --output env.redacted
```

Blindfold refuses to overwrite an existing output unless `--force` is supplied. Forced
replacement is atomic. Surrogate mode produces cryptographically randomized,
operation-local opaque values; equal secrets match within one operation but cannot be
correlated across separate runs.

For a dotenv file, `env-ref` keeps the variable relationship:

```text
OPENAI_API_KEY=${OPENAI_API_KEY}
DATABASE_URL=${DATABASE_URL}
```

`block` returns a failure instead of printing transformed input when sensitive content
is found.

## Mask Content With SafeRefs

Masking stores detected values in the encrypted local vault and writes opaque,
session-scoped references:

```sh
export BLINDFOLD_MASTER_KEY="$(openssl rand -hex 32)"
blindfold mask .env --ttl-seconds 3600
blindfold mask config.json --output config.masked.json
```

Equal values reuse one SafeRef within the invocation. Email and phone findings use PII
references, PEM values use private-key references, and all other detected values use
secret references. Output replacement follows the same create-new/explicit-`--force`
rules as `redact`.

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

## Make One API Call with a Secret

Use `blindfold call` when an agent or script needs one bearer-token HTTP request but
should not see the token in output:

```sh
export STRIPE_SECRET_KEY='sk_test_fake_blindfold_example_1234567890'
blindfold allow domain api.stripe.com
blindfold call --secret STRIPE_SECRET_KEY --url https://api.stripe.com/v1/customers
```

Blindfold reads the named environment variable, sends it only as
`Authorization: Bearer ...`, applies the project domain allow/deny policy, bounds the
response body, redacts the selected value from the response, and records only
payload-free trace metadata when `--trace` is enabled. This is a narrow broker, not a
general HTTP client or transparent network proxy. Optional `--body` JSON is limited to
64 KiB and must not contain the selected secret or another detected credential.

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

Clear the current working-directory/session scope:

```sh
blindfold vault clear --yes
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
  --openai-upstream https://api.openai.com \
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

The proxy accepts JSON POST bodies and sanitizes every string value, including nested
tool arguments. The only streaming exceptions are bounded Anthropic response SSE,
bounded OpenAI-compatible response SSE on `chat/completions`, and JSON-object text
frames on the OpenAI Responses WebSocket endpoint. SSE requests, SSE on any other
route, binary or arbitrary WebSockets, unsupported non-empty media types, sensitive
URL/query values, proxy loops, and other HTTP methods fail closed. Provider
authentication headers (`Authorization`, `x-api-key`, and `api-key`) are intentionally
forwarded only to the allowlisted upstream and must be managed by the caller.

## Noninteractive Coding Agents

Launch an installed coding agent through an ephemeral loopback proxy. Native arguments
go after `--`:

```sh
blindfold run claude -- --print "summarize this repo"
blindfold run codex -- exec "summarize this repo"
blindfold run codex -- review
blindfold run opencode -- run "inspect this project"
```

No persistent Claude, Codex, or OpenCode configuration is changed. The child starts with
an allowlisted environment, so parent API-key variables and unrelated secrets are not
inherited. Authenticate the agent with its persistent credential store or login flow;
environment-only provider authentication is not available. All supported child
stdout/stderr is captured and sanitized before Blindfold prints it.

Blindfold sets proxy variables for the child process. For proxy-aware clients,
direct CONNECT tunnels to known LLM providers are blocked, common development
registries are allowed, and unknown domains that pass through the guard proxy block
until you allow them for the project:

```sh
blindfold allow domain api.example.com
blindfold status
blindfold deny domain api.example.com
```

Only Claude `--print`/`-p`, Codex `exec`/`review`, and OpenCode `run` are accepted.
Interactive/TUI, resume, server, plugin, remote-control, search, and dangerous bypass
modes fail before the child starts. Blindfold has no `run` bypass flag, bypass
environment variable, or generated shell-wrapper command.

Important: `blindfold run ...` does not mediate agent file reads. If OpenCode, Codex,
or Claude opens `.env` directly from the project, it can read the raw file. Trace
records mark agent sessions as degraded with `direct_filesystem_unmediated`; only
traffic that passes through Blindfold's managed provider proxy is sanitized. Full
file-read protection requires future filesystem mediation or sandboxing.

The managed runner sanitizes supported provider traffic and blocks direct known-provider
CONNECT tunnels for proxy-aware clients. It does not mediate local file reads or control
network clients that ignore proxy settings. Automatic PII detection currently covers
RFC-valid email addresses and valid,
`+`-prefixed international phone numbers. Names, postal addresses, national IDs,
account numbers, and semantic PII are not detected. The TypeScript SDK can additionally
tokenize PII values explicitly supplied by an application; it does not broaden the
automatic detector set. The Python SDK provides the same explicit application boundary
with a provider-client wrapper.

See [Noninteractive coding agents](docs/coding-agents.md) for the exact protocol and
argument contract. See [Plugin manifests and validation](docs/plugins.md) for embedded
adapter discovery and validation-only external directory checks.

## Locked Container Runs

Build the local evaluation image once, export the standard provider key on the host,
then keep the same noninteractive agent arguments:

```sh
docker build -f containers/Dockerfile.locked -t blindfold-locked:local .

: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY on the host}"
bf container run claude -- --print "summarize this repo"

: "${OPENAI_API_KEY:?set OPENAI_API_KEY on the host}"
bf container run codex -- exec "summarize this repo"

: "${OPENROUTER_API_KEY:?set OPENROUTER_API_KEY on the host}"
bf container run opencode --provider openrouter -- run "inspect this project"
```

The host key is materialized in a private temporary file and mounted read-only into the
gateway container. It is never mounted into the agent container. The agent receives
Docker's `none` network, a read/write mount of only the current workspace, an ephemeral
home, and a read-only per-session volume containing one Unix socket. The gateway owns
the only external network path, discards agent-supplied provider authentication, injects
its own credential, and forwards only supported sanitized model requests. Generic web,
package, Git, SSH, and CONNECT traffic is unavailable in this mode.

Use `--credential-file /absolute/path` instead of the standard provider environment
variable when desired. Release images must be selected with
`--image registry/name@sha256:<digest>`; only `blindfold-locked:local` is accepted as a
tagged development image.

This establishes a meaningful egress guarantee: subject to the trusted host, Docker
Engine, image, and absence of a container escape, the agent process tree has no direct
IP egress. It does not make detection perfect. An agent can transform, encode, split,
or semantically reconstruct a sensitive fact inside the permitted model channel, and
the raw mounted workspace can contain values Blindfold does not recognize. See
[Locked container boundary](docs/container-boundary.md) for the exact claim and threat
model.

### Harness Adapters

Claude, Codex, and OpenCode now use embedded strict TOML manifests for harness
compatibility metadata, pinned versions, noninteractive modes, providers, transports,
events, and permissions.
The manifest parser and host can also validate an explicitly supplied plugin directory
without searching the current project. There is no external install, activation, or
execution command yet, and native tool hooks are not wired into `bf run`.

An adapter's TOML manifest is data, not executable code. It may reference one contained
out-of-process entrypoint and declare supported versions, commands, hooks, and required
capabilities. The host bounds and strictly parses the manifest, rejects symlinks and
escaping entrypoints, and never auto-loads project plugins. An entrypoint cannot replace
Blindfold's detector, policy engine, SafeRef checks, sanitizer, provider proxy, trace
schema, or fail-closed decisions.

Installation must be an explicit user action. Blindfold will not auto-load a manifest
from a repository, working tree, dependency directory, agent output, or URL. Project
content remains untrusted, and upstream agent plugin modes remain rejected by protected
`run` commands.

Before a built-in launch, Blindfold validates the embedded schema, exact capability
contract, resolved executable, and pinned harness version. Current pins are documented
in [Noninteractive coding agents](docs/coding-agents.md); missing, ambiguous, or
incompatible output rejects the run before proxy startup. A version probe is a
compatibility check, not executable authentication or process containment. Tool-result
hook events are reserved but not declared by current manifests until replacement
behavior is verified.
The provider proxy remains the final check for supported model traffic. Native `bf run`
does not prevent direct socket exfiltration; `bf container run` adds that OS network
boundary without claiming perfect payload detection. See
[ADR 0009](docs/decisions/0009-harness-adapter-security-boundary.md).

Manifest permissions describe the compatibility environment the runner supplies; they
are not claims of OS-enforced filesystem, process, or network isolation.
Embedded adapters use the core-owned `builtin-v1` protocol. `stdio-json-v1` is reserved
for future contained external entrypoints and is not an executable path today.

## Python SDK

The dependency-free SDK masks application-registered values across wrapped client calls:

```python
from blindfold import Boundary
from openai import OpenAI

with Boundary(
    secrets=["sk_test_fake_blindfold_1234567890"],
    pii=["alice@example.test"],
) as boundary:
    client = boundary.wrap(OpenAI())
    response = client.responses.create(
        model="gpt-5",
        input="Use sk_test_fake_blindfold_1234567890 for alice@example.test",
    )
    user_text = boundary.restore(response.output_text, destination="end_user")
```

Masking is the default; irreversible `redact` and fail-closed `block` modes are also
available. PII restoration requires the `end_user` destination. Secrets are never
restored into normal model or user output. This SDK is an in-process boundary and does
not intercept arbitrary filesystem, environment, or network access. See
[`sdk/python`](sdk/python/README.md).

## Request Tracing

Tracing is disabled by default. Enable payload-free metadata for a single command or a
managed agent session:

```sh
bf redact .env --trace
bf run claude --trace -- --print "summarize this repo"
```

Inspect the retained traces:

```sh
bf trace list
bf trace show req_...
bf trace tail
bf trace export req_... --redacted
bf trace clear --yes
```

Trace records contain request IDs, command/session activity or provider route, coverage
status, before/after byte counts, detector categories, sanitized structural pointers
such as `/env/DATABASE_URL`,
occurrence counts, outcomes, and closed issue codes. They never contain payloads,
authorization headers, query strings, original spans, or arbitrary messages. Storage is
owner-only, bounded, rotated, schema-validated, and independent from vault audit data.

There is intentionally no raw trace mode. See [Request tracing](docs/tracing.md) for the
schema and limitations.

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

## TypeScript SDK

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
[Locked container boundary](docs/container-boundary.md),
[Noninteractive coding agents](docs/coding-agents.md),
[Claude Code limitations](docs/claude-code.md), [MCP preview](docs/mcp.md), and
[application SDKs](docs/sdk.md) before using Blindfold. The
[adversarial verification report](BLINDFOLD_STRESS_TEST_REPORT.md) separates tested
behavior from release evidence that remains incomplete.

The [proxy and protocol lifecycle note](docs/proxy-protocol-lifecycle.md) records which
model-boundary features remain required and which compatibility branches may be
reviewed for future archival.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
npm --prefix sdk/typescript test
PYTHONPATH=sdk/python/src python3 -m unittest discover -s sdk/python/tests -v
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
