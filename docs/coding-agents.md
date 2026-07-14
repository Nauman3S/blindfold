# Noninteractive Coding Agents

Blindfold supports only explicit, noninteractive coding-agent commands:

```sh
bf run claude -- --print "summarize this repo"
bf run codex -- exec "summarize this repo"
bf run codex -- review
bf run opencode -- run "inspect this project"
```

Interactive/TUI, resume, server, remote-control, plugin, search, and permission-bypass
modes are rejected before the child starts. There is no `run` bypass flag, environment
bypass, or generated shell wrapper. Run the native agent directly when Blindfold is not
intended to manage that invocation.

Here, `plugin` means an upstream agent plugin mode or URL. Blindfold adapter manifests
are different: they are strictly parsed compatibility data and do not enable an upstream
agent plugin mode.

## Compatibility Gates

`bf run` executes `--version` through a bounded, minimal-environment probe before it
starts the model proxy or the agent. The first release accepts only the exact versions
used by the fake-upstream and installed-client checks. A future patch is rejected until
its transports and configuration behavior are tested.

| Adapter | Accepted harness version |
|---|---|
| Claude Code | `2.1.202` |
| Codex CLI | `0.144.4` |
| OpenCode | `1.18.0` |

These exact pins were refreshed from the published npm distribution tags on
2026-07-14: [Claude Code](https://www.npmjs.com/package/@anthropic-ai/claude-code),
[Codex CLI](https://www.npmjs.com/package/@openai/codex), and
[OpenCode](https://www.npmjs.com/package/opencode-ai). They are tested compatibility
claims, not open-ended version ranges.

Missing, malformed, ambiguous, truncated, timed-out, nonzero, or incompatible version
output fails before agent startup. The probe executes the selected harness binary, so it
is compatibility evidence, not executable authentication or a sandbox. `bf doctor`
validates the embedded contracts but does not execute installed agent binaries.

## Managed Boundary

For every supported invocation, Blindfold:

1. starts an ephemeral loopback provider proxy;
2. starts a deny-by-default proxy-aware egress guard;
3. clears the parent environment and passes only a small operational allowlist;
4. injects an ephemeral provider base URL into the agent configuration;
5. captures and sanitizes child stdout and stderr; and
6. records payload-free trace metadata only when `--trace` is selected.

The transport contract is intentionally narrow:

| Agent command | Managed provider transport |
|---|---|
| `claude --print ...` / `claude -p ...` | Anthropic JSON POST; bounded Anthropic response SSE |
| `codex exec ...` | OpenAI JSON POST or JSON-object text frames on `/responses` WebSocket |
| `codex review` | Same Codex Responses transports |
| `opencode run ...` | OpenAI, Anthropic, or OpenRouter JSON POST; bounded Anthropic and OpenAI-compatible response SSE |

SSE requests, response SSE outside Anthropic messages and OpenAI-compatible
chat-completions, binary WebSocket frames, arbitrary WebSocket paths, non-POST HTTP
operations, and unsupported non-empty media types fail closed. The proxy
sanitizes every string value in accepted JSON rather than maintaining a fragile list of
provider fields.

## Network Policy

The child receives `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY`. Known LLM provider
CONNECT tunnels and unknown domains are blocked when the client honors proxy settings.
Common package registries are allowed by default; project-specific destinations are
explicit:

```sh
bf allow domain api.example.com
bf status
bf deny domain api.example.com
```

This is destination control, not arbitrary TLS inspection. During native `bf run`, a
process that ignores proxy settings can still open a direct socket because that mode
does not install an OS network sandbox.

## Credential And File Boundary

Parent API-key variables and unrelated environment values are not inherited. In native
`bf run`, provider authentication uses the agent's persistent login or credential
store; it is not brokered by Blindfold. Locked mode uses the separate gateway-owned host
credential described below.

The agent still runs in the real working directory. If it opens `.env`, `.env.local`, a
cloud credential file, or another readable path, it receives the file exactly as stored.
Use `bf mask`, `bf redact`, `bf exec`, and `bf call` for their explicit managed paths.
`bf run --trace` marks the session degraded with
`direct_filesystem_unmediated`.

Consequently, `bf run` is a managed model-traffic boundary, not whole-agent containment.
It must not be described as guaranteeing that an agent cannot read or directly
exfiltrate a local secret. Locked mode closes ordinary direct IP egress, but the stronger
claim that the agent cannot obtain a raw project secret still requires a staged
sanitized workspace and scanned patch export.

## Locked Container Mode

Use `bf container run` when direct network bypass must be OS-blocked:

```sh
bf container run claude -- --print "summarize this repo"
bf container run codex -- exec "summarize this repo"
bf container run opencode --provider openrouter -- run "inspect this project"
```

This mode runs the agent with Docker `--network none`. Its only cross-container path is
a per-session filesystem Unix socket to a separate Blindfold gateway. Only the gateway
has external networking and the real provider credential. Agent-supplied auth is
discarded, the trusted credential is injected after payload sanitization, and no generic
web/package/Git/SSH/CONNECT route exists. The agent process re-checks that its Linux
network namespace has no non-loopback IPv4 or IPv6 route before starting the harness.

The exact guarantee and exclusions are documented in
[Locked Container Boundary](container-boundary.md). This blocks ordinary direct IP
egress; it cannot guarantee that a transformed or semantic sensitive value will be
detected inside the permitted model channel.

## Upstream Overrides

Compatible test or enterprise gateways can be selected explicitly:

```sh
bf run claude --anthropic-upstream https://gateway.example/anthropic \
  -- --print "summarize this repo"

bf run codex --openai-upstream https://gateway.example/openai \
  -- review

bf run opencode --openrouter-upstream https://openrouter.ai/api \
  -- run "inspect this project"
```

No persistent Claude, Codex, or OpenCode configuration is modified.

## Harness Adapter Status

The strict TOML schema, manifest parser, explicit-directory loader, contained-entrypoint
validation, capability declarations, and exact version probes are implemented. The
three commands above use embedded manifests and retain their provider fake-upstream
conformance tests.

The manifest itself is data. It may reference a contained out-of-process entrypoint, but
the host does not load dynamic libraries or execute project-local code. Blindfold does
not discover manifests from a project directory, repository configuration, dependency
tree, agent response, or remote URL. An adapter cannot replace detection, policy,
SafeRef resolution, sanitization, tracing, or provider-proxy enforcement.

There is no external install, activation, or execution command. Native pre/post-tool
hook injection is not implemented. Current manifests therefore do not declare
`tool-request` or `tool-result` events. Adding either event requires harness-specific
replacement, failure, subagent, and provider-boundary conformance tests.

An external package reserved for future activation uses the fixed filename
`blindfold-plugin.toml` and a finite version range:

```toml
manifest_version = 1
id = "dev.example.claw-code"
version = "0.1.0"
kind = "harness-adapter"
protocol = "stdio-json-v1"
entrypoint = "bin/blindfold-claw-code"

[harness]
command = "claw-code"
version = ">=1.4.0, <1.5.0"
noninteractive_modes = ["run"]

[capabilities]
providers = ["open-ai"]
transports = ["http-json"]
events = ["model-request", "model-response", "command-output"]

[permissions]
filesystem = ["workspace-read", "workspace-write", "session-temp"]
network = ["model-proxy"]
environment = ["path", "home", "temp", "locale", "terminal"]
spawn_harness = true
spawn_tools = true
```

The host rejects unknown fields, wildcard or one-sided version ranges, unsafe command
names, duplicate declarations, manifest symlinks, and entrypoints that escape their
explicit installation directory. This package can be validated by the library today,
but `bf run claw-code` is not enabled until external execution is implemented and tested.

When those hooks are implemented, bounded tool results will pass through core
sanitization before the next model call. The provider proxy will still perform the final
request and response check. Neither mechanism stops a tool from sending data directly
in native mode. Locked container mode supplies the separate OS egress control; hooks do
not supersede it.
