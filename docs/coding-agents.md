# Coding Agent Wrappers

Blindfold can launch Claude Code, Codex CLI, and OpenCode through an ephemeral local
application proxy. It does not modify the agents' persistent configuration.

## Direct Usage

```sh
blindfold run --guard claude -- --print "summarize this repo"
blindfold run --guard codex -- exec "summarize this repo"
blindfold run --guard codex -- review
blindfold run --guard opencode -- run "inspect this project"
```

Arguments after `--` are passed to the native agent unchanged.

The default upstreams are:

- Claude and OpenCode Anthropic: `https://api.anthropic.com`
- Codex and OpenCode OpenAI: `https://api.openai.com`
- OpenCode OpenRouter: `https://openrouter.ai/api`

Override them only when using a compatible gateway:

```sh
blindfold run --guard claude \
  --anthropic-upstream https://gateway.example/anthropic \
  -- --print --model sonnet "summarize this repo"

blindfold run --guard codex \
  --openai-upstream https://gateway.example/openai \
  -- review

blindfold run --guard opencode \
  --openrouter-upstream https://openrouter.ai/api \
  -- run "inspect this project"
```

## Keep Native Command Names

For the current shell:

```sh
eval "$(blindfold shell-init zsh)"
```

Use `bash` instead of `zsh` when appropriate. After activation, normal commands are
wrapped:

```sh
claude
codex review
opencode run "fix the tests"
```

To activate this for future shells, add the `eval` command to `.zshrc` or `.bashrc`.
The generated functions call the real executable with `command`, so they do not recurse.
Bare interactive `claude`, `codex`, or `opencode` shell-wrapper invocations will fail
closed under Guard until those transports are proven safe. Pass the supported
non-interactive arguments shown above.

## Opt Out

Opt out for one invocation:

```sh
bf-off claude
bf-off codex review
bf-off opencode
```

Equivalent explicit forms:

```sh
BLINDFOLD_BYPASS=1 claude
blindfold run codex --no-proxy -- review
```

Opt-out mode launches the native executable directly and prints a visible bypass notice.
It does not change persistent configuration.

## Agent Integration

- Claude receives an ephemeral `ANTHROPIC_BASE_URL`.
- Codex receives an ephemeral `openai_base_url` CLI configuration override for
  non-interactive `exec` and `review` runs. Interactive Codex currently uses a
  WebSocket transport that Blindfold does not sanitize yet, so Guard fails closed for
  that mode.
- OpenCode receives an `OPENCODE_CONFIG_CONTENT` overlay for its OpenAI and Anthropic
  provider base URLs (`/openai/v1`, `/anthropic/v1`, and `/openrouter/v1`). Existing
  inline settings are retained.

## Compatibility Matrix

`Proven` means an automated fake-upstream regression sends a raw fixture through the
managed agent path and verifies that the provider receives only redacted content and
that the agent receives a redacted response.

| Agent mode | Provider route | Inspectable transport | Credential source | Status | Notes |
|---|---|---|---|---|---|
| `claude --print ...` / `claude -p ...` | Anthropic through `/anthropic/v1` | HTTP JSON; Anthropic SSE sanitization is supported by the proxy | Native Claude login/config; parent env credentials are stripped | Proven for HTTP JSON | Interactive Claude, resume, remote, worktree, plugin URL, and permission-bypass modes fail closed. |
| `codex exec ...` | OpenAI through `/openai/v1` | HTTP JSON | Native Codex login/config; parent env credentials are stripped | Proven for HTTP JSON | Use this for guarded non-interactive Codex tasks. |
| `codex review` | OpenAI through `/openai/v1` | HTTP JSON | Native Codex login/config; parent env credentials are stripped | Proven for HTTP JSON | Guard injects the base URL and fake-upstream coverage verifies request/response redaction. |
| interactive `codex` | OpenAI WebSocket path | WebSocket | Native Codex login/config | Unsupported; fails closed | Blindfold refuses this mode before launch because WebSocket sanitization is not implemented. |
| `opencode run ...` with OpenAI | OpenAI through `/openai/v1` | HTTP JSON | Native OpenCode login/config; parent env credentials are stripped | Proven for HTTP JSON | Current fake-upstream coverage exercises the OpenAI provider route. |
| `opencode run ...` with Anthropic | Anthropic through `/anthropic/v1` | HTTP JSON; Anthropic SSE sanitization is supported by the proxy | Native OpenCode login/config; parent env credentials are stripped | Proven for HTTP JSON | Runtime config is injected and fake-upstream coverage verifies request/response redaction. |
| `opencode run ...` with OpenRouter | OpenRouter through `/openrouter/v1` | OpenAI-compatible HTTP JSON | Native OpenCode login/config; parent env credentials are stripped | Proven for HTTP JSON | Route is configured through the OpenAI-compatible proxy path and covered by fake-upstream tests. |
| OpenCode TUI/server mode | OpenAI, Anthropic, and OpenRouter config overlay | Depends on OpenCode mode/plugins | Native OpenCode login/config | Unsupported; fails closed | Use explicit `opencode run ...` for the currently tested guarded path. |
| Agent plugins/tools | Varies | Varies | Varies | Not mediated by wrapper alone | Use `blindfold exec`, `blindfold call`, MCP stdio preview, or future broker integrations for scoped secret use. |

The proxy exists only for the child process lifetime and binds to an ephemeral loopback
port. The child receives an allowlisted environment and does not inherit parent API-key
variables or unrelated secrets. Authentication must use the agent's persistent
credential store or login flow. Environment-only provider authentication still requires
a visible `--no-proxy` bypass; the current broker commands cover scoped child
execution and one bearer-token HTTP call, not agent provider login.

For non-interactive `codex exec`, `codex review`, and `opencode run`, Blindfold captures
child stdout/stderr, redacts detected secrets, then prints the sanitized output while
preserving the child exit code. Interactive passthrough modes are not captured, so their
terminal output is not sanitized.

## Guard Egress Policy

Guard mode sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` for the child
agent. For proxy-aware clients, direct CONNECT tunnels to known LLM providers such as
OpenAI, Anthropic, OpenRouter, Gemini, Mistral, or Groq are blocked.

Common development domains are allowed by default for proxy-aware clients: GitHub, npm,
PyPI, crates.io, and Go module mirrors. Unknown domains that pass through the guard
proxy block by default until the project allows them:

```sh
blindfold allow domain api.example.com
blindfold status
blindfold deny domain api.example.com
```

This is destination control, not TLS body inspection. Blindfold does not install a root
CA in v1 and does not inspect arbitrary encrypted HTTPS payloads.

## Current Boundary

The wrappers sanitize supported provider JSON and SSE request/response fields. Guard
mode also sets proxy environment variables, sanitizes captured non-interactive child
stdout/stderr, and blocks direct known-provider CONNECT tunnels for proxy-aware clients.
They do not currently sanitize interactive terminal output, broker provider credentials
into the agent process, mediate direct filesystem access, or control network clients
that ignore proxy settings.
`--strict` therefore refuses to start instead of claiming full workspace controls exist.

Agent file reads are not mediated. If an agent opens `.env`, `.env.local`, or any other
project file directly, it reads the file from disk exactly as stored. Use `blindfold
redact FILE` for one-off inspection, `blindfold exec` for controlled child-process
secret injection, or `blindfold call` for one bearer-token HTTP request. `run --trace`
records the session as degraded with
`direct_filesystem_unmediated`; it does not redact direct file reads.

OpenCode providers other than `openai`, `anthropic`, and `openrouter` are not routed
through Blindfold. Managed OpenCode settings may also override runtime configuration;
verify organizational policy before relying on the wrapper.
