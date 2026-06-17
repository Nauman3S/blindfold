# Coding Agent Wrappers

Blindfold can launch Claude Code, Codex CLI, and OpenCode through an ephemeral local
application proxy. It does not modify the agents' persistent configuration.

## Direct Usage

```sh
blindfold run --guard claude -- --version
blindfold run --guard codex -- exec "summarize this repo"
blindfold run --guard codex -- review
blindfold run --guard opencode -- run "inspect this project"
```

Arguments after `--` are passed to the native agent unchanged.

The default upstreams are:

- Claude and OpenCode Anthropic: `https://api.anthropic.com`
- Codex and OpenCode OpenAI: `https://api.openai.com/v1`
- OpenCode OpenRouter: `https://openrouter.ai/api/v1`

Override them only when using a compatible gateway:

```sh
blindfold run --guard claude \
  --anthropic-upstream https://gateway.example/anthropic \
  -- --model sonnet

blindfold run --guard codex \
  --openai-upstream https://gateway.example/openai/v1 \
  -- review

blindfold run --guard opencode \
  --openrouter-upstream https://openrouter.ai/api/v1 \
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

The proxy exists only for the child process lifetime and binds to an ephemeral loopback
port. The child receives an allowlisted environment and does not inherit parent API-key
variables or unrelated secrets. Authentication must use the agent's persistent
credential store or login flow. Environment-only provider authentication requires a
visible `--no-proxy` bypass until a credential broker is implemented.

## Guard Egress Policy

Guard mode sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` for the child
agent. Proxy-aware clients cannot open direct tunnels to known LLM providers such as
OpenAI, Anthropic, OpenRouter, Gemini, Mistral, or Groq.

Common development domains are allowed by default: GitHub, npm, PyPI, crates.io, and Go
module mirrors. Unknown domains block by default until the project allows them:

```sh
blindfold allow domain api.example.com
blindfold status
blindfold deny domain api.example.com
```

This is destination control, not TLS body inspection. Blindfold does not install a root
CA in v1 and does not inspect arbitrary encrypted HTTPS payloads.

## Current Boundary

The wrappers sanitize supported provider JSON and SSE request/response fields. Guard
mode also sets proxy environment variables and blocks direct known-provider CONNECT
tunnels for proxy-aware clients. They do not currently sanitize interactive terminal
output, broker provider credentials, mediate direct filesystem access, or control
network clients that ignore proxy settings. `--strict` therefore refuses to start
instead of claiming full workspace controls exist.

Agent file reads are not mediated. If an agent opens `.env`, `.env.local`, or any other
project file directly, it reads the file from disk exactly as stored. Use `blindfold
redact FILE` for one-off inspection or `blindfold exec` for controlled child-process
secret injection. `run --trace` records the session as degraded with
`direct_filesystem_unmediated`; it does not redact direct file reads.

OpenCode providers other than `openai` and `anthropic` are not routed through Blindfold.
Managed OpenCode settings may also override runtime configuration; verify organizational
policy before relying on the wrapper.
