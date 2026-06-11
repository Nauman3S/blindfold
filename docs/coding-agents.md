# Coding Agent Wrappers

Blindfold can launch Claude Code, Codex CLI, and OpenCode through an ephemeral local
application proxy. It does not modify the agents' persistent configuration.

## Direct Usage

```sh
blindfold run claude -- --version
blindfold run codex -- review
blindfold run opencode -- run "inspect this project"
```

Arguments after `--` are passed to the native agent unchanged.

The default upstreams are:

- Claude and OpenCode Anthropic: `https://api.anthropic.com`
- Codex and OpenCode OpenAI: `https://api.openai.com/v1`

Override them only when using a compatible gateway:

```sh
blindfold run claude \
  --anthropic-upstream https://gateway.example/anthropic \
  -- --model sonnet

blindfold run codex \
  --openai-upstream https://gateway.example/openai/v1 \
  -- review
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
- Codex receives an ephemeral `openai_base_url` CLI configuration override.
- OpenCode receives an `OPENCODE_CONFIG_CONTENT` overlay for its OpenAI and Anthropic
  provider base URLs (`/openai/v1` and `/anthropic/v1`). Existing inline settings are
  retained.

The proxy exists only for the child process lifetime and binds to an ephemeral loopback
port. Authentication continues to use each agent's existing environment or credential
store.

## Current Boundary

The wrappers sanitize supported provider JSON and SSE request/response fields. They do
not currently sanitize interactive terminal output, isolate provider credentials from
the agent process, or prevent direct filesystem and network access. `--strict` therefore
refuses to start instead of claiming those controls exist.

OpenCode providers other than `openai` and `anthropic` are not routed through Blindfold.
Managed OpenCode settings may also override runtime configuration; verify organizational
policy before relying on the wrapper.
