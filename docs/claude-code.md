# Claude Code Integration

The shared wrapper and opt-out workflow is documented in
[Coding Agent Wrappers](coding-agents.md). This page records Claude-specific boundary
details.

## Status

`blindfold run claude` starts a local Anthropic-compatible application proxy and points
the Claude process at it with an ephemeral `ANTHROPIC_BASE_URL`. No persistent Claude
configuration is changed. Strict mode refuses to start because the full boundary cannot
yet be established.

## Intended Protected Paths

The wrapper will protect only paths it can establish and verify, expected to include:

- supported Anthropic-compatible JSON requests routed through the local proxy; and
- supported JSON and SSE responses routed back through the proxy.

Startup must list each path as protected, degraded, or unprotected.

## Bypass Risks

The following remain unprotected unless the wrapper can explicitly mediate them:

- direct provider endpoints or credentials configured outside the wrapper;
- inherited raw secrets in the agent process environment;
- direct filesystem or network access not covered by a supported hook;
- commands launched outside `blindfold exec`;
- unsupported Claude Code versions, hooks, plugins, or transports; and
- child processes intentionally exfiltrating a value they were approved to receive.

The current preview does not sanitize the interactive terminal stream, install file/tool
hooks, isolate provider credentials from the agent environment, or prevent direct
network/filesystem bypasses.

`--strict` refuses to start because these controls cannot yet establish the documented
MVP boundary. It does not create an OS sandbox or network firewall.

## Preview Workflow

```sh
blindfold init
blindfold doctor
blindfold run claude
```

Pass native Claude arguments after `--`, for example:

```sh
blindfold run claude -- --model sonnet
```

Use `blindfold run claude --no-proxy -- ...` for a visible one-run bypass.

## Troubleshooting Contract

Diagnostics must identify configuration, local storage, loopback listener, and
integration readiness without printing secret values, request bodies, response bodies,
or the process environment.
