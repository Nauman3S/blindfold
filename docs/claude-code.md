# Claude Code Integration

## Status

Claude Code support is a `v0.1.0` target. `blindfold run -- claude` is not implemented in
the current skeleton.

## Intended Protected Paths

The wrapper will protect only paths it can establish and verify, expected to include:

- supported Anthropic-compatible LLM requests routed through the local proxy;
- wrapper-managed model responses;
- supported file or tool results routed through documented hooks or brokers;
- secrets passed through `blindfold exec`; and
- wrapper-managed stdout and stderr.

Startup must list each path as protected, degraded, or unprotected.

## Bypass Risks

The following remain unprotected unless the wrapper can explicitly mediate them:

- direct provider endpoints or credentials configured outside the wrapper;
- inherited raw secrets in the agent process environment;
- direct filesystem or network access not covered by a supported hook;
- commands launched outside `blindfold exec`;
- unsupported Claude Code versions, hooks, plugins, or transports; and
- child processes intentionally exfiltrating a value they were approved to receive.

`--strict` must refuse to start when required proxy, hook, environment, or version checks
cannot establish the documented boundary. It does not create an OS sandbox or network
firewall.

## Planned Workflow

```sh
blindfold init
blindfold doctor
blindfold run -- claude
```

Until those commands are implemented and a release is published, do not use Blindfold
with real credentials.

## Troubleshooting Contract

Diagnostics must identify configuration, local storage, loopback listener, and
integration readiness without printing secret values, request bodies, response bodies,
or the process environment.
