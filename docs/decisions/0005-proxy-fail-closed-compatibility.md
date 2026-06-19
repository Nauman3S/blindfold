# ADR 0005: Proxy Fail-Closed Compatibility Gates

- Status: Accepted
- Date: 2026-06-17

## Context

Blindfold's guard mode depends on agent traffic being routed through an application
proxy that can inspect and sanitize provider payloads. Coding agents may use different
provider transports by mode or version, including JSON over HTTP, Server-Sent Events,
WebSockets, local plugins, or direct provider clients.

An unsupported transport must not become a silent bypass. A working wrapper must also
be proven by traffic reaching a fake upstream redacted, not merely by environment
variables being set.

## Decision

Guarded provider traffic must fail closed:

- inspectable HTTP JSON and SSE requests may be forwarded only after sanitization;
- allowlisted provider WebSocket text frames may be forwarded only after bounded
  bidirectional sanitization; other upgrades and binary/raw frames fail closed;
- unsupported content types are rejected unless the body is empty;
- direct known-provider egress is blocked for proxy-aware clients; and
- error bodies, traces, and logs must not include raw payloads, headers, query strings,
  or detected values.

A coding-agent mode is supported only when an automated fake-upstream test proves:

- the agent sends provider traffic to Blindfold;
- a raw fixture in the prompt is redacted before the fake upstream receives it;
- provider responses are sanitized before returning to the agent;
- unsupported transports fail closed; and
- trace records remain payload-free.

Modes without this proof must be documented as preview, degraded, or unsupported.

## Consequences

Some agent modes may be refused even if they appear configurable. This is preferable to
claiming protection for a path Blindfold cannot inspect. Codex 0.141 responses
WebSockets are supported as of 2026-06-19, but interactive Codex remains blocked because
its terminal stream is not captured and sanitized.

Provider authentication credentials may still be sent to their intended provider as
part of the authenticated provider request. Blindfold's guard promise is that project
secrets and detected sensitive payload values are not forwarded on managed paths.
