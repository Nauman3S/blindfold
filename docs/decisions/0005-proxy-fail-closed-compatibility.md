# ADR 0005: Proxy Fail-Closed Compatibility Gates

- Status: Accepted principle; transport grammar updated by ADR 0008 and later
  OpenAI-compatible chat-completions SSE conformance
- Date: 2026-06-17

## Context

Blindfold's managed runner depends on agent traffic being routed through an application
proxy that can inspect and sanitize provider payloads. Coding agents may use different
provider transports by mode or version, including JSON over HTTP, Server-Sent Events,
WebSockets, local plugins, or direct provider clients.

An unsupported transport must not become a silent bypass. A working wrapper must also
be proven by traffic reaching a fake upstream redacted, not merely by environment
variables being set.

## Decision

Managed provider traffic must fail closed:

- JSON POST bodies may be forwarded only after recursive sanitization;
- bounded Anthropic response SSE is accepted only on `messages`; SSE requests and
  OpenAI SSE fail closed;
- OpenAI Responses WebSockets accept only JSON-object text messages on the allowlisted
  route; other upgrades, opaque text, nonempty control, and binary frames fail closed;
- unsupported content types are rejected even when the body is empty;
- direct known-provider egress is blocked for proxy-aware clients; and
- error bodies, traces, and logs must not include raw payloads, headers, query strings,
  or detected values.

A coding-agent mode is supported only when an automated fake-upstream test proves:

- the agent sends provider traffic to Blindfold;
- a raw fixture in the prompt is redacted before the fake upstream receives it;
- provider responses are sanitized before returning to the agent;
- unsupported transports fail closed; and
- trace records remain payload-free.

Modes without this proof are unsupported and must fail before the child starts.

## Consequences

Some agent modes may be refused even if they appear configurable. This is preferable to
claiming protection for a path Blindfold cannot inspect. The supported runner grammar is
Claude print, Codex exec/review, and OpenCode run. Interactive/TUI modes are outside the
runner.

Provider authentication credentials may still be sent to their intended provider as
part of the authenticated provider request. Blindfold's managed-path promise is that project
secrets and detected sensitive payload values are not forwarded on managed paths.

## Later Update

OpenCode `1.18.0` conformance established response SSE on the exact
`chat/completions`/`v1/chat/completions` routes. That response grammar now accepts only
JSON `data` events and exact `[DONE]`, sanitizes every JSON textual leaf, and rejects
opaque data or SSE on all other OpenAI-compatible routes. The original fail-closed
principle is unchanged.
