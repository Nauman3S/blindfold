# Proxy And Protocol Lifecycle

## Purpose

This note separates model-boundary behavior that remains architectural from
compatibility branches that may be archived after external harness adapters are proven.
It is an inventory, not an implementation or deletion decision.

## Keep

The provider proxy remains the final model-boundary control even when a harness exposes
tool hooks. Keep:

- recursive sanitization of supported request and response JSON strings;
- bounded parsing before release, including split-boundary detection;
- explicit upstream, route, method, media-type, header, and URL/query validation;
- provider-auth forwarding only to the selected allowlisted provider;
- loop detection, safe static errors, and payload-free trace metadata;
- fail-closed handling for unknown or opaque protocols; and
- fake-upstream conformance tests for every supported adapter/version combination.

The currently supported bounded Anthropic response SSE grammar and JSON-object OpenAI
Responses WebSocket grammar also remain while a supported, tested noninteractive client
requires them. Their narrow parsers should not become general streaming proxies.

## Candidates For Future Archival

After external adapter installation/execution and its conformance suite are implemented,
review:

- hard-coded Claude, Codex, and OpenCode command/version selection that an installed
  manifest and built-in adapter supersede;
- provider-specific routing branches that no supported adapter can reach;
- Anthropic SSE or OpenAI Responses WebSocket support if no installed, supported client
  version requires that transport;
- legacy compatibility aliases and error paths for removed interactive, resume, server,
  remote-control, or upstream plugin modes; and
- deferred MITM-proxy research if OS containment plus the application proxy becomes the
  accepted long-term boundary.

Archive a branch only after usage search, fake-upstream tests, release notes, and an ADR
show that no supported adapter depends on it. Removing a parser solely because hooks
exist would be unsafe: hooks are not the final model-boundary check.
