# ADR 0006: MITM Proxy Library Evaluation

- Status: Deferred; not part of the ADR 0008 runner
- Date: 2026-06-17

## Context

Application-level base URL routing does not cover every agent/provider transport. Some
agents may use WebSockets, local app servers, plugins, or provider clients that do not
honor base URL settings. Blindfold needs a way to evaluate deeper inspection without
building a full TLS MITM stack from scratch.

The security requirement is still fail-closed compatibility, not "never fail".
Unsupported or uninspectable traffic must be rejected before raw request bodies leave
the machine.

## Candidates Reviewed

### `hudsucker`

Primary spike candidate.

Observed properties:

- MIT OR Apache-2.0.
- Current release: `0.24.1`.
- Rust version: `1.85.0`.
- Supports HTTP/S request modification, response modification, and WebSocket message
  modification.
- Provides `rcgen` CA support, rustls client support, optional native TLS, and optional
  HTTP/2.

This best matches Blindfold's need to inspect HTTP, SSE, and WebSocket payloads without
owning the whole proxy/TLS implementation.

### `http-mitm-proxy`

Fallback candidate.

Observed properties:

- MIT.
- Current release: `0.18.0`.
- Built on Hyper 1.x, `http-body-util`, `hyper-util`, `tokio-rustls`, `rcgen`, and
  `tracing`.
- Supports signing certificates on the fly and SSE.
- WebSocket support is raw traffic only; Blindfold would need its own frame parser and
  redactor.

This may be useful if Hudsucker fails a focused spike, but raw WebSocket handling is a
gap for agent compatibility.

### `third-wheel`

Not a primary candidate.

Observed properties:

- MIT.
- Current crate release: `0.6.0`.
- Package description says alpha; repository README says beta.
- Older, smaller project with fewer commits and no current release metadata surfaced
  during review.

Keep as reference material only unless the maintained candidates fail.

## Decision

Do not add a MITM dependency to the main runtime yet.

Do not add MITM to the `v0.1.0` runner. If a later ADR reopens the work, evaluate an
explicit opt-in proxy using `hudsucker` first. The spike must prove:

- owner-only CA material handling;
- explicit user trust instructions without silent root CA installation;
- HTTP JSON, SSE, and WebSocket redaction before forwarding;
- fail-closed behavior for unsupported frames/transports;
- direct-provider egress blocks remain active; and
- fake-upstream tests prove raw fixtures never reach providers.

If Hudsucker cannot satisfy these gates with a small and maintainable integration,
evaluate `http-mitm-proxy` next. Do not build a custom MITM proxy until both maintained
crate paths are rejected with written evidence.

## Consequences

MITM mode can improve coverage for proxy-aware HTTPS clients, but it cannot guarantee
that nothing escapes. It does not mediate local file reads, malicious local processes,
clients that ignore proxy settings unless egress blocks them, certificate pinning, raw
TCP sockets, or QUIC/UDP unless those paths are separately blocked.

The managed runner must remain usable without trusting a local root CA. Any future deep
inspection must be explicit, separately reviewed, and visibly different from the
current base-URL-routed model boundary.
