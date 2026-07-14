# ADR 0010: Locked Model-Only Container Boundary

## Status

Accepted for preview implementation.

## Context

The native noninteractive runner sanitizes supported model traffic but cannot stop an
agent or tool from ignoring proxy variables and opening a direct socket. Harness hooks
also cannot provide that guarantee: they are version-specific observations inside an
untrusted harness and do not contain the whole process tree.

## Decision

Add a separate `bf container run` tier. The untrusted agent container uses Docker's
`none` network. A trusted gateway container owns external networking and the real
provider credential. The containers share one per-session filesystem Unix socket. An
agent-side loopback relay preserves the base-URL UX expected by supported harnesses.

The gateway uses the existing non-pluggable provider parser and sanitizer. It replaces
all agent provider-auth headers with its own gateway-only credential. Each run selects
one fixed known provider origin. The locked tier provides no generic web, package, Git,
SSH, MCP-network, or CONNECT egress.

Release images require a digest. Agent versions remain exact compatibility pins. The
agent launch drops all capabilities, sets no-new-privileges, uses a read-only root,
isolated ephemeral home, bounded resources, and no Docker log persistence. The gateway
does not mount the workspace; the agent does not mount the credential.

## Consequences

Direct IP egress by ordinary agent/tool processes is OS-blocked, assuming a trusted
host/runtime and no escape. The provider proxy becomes the only permitted model
crossing, independent of native tool hooks.

Development convenience is intentionally reduced: dependency installation, web search,
remote Git, and network MCP do not work during a locked run. Native `bf run` remains a
compatibility preview with weaker containment and must say so.

The decision does not imply perfect sensitive-data prevention. Unknown, transformed,
encoded, or semantic values may evade detection inside permitted model traffic. A
future tier must use a staged sanitized workspace and scanned patch export to reduce
what the agent can read.

## Rejected Alternatives

- Proxy variables alone: clients can ignore them.
- Harness pre/post-tool hooks alone: incomplete, bypassable, and not process-tree
  containment.
- A shared Docker bridge: gives the agent an IP interface and a wider attack surface.
- Transparent TLS interception as the primary boundary: adds CA/protocol complexity but
  still requires OS routing enforcement.
- Generic package/HTTP CONNECT in the locked tier: provides an opaque exfiltration
  channel and invalidates the model-only claim.
