# ADR 0004: Managed Boundary and Initial Platforms

- Status: Accepted boundary; runner-mode wording superseded by ADR 0008
- Date: 2026-06-11

## Context

A wrapper and application-level proxy cannot mediate every filesystem, subprocess, or
network path available to an AI coding agent. Platform-specific key storage and process
behavior also require dedicated release evidence.

## Decision

`v0.1.0` guarantees apply only to supported operations routed through a Blindfold
wrapper, proxy, broker, or execution component and reported as protected at startup.
Direct provider traffic, file reads, commands, and network calls outside those components
are outside the boundary.

ADR 0008 removed the preview runner `--strict` mode. The current runner always
establishes its managed model-traffic controls but reports filesystem reads and direct
network clients as unmediated. It does not claim OS sandboxing, transparent TLS
interception, brokered filesystem access, or OS-enforced network egress.

Support macOS and Linux for `v0.1.0`, subject to the tested release matrix in
`docs/platforms.md`. Windows and other platforms are unsupported, even if compilation
succeeds.

## Consequences

The product promise is narrower than whole-machine secret containment but can be tested
and communicated accurately. Startup diagnostics and documentation are security
features: they must name degraded and unprotected paths.

Windows requires a separate architecture decision and security validation before it can
be described as experimental or supported.
