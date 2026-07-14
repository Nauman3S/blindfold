# ADR 0008: One Constrained Noninteractive Runner

## Status

Accepted.

## Context

The earlier agent preview exposed guard, degraded, strict, bypass, shell-wrapper, and
interactive concepts before Blindfold had OS containment. That surface was difficult to
explain and allowed invocations that could not share one verified output and transport
contract.

## Decision

`blindfold run` has one managed behavior and accepts only:

- Claude `--print` / `-p`;
- Codex `exec` and `review`; and
- OpenCode `run`.

Selectable `--guard`, `--no-proxy`, preview `--strict`, `BLINDFOLD_BYPASS`, generated
shell wrappers, and interactive/TUI modes are removed. Native agent commands are the
clear way to run outside Blindfold.

Every accepted run establishes the provider proxy, proxy-aware egress guard, minimal
environment, and captured sanitized output. The protocol grammar is limited to JSON
POST, Anthropic response SSE, and JSON-object OpenAI Responses WebSocket text messages.
Other security-sensitive transports fail closed.

The runner remains a managed model-traffic boundary. Startup, traces, and documentation
must continue to report direct filesystem reads and clients that ignore proxy settings
as unmediated. Whole-agent containment is a separate future release gate.

## Consequences

- The CLI and documentation have one supported invocation form.
- Every accepted agent mode has captured output and bidirectional provider sanitization.
- Claude response SSE and Codex Responses WebSockets remain because the supported
  noninteractive clients require them; their grammars are narrowly gated.
- Existing shell-wrapper and bypass workflows stop working and fail visibly.
- Users needing interactive agents run the native command with no implication that
  Blindfold protects it.

This decision supersedes the selectable runner-mode and opt-out portions of earlier
managed-boundary documentation. It does not change the explicit non-containment limits
in ADR 0004 or the fail-closed principle in ADR 0005.

ADR 0009 supplies strict manifests and bounded version gates around this command and
transport contract. External adapter execution and native tool hooks remain future
work. Adapters do not restore interactive modes or make core enforcement pluggable.
