# Guarantees and Limitations

## Current State

Blindfold is pre-release. Implemented managed paths have regression tests, but the
statements below remain release acceptance criteria until platform and end-to-end
evidence is complete.

## Managed-Boundary Guarantees

For a supported operation with valid policy and every required managed control
established:

- detected raw secrets and supported PII are removed or blocked before managed LLM
  requests leave the machine;
- detected raw secrets are removed or blocked before managed provider responses reach
  the agent;
- captured child stdout and stderr are sanitized before they reach the local user;
- Blindfold does not intentionally write raw values to its logs, traces, metrics labels,
  audit records, or diagnostics;
- SafeRefs contain no raw or secret-derived substring;
- SafeRefs are restored only for a trusted destination and authorized operation;
- child processes receive only explicitly selected secret values and permitted
  environment variables;
- malformed, opaque, or unsupported security-sensitive managed input is rejected rather
  than forwarded uninspected; and
- the proxy listens on loopback unless an explicit, authenticated non-loopback
  configuration is supported and selected.

Each statement requires regression tests using fake fixture values. A path that cannot
establish its controls must be reported as degraded or unprotected. A future
whole-agent containment mode must refuse to start when any required OS control is
missing.

The harness-adapter layer does not expand these guarantees by itself. Built-in runs now
validate their strict embedded manifests, exact declared capability contracts, resolved
commands, and pinned harness versions before proxy startup. A version check does not
authenticate an executable. A TOML manifest remains compatibility data and cannot grant
authority or disable a core check.

External adapter execution and native tool-result hooks are not implemented. An
external adapter-backed invocation must not be reported as protected until it is
explicitly installed and activated, all required hooks are established, and the core
provider proxy passes its model-boundary conformance test.

## Non-Guarantees

Blindfold does not guarantee:

- secrecy for direct LLM/provider traffic, file reads, network requests, shell commands,
  or tools that bypass Blindfold;
- containment of a malicious process, operating system, user account, or dependency;
- prevention of exfiltration by a child process intentionally given a secret;
- detection of every secret or sensitive semantic fact;
- protection against memory inspection, swap, debuggers, hardware, or side channels;
- deletion from backups after encrypted local records are removed;
- availability under hostile or excessively large input; or
- any Windows behavior for `v0.1.0`.

Blindfold also does not guarantee that a harness hook prevents direct exfiltration. A
future hook could sanitize a supported tool result before the next model call, and the
provider proxy can enforce the final supported model crossing. A tool can still open a
direct network connection or read a host file unless OS containment prevents it.

In particular, `bf run` does not mediate `.env`, home-directory credential files,
persistent agent login stores, or direct sockets opened by clients that ignore proxy
settings. It is a managed model-traffic boundary, not whole-agent containment.

## Accurate Status

Documentation and startup output must use these terms consistently:

- **Protected:** the required managed controls are established and tested for the path.
- **Degraded:** some controls are active, but a documented limitation reduces coverage.
- **Unprotected:** the path is outside Blindfold or required controls are unavailable.

The project must not use absolute claims such as "secrets can never leak" or imply that
future sandbox, filesystem mediation, or network egress controls already exist.

Installing a harness adapter must not be described as trusting its entrypoint or
enabling whole-agent protection. Project-local plugins are never auto-loaded, and the
current CLI does not execute external adapter entrypoints.

In-harness tool requests and results are not currently observed or protected by native
hooks. They are protected only if their content later crosses a supported provider path.

Supported automatic PII means RFC-valid email addresses and valid `+`-prefixed
international phone numbers. It does not include names, postal addresses, national
identifiers, financial account numbers, or semantic inference.
