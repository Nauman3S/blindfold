# Guarantees and Limitations

## Current State

No security guarantee applies to the pre-release implementation skeleton. The statements
below are acceptance criteria for `v0.1.0`, and will apply only after release evidence
shows the relevant path is implemented and active.

## Managed-Boundary Guarantees

For a supported operation that startup diagnostics report as protected, with valid
policy and no bypass:

- detected raw secrets are removed or blocked before managed LLM requests leave the
  machine;
- detected raw secrets are removed or blocked before managed responses or tool output
  reach the agent;
- Blindfold does not intentionally write raw values to its logs, traces, metrics labels,
  audit records, or diagnostics;
- SafeRefs contain no raw or secret-derived substring;
- SafeRefs are restored only for a trusted destination and authorized operation;
- child processes receive only explicitly selected secret values and permitted
  environment variables;
- malformed or unsupported security-sensitive managed input is rejected rather than
  forwarded uninspected; and
- the proxy listens on loopback unless an explicit, authenticated non-loopback
  configuration is supported and selected.

Each statement requires regression tests using fake fixture values. A path that cannot
establish its controls must be reported as degraded or unprotected; strict mode must
refuse to start when a required control is missing.

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

## Accurate Status

Documentation and startup output must use these terms consistently:

- **Protected:** the required managed controls are established and tested for the path.
- **Degraded:** some controls are active, but a documented limitation reduces coverage.
- **Unprotected:** the path bypasses Blindfold or required controls are unavailable.

The project must not use absolute claims such as "secrets can never leak" or imply that
future sandbox, filesystem mediation, or network egress controls already exist.
