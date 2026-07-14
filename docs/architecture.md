# Architecture

## Status

The detector, policy, portable encrypted vault, masking/redaction paths, execution
runtime, constrained application proxy, noninteractive agent runner, application SDKs,
diff scanner, and stdio MCP preview are implemented. OS keychain adapters, whole-agent
sandboxing, and production support evidence remain incomplete. The strict adapter
manifest/host layer and built-in version gates from
[ADR 0009](decisions/0009-harness-adapter-security-boundary.md) are implemented;
external adapter execution and native tool hooks remain incomplete.

## Components

```text
Agent / wrapper
    |
    +--> managed file and tool input
    +--> managed LLM request
    +--> approved exec request
              |
              v
      normalize and classify
              |
              v
      detector and policy engine
          |              |
          | redact       | restore only to trusted destination
          v              v
   agent/provider     local process/API
          ^              |
          +--- sanitize output

SafeRef mappings <--> encrypted local vault
safe metadata    ---> append-only audit
```

The core owns security-domain types and invariants. The CLI composes scanning, vault,
proxy, execution, and integration components. Full runtime enforcement of the versioned
project configuration and policy override hierarchy is not yet integrated.

## Managed Data Flow

1. A supported integration sends content to Blindfold rather than directly to its
   destination.
2. Blindfold parses or normalizes the supported format.
3. Detectors identify sensitive spans without logging raw input.
4. Policy selects `redact`, `block`, `warn`, or `restore` based on sensitivity, source,
   destination, operation, and mode.
5. Redaction replaces a value with a non-restorable marker, randomized operation-local
   surrogate, environment reference, or SafeRef according to the managed operation.
6. Only a policy-trusted local operation may resolve a vault-backed SafeRef.
7. Managed provider responses are sanitized before the agent sees them; captured child
   stdout and stderr are sanitized before the local user sees them.
8. Audit records contain safe metadata, never plaintext values.

Malformed or unsupported security-sensitive input must fail closed instead of being
forwarded without inspection.

## Harness Adapter Boundary

The harness adapter layer separates agent compatibility from enforcement:

```text
embedded strict TOML manifest
                  |
                  v
        built-in adapter selection and capability gates
                  |
       +----------+------------------+
       |                             |
       v                             v
future tool-result hook         provider request/response
       |                             |
       v                             v
core sanitizer                 core provider proxy
       |                             |
       +----------> harness <--------+

explicit external plugin directory --> validation only; no execution path
```

The manifest is data, not code. It may select a built-in compatibility adapter or
reference a contained out-of-process entrypoint and declare version, command, hook, and
routing requirements. It cannot supply in-process hooks, replace detectors or policy,
resolve SafeRefs, alter restoration destinations, or bypass proxy checks. All
enforcement stays in non-pluggable Blindfold core code.

Any future external adapter requires explicit user installation and activation.
Blindfold does not auto-load project, working-tree, dependency, or agent-supplied
manifests. There is no install, activation, or external execution command yet. The
current built-in adapters check the embedded schema, exact capability contract, resolved
command, pinned harness version, and invocation grammar. Any mismatch fails before the
child starts. The external entrypoint protocol is reserved but not executed by `bf run`.
Built-ins use `builtin-v1`; `stdio-json-v1` applies only to that future external protocol.

A future supported tool-result hook will sanitize its bounded payload before the harness
can place that result in the next model request. Current built-in manifests do not claim
that event. The provider proxy remains the final check at the model boundary because
hooks may be absent, bypassed, or changed by an upstream harness.
Neither layer prevents a tool from exfiltrating directly over an unmediated socket; that
requires the planned OS containment boundary.

## Trust Boundaries

The Blindfold process and its local vault are trusted to handle plaintext. Agents, LLM
providers, arbitrary tools, and their output are untrusted. An approved child process is
trusted only for the named secret and operation it was granted.

The operating system and user account are prerequisites, not boundaries Blindfold can
defend. Direct traffic, reads, or commands outside the wrapper/proxy/broker remain
outside the managed boundary.

## Storage

The current portable vault stores authenticated XChaCha20-Poly1305 encrypted records in
an atomically replaced local file. Its 32-byte master key is supplied by the caller and
is not stored beside ciphertext. macOS Keychain and Linux Secret Service adapters remain
future work. Vault and audit paths reject symlinks, but descriptor-relative filesystem
operations remain future hardening. See [ADR 0002](decisions/0002-vault-backend.md).

## SafeRefs

Agent-visible references use a versioned, opaque grammar:

```text
{{BLINDFOLD:v1:<kind>:<opaque-id>}}
```

The identifier contains no plaintext or secret-derived substring. Resolution is scoped
to project/session and policy. See
[ADR 0003](decisions/0003-saferef-format.md).

## Dependency Architecture

Blindfold uses Rust 1.96.0 and edition 2024. Dependencies are added only for focused
capabilities that are safer or materially easier to maintain than an in-house
implementation. Default features are disabled when unnecessary, and duplicate
frameworks are avoided. See [ADR 0001](decisions/0001-rust-baseline.md).

Adapter manifests use maintained ecosystem crates rather than custom parsers: `serde`
for the closed typed schema, `toml` for decoding, and `semver` for finite compatibility
ranges. Process limits and environment isolation reuse `blindfold-exec`.

## Platform Boundary

macOS and Linux are development targets pending release installation and key-management
evidence. Windows is explicitly unsupported. Platform details and key-service
assumptions are documented in
[ADR 0004](decisions/0004-managed-boundary-and-platforms.md) and
[platforms.md](platforms.md).
