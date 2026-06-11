# Architecture

## Status

This is the target architecture for `v0.1.0`. The repository is currently a foundation
skeleton and does not yet provide the described protection.

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

The core owns security-domain types and invariants. The CLI composes configuration,
scanning, policy, vault, proxy, execution, and integration components without weakening
their defaults.

## Managed Data Flow

1. A supported integration sends content to Blindfold rather than directly to its
   destination.
2. Blindfold parses or normalizes the supported format.
3. Detectors identify sensitive spans without logging raw input.
4. Policy selects `redact`, `block`, `warn`, or `restore` based on sensitivity, source,
   destination, operation, and mode.
5. Redaction replaces a value with an opaque SafeRef. The mapping is encrypted locally.
6. Only a policy-trusted local operation may resolve the SafeRef.
7. Managed responses and process output pass through sanitization before the agent sees
   them.
8. Audit records contain safe metadata, never plaintext values.

Malformed or unsupported security-sensitive input must fail closed instead of being
forwarded without inspection.

## Trust Boundaries

The Blindfold process and its local vault are trusted to handle plaintext. Agents, LLM
providers, arbitrary tools, and their output are untrusted. An approved child process is
trusted only for the named secret and operation it was granted.

The operating system and user account are prerequisites, not boundaries Blindfold can
defend. Direct traffic, reads, or commands outside the wrapper/proxy/broker remain
outside the managed boundary.

## Storage Direction

The planned vault uses authenticated encrypted records in a local database. A random
master key is stored or wrapped by macOS Keychain or a Linux Secret Service provider;
the key is not stored beside ciphertext. See
[ADR 0002](decisions/0002-vault-backend.md).

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

## Platform Boundary

The first release targets macOS and Linux. Windows is explicitly unsupported. Platform
details and key-service assumptions are documented in
[ADR 0004](decisions/0004-managed-boundary-and-platforms.md) and
[platforms.md](platforms.md).
