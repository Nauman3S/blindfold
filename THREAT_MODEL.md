# Threat Model

## Purpose

Blindfold is a local boundary that reduces accidental disclosure of credentials and
sensitive data while AI coding agents use supported tools. This document describes the
intended `v0.1.0` design. The current pre-release skeleton does not yet implement these
controls.

## Security Objective

For traffic and operations actually routed through a supported Blindfold component,
detected raw values should not reach an untrusted LLM destination, agent-visible managed
output, Blindfold logs, audit records, or diagnostics. Restoration is allowed only into a
destination explicitly trusted by policy.

This objective is scoped to the managed boundary. It is not a claim of whole-machine
containment or perfect secret detection.

## Assets

- credentials, tokens, private keys, certificates, and credential-bearing URLs;
- caller-identified PII supplied to the preview SDK; automatic PII discovery is not
  currently implemented;
- vault encryption keys and SafeRef mappings;
- policy configuration and audit integrity;
- sanitized prompts, responses, and command output; and
- an accurate description of which paths are protected.

## Actors

- **User:** configures Blindfold and authorizes operations.
- **Agent/model:** untrusted for raw secrets; may make mistakes or attempt to solicit
  sensitive data.
- **Approved local process:** trusted only for the specific values and operation granted
  by policy.
- **LLM or API provider:** external and untrusted for values policy does not permit.
- **Tool or MCP server:** untrusted unless a destination and field are explicitly trusted.
- **Local attacker:** another process or user with access to the account or machine.
- **Dependency/upstream:** code or services that may be vulnerable, compromised, or log
  unexpected input.

## Trust Boundaries and Data Flow

```text
untrusted agent
      |
      | managed prompt, file/tool result, or command request
      v
Blindfold ingress -> detector -> policy -> redaction/SafeRef
      |                                  |
      | sanitized data                   | encrypted local mapping
      v                                  v
external provider or agent          vault + OS-protected key

SafeRef + approved operation -> policy -> trusted local destination
                                      -> sanitized result -> agent
```

Blindfold's trusted computing base includes its process, policy, detector and redaction
logic, vault implementation, selected OS credential service, and dependencies handling
sensitive data. The agent, model, provider, and general tool output are untrusted.

## Entry Points

- LLM requests and responses accepted by the local proxy;
- supported file and tool reads routed through a wrapper or broker;
- command arguments, selected environment values, stdout, and stderr handled by
  `blindfold exec`;
- configuration and policy files;
- vault and audit commands;
- future MCP requests and responses; and
- generated changes scanned by future diff checks.

## Assumptions

- the operating system, kernel, user account, Blindfold binary, and configured OS
  credential service are not compromised;
- users route protected operations through supported Blindfold integrations;
- release artifacts and dependencies are obtained through a trusted channel;
- policy and local configuration are not maliciously modified by an attacker with the
  user's permissions;
- fake test values are never valid credentials; and
- upstream protocol behavior remains within the supported and tested subset.

## In-Scope Threats

| Threat | Planned mitigation |
|---|---|
| Raw value in a managed prompt or response | Structured normalization, detection, redaction, and response scanning |
| Raw value in managed tool or shell output | Streaming sanitization with bounded overlap before release |
| Blindfold logs or errors capture payloads | Safe structured fields; raw payload logging disabled by construction |
| Unauthorized SafeRef restoration | Opaque scoped references plus destination-aware policy |
| Forged, replayed, expired, or cross-project SafeRef | Validation, scope binding, expiry, and deny-by-default restoration |
| Malformed or unsupported sensitive input bypasses checks | Fail closed with a redacted diagnostic |
| Proxy becomes remotely reachable | Loopback default; explicit authenticated configuration for other binds |
| Secret reaches an unintended child | Explicit allowlist and minimal child environment |
| Vault files disclose mappings | Authenticated encryption; key protected separately by the OS credential service |
| Dependency vulnerability or incompatible license | `cargo audit`, `cargo deny`, review, and minimal dependencies |
| Credential committed to the repository | Redacted Gitleaks CI plus isolated, explicitly allowed fake fixtures |
| Split value evades stream scanning | Bounded buffering and tests at every supported split boundary |

## Non-Goals and Out-of-Scope Threats

For `v0.1.0`, Blindfold does not protect against:

- a compromised OS, kernel, shell, user account, Blindfold binary, or credential service;
- memory scraping, swap inspection, debugger access, hardware attacks, or side channels;
- a malicious approved child process intentionally exfiltrating a provided secret;
- direct filesystem, network, provider, tool, or subprocess access that bypasses
  Blindfold;
- transparent TLS interception or system-wide network enforcement;
- perfect detection of unknown, encrypted, heavily transformed, or semantically hidden
  values;
- denial of service by an agent, provider, tool, or local process;
- malicious repository content exploiting software outside Blindfold; or
- Windows security guarantees or production support.

Strict mode may reject known degraded configurations, but `v0.1.0` does not provide a
container or OS sandbox, egress firewall, brokered filesystem, or process-tree
containment.

## Residual Risks

- Detector false negatives can allow a raw value through a managed path.
- Detector false positives can block or alter benign data.
- Streaming output may require buffering that affects latency and availability.
- Labels, paths, timing, finding counts, and SafeRef use can reveal metadata even when
  values are hidden.
- OS keychain behavior and desktop/session availability differ across macOS and Linux.
- A dependency may unexpectedly format, serialize, retain, or transmit sensitive data.
- Users may misunderstand degraded startup status or configure an unprotected bypass.
- Encrypted vault artifacts may remain in filesystem backups after local deletion.

## Security Invariants

1. Raw values are redacted before managed logs, traces, metrics labels, audit records,
   errors, or user-visible diagnostics.
2. Raw-value types do not expose unsafe default `Debug`, `Display`, or serialization.
3. Telemetry is off by default and excludes payloads and sensitive metadata if added.
4. Restoration requires both an authorized operation and a trusted destination.
5. Unsupported security-sensitive input fails closed.
6. Proxy listeners bind to loopback by default.
7. Child processes receive only explicitly approved secrets and environment variables.
8. Audit records contain SafeRefs or keyed fingerprints, never raw values.
9. Tests use fake isolated fixtures and search outputs and artifacts for fixture values.
10. Startup diagnostics accurately identify protected, degraded, and unprotected paths.

## Review Triggers

Update this model before adding a restoration destination, remote listener, new vault or
key backend, telemetry, Windows support, sandbox claim, protocol integration, or feature
that changes which process can receive plaintext.
