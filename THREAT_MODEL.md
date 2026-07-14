# Threat Model

## Status And Objective

This document describes the implemented `v0.1.0` managed boundary. Blindfold removes,
masks, or blocks detected and application-registered values on supported paths before
they reach an LLM, agent-visible managed output, diagnostics, audit, or trace storage.
Plaintext restoration is limited to an independently authorized trusted operation and
destination.

This is not whole-agent containment. `bf run` protects accepted provider traffic and
captured process output; it does not prevent the agent from reading host files or opening
a socket that ignores proxy settings.

The strict harness-manifest parser/host and built-in version gates from ADR 0009 are
implemented. External adapter execution and native tool hooks are not. This does not
change the current managed-boundary objective.

## Protected Assets

- detected credentials, tokens, passwords, private keys, credential-bearing URLs,
  RFC-valid email addresses, and valid international phone numbers;
- secrets and PII explicitly registered with an application SDK;
- caller-selected environment values used by `bf exec` or `bf call`;
- vault master keys, encrypted mappings, scoped SafeRefs, and expiry metadata;
- policy, audit, and payload-free trace integrity; and
- an accurate account of which paths are managed or unmediated.

Names, addresses, national identifiers, account numbers, encrypted content, transformed
secrets, and other semantic sensitive facts are not automatically detected.

## Trust Boundaries

Trusted:

- the Blindfold process and its detector, policy, proxy, vault, execution, and broker
  components;
- the operating system, kernel, user account, and release artifact;
- a child process only for a specific secret explicitly granted through `bf exec`; and
- a remote API only for the exact value intentionally sent by `bf call` or provider
  authentication.

Untrusted:

- agents, models, model responses, arbitrary tool output, repository content, and MCP
  clients/servers unless an operation says otherwise;
- unsupported provider protocols and media types; and
- forged, expired, cross-project, or otherwise unauthorized SafeRefs;
- harness-adapter manifests, hook payloads, harness version output, and all project-local
  files that resemble plugin or adapter configuration; and
- installed adapter metadata until core validates its schema, version, invocation, and
  capability requirements for the current run.

The current caller-supplied vault key is trusted but not OS-keychain managed. Agent
persistent login stores are outside Blindfold and may be readable by the agent process.

## Implemented Data Paths

| Path | Protection | Plaintext recipient |
|---|---|---|
| `scan` | bounded detection; values never printed | Blindfold detector only |
| `redact` | placeholder, schema, env-ref, surrogate, or block | none |
| `mask` | encrypted vault storage plus scoped opaque SafeRefs | Blindfold vault only |
| `exec` | minimal env, selected injection, bounded captured-output redaction | explicitly selected child |
| `call` | allowed-host bearer injection and bounded response redaction | explicitly allowed API |
| provider proxy | recursive JSON sanitization in both directions | allowlisted provider receives sanitized payload plus its own auth |
| agent runner | clean parent env, managed provider route, proxy-aware egress policy, captured output | supported noninteractive agent receives no parent env secrets |
| MCP stdio | recursive agent-bound sanitization; CLI restoration denied | no plaintext restoration in CLI preview |
| Python SDK | registered strings protected in supported request and response shapes | PII may restore only to `end_user` |
| TypeScript SDK | explicitly registered strings tokenized before the caller sends them | PII may restore only to `end_user` |

Secrets are never restored into ordinary model, log, memory, or user output by either
SDK. SafeRef syntax is not authorization.

## Agent Runner Contract

The runner accepts only:

```sh
bf run claude -- --print "prompt"
bf run codex -- exec "prompt"
bf run codex -- review
bf run opencode -- run "prompt"
```

Interactive/TUI, resume, server, remote-control, plugin, search, and permission-bypass
modes fail before launch. There is no Blindfold runner bypass switch or shell wrapper.

Accepted provider protocols are restricted to:

- JSON POST bodies;
- bounded Anthropic response SSE on `messages`; and
- JSON-object text messages on the OpenAI Responses WebSocket.

SSE requests, OpenAI SSE, unknown content types, sensitive JSON keys, non-POST HTTP,
arbitrary WebSocket paths, opaque/binary frames, nonempty control frames, and proxy-loop
markers fail closed. Responses are fully bounded before release, so split values cannot
escape at network chunk boundaries.

## Explicitly Unmediated Paths

During `bf run`, Blindfold does not mediate:

- reads of `.env`, workspace files, `~/.ssh`, `~/.aws`, `.netrc`, agent login stores, or
  any other file available to the current user;
- direct TCP, UDP, DNS, Unix-socket, IPC, or subprocess activity that ignores configured
  proxy variables;
- transformations or exfiltration performed by a process intentionally given plaintext;
- requests made outside the supported Blindfold command/SDK/proxy path; or
- memory inspection, swap, debuggers, a compromised OS/account, hardware, or side
  channels.

Trace records mark runner sessions degraded with `direct_filesystem_unmediated`. They
cannot observe what an agent read from disk or sent through an unmediated socket.

## Harness Adapter Threats

Harness adapters are declarative TOML data. Any future external adapter must be
explicitly installed by the user. Blindfold must never auto-load a project-local
manifest or load an adapter as an in-process dynamic library. A manifest may reference a
contained out-of-process entrypoint, but validation alone does not authorize execution
or grant capabilities. Core enforcement remains non-pluggable.

An adapter-backed launch must fail before starting the child when its manifest schema or
plugin protocol, harness compatibility version, noninteractive command grammar, or
required capability is unknown or incompatible. Repository content and agent output
cannot grant an adapter capability.

Future supported tool-result hooks could reduce one exposure path by routing bounded
results through the core sanitizer before the next model call. Hook payloads would be
untrusted, and a hook would not prove that every tool path was observed. The provider
proxy remains the final check for supported model traffic. A malicious tool can still
send data directly over TCP, UDP, DNS, Unix sockets, IPC, or another unmediated path;
preventing that requires OS-enforced containment.

Adapter control status:

| Threat | Control and status |
|---|---|
| Malicious project adapter/plugin manifest | explicit-directory-only host loading implemented; CLI installation/activation pending |
| Malformed manifest or escaping entrypoint | strict bounded TOML, symlink rejection, and canonical containment implemented |
| Unknown or incompatible harness | exact compatibility-version probe implemented for built-in runs; this does not authenticate the executable |
| Adapter requests unavailable control | exact built-in capability validation implemented; external execution pending |
| Hook bypass or unsupported tool-result shape | native hooks pending; provider proxy remains final model check |
| Tool sends data outside model path | OS network/process isolation not implemented |

## In-Scope Threats And Controls

| Threat | Implemented control |
|---|---|
| Raw value in accepted provider JSON | recursive string-value sanitization; sensitive keys reject the exchange |
| Raw value split across SSE chunks or WebSocket fragments | bounded full response collection or reassembled text-message parsing |
| Opaque transport bypass | narrow route/method/media grammar and fail-closed rejection |
| Raw value in managed child output | bounded concurrent capture and exact/detector redaction before printing |
| Inherited parent env secrets | child `env_clear` plus operational allowlist |
| Forged/replayed SafeRef | random syntax, authenticated vault, project/session scope, kind and expiry checks |
| Secret in trace/audit/error | closed schemas without payload/header/query fields and safe static errors |
| Remote proxy exposure | CLI listeners bind to ephemeral loopback addresses |
| Unsafe output overwrite | create-new default and explicit atomic `--force` replacement |
| Committed secret | diff scanning, Gitleaks CI, and isolated synthetic fixtures |

## Residual Risks

- Detector false negatives can pass an unknown or transformed value on a managed path.
- Detector false positives can alter or reject benign data.
- Provider authentication headers intentionally reach their named provider.
- Fully buffering accepted SSE improves split-boundary safety but increases latency and
  denial-of-service pressure within configured limits.
- Labels, timing, counts, SafeRef use, and safe structural locations reveal metadata.
- Encrypted vault records can remain in filesystem backups after local deletion.
- The caller-managed vault key and persistent agent credentials are not yet isolated by
  an OS credential broker.

## Security Invariants

1. Raw-value types do not expose plaintext through ordinary formatting or serialization.
2. Accepted managed payloads are sanitized or rejected before forwarding.
3. SafeRefs contain random opaque IDs and are non-authorizing by themselves.
4. Restoration requires scope, lifetime, operation, destination, and vault checks.
5. Unsupported security-sensitive input fails closed.
6. Managed listeners are loopback-only in current CLI use.
7. Audit, trace, error, and diagnostic schemas cannot contain arbitrary payloads.
8. Tests use synthetic fixtures and search all managed outputs/artifacts for raw values.
9. Startup and documentation identify filesystem and direct-network gaps explicitly.
10. Whole-agent containment is never claimed without OS-enforced workspace, process,
    credential, IPC, and network isolation.
11. Adapter manifests are non-authorizing data and cannot replace core enforcement.
12. No project-owned adapter or plugin is activated without explicit user install.

## Review Triggers

Update this model before adding a plaintext restoration destination, provider protocol,
remote listener, vault/key backend, automatic detector category, agent command family,
filesystem mediation, OS sandbox, telemetry, or supported platform.
Harness manifest schema changes, install/discovery behavior, hook capability changes,
or making any enforcement component pluggable are also mandatory review triggers.
