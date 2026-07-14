# Blindfold Rollout Plan

> Let agents use secrets without sending them to an LLM.

## Release Scope

`v0.1.0` is a managed-boundary release, not a whole-agent sandbox.

Included:

- bounded file and directory scanning;
- irreversible redaction, blocking, schema, environment-reference, surrogate, and
  vault-backed masking operations;
- encrypted, scoped, expiring SafeRef storage;
- explicit-secret command execution and one-call HTTP brokering;
- fail-closed OpenAI/Anthropic provider proxying;
- noninteractive Claude, Codex, and OpenCode runners;
- diff scanning, policy, audit, payload-free tracing, and MCP stdio transformation;
- dependency-free Python and TypeScript application SDKs.
- strict TOML harness-adapter manifests, explicit-directory plugin validation, and
  fail-closed exact built-in harness version gates.

Excluded:

- interactive/TUI agent sessions;
- shell wrappers and Blindfold bypass switches;
- arbitrary HTTP methods, media types, streaming protocols, and agent server modes;
- transparent TLS interception;
- OS-enforced filesystem, process-tree, and direct-network containment;
- brokered provider-login credentials and OS keychain-backed vault keys;
- perfect detection of unknown or transformed sensitive values.
- external adapter installation/execution and native agent tool-call hooks.

## Command Contract

```sh
bf scan .
bf redact .env
bf mask .env
bf exec --secret NAME -- command args...
bf call --secret NAME --url https://approved.example/path

bf run claude -- --print "prompt"
bf run codex -- exec "prompt"
bf run codex -- review
bf run opencode -- run "prompt"
```

`bf run` has one behavior: establish the managed model boundary or fail. There is no
guard/degraded/bypass mode selector. A native agent command remains outside Blindfold.

## Protection Contracts

| Surface | Protected | Explicit limitation |
|---|---|---|
| `scan` | bounded known-pattern detection without printing values | incomplete scans return a distinct failure code |
| `redact` | detected values transformed before output | irreversible modes cannot be restored |
| `mask` | detected values stored locally and replaced by opaque SafeRefs | requires the caller-managed vault key |
| `exec` | selected env values injected and exact values removed from captured output | child receives plaintext and is trusted for that grant |
| `call` | bearer value inserted only for an allowed destination | only the narrow supported request grammar is accepted |
| provider proxy | accepted JSON/string fields sanitized in both directions | unsupported methods/media/transports fail closed |
| agent runner | provider traffic, parent env, proxy-aware destinations, stdout/stderr | local file reads and clients ignoring proxy settings remain unmediated |
| harness adapter | embedded schema, capability contract, resolved command, and pinned version | version output is not executable authentication; external execution and tool-call hooks are not implemented |
| Python SDK | registered values protected through wrapped calls and responses | same-process code and unwrapped I/O can bypass it |

## Supported Provider Protocols

- OpenAI and Anthropic JSON POST bodies.
- Anthropic `text/event-stream` responses only, bounded and sanitized before release.
- OpenAI Responses WebSocket only, using JSON-object text messages.
- Empty WebSocket ping/pong control messages.

SSE requests, OpenAI SSE, arbitrary WebSocket paths, binary/opaque frames, non-POST HTTP
operations, malformed structured payloads, and unsupported non-empty media types are
rejected.

## Security Invariants

1. Raw-value types do not expose plaintext through normal formatting or serialization.
2. SafeRefs are random, opaque, scoped, expiring, and non-authorizing by themselves.
3. Restoration requires an independently authorized operation and destination.
4. Secrets are never restored into ordinary model, log, or user output.
5. Unsupported security-sensitive input fails before forwarding.
6. Managed listeners bind to loopback.
7. Child processes inherit only an explicit operational environment.
8. Audit and trace records use closed, payload-free schemas.
9. Fake fixture values are searched across stdout, stderr, logs, traces, vault artifacts,
   proxy captures, and generated outputs in regression tests.
10. Documentation distinguishes the managed model boundary from whole-agent containment.

## Completed For This Rollout

- [x] Remove interactive/TUI agent paths.
- [x] Remove `--no-proxy`, `BLINDFOLD_BYPASS`, selectable `--guard`, preview `--strict`,
  and generated shell wrappers.
- [x] Make proxy-aware egress control mandatory for every supported agent run.
- [x] Capture and sanitize output for every supported agent command.
- [x] Restrict Claude to print mode, Codex to exec/review, and OpenCode to run.
- [x] Restrict HTTP and streaming protocol grammars and add negative tests.
- [x] Add a Python SDK with mask/redact/block modes and client/transport wrappers.
- [x] Add vault-backed CLI masking.
- [x] Keep startup and trace coverage honest about unmediated local file reads.
- [x] Add strict adapter manifests and reject missing, ambiguous, or incompatible
  pinned Claude, Codex, and OpenCode versions before proxy or agent startup.

## Remaining Before `v0.1.0`

- [ ] Add OS keychain/Secret Service retrieval for the vault key.
- [ ] Publish installed-agent and fake-upstream compatibility evidence for every allowed
  version range in release CI.
- [ ] Add packaging, signed release artifacts, SBOM, `cargo audit`, and `cargo deny` gates.
- [ ] Run installed Claude, Codex, and OpenCode smoke tests against controlled fake
  upstreams on macOS and Linux.
- [ ] Add property/fuzz coverage for proxy framing, SafeRef parsing, masking spans, and
  malformed configuration.
- [ ] Complete an external security review of the release threat model and managed
  protocol implementations.

## Whole-Agent Containment Track

The stronger statement, “the agent cannot obtain a registered raw secret,” requires a
separate containment release. Its minimum design is:

1. a disposable sanitized workspace rather than the raw repository;
2. an isolated home directory and allowlisted environment;
3. OS-enforced filesystem, PID/IPC, inherited-descriptor, Unix-socket, and network
   restrictions inherited by every subprocess;
4. a long-lived local broker that alone can resolve SafeRefs for an exact operation,
   destination, field, and TTL;
5. provider authentication owned by Blindfold rather than readable agent files; and
6. a verified patch/diff path for applying sanitized workspace changes.

Protected startup must fail when any required containment primitive, transport, or scan
is unavailable. Until that track is implemented and independently verified, `bf run`
must never claim whole-agent containment.

## Release Verification

Every merge and release candidate must pass:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
npm test --prefix sdk/typescript
PYTHONPATH=sdk/python/src python3 -m unittest discover -s sdk/python/tests -v
```

Release fixtures must also prove that registered fake values are absent from managed
provider captures, user-visible process output, trace/audit records, and serialized
vault artifacts. A missing control or unsupported protocol is a blocked run, never a
silent downgrade.
