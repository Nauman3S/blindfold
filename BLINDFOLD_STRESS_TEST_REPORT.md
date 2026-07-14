# Blindfold Adversarial Verification Report

Date: 2026-07-14

This report supersedes the earlier June stress-test snapshot. It separates the native
managed boundary, the locked-container preview, and release evidence that is still
missing. Current scope and limitations are defined by `README.md`, `THREAT_MODEL.md`,
and `docs/guarantees.md`.

## Evaluated Boundaries

The managed application and native-runner tests cover:

- scanning, redaction, blocking, surrogates, and encrypted vault-backed masking;
- explicit-secret child execution and one-call bearer brokering;
- JSON provider proxying, bounded Anthropic and OpenAI-compatible response SSE, and
  bounded OpenAI Responses WebSockets;
- native Claude print, Codex exec/review, and OpenCode run commands;
- strict TOML adapter manifests, explicit-directory plugin validation, and exact
  built-in harness version probes;
- payload-free audit and tracing, MCP stdio transformation, and the Python and
  TypeScript application SDKs.

Native `bf run` is a managed model-traffic boundary. It has no OS filesystem or network
containment. An agent can read the real workspace and home paths available to the user,
and a process that ignores proxy variables can open a direct socket.

The separate `bf container run` preview is implemented with a Docker `network=none`
agent and a networked, credential-owning Blindfold gateway. Static tests verify the
constructed Docker argv, fixed agent/provider pairs, digest policy, credential input
validation, gateway/agent mount separation, and exact session cleanup. The repository
does not yet contain an automated live-Docker end-to-end topology test. A manual Docker
Desktop test on macOS/ARM64 is recorded below, but the locked mode remains a preview
pending repeatable cross-platform release evidence.

Interactive/TUI agent modes, runner bypass switches, arbitrary protocols, external
adapter execution, native tool hooks, staged/sanitized filesystem mediation, scanned
patch export, broad semantic PII detection, and Windows support are outside the tested
boundary.

## Verification Commands

The implementation worktree is checked with:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo doc --workspace --no-deps
npm --prefix sdk/typescript test
PYTHONPATH=sdk/python/src python3 -m unittest discover -s sdk/python/tests -v
uv build sdk/python
./scripts/manual_guard_smoke.sh
```

The Rust, SDK, package-build, and fake-agent/provider checks have passed in this
implementation worktree. Test counts are intentionally omitted because they change as
the preview evolves. These commands do not start a Docker Engine by themselves.

The manual 2026-07-14 Docker Desktop 4.78.0 / Engine 29.5.3 check built image ID
`sha256:4fdb378eef0ac4e9025ea4fc25a52fc1a1e95a4090691e8b438e85add27c87db`
and inspected a live locked Codex session using a synthetic invalid provider key. The
agent reported `network=none`, `ipc=none`, a read-only root, all capabilities dropped,
`no-new-privileges`, no Docker logs, only workspace plus read-only socket mounts, and no
provider credential in its mounts or environment. The gateway had the bridge network,
socket plus read-only credential mounts, and no workspace mount. `/proc/net/route` had
no IPv4 entries; `/proc/net/ipv6_route` named only `lo`; a public-IP TCP connection
failed with `ENETUNREACH`; DNS failed with `EAI_AGAIN`. The request reached the gateway,
failed closed at the real upstream as expected for the fake key, and cleanup left no
labeled container or volume. Controlled fake-provider sanitization remains covered by
the proxy integration suite rather than this live run.

The same image ran the exact Claude Code `2.1.202`, Codex CLI `0.144.4`, and OpenCode
`1.18.0` probes. Claude returned the real provider's invalid-key failure through the
gateway. Codex exercised its Responses WebSocket and HTTP fallback and failed closed on
the synthetic credential. OpenCode reached its gateway path; its long invalid-key retry
was interrupted. That interruption exposed and led to a fix for graceful Ctrl-C cleanup,
which was then verified against the rebuilt image during both startup and an active
agent run: the launcher returned status 130 and left no `io.blindfold.session`
container, volume, or temporary credential directory.

Before release, the locked preview additionally needs a local-Docker test that inspects
the running namespaces and mounts, proves the provider credential is unavailable to the
agent, proves the workspace is unavailable to the gateway, sends sanitized traffic to a
controlled fake provider, and verifies cleanup. The test must use synthetic credentials
and data.

## Adversarial Cases Covered

- raw fixture values in provider requests and responses;
- unknown JSON value fields and sensitive JSON object keys;
- malformed, opaque, unsupported, and oversized content;
- Anthropic and OpenAI-compatible SSE split across upstream network chunks;
- fragmented OpenAI Responses WebSocket messages in both directions;
- opaque/binary WebSocket messages, nonempty control frames, arbitrary paths, query
  strings, unsupported upgrades, and proxy-loop markers;
- sensitive URL path/query/header metadata and untrusted upstream headers;
- inherited parent environment secrets and sanitized bounded process output;
- duplicate masked values and PII/private-key SafeRef classification;
- missing vault keys, symlinked storage, output overwrite, expired/cross-scope/forged
  references, and payload-free audit/trace artifacts;
- SDK overlapping values, unknown/malformed SafeRefs, recursive request/response
  shapes, binary/streaming/cyclic values, async responses, and destination-limited
  restoration;
- interactive Claude, Codex, and OpenCode commands rejected before harness launch;
- missing, ambiguous, marker-mismatched, and incompatible harness versions rejected
  before native proxy or harness startup;
- project-directory plugin discovery, symlinked manifests, escaping entrypoints, unsafe
  executable search paths, oversized probe output, and timed-out probes rejected;
- removed runner flags, bypass environment behavior, and shell wrapper commands;
- locked-run missing credentials, invalid provider selection, mutable release image
  references, credential symlinks or workspace hard-link exposure, and unsafe boundary
  configuration rejected; and
- locked Docker argv requiring `network=none` for the agent, no credential mount in the
  agent, no workspace mount in the gateway, resource restrictions, and exact resource
  cleanup commands.

## Current Security Conclusions

Within a supported managed path, malformed or opaque input fails closed. Detected or
application-registered synthetic values did not appear in fake upstream payloads,
managed process output, diagnostics, audit, traces, or serialized vault artifacts in
the recorded tests.

That result is not a claim of complete PII or secret detection. Automatic PII detection
currently covers RFC-valid email addresses and valid `+`-prefixed international phone
numbers. Names, postal addresses, national identifiers, account numbers, and other
semantic PII are not automatically detected. Encoded, encrypted, split, transformed,
or semantically reconstructed values can evade detection.

Supported SSE remains because the accepted noninteractive clients require it. Requests
using SSE are rejected; response SSE is restricted to bounded Anthropic messages and
OpenAI-compatible chat-completions. Accepted SSE is fully buffered, and WebSocket
fragments are reassembled before sanitization.

## Locked Boundary Claim

Subject to a trusted and patched host and local Docker Engine, the selected immutable
image, the emitted Docker controls, and no container/runtime escape, a successful locked
run gives the agent process tree no non-loopback network route. Its only
cross-container path is the per-session Unix socket to Blindfold's gateway. Ordinary
agent and tool processes cannot establish direct IP egress, and supported model traffic
can leave only after the gateway accepts and sanitizes it.

This is an egress-path guarantee, not proof that no sensitive fact can leave. The agent
still receives a read/write bind mount of the raw current workspace. It may read a raw
value and transform or describe it in a way the detector does not recognize inside an
otherwise valid model request. Container escapes, host/runtime/image compromise, side
channels, and detector false negatives remain outside the guarantee.

## Remaining Release Evidence

- live locked-topology and fake-provider tests on the claimed macOS and Linux hosts;
- installed Claude, Codex, and OpenCode compatibility runs for every pinned version;
- OS keychain or Secret Service handling for the vault key;
- fuzz/property coverage for framing, SafeRefs, masking spans, and malformed config;
- signed release artifacts, checksums, SBOM, audit/deny gates, and installation tests;
- staged sanitized workspace and scanned patch export for any future claim that the
  agent cannot obtain a raw project secret; and
- external adapter execution and native tool hooks, if they enter release scope.

No document or startup message should describe native `bf run` as whole-agent
containment, describe locked mode as perfect secret prevention, or imply complete PII
detection.
