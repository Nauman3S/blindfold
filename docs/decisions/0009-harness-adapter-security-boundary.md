# ADR 0009: Declarative Harness Adapters

- Status: Accepted; manifest host and built-in version gates implemented
- Date: 2026-07-14

## Context

Blindfold currently recognizes a small set of coding-agent commands in the CLI. Keeping
every harness version, invocation grammar, and hook convention in the security core
would couple compatibility work to enforcement code. A conventional executable plugin
system would create the opposite problem: third-party code could run inside the trusted
process or replace controls that Blindfold relies on.

Repositories are untrusted input. Opening a project must never cause repository-owned
plugin code or configuration to become trusted.

## Decision

Blindfold harness adapters are compatibility packages. Their TOML manifest is data, not
executable code. A manifest may identify a built-in adapter or a contained
out-of-process entrypoint, supported harness/version ranges, required Blindfold
capabilities, noninteractive command grammar, provider-routing requirements, and
supported hook events. It cannot provide an in-process dynamic library, shell command,
detector, policy engine, resolver, sanitizer, proxy, or restoration implementation.

Core enforcement is non-pluggable. Detection, policy invariants, SafeRef authorization,
vault access, request/response sanitization, provider-proxy checks, trace schemas, and
fail-closed decisions remain compiled Blindfold behavior. An adapter can request a
capability; it cannot weaken, replace, or mark that capability successful.

Any future external entrypoint remains untrusted and out of process. The Blindfold host
owns spawning, environment construction, message limits, timeouts, capability checks,
and termination. Merely validating an installed entrypoint does not authorize executing
it or give it vault, arbitrary filesystem, network, or restoration access.

Installation and activation must be explicit user actions. Blindfold must not discover or auto-load
an adapter from the working tree, repository configuration, dependency directory, agent
output, or downloaded URL. In particular, a project-local manifest is untrusted data
and cannot activate an adapter. Upstream agent plugin modes remain outside protected
`bf run` invocations.

Before launch, core must validate the manifest schema and gate the adapter against:

- the manifest schema and plugin protocol version;
- the selected harness and pinned harness version;
- the exact noninteractive invocation family; and
- every required hook, provider-routing, output-capture, and transport capability.

An unknown, missing, ambiguous, or incompatible version/capability fails before the
child starts. Installed does not mean compatible or protected.

A future built-in adapter may route a bounded supported tool-result hook payload through
the core sanitizer before that result can be used in the next model call. Hook input
would be untrusted and unsupported shapes would fail closed. Hooks are defense in depth,
not the final model boundary: the provider proxy still parses and sanitizes every
supported model request and response before forwarding.

Neither hooks nor the provider proxy contain a tool that opens its own socket. Direct
tool network exfiltration, raw filesystem reads, IPC, and clients that bypass configured
proxies require OS-enforced process, filesystem, and network containment. Until those
controls exist, adapter-backed sessions remain managed model-traffic boundaries.

## Consequences

- Harness compatibility can evolve without making enforcement code extensible.
- A malicious repository cannot gain execution merely by declaring a plugin.
- Third-party manifests cannot add arbitrary commands or restoration destinations.
- Every adapter/version combination needs conformance tests with a fake provider and
  synthetic sensitive values before it can be reported as protected.
- A hook can reduce the time sensitive tool output remains visible to the harness, but
  the provider proxy remains the authoritative check before a model boundary crossing.
- Whole-agent secrecy remains a separate release gate requiring OS containment.

## Implementation Status

The strict TOML parser, finite harness-version requirements, explicit-directory loader,
manifest and entrypoint containment checks, bounded executable probing, and embedded
Claude/Codex/OpenCode manifests are implemented. Built-in runs fail before proxy startup
when a compatibility marker or pinned version check fails. This probe does not
authenticate or contain the selected executable.

External adapter execution, an installation CLI, and native pre/post-tool hook injection
remain unimplemented. Current manifests do not declare tool-request or tool-result
events. ADR 0008 remains authoritative for the supported noninteractive command surface.
