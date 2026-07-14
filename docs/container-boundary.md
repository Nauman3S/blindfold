# Locked Container Boundary

## User Contract

The locked preview keeps the agent CLI arguments unchanged:

```sh
bf container run claude -- --print "review these changes"
bf container run codex -- exec "fix the tests"
bf container run opencode --provider openrouter -- run "inspect this project"
```

The standard host variables are `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and
`OPENROUTER_API_KEY`. `--credential-env NAME` selects another host variable and
`--credential-file PATH` selects a regular, non-symlink file. No real provider
credential is put in the agent environment, home, arguments, image, or workspace.

Build the explicit local evaluation image with:

```sh
docker build -f containers/Dockerfile.locked -t blindfold-locked:local .
```

The launcher resolves that local tag to its current immutable image ID before creating
either container, so the gateway and agent use the same build for the session. The
local build is still a development trust decision, not a published release artifact.

Release use must pass an immutable image reference:

```sh
bf container run codex \
  --image registry.example/blindfold@sha256:<64-lowercase-hex> \
  -- exec "summarize this repo"
```

## Enforced Topology

```text
agent container                                  gateway container
network=none                                     Docker bridge egress
no non-loopback route                            real provider credential
127.0.0.1 Blindfold relay                        Blindfold provider proxy
        |                                                |
        +---- per-session filesystem Unix socket --------+
                                                         |
                                               fixed provider origin
```

The agent container has `--network none`, all Linux capabilities dropped,
`no-new-privileges`, a read-only root filesystem, no Docker socket, no host home, no
SSH agent, no host device mounts, no published ports, bounded processes/memory/CPU, and
Docker log storage disabled. It mounts only the canonical current workspace and the
socket volume. Startup checks that the Linux namespace has no non-loopback IPv4 or IPv6
route. This route check tolerates inert tunnel-device names exposed by some Docker
Desktop kernels.

The gateway has no workspace mount. It mounts the provider credential read-only and the
socket volume read/write. The gateway strips `authorization`, `x-api-key`, and
`api-key` supplied by the agent, injects its own provider-specific value, disables
redirects and environment proxies, strips client compression negotiation so upstream
bodies remain inspectable, and accepts only the proxy's bounded route, method, media,
JSON, SSE, and WebSocket grammars. One session selects one fixed provider origin.
Credentialed HTTP queries are rejected except Claude's exact `beta=true` messages query.

The design uses Docker's `none` driver because Docker specifies that it creates only
the loopback device. A bridge marked `internal` was rejected for this tier because it
is a larger and less direct boundary. See Docker's
[none network driver](https://docs.docker.com/engine/network/drivers/none/) and
[container run reference](https://docs.docker.com/reference/cli/docker/container/run/).
The filesystem socket is shared through a session-scoped
[Docker named volume](https://docs.docker.com/engine/storage/volumes/); no TCP network
joins the containers.

## Exact Guarantee

The defensible claim is:

> Given the selected immutable image, a trusted and patched host and Docker Engine, the
> emitted Docker arguments, and no container/runtime escape, the agent process tree has
> no non-loopback IP route. Its only cross-container path is the per-session
> Unix socket to Blindfold. Ordinary agent and tool processes cannot establish direct
> IP egress; supported model traffic can leave only after Blindfold accepts and
> sanitizes it.

The launcher fails before the agent starts when Docker is unavailable, the context is
remote, the image is not digest-pinned (except the named local development image), the
credential is unsafe, the workspace exposes special IPC/device files, the provider
selection is unsupported, or a session resource cannot be established.
On Ctrl-C, the launcher stops the foreground agent, removes the exact gateway and socket
volume, and exits with status 130. A host crash or uncatchable termination can still
leave resources for manual cleanup.

## Verification Status

The implementation has unit and CLI regression tests for the exact Docker arguments,
agent/gateway mount separation, fixed provider origins, input rejection, and exact
session cleanup. On 2026-07-14 a manual Docker Desktop test on macOS/ARM64 inspected the
running containers and confirmed `network=none`, no IPv4 route, loopback-only IPv6
routes, `ENETUNREACH` for a direct public-IP connection, DNS failure, gateway-only
credential mounting, agent-only workspace mounting, the intended gateway path, and
exact cleanup. The synthetic invalid provider key reached the gateway and failed closed
at the upstream; proxy integration tests separately exercise sanitized request and
response traffic against controlled local providers.

The ordinary automated suite still does not start Docker, and this manual result is not
a cross-platform release matrix. Until live topology checks are automated and pass on
each claimed host platform, this mode remains preview.

See [Development](development.md) for the required live checks and the
[Adversarial Verification Report](../BLINDFOLD_STRESS_TEST_REPORT.md) for the current
evidence boundary.

## What This Does Not Guarantee

This is egress-path enforcement, not proof that no sensitive fact can ever leave.
Detector false negatives remain possible. An agent that can read a raw value can encode,
split, compress, encrypt, or describe it semantically inside an otherwise valid model
request. Side channels, malicious or compromised Docker/runtime components, image
supply-chain compromise, kernel/container escapes, host compromise, and values outside
the implemented detectors are not solved here.

The locked agent path currently replaces detected values with one-way placeholders.
The Python and TypeScript SDKs instead provide session-local SafeRef masking and
destination-scoped PII restoration to `end_user`; neither SDK restores secrets. That
registered-value restoration model is not yet implemented by the container gateway.

The current workspace is a direct read/write bind mount. It does not expose the host
home or parent directory, and the launcher rejects sockets, FIFOs, device nodes, and
nested mount devices before launch. A future stronger filesystem tier will stage a
sanitized workspace and export only a scanned patch.

Generic web, package-manager, Git, SSH, MCP-network, and arbitrary CONNECT access is
deliberately unavailable. Adding any opaque egress channel would invalidate the
model-only guarantee. Interactive/TUI, resume, server, remote-control, agent-plugin,
search, and permission-bypass modes remain unsupported.

## Docker Sandboxes Research

Docker's current `sbx` product is a useful future outer isolation layer: it runs agents
in microVMs, blocks raw TCP/UDP/ICMP and private/host access by default, and performs
host-side credential injection. Its credential model independently validates the same
sentinel/injection approach used here. See the official
[security defaults](https://docs.docker.com/ai/sandboxes/security/defaults/),
[credential isolation](https://docs.docker.com/ai/sandboxes/security/credentials/), and
[Docker Sandboxes overview](https://docs.docker.com/ai/sandboxes/).

Blindfold does not currently depend on `sbx`. Its balanced policy deliberately permits
package and code-host domains, and its workspace remains agent-readable, so it does not
replace Blindfold's payload sanitizer or the model-only socket topology. The current
`v0.35.0` release also has no Linux/ARM64 build according to the
[official GitHub release](https://github.com/docker/sbx-releases/releases/tag/v0.35.0).
Version `0.33.0` closed DNS-policy and ICMP-restart exfiltration gaps, which is evidence
that an `sbx` integration must use an exact tested minimum/current version rather than
an open-ended compatibility claim.
