# Locked Container Image

This image is the common runtime used by the trusted Blindfold gateway and the
network-disabled agent container. It pins the supported harness package versions:

- Claude Code `2.1.202`
- Codex CLI `0.144.4`
- OpenCode `1.18.0`

Build a local evaluation image:

```sh
docker build -f containers/Dockerfile.locked -t blindfold-locked:local .
```

`blindfold-locked:local` is accepted only as an explicitly marked development image.
The launcher resolves it to one image ID before starting either session container.
A release run must select an immutable registry reference containing
`@sha256:<64 lowercase hex characters>`. Tags are not a release trust anchor.

Do not run this image manually and assume it is locked. The enforced topology requires
the `bf container run` launcher: the agent receives Docker's `none` network, the
gateway alone receives network access and the provider credential, and the two share
only a per-session filesystem Unix socket.

Read the [Locked Container Boundary](../docs/container-boundary.md) before evaluating
the image. Static launcher tests and the recorded manual Docker Desktop check do not
replace the per-platform live release evidence described in
[Development](../docs/development.md).
