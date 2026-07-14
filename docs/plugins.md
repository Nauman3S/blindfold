# Plugin Manifests and Validation

Blindfold has three embedded harness-adapter manifests for the supported noninteractive
Claude, Codex, and OpenCode commands. List their declared compatibility metadata without
locating or starting the harness binaries:

```sh
blindfold plugin list
```

Example output:

```text
dev.blindfold.claude-code plugin=0.1.0 protocol=builtin-v1 command=claude harness="=2.1.202" modes=print
dev.blindfold.codex-cli plugin=0.1.0 protocol=builtin-v1 command=codex harness="=0.144.4" modes=exec,review
dev.blindfold.opencode plugin=0.1.0 protocol=builtin-v1 command=opencode harness="=1.18.0" modes=run
```

`plugin list` strictly parses the embedded manifests. It does not probe installed
harness commands. The separate `blindfold run` startup path resolves the selected
harness and checks its pinned version before starting the managed provider boundary.

## Validate Explicit Directories

Validate one or more directory-based manifests by supplying every absolute directory:

```sh
blindfold plugin validate "$PWD/path/to/example-adapter"
blindfold plugin validate /opt/blindfold/adapter-a /opt/blindfold/adapter-b
```

Each directory must contain the fixed `blindfold-plugin.toml` filename and the declared
executable entrypoint. Blindfold strictly parses bounded UTF-8 TOML, rejects unknown
fields, symlinked manifests, duplicate directories or IDs, and entrypoints that are not
executable files contained by their directory.

A successful result prints validated manifest metadata followed by an explicit boundary
statement:

```text
dev.example.adapter plugin=1.0.0 protocol=stdio-json-v1 command=example-agent harness=">=1.2.0, <2.0.0" modes=exec
Validated 1 explicit plugin directory; no plugin was installed, activated, or executed.
```

Validation is structural only. It does not:

- search the project, home directory, registry, or network for plugins;
- install, activate, spawn, or execute an external adapter entrypoint;
- probe the manifest's harness command or establish runtime compatibility;
- grant the declared permissions or enable the reserved `stdio-json-v1` protocol; or
- add native pre-tool or post-tool hooks to a coding-agent session.

Project files remain untrusted and are never auto-loaded as adapter manifests. Current
`blindfold run` commands use only the closed embedded `builtin-v1` adapters. The managed
provider proxy remains the enforcement boundary for supported model traffic, and plugin
validation does not provide filesystem mediation, network containment, or whole-agent
protection. `bf container run` supplies a separate non-pluggable OS egress boundary;
adapter metadata and future hooks cannot weaken or replace it.
