# Blindfold Plugin Host

`blindfold-plugin-host` contains the host-owned preparation boundary for constrained
agent plugins. It deliberately does not load plugins from the current project or search
for manifests. The caller supplies exact installed plugin directories.

The host also resolves agent executables and probes their versions with null stdin, bounded
stdout/stderr, a wall-clock timeout, a fresh temporary working directory, and an otherwise
empty environment containing only a validated explicit `PATH`. This supports
`/usr/bin/env node` launchers without passing `HOME` or arbitrary parent variables. Probe
output is never returned or included in errors.
A probe succeeds only when one unambiguous semantic version is present and satisfies the
caller's `semver::VersionReq`. Claude/Codex manifests can require an identity marker;
markerless output is supported for OpenCode, whose installed CLI can print only `1.17.3`.

Plugin manifest parsing and capability policy belong to `blindfold-plugin-api`; this crate
loads only that API's fixed `blindfold-plugin.toml` filename from explicitly supplied
installation directories. Reads are bounded, manifest symlinks and duplicate IDs are
rejected, and canonical executable entrypoints must remain within their installation.
Returned entrypoints are validated metadata only. This crate does not install, activate,
spawn, or execute external adapter entrypoints.

Calling the separate version-probe API executes the selected harness binary. The probe
provides bounded compatibility evidence; it does not authenticate that binary or provide
filesystem and network containment.
