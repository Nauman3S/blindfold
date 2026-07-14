# Blindfold Plugin API

`blindfold-plugin-api` defines the strict, bounded TOML manifest contract used by
Blindfold harness adapters. It parses bytes already supplied by a caller and validates
the closed schema, identifiers, relative entrypoint, finite harness version range,
capabilities, and permission combinations.

This crate does not discover files, install or activate plugins, resolve entrypoints,
probe harness versions, or execute plugin code. Unknown fields and values are rejected,
and parse errors do not include attacker-controlled manifest contents.

The fixed filename for a directory-based manifest is `blindfold-plugin.toml`. Filesystem
containment and executable checks belong to `blindfold-plugin-host`; runtime capability
enforcement remains the responsibility of the Blindfold host using the parsed data.

`builtin-v1` identifies core-owned embedded adapters and has no external execution path.
`stdio-json-v1` is a reserved manifest value for a future external protocol; parsing a
manifest that declares it does not enable or execute that protocol.
