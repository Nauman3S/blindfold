# ADR 0003: Versioned Opaque SafeRefs

- Status: Accepted
- Date: 2026-06-11

## Context

Agents need stable references to values they cannot see. References must not disclose a
raw prefix, suffix, hash, account identifier, or user-provided label that may itself be
sensitive. User text may also resemble a reference.

## Decision

Use this agent-visible envelope:

```text
{{BLINDFOLD:v1:<kind>:<opaque-id>}}
```

`kind` is a closed non-sensitive category. `opaque-id` is random or keyed and contains
no plaintext or secret-derived substring. It is bound in the vault to project, session,
policy metadata, expiry, and the encrypted value.

Parsing is strict and length-bounded. Unknown versions, kinds, malformed values, forged
references, expired references, and cross-scope replay do not restore. User-authored text
that matches the shape remains inert unless a valid scoped mapping and authorized
destination exist.

Human-friendly labels may be displayed separately only after sensitivity review; they
are not part of the security identity.

## Consequences

The envelope is recognizable and versionable without exposing the secret. It is not an
authorization token by itself. The vault and policy engine remain necessary for every
restoration.
