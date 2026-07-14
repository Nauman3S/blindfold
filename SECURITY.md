# Security Policy

## Supported Versions

Blindfold has not published a production release. The `main` branch is under active
development and must not be relied on to protect real credentials.

After `v0.1.0`, security fixes will be provided for the latest released minor version.
Older pre-1.0 minors may receive fixes when a safe backport is practical, but are not
covered by a standing support commitment.

## Reporting a Vulnerability

Use GitHub's **Report a vulnerability** private reporting form for this repository. Do
not open a public issue, discussion, or pull request for an undisclosed vulnerability.
If private vulnerability reporting is unavailable, open a public issue containing only
a request for a private contact channel and no technical details.

Include:

- the affected version or commit;
- the managed path and platform involved;
- impact and prerequisites;
- minimal reproduction steps using fake values;
- whether raw values reached LLM traffic, output, logs, audit, storage, or another
  destination; and
- any suggested mitigation.

Never include a live credential, production dataset, customer PII, or an exploit against
a system you do not own.

## Response Targets

Maintainers aim to:

- acknowledge a report within 3 business days;
- provide an initial severity and next-step assessment within 7 business days; and
- coordinate a fix and disclosure date based on impact and exploitability.

These are response targets, not guaranteed service levels. Reporters will be informed if
investigation needs more time.

## Safe Research

Test only with accounts, hosts, repositories, and data you own or are explicitly
authorized to assess. Use isolated local services and fixtures clearly marked as fake.
Avoid denial of service, persistence, social engineering, privacy violations, and access
to other users' data.

The project's committed examples under `tests/fixtures/` are inert test material. They
must never be accepted by a real provider and must not be replaced with live values.

## Scope Notes

Security reports are especially useful for:

- a raw value crossing a path Blindfold reports as protected;
- secret material appearing in managed logs, errors, audit, or diagnostics;
- unauthorized SafeRef restoration;
- policy fail-open behavior;
- proxy exposure beyond the configured listener;
- vault key or plaintext storage defects; and
- bypasses that contradict [THREAT_MODEL.md](THREAT_MODEL.md).

For the harness-adapter architecture, reports are also in scope when a project
can auto-activate an adapter, a manifest causes arbitrary code execution, incompatible
versions or missing capabilities fail open, or an adapter can replace or disable a
core security control. Adapter TOML is untrusted data, and any future installation must
require an explicit user action. No external installation or activation command exists
today.

Once native harness hooks are supported, failure to sanitize a managed tool result
before its next model call is relevant. Direct network exfiltration by a tool remains
outside native `bf run`. In locked `bf container run`, an ordinary tool gaining direct
IP egress or the gateway credential contradicts the documented boundary and is in
scope. Neither mode promises detection of transformed or semantic sensitive values.

Behavior explicitly identified as outside the managed boundary may still be worth
reporting when the product or documentation makes that limitation unclear.
