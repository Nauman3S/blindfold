# SDK Preview Threat Model

The preview protects against accidentally placing caller-identified secrets or PII in
an LLM request. It permits PII restoration only for an explicit `end_user` destination
and never restores secrets.

It does not detect values automatically, encrypt mappings, persist mappings, isolate
memory, authenticate callers, or protect a compromised application process. Applications
must not log the original values or expose the `BlindfoldBoundary` instance to untrusted
code.
