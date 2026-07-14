# TypeScript SDK Threat Model

The preview protects against accidentally placing caller-identified secrets or PII in
an LLM request. It permits PII restoration only for an explicit `end_user` destination
and never restores secrets.

Unlike the Python SDK, this preview does not wrap client request and response objects.
Callers must pass every outbound string through `toLLM` and every model result requiring
PII restoration through `fromLLM`.

It does not detect values automatically, encrypt mappings, persist mappings, isolate
memory, authenticate callers, or protect a compromised application process. Applications
must not log original values, bypass the explicit calls, or expose the
`BlindfoldBoundary` instance to untrusted code.
