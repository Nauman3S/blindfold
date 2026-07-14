# Python SDK Threat Model

The SDK prevents caller-registered strings from accidentally crossing either direction
of a supported wrapped model client or callable transport. It masks request arguments
and supported response shapes with unpredictable, session-local SafeRefs, permits PII
restoration only for an explicit `end_user` destination, never restores secrets to
ordinary output, and rejects unknown or malformed SafeRefs during restoration.

The SDK does not scan files or environment variables, intercept arbitrary I/O, encrypt
process memory, authenticate callers, isolate provider credentials, or enforce process,
filesystem, and network policy. It cannot protect values that were not registered or
requests that bypass the wrapper. Opaque streaming, binary, cyclic, or unsupported
payload shapes fail closed rather than being returned uninspected. Code in the same
process can inspect application memory, the original environment, or invoke the
underlying client directly.
