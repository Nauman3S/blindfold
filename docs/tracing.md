# Request Tracing

Blindfold tracing explains managed proxy behavior without creating a payload log.
It is disabled unless `--trace` is supplied to `blindfold run` or `bf run`.

```sh
bf run claude --trace
bf trace list
bf trace show req_...
bf trace tail
bf trace export req_... --redacted
bf trace clear --yes
```

## Retained Metadata

Each version 1 record contains:

- an operation-local request ID;
- provider route;
- protected, degraded, or unprotected coverage;
- succeeded, rejected, failed, or timed-out outcome;
- request and response byte counts before and after sanitization;
- operation-local replacement IDs such as `S1`;
- closed detector categories;
- sanitized JSON pointers; arbitrary object keys become `*`;
- replacement occurrence counts; and
- a closed issue code when coverage is not protected.

## Never Retained

Trace records cannot represent:

- original or sanitized request/response payloads;
- authorization or unknown headers;
- query strings;
- detected byte spans or secret-derived fingerprints;
- arbitrary error messages; or
- raw debugging data.

There is no `--raw` mode.

## Storage

Records use `.blindfold/trace.jsonl`, independently from
`.blindfold/audit.jsonl`. The store:

- requires an owner-only existing `.blindfold` directory on Unix;
- creates files with owner-only permissions;
- rejects symlinked active, lock, and rotation paths;
- validates every line against a closed versioned schema;
- rotates at 1 MiB and retains three prior files; and
- requires `trace clear --yes` for deletion.

`trace tail` currently displays the most recent retained record; it does not continuously
follow the file.

## Coverage Meaning

- `protected`: supported content was inspected in both directions.
- `degraded`: some protected processing occurred, but the exchange ended with a visible
  limit, format, or upstream issue.
- `unprotected`: Blindfold rejected the exchange before establishing inspected traffic.

Tracing describes only requests that reach the managed local proxy. Direct filesystem or
network bypasses remain outside this trace boundary.
