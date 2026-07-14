# Blindfold Use Cases

## Command Summary

| Task | Command |
|---|---|
| Scan a repository | `bf scan .` |
| Redact detected values | `bf redact .env` |
| Replace values with vault-backed SafeRefs | `bf mask .env` |
| Run a command with selected env values | `bf exec --secret NAME -- command` |
| Make an authorized bearer call | `bf call --secret NAME --url https://host/path` |
| Run Claude noninteractively | `bf run claude -- --print "prompt"` |
| Run Codex noninteractively | `bf run codex -- exec "prompt"` |
| Run a Codex review | `bf run codex -- review` |
| Run OpenCode noninteractively | `bf run opencode -- run "prompt"` |

Interactive/TUI sessions are not part of the Blindfold runner. Run native agent commands
directly when Blindfold is not intended to manage that invocation.

## Scan Before Sharing

```sh
bf scan .
bf scan config.json --json
```

Exit code `2` means findings were detected. Exit code `3` means the scan was incomplete
because a read, file-size, or traversal limit prevented complete inspection.

## Redact Or Block Content

```sh
bf redact .env
bf redact config.json --mode schema-only
bf redact config.json --mode placeholder
bf redact config.json --mode surrogate
bf redact config.json --mode block
bf redact .env --mode env-ref
```

`placeholder`, `schema-only`, and `env-ref` are irreversible transformations. A
surrogate is stable only within one operation. `block` emits no transformed payload when
a finding exists.

Write to a different file:

```sh
bf redact .env --output env.redacted
```

Existing output is not replaced unless `--force` is explicit.

## Mask With SafeRefs

Masking keeps a local encrypted mapping and emits only opaque references:

```sh
export BLINDFOLD_MASTER_KEY="$(openssl rand -hex 32)"
bf mask .env --ttl-seconds 3600
bf mask config.json --output config.masked.json
```

Within one invocation, equal values receive the same SafeRef. Email and phone findings
receive PII references, private keys receive private-key references, and other findings
receive secret references. The key must be supplied again to reopen the vault; do not
place it in the project.

## Give One Command A Secret

```sh
export DEMO_API_KEY='sk-proj-fake-blindfold-example-1234567890'
bf exec --secret DEMO_API_KEY -- sh -c 'test -n "$DEMO_API_KEY"; echo ready'
```

The child receives the selected plaintext value and is trusted for that grant. Blindfold
uses a minimal environment, rejects the secret in command arguments, captures output,
and removes exact injected values before printing it. This is not a process sandbox.

## Make One Brokered HTTP Call

```sh
export STRIPE_SECRET_KEY='sk_test_fake_blindfold_example_1234567890'
bf allow domain api.stripe.com
bf call --secret STRIPE_SECRET_KEY \
  --url https://api.stripe.com/v1/customers
```

Blindfold inserts the selected value only as a bearer credential for the approved host,
bounds and sanitizes the response, and records no request/response payload in traces.

## Run A Coding Agent

```sh
bf run claude -- --print "summarize this repository"
bf run codex -- exec "find the failing test"
bf run codex -- review
bf run opencode -- run "inspect this project"
```

Only these noninteractive command families are accepted. The runner clears the parent
environment, configures an ephemeral provider proxy, starts proxy-aware destination
control, and captures sanitized stdout/stderr. Unsupported command modes fail before
the child starts.

Each built-in adapter also resolves the exact executable and requires a compatible
version before the proxy or agent starts:

| Harness | Accepted version |
|---|---|
| Claude Code | `2.1.152` |
| Codex CLI | `0.144.1` |
| OpenCode | `1.17.3` |

Missing, ambiguous, and different version output blocks the run. Version output proves
compatibility only; it does not authenticate the executable. Future releases remain
blocked until their traffic and tool behavior is tested.

Unknown domains observed through the egress proxy block by default:

```sh
bf allow domain api.example.com
bf status
bf deny domain api.example.com
```

The runner does not mediate reads from the working directory or sockets opened by a
client that ignores proxy settings. An agent opening `.env` still reads its raw content.
Use the native command directly to operate outside Blindfold; there is intentionally no
Blindfold bypass flag.

## Python SDK

```python
from blindfold import Boundary
from openai import OpenAI

with Boundary(
    secrets=["sk_test_fake_blindfold_1234567890"],
    pii=["alice@example.test"],
) as boundary:
    client = boundary.wrap(OpenAI())
    response = client.responses.create(
        model="gpt-5",
        input="Use sk_test_fake_blindfold_1234567890 for alice@example.test",
    )
    user_text = boundary.restore(response.output_text, destination="end_user")
```

The wrapper masks registered strings in outbound arguments and inbound supported
results. PII restoration requires `end_user`; secrets are never restored to normal
output. The SDK is an in-process boundary and does not intercept arbitrary files,
environment access, or unwrapped network clients.

## Trace Without Payloads

```sh
bf redact .env --trace
bf run codex --trace -- exec "summarize this repo"
bf trace list
bf trace tail
bf trace export req_... --redacted
```

Trace records contain closed route, coverage, outcome, byte-count, category, and
structural-pointer fields. They contain no payload, credential header, query string, or
raw detector span.

## Current Guarantee Boundary

For supported operations routed through Blindfold, detected or registered values are
removed, masked, or blocked at the managed boundary. This does not guarantee detection
of every unknown secret and does not contain an agent process that can read the host
filesystem or bypass proxy settings. The exact contract is maintained in
[Guarantees and Limitations](docs/guarantees.md).
