# Blindfold Python SDK

The Python SDK masks caller-registered secrets and PII in supported LLM requests and
responses. It has no runtime dependencies and stores mappings only in process memory.

## Client wrapper

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
        input=(
            "List customers using stripe key "
            "sk_test_fake_blindfold_1234567890 for alice@example.test."
        ),
    )

    # PII restoration is explicit and allowed only at the end-user boundary.
    user_text = boundary.restore(response.output_text, destination="end_user")
```

The wrapped client recursively protects strings in method arguments and returned
provider data. Custom response objects are exposed through a proxy that protects their
attributes and method results. The application must explicitly choose a destination
before restoring PII. Secrets are never restored by `Boundary.restore()`.

Registering an existing environment variable is concise:

```python
boundary = Boundary()
boundary.register_env("STRIPE_API_KEY")
```

This registers the current value but does not remove or replace the original process
environment variable. Environment isolation is provided by the Blindfold CLI, not the
in-process SDK.

## Transport wrapper

Provider-neutral code can wrap a callable instead:

```python
from blindfold import Boundary

boundary = Boundary(secrets=["fake-api-key"])

@boundary.wrap_transport
def send(request: dict[str, object]) -> dict[str, object]:
    # The request contains a stable opaque SafeRef, not fake-api-key.
    return http_transport(request)

response = send({"input": "Use fake-api-key"})
```

## Protection modes

```python
from blindfold import Boundary

boundary = Boundary(secrets=["fake-api-key"])

boundary.protect("Use fake-api-key", mode="mask")   # stable session SafeRef
boundary.protect("Use fake-api-key", mode="redact") # irreversible placeholder
boundary.protect("public text", mode="block")       # raises if a value is present
```

`mask` is the default. `block` raises before the wrapped client or transport is
called and when a provider response contains a registered value. Unknown and malformed
Blindfold SafeRefs in model output fail closed. Streaming request and response objects
are intentionally unsupported because this package cannot inspect them eagerly without
changing their behavior.

## Security boundary

The SDK protects strings that the application identifies and passes through a
`Boundary`. It does not discover secrets automatically. It does not provide process,
filesystem, memory, or network containment; a compromised application or unwrapped
transport can bypass it. The in-memory registry contains plaintext values until the
boundary is closed.

Use one boundary per logical session, keep it away from untrusted code, and avoid
logging raw inputs before they pass through the boundary.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
uv build
```
