# Application SDKs

## Python

The dependency-free Python SDK wraps client objects or callable transports so
registered values are protected in supported outbound arguments and inbound results:

```python
from blindfold import Boundary
from openai import OpenAI

with Boundary(secrets=[secret], pii=[customer_email]) as boundary:
    client = boundary.wrap(OpenAI())
    response = client.responses.create(
        model="gpt-5",
        input=f"Check {customer_email} using {secret}",
    )
    result = boundary.restore(response.output_text, destination="end_user")
```

`mask` is the default protection mode. `redact` is irreversible and `block` refuses a
call containing a registered value. PII restoration requires `end_user`; secret
restoration is always denied. Unknown and malformed SafeRefs fail closed. Unsupported
opaque or streaming response shapes are rejected instead of returned uninspected.

```sh
PYTHONPATH=sdk/python/src python3 -m unittest discover -s sdk/python/tests -v
```

## TypeScript

The TypeScript preview exposes explicit tokenization:

```ts
const safe = boundary.toLLM(input, [
  { value: customer.email, kind: "pii" },
]);

const modelResult = await callModel(safe.text);
const userResult = boundary.fromLLM(modelResult, "end_user");
```

```sh
npm --prefix sdk/typescript test
```

Both SDKs keep mappings in process memory. They do not detect arbitrary secrets,
intercept filesystem or environment reads, mediate unwrapped transports, isolate
provider credentials, or provide a process/network sandbox.
