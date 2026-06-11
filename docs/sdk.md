# TypeScript SDK Preview

The dependency-free preview in `sdk/typescript` demonstrates application-controlled
tokenization:

```ts
const safe = boundary.toLLM(input, [
  { value: customer.email, kind: "pii" },
]);

const modelResult = await callModel(safe.text);
const userResult = boundary.fromLLM(modelResult, "end_user");
```

PII restoration requires the `end_user` destination. Secret restoration is always
denied. Forged references remain inert.

The preview stores mappings in process memory only. It has no automatic detector,
encrypted persistence, access-control boundary, or cross-process protocol.

```sh
npm --prefix sdk/typescript test
```
