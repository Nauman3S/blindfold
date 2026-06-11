# Blindfold TypeScript SDK Preview

This dependency-free preview demonstrates destination-aware tokenization for application
text. It is not connected to the Rust vault and stores mappings only in process memory.

```ts
import { BlindfoldBoundary } from "./src/index.ts";

const boundary = new BlindfoldBoundary();
const safe = boundary.toLLM("Email alice@example.test", [
  { value: "alice@example.test", kind: "pii" },
]);

const modelText = `Reply to ${safe.text.split(" ").at(-1)}`;
const userText = boundary.fromLLM(modelText, "end_user");
```

Rules:

- PII can be restored only to `end_user`.
- Secrets are never restored by `fromLLM`.
- Forged and unknown tokens remain inert.
- Mappings are process-local and disappear on `clear()` or process exit.

Run tests with Node 22.6 or newer:

```sh
npm test
```
