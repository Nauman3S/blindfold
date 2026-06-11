import assert from "node:assert/strict";
import test from "node:test";

import { BlindfoldBoundary } from "../src/index.ts";

test("tokenizes values before an LLM call", () => {
  const boundary = new BlindfoldBoundary();
  const safe = boundary.toLLM("Email alice@example.test and key fake-secret", [
    { value: "alice@example.test", kind: "pii" },
    { value: "fake-secret", kind: "secret" },
  ]);

  assert.equal(safe.replacements, 2);
  assert.doesNotMatch(safe.text, /alice@example\.test|fake-secret/);
});

test("restores PII only to the end user", () => {
  const boundary = new BlindfoldBoundary();
  const token = boundary.tokenize("alice@example.test", "pii");

  assert.equal(boundary.fromLLM(`Contact ${token}`, "end_user"), "Contact alice@example.test");
  assert.throws(() => boundary.fromLLM(token, "log"), /end_user/);
});

test("never restores secrets", () => {
  const boundary = new BlindfoldBoundary();
  const token = boundary.tokenize("fake-secret", "secret");

  assert.throws(() => boundary.fromLLM(token, "end_user"), /not allowed/);
  assert.throws(() => boundary.fromLLM(token, "llm"), /not allowed/);
});

test("forged tokens remain inert", () => {
  const boundary = new BlindfoldBoundary();
  const forged = "{{BLINDFOLD:SDK:v1:PII:999999}}";

  assert.equal(boundary.fromLLM(forged, "end_user"), forged);
});
