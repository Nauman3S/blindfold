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

test("uses unpredictable tokens across boundary instances", () => {
  const first = new BlindfoldBoundary().tokenize("alice@example.test", "pii");
  const second = new BlindfoldBoundary().tokenize("alice@example.test", "pii");

  assert.match(first, /^\{\{BLINDFOLD:SDK:v1:PII:[0-9a-f]{32}\}\}$/);
  assert.notEqual(first, second);
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
  const forged = "{{BLINDFOLD:SDK:v1:PII:00000000000000000000000000000000}}";

  assert.equal(boundary.fromLLM(forged, "end_user"), forged);
});

test("does not collide with token-shaped input or existing mappings", () => {
  const boundary = new BlindfoldBoundary();
  const existing = boundary.tokenize("alice@example.test", "pii");
  const tokenShapedInput = "{{BLINDFOLD:SDK:v1:PII:00000000000000000000000000000000}}";
  const safe = boundary.toLLM(`${tokenShapedInput} fake-secret`, [
    { value: "fake-secret", kind: "secret" },
  ]);
  const generated = safe.text.slice(tokenShapedInput.length + 1);

  assert.ok(safe.text.startsWith(`${tokenShapedInput} `));
  assert.notEqual(generated, tokenShapedInput);
  assert.notEqual(generated, existing);
  assert.equal(boundary.fromLLM(tokenShapedInput, "end_user"), tokenShapedInput);
});

test("replaces overlapping values longest-first", () => {
  const boundary = new BlindfoldBoundary();
  const safe = boundary.toLLM("alice@example.test", [
    { value: "alice", kind: "pii" },
    { value: "alice@example.test", kind: "pii" },
    { value: "PII", kind: "pii" },
  ]);

  assert.equal(safe.replacements, 1);
  assert.doesNotMatch(safe.text, /alice|@example\.test/);
  assert.equal(boundary.fromLLM(safe.text, "end_user"), "alice@example.test");
});
