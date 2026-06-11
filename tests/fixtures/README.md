# Fake Security Fixtures

Every value in this directory is synthetic, inert, and committed only to test parsing,
detection, redaction, and leak-regression behavior.

Rules:

- Never replace these files with copied or mutated live credentials.
- Keep fixtures below this directory; it is the only path exempted from Gitleaks.
- Use `example.com`, documentation networks, and local endpoints.
- Tests should identify fixtures by name and must not print plaintext on failure.
- A fixture must include `BLINDFOLD_FAKE_FIXTURE` in nearby metadata where its format
  permits.

Contents:

- `secrets/provider-tokens.env`: fake provider-shaped token and credential strings.
- `env-files/application.env`: realistic fake application environment.
- `structured/credentials.json`: nested fake structured credentials and PII.
- `private-keys/example.invalid.pem`: nonfunctional private-key-shaped block.
- `logs/agent-output.log`: fake accidental disclosure in command output.

None of these values was issued by a provider or generated as a usable cryptographic
key. Reserved domains and documentation IP ranges prevent real service access.
