# Policy Model

## Status

The deterministic policy library and preset matrix are implemented. CLI inspection is
available through `blindfold policy check`. Runtime commands do not yet load and enforce
the complete project/local override model described below, so configuration precedence
remains preview work.

## Inputs

A policy decision considers:

- sensitivity and detector category;
- source, such as file, environment, prompt, response, or process output;
- destination, such as agent, LLM provider, local process, API field, log, or audit;
- operation and tool identity;
- project and session scope;
- active mode; and
- an explicit allow or deny rule.

## Actions

- `redact`: replace a raw value with a SafeRef or safe structural representation.
- `block`: stop the operation without echoing the value.
- `warn`: continue only where the destination is non-sensitive by default and policy
  explicitly permits warning behavior.
- `restore`: resolve a SafeRef into plaintext only for a trusted destination.

An untrusted destination cannot request or override `restore`.

## Precedence

Highest precedence wins:

1. invariant hard-deny rules;
2. explicit project deny rules;
3. narrow command-line restrictions;
4. local uncommitted overrides;
5. project configuration;
6. mode defaults; and
7. built-in fail-closed defaults.

An allow rule cannot override a security invariant. Invalid, missing, ambiguous, or
unsupported policy affecting a sensitive operation fails closed.

## Modes

- `chill`: lower-friction scanning, but never permits raw secrets to LLM, log, audit, or
  agent-output destinations.
- `balanced`: default detection and blocking/redaction policy.
- `strict`: requires all declared managed controls and refuses known bypass or degraded
  conditions.
- `ci`: non-interactive, deterministic, redacted output and failure on prohibited
  findings.

Modes are explicit policy data, not scattered conditional behavior.

## Example Target Configuration

```yaml
version: 1
mode: balanced
redaction:
  secrets:
    mode: env-ref
  pii:
    mode: placeholder
  private_keys:
    mode: block
exec:
  allow_secret_injection: true
  reveal_to_agent: false
audit:
  enabled: true
  store_raw_values: false
```

The final schema may evolve before release, but configuration remains versioned and
unknown security-sensitive fields must not silently weaken policy.
