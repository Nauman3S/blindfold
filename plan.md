# Blindfold Build Plan

> Let agents use secrets without leaking secrets.

## How to Use This Plan

This document is the product brief, implementation roadmap, and release checklist for
Blindfold. Keep it updated as decisions are made and work is completed.

### Project Status

| Field | Value |
|---|---|
| Current phase | Security/UX hardening; several integrations remain preview or incomplete |
| Target release | `v0.1.0` - managed coding-agent traffic preview |
| Primary platform | macOS and Linux development targets; not release-supported yet |
| Primary integration | Claude Code, Codex CLI, and OpenCode degraded wrappers |
| Implementation language | Rust 1.96.0, edition 2024 |
| License | Apache License 2.0 |

### Architecture Delta: Guard First, Strict Later

This plan supersedes earlier wording that implied `blindfold run` can make an
unmodified local agent unable to read local files. It cannot. If OpenCode, Claude Code,
Codex, or another agent runs normally in the real project, the agent process can read
files that the current user can read.

Blindfold's product promise must be split by mode:

| Mode | Agent can read local files? | LLM/provider sees secrets? | Requires container/sandbox? |
|---|---:|---:|---:|
| `scan` | yes | n/a | no |
| `proxy` | yes | no, if traffic is routed through Blindfold | no |
| `guard` | yes | no for managed LLM traffic; direct LLM egress should be blocked | no |
| `strict` | no raw secret workspace by design | no | yes |

Guard mode is the practical v1 wedge:

```sh
bf run --guard opencode
```

In guard mode the agent works in the real repository. Blindfold configures supported
agents to send OpenAI-compatible, Anthropic-compatible, OpenRouter, or other configured
LLM traffic through the local redaction proxy. The egress guard should block direct
known-provider traffic that bypasses Blindfold. Guard mode protects outbound managed
LLM traffic; it does not protect local file reads, local agent logs, or network clients
that ignore proxy settings.

Strict mode is the later stronger promise:

```sh
bf run --strict opencode
```

Strict mode must use a container or OS sandbox with a managed workspace, fake home,
sanitized environment, blocked direct provider egress, and brokered secret access. Only
strict mode may claim that the agent process cannot see raw secrets in its filesystem or
environment.

Do not reintroduce a temporary copied worktree as default guard behavior. It changes how
agents use Git, worktrees, submodules, generated files, and edits. Any managed workspace
belongs under strict mode with an explicit patch/apply flow.

### Task Status Legend

- `[ ]` Not started
- `[~]` In progress
- `[x]` Complete and verified
- `[!]` Blocked; add the reason beside the task
- `[-]` Removed from scope; add the decision reference

### Execution Rules

1. A task is complete only when its implementation, tests, and relevant documentation
   are complete.
2. A phase is complete only when every required task and exit criterion passes.
3. Security-sensitive behavior must have negative tests proving raw values do not leak.
4. New scope goes into the backlog unless it is required for a current phase exit
   criterion.
5. Record material architecture and security decisions in `docs/decisions/`.
6. Use fake but realistic credentials in all committed fixtures.
7. Never use production credentials during development, tests, demos, or CI.

## 1. Project Summary

Name: Blindfold
Tagline: Let agents use secrets without leaking secrets.

Blindfold is a local-first privacy and secrets boundary for AI coding agents.

It aims to let Claude Code, Codex, Cursor, MCP tools, and custom agents work with real
projects while reducing disclosure of detected credentials on explicitly managed
outbound paths. Automatic PII discovery, arbitrary local file-read mediation, and
whole-agent containment are not currently implemented.

The core idea:

In guard mode, the agent can read local files, but Blindfold prevents detected secrets
from being sent through managed LLM/provider traffic.

In strict mode, the agent runs in a managed workspace where raw secrets are absent and
secret use goes through Blindfold's broker.

Blindfold should start with Claude Code support, but the architecture must be agent-agnostic.

---

## 2. License and Project Model

Use Apache License 2.0 for the open-source core.

Reasoning:

* Friendly to developers and companies.
* Allows commercial use.
* Includes explicit patent grant.
* Easier for enterprises to adopt than AGPL.
* More suitable than MIT for security infrastructure.

Recommended model:

Open-source core:
- CLI
- local proxy
- detector engine
- redaction engine
- local vault
- Claude Code wrapper
- basic MCP proxy
- policy file
- audit logs
Paid/team features later:
- central dashboard
- team policy management
- SSO/SAML
- centralized audit logs
- compliance exports
- advanced detectors
- hosted policy updates
- enterprise support

Do not start closed source. Developers will not trust a secret-handling local agent proxy unless they can inspect it.

---

## 3. Core Product Promise

Blindfold should guarantee this within its controlled boundary:

1. Raw secrets are never sent to LLM requests managed by Blindfold.
2. Raw secrets are never shown to the agent in managed tool outputs.
3. Raw secrets are never intentionally written to Blindfold logs.
4. Agents can reference secrets using safe placeholders.
5. Trusted local runtime can use real secrets without revealing them to the model.

Avoid absolute claims like:

Impossible to leak secrets.
100% guaranteed protection.
No agent can ever bypass it.

Instead, be honest:

Blindfold guard mode protects traffic and tools routed through Blindfold.
Strict mode can sandbox agents to prevent direct filesystem and environment bypasses.

---

## 4. High-Level Architecture

AI Coding Agent
Claude Code / Codex / Cursor / Custom
        |
        v
Blindfold Boundary
        |
        +-- LLM Proxy
        +-- Egress Guard
        +-- Shell/Command Proxy
        +-- MCP Proxy
        +-- Detector Engine
        +-- Tokenization Engine
        +-- Local Vault
        +-- Policy Engine
        +-- Audit Log
        +-- Strict Workspace Runner
        |
        v
LLM Provider / Local Model / Tools / Shell / APIs

The agent should see safe references such as:

STRIPE_SECRET_KEY={{SECRET:STRIPE_SECRET_KEY}}
DATABASE_URL={{ENV:DATABASE_URL}}
CUSTOMER_EMAIL={{PII:EMAIL:customer_1}}
TLS_PRIVATE_KEY={{PRIVATE_KEY:TLS_PRIVATE_KEY}}

The local trusted runtime may restore these values only when policy allows it, such as inside a subprocess environment variable or API request header.

---

## 5. Main Components

### 5.1 CLI

Binary name:

blindfold

Primary commands:

blindfold init
blindfold doctor
blindfold run --guard claude
blindfold run --guard codex
blindfold run --guard opencode
blindfold run --strict opencode
blindfold proxy
blindfold scan .
blindfold redact .env
blindfold exec --secret STRIPE_SECRET_KEY -- npm test
blindfold call --secret STRIPE_SECRET_KEY --url https://api.stripe.com/v1/customers
blindfold audit
blindfold status
blindfold allow domain api.example.com
blindfold deny domain suspicious.example.com
blindfold policy check
blindfold mcp

Initial priority:

blindfold init
blindfold run --guard opencode
blindfold scan .
blindfold exec --secret NAME -- command

The first release must feel simple.

Good first-run UX:

blindfold init
blindfold run --guard opencode

Output example:

Blindfold Guard active.
Protected:
- LLM requests routed through Blindfold
- OpenAI/Anthropic/OpenRouter provider bodies redacted when routed
- Direct known-provider egress blocked when the egress guard is active
Not protected:
- Local file reads by the agent
- Agent local logs
- Network clients that ignore proxy settings
Mode: balanced

Use `--strict` for workspace isolation.

### 5.2 Local LLM Proxy

Implement a local HTTP proxy that can sit between agents and LLM providers.

Support initially:

OpenAI-compatible API
Anthropic-compatible API
OpenRouter/OpenAI-compatible routing

Later:

Ollama-compatible API
Gemini-compatible API
Mistral-compatible API
Groq-compatible API
generic HTTP CONNECT proxy

The proxy must:

1. Receive LLM requests.
2. Normalize request payload.
3. Scan all text fields.
4. Replace secrets/PII with safe placeholders.
5. Store placeholder mappings in local vault.
6. Forward sanitized request to upstream provider.
7. Receive model response.
8. Scan model response.
9. Redact any leaked/reconstructed secrets.
10. Return sanitized response to agent.

Important:

* Support streaming responses.
* For streaming, scan with chunk overlap so secrets split across chunks are still detected.
* Never log raw prompt or raw response by default.
* Do not install a root CA or claim arbitrary HTTPS body inspection in v1.

### 5.2.1 Egress Network Guard

The egress guard controls outbound network destinations. It should not try to redact
arbitrary encrypted HTTPS bodies by default.

Default approach:

1. Run an explicit local HTTP/HTTPS proxy on `127.0.0.1:8789`.
2. Set `HTTP_PROXY`, `HTTPS_PROXY`, and compatible proxy variables for the agent.
3. Set provider base URLs so known LLM traffic uses the Blindfold LLM proxy.
4. Block direct `CONNECT` traffic to known LLM providers such as:
   - `api.openai.com`
   - `api.anthropic.com`
   - `openrouter.ai`
   - `generativelanguage.googleapis.com`
   - `api.mistral.ai`
   - `api.groq.com`
5. Allow common development domains by policy, such as GitHub, npm, PyPI, crates.io,
   and Go module mirrors.
6. Ask or block unknown domains according to project policy.

Important:

* No default TLS MITM.
* If Blindfold cannot inspect the body, it controls by destination policy.
* Known LLM APIs should use the application-aware LLM proxy, not generic MITM.
* Network clients that ignore proxy environment variables remain outside guard mode
  until strict/container networking is implemented.

### 5.3 Detector Engine

The detector engine should combine multiple methods.

Detection categories:

Secrets:
- API keys
- cloud credentials
- GitHub tokens
- OpenAI/Anthropic keys
- Stripe keys
- Slack tokens
- JWTs
- OAuth client secrets
- database URLs with credentials
- auth headers
- bearer tokens
Files:
- .env
- .env.*
- id_rsa
- id_ed25519
- *.pem
- *.key
- *.p12
- kubeconfig
- terraform.tfstate
- .npmrc
- .pypirc
- application-prod.yml
Crypto material:
- private keys
- SSH private keys
- TLS private keys
- certificates
- cert chains
PII:
- emails
- phone numbers
- names where possible
- addresses where possible
- credit card-like values
- IBAN/account-like values
- national IDs where possible

Detection methods:

1. Regex patterns for known key formats.
2. Gitleaks-compatible rules.
3. Entropy detection.
4. Contextual detection around names like password, secret, token, api_key, client_secret.
5. Structured parsers for .env, JSON, YAML, TOML, XML.
6. PEM/private-key block detection.
7. URL parser for database URLs.

Important rule:

Entropy alone should usually not block.
Entropy + secret-like context should redact.
Known secret format should redact.
Private key material should strongly redact or block.

Avoid too many false positives. Developer trust depends on low friction.

### 5.4 Tokenization and Safe References

Blindfold should not only replace with [REDACTED].

Use stable, meaningful placeholders.

Examples:

{{SECRET:OPENAI_API_KEY}}
{{SECRET:STRIPE_SECRET_KEY}}
{{ENV:DATABASE_URL}}
{{PII:EMAIL:customer_1}}
{{PII:ADDRESS:customer_1}}
{{PRIVATE_KEY:TLS_PRIVATE_KEY}}
{{CERT:TLS_CERT}}

Placeholder requirements:

- Stable within session/project.
- Not reversible by the LLM.
- Meaningful enough for the agent to reason.
- Short enough to avoid huge token overhead.
- Collision-resistant.
- Safe to display in logs.

Support these redaction modes:

env-ref:
  Show only environment variable references.
schema-only:
  Show config keys but empty values.
placeholder:
  Replace sensitive values with stable placeholders.
surrogate:
  Replace with fake format-preserving values.
synthetic:
  Replace PII with realistic fake values.
block:
  Stop request/tool output if too risky.

Example:

Real .env:

STRIPE_SECRET_KEY=sk_live_real_abc123
DATABASE_URL=postgres://admin:real-password@prod-db/app

Agent sees in env-ref mode:

STRIPE_SECRET_KEY={{ENV:STRIPE_SECRET_KEY}}
DATABASE_URL={{ENV:DATABASE_URL}}

Agent sees in placeholder mode:

STRIPE_SECRET_KEY={{SECRET:STRIPE_SECRET_KEY}}
DATABASE_URL={{SECRET:DATABASE_URL}}

Agent sees in schema-only mode:

STRIPE_SECRET_KEY=
DATABASE_URL=

Agent sees in surrogate mode:

STRIPE_SECRET_KEY=sk_live_blindfold_7f3a000000
DATABASE_URL=postgres://user:password@localhost:5432/app

### 5.5 Local Vault

The local vault stores mappings between raw values and placeholders.

Requirements:

- Local-only by default.
- Encrypted at rest.
- Never exposed to LLM.
- Never logged raw.
- Session-aware.
- Project-aware.
- Supports TTL.
- Supports audit metadata.

Vault record example:

{
  "placeholder": "{{SECRET:STRIPE_SECRET_KEY}}",
  "kind": "secret",
  "label": "STRIPE_SECRET_KEY",
  "hash": "sha256:...",
  "source": ".env",
  "scope": "project",
  "created_at": "2026-06-10T12:00:00Z",
  "ttl": "session"
}

Do not store raw values in plain JSON.

For MVP, acceptable storage options:

macOS Keychain / Linux Secret Service / Windows Credential Manager
or encrypted local SQLite
or encrypted local file with OS keychain-derived key

Keep implementation pragmatic, but do not store raw secrets unencrypted.

### 5.6 Policy Engine

Policy must be destination-aware.

Example destinations:

llm_request
llm_response
agent_chat
tool_input
tool_output
shell_stdout
shell_stderr
file_read
file_write
log
audit
vector_memory
local_subprocess_env
trusted_api_call
end_user

Default rules:

mode: balanced
llm_request:
  secrets: redact
  private_keys: block
  pii: redact
llm_response:
  secrets: redact
  private_keys: redact
  pii: redact
shell_output:
  secrets: redact
  private_keys: redact
  pii: redact
file_read:
  secrets: redact
  private_keys: block
  pii: redact
local_subprocess_env:
  secrets: restore
  reveal_to_agent: false
logs:
  secrets: redact
  pii: redact
  raw_values: never

Preset modes:

chill:
  low interruption, mostly redact, few blocks
balanced:
  default; redact secrets, block private keys
strict:
  stronger blocking, sandbox recommended
ci:
  fail on leaks and unsafe generated diffs

### 5.7 Secret Execution Runtime

This is the killer feature.

The agent should be able to ask to run commands with secrets, but not see the secrets.

Example:

blindfold exec --secret STRIPE_SECRET_KEY -- npm test

Blindfold should:

1. Resolve STRIPE_SECRET_KEY locally.
2. Inject it into subprocess env.
3. Run the command.
4. Capture stdout/stderr.
5. Redact stdout/stderr.
6. Return sanitized result to agent.
7. Audit the action without logging raw secret.

Agent-visible result:

Command completed.
Secrets injected:
- STRIPE_SECRET_KEY
Exit code: 0
Output redacted:
- 2 secret-like values
- 5 customer PII fields

Support later:

blindfold exec --env-file .env.local -- npm test
blindfold call --secret STRIPE_KEY --url https://api.stripe.com/v1/customers

Never show the real secret to the agent.

### 5.8 File Read Protection

When the agent reads a file, Blindfold should scan and transform before returning content.

High-risk files:

.env
.env.*
*.pem
*.key
*.p12
terraform.tfstate
kubeconfig
.aws/credentials
.npmrc
.pypirc

Default behavior:

.env files:
  show keys, redact values
private key files:
  block or summarize
cert files:
  allow public cert summary, block private keys
terraform state:
  block by default or heavily redact
logs:
  redact secrets and PII

Example blocked message:

Blocked: private key file detected.
File:
  ./certs/prod.key
Why:
  Private keys should never be sent to an LLM.
What the agent can use instead:
  {{PRIVATE_KEY:TLS_PRIVATE_KEY}}

### 5.9 Shell Output Protection

Any command output routed through Blindfold should be scanned before reaching the agent.

Examples to protect:

cat .env
printenv
env
kubectl logs
docker logs
terraform output
aws configure list
grep -R password .

Do not necessarily block everything. Prefer redact where possible.

But for dangerous commands, warn or block in strict mode.

Command policy examples:

printenv:
  chill: redact output
  balanced: redact output + warning
  strict: block unless explicit
cat .env:
  balanced: return redacted file
cat private.key:
  block

### 5.10 Generated Diff Scanner

Before an agent writes code or produces a patch, scan generated changes.

Block or warn if:

- API key is hardcoded
- secret is added to frontend code
- .env file is committed
- private key is written
- real token appears in test fixture
- authorization header contains raw token

Output example:

Blocked generated diff.
Reason:
  Hardcoded secret-like value added to src/client.ts.
Suggested fix:
  Use process.env.STRIPE_SECRET_KEY instead.

This should be part of CI mode too.

### 5.11 MCP Proxy

MCP is important because agents increasingly use MCP servers to call tools.

Build basic MCP proxy after the initial CLI/proxy MVP.

MCP proxy responsibilities:

1. Intercept MCP tool calls.
2. Redact tool arguments.
3. Resolve allowed SafeRefs only inside trusted tool calls.
4. Redact tool responses.
5. Enforce per-tool secret scopes.
6. Audit tool usage.

Example:

Agent calls:
  stripe.list_customers(secret="{{SECRET:STRIPE_SECRET_KEY}}")
Blindfold:
  resolves secret locally
  calls tool
  redacts customer PII
  returns summary

Policy should define which tools can use which secrets.

---

## 6. Recommended Tech Stack

Use a systems-friendly language for the core CLI/proxy.

Recommended:

Rust

Reasons:

- Great single-binary distribution.
- Good performance.
- Good security story.
- Strong typing.
- Good CLI ecosystem.
- Good for streaming proxy and scanners.

Alternative:

Go

Go is also acceptable and may be faster to ship.

Suggested stack if using Rust:

CLI:
  clap
HTTP proxy:
  axum or hyper
Async runtime:
  tokio
Config:
  serde + toml/yaml
Storage:
  sqlite + encryption
  or OS keychain bindings
Regex:
  regex crate
Secret rules:
  implement Gitleaks-compatible subset
  or shell out to gitleaks for MVP if needed
Testing:
  cargo test
  integration tests with fake agents

For SDKs later:

TypeScript SDK
Python SDK

Do not start with many SDKs. Start with CLI and local proxy.

---

## 7. Repository Structure

Suggested structure:

blindfold/
  README.md
  LICENSE
  SECURITY.md
  CONTRIBUTING.md
  THREAT_MODEL.md
  docs/
    quickstart.md
    claude-code.md
    codex.md
    cursor.md
    mcp.md
    policy.md
    modes.md
    guarantees.md
    limitations.md
    architecture.md
  crates/
    blindfold-cli/
    blindfold-core/
    blindfold-detectors/
    blindfold-policy/
    blindfold-vault/
    blindfold-proxy/
    blindfold-egress-guard/
    blindfold-exec/
    blindfold-mcp/
    blindfold-strict-runner/
  examples/
    claude-code-basic/
    node-stripe-demo/
    python-fastapi-pii/
    mcp-secret-call/
    ci-secret-scan/
  tests/
    fixtures/
      secrets/
      env-files/
      pii/
      private-keys/
      logs/

If using Go:

cmd/blindfold/
internal/core/
internal/detectors/
internal/policy/
internal/vault/
internal/proxy/
internal/exec/
internal/mcp/
examples/
docs/

---

## 8. Configuration

Default config file:

.blindfold.yaml

Example:

version: 1
mode: guard
redaction:
  secrets:
    mode: env-ref
  pii:
    mode: placeholder
  private_keys:
    mode: block
files:
  protect:
    - ".env"
    - ".env.*"
    - "**/*.pem"
    - "**/*.key"
    - "**/terraform.tfstate"
  ignore:
    - "node_modules/**"
    - ".git/**"
    - "dist/**"
    - "build/**"
exec:
  allow_secret_injection: true
  reveal_to_agent: false
audit:
  enabled: true
  store_raw_values: false
llm:
  proxy:
    listen: "127.0.0.1:8787"
    openai: true
    anthropic: true
    openrouter: true
network:
  guard:
    enabled: true
    listen: "127.0.0.1:8789"
  llm_providers:
    direct: block
    via_blindfold_proxy: allow
  allow:
    - github.com
    - api.github.com
    - registry.npmjs.org
    - pypi.org
    - files.pythonhosted.org
    - crates.io
    - static.crates.io
    - index.crates.io
    - proxy.golang.org
    - sum.golang.org
  ask:
    - "*.company.com"
    - localhost
    - 127.0.0.1
  block_unknown: true
strict:
  engine: docker
  workspace: managed-copy
  mount_home: false
  network: guarded

Support local overrides:

.blindfold.local.yaml

Do not commit local override by default.

---

## 9. Delivery Roadmap

### Dependency Order

The critical path is:

`P0 Foundation -> P1 Detection -> P2 Policy/SafeRefs -> P3 Vault -> P4 Proxy
-> P4B Egress Guard -> P5 Exec -> P6 Guard Mode Runner -> P7 Release hardening`

The generated diff scanner and MCP proxy can begin after P2, but neither may delay the
`v0.1.0` critical path unless a release gate depends on it.

### Milestone Tracker

Update this table at least once per work session. Use exact dates in `YYYY-MM-DD`
format. Add a blocker link or note whenever status is `[!]`.

| Phase | Scope | Status | Owner | Target date | Depends on | Verification |
|---|---|---|---|---|---|---|
| P0 | Foundation and security contracts | `[x]` | Codex | 2026-06-11 | None | Exit criteria |
| P1 | Detector and redaction engine | `[~]` | Codex | TBD | P0 | `V-03`, `V-08`, `V-09` |
| P2 | SafeRefs and policy | `[~]` | Codex | TBD | P1 | `V-13`, `V-14` |
| P3 | Encrypted vault and audit | `[~]` | Codex | TBD | P2 | `V-06`, `V-10` |
| P4 | Local LLM proxy | `[~]` | Codex | TBD | P1-P3 | `V-07`, `V-11` |
| P4B | Egress network guard | `[ ]` | Codex | TBD | P4 | Phase exit criteria |
| P5 | Secret execution runtime | `[~]` | Codex | TBD | P1-P3 | `V-06`, `V-12` |
| P6 | Guard mode agent runner | `[~]` | Codex | TBD | P4-P5, P4B for full guard | `V-05` |
| P7 | Release hardening | `[~]` | Codex | TBD | P0-P6 | `V-01` through `V-18` |
| P8 | Generated diff scanner | `[~]` | Codex | TBD | P2 | Phase exit criteria |
| P9 | MCP proxy | `[~]` | Codex | Backlog | P2-P4 | Phase exit criteria |
| P10 | App SDK preview | `[x]` | Codex | 2026-06-11 | Stable core contracts | Phase exit criteria |

For active tasks, append this metadata to the task line or track it in the issue system:

```text
Owner: <name> | Target: YYYY-MM-DD | Issue: <link/id> | Evidence: <link/path>
```

### Phase 0: Foundation and Security Contracts

**Goal:** Establish repository, build, test, documentation, and security invariants
before implementing secret-handling behavior.

**Depends on:** Nothing

**Required tasks:**

- [x] `P0-01` Initialize the Rust workspace and crate structure.
- [x] `P0-02` Add `LICENSE`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, and
  `THREAT_MODEL.md`.
- [x] `P0-03` Add `docs/decisions/` and record the language, vault backend, placeholder
  format, and supported-boundary decisions.
- [x] `P0-04` Implement the CLI skeleton with `--help`, `--version`, `init`, and
  `doctor`.
- [x] `P0-05` Define versioned `.blindfold.yaml` configuration types, defaults,
  validation, and human-readable errors.
- [x] `P0-06` Define core data types: `Finding`, `SecretKind`, `Destination`,
  `Action`, `SafeRef`, `Source`, and `Sensitivity`.
- [x] `P0-07` Define a redacted error type that cannot accidentally format raw secret
  values.
- [x] `P0-08` Add structured logging with safe fields only and raw payload logging
  disabled by construction.
- [x] `P0-09` Add unit, integration, and end-to-end test directories with fake
  realistic fixtures.
- [x] `P0-10` Add formatting, linting, tests, dependency audit, and secret scanning to
  CI.
- [x] `P0-11` Document supported platforms and decide whether Windows is unsupported
  or experimental for `v0.1.0`.
- [x] `P0-12` Add a changelog and release versioning policy.

**Deliverables:**

- `blindfold --help`
- `blindfold init`
- `blindfold doctor`
- A CI pipeline that passes on an empty implementation skeleton

**Exit criteria:**

- [x] A clean checkout builds and tests with documented commands.
- [x] Invalid configuration fails closed with no raw values in the error.
- [x] `doctor` reports config, storage, loopback port, and supported integration
  readiness without printing secret values.
- [x] Security boundaries and non-goals are documented.

### Phase 1: Detector and Redaction Engine

**Goal:** Reliably detect and transform secrets in files, stdin, and arbitrary text.

**Depends on:** P0

**Required tasks:**

- [x] `P1-01` Define a detector interface with detector name, confidence, span,
  sensitivity, and optional safe label.
- [x] `P1-02` Implement known-format detectors for initial providers: OpenAI,
  Anthropic, GitHub, Stripe, Slack, AWS, bearer tokens, JWTs, and OAuth secrets.
- [x] `P1-03` Implement PEM and private-key block detection.
- [x] `P1-04` Parse and redact credential-bearing URLs without corrupting valid URL
  structure.
- [~] `P1-05` Add structured parsers for `.env`, JSON, YAML, and TOML. `.env` catalog
  support exists; dedicated JSON/YAML/TOML structural transforms remain.
- [x] `P1-06` Implement entropy plus secret-context detection; entropy alone must not
  block by default.
- [x] `P1-07` Implement deterministic overlap resolution for conflicting findings.
- [x] `P1-08` Implement redaction modes: `env-ref`, `schema-only`, `placeholder`,
  cryptographically randomized operation-local `surrogate`, and `block`. Defer
  synthetic typed PII until typed PII detection exists. Evidence: detector tests,
  2026-06-11.
- [x] `P1-09` Ensure replacements preserve useful structure and never reveal a raw
  prefix or suffix that policy classifies as sensitive.
- [x] `P1-10` Implement recursive scanning with ignore rules, symlink policy, file-size
  limits, binary-file handling, and no traversal outside the requested root.
- [x] `P1-11` Implement `blindfold scan [PATH]` with text/JSON completeness metadata
  and distinct clean/findings/incomplete exit codes.
- [x] `P1-12` Implement `blindfold redact [FILE]`, stdin, and atomic protected file
  output.
- [~] `P1-13` Add a detector corpus with true positives, false positives, encoded
  variants, split values, and malformed structured data.
- [~] `P1-14` Add fuzz/property tests asserting redaction never reproduces detected
  input and never panics on arbitrary bytes.
- [ ] `P1-15` Benchmark large files and repositories; establish initial performance
  budgets.

**Exit criteria:**

- [x] Known-format fixtures are detected with source location and category.
- [ ] Redacted `.env`, JSON, YAML, TOML, and URLs remain syntactically useful.
- [x] Private keys are blocked in balanced mode.
- [ ] The false-positive corpus passes the agreed threshold.
- [x] Raw fixture values do not appear in stdout, stderr, logs, panic output, snapshots,
  or JSON reports unless an explicit unsafe test-only harness is used.
- [x] Contextual matches cover the complete accepted lexical value or are rejected;
  punctuation-rich and oversized regression tests pass.

### Phase 2: SafeRefs and Destination-Aware Policy

**Goal:** Make every reveal, redact, warn, and block decision explicit and testable.

**Depends on:** P1

**Required tasks:**

- [x] `P2-01` Specify the SafeRef grammar, escaping rules, maximum length, and version.
- [x] `P2-02` Generate stable SafeRefs within project/session scope without putting a
  secret-derived substring in the reference.
- [x] `P2-03` Detect and safely handle user text that resembles a SafeRef.
- [~] `P2-04` Implement policy evaluation by destination, sensitivity, source, command,
  file pattern, tool, and mode.
- [x] `P2-05` Implement `chill`, `balanced`, `strict`, and `ci` presets as explicit
  policy data.
- [~] `P2-06` Define precedence for defaults, project config, local overrides,
  command-line flags, and explicit deny rules.
- [x] `P2-07` Implement `redact`, `block`, `warn`, and `restore` actions; restoration
  must require a trusted destination.
- [x] `P2-08` Implement scoped allow rules with reason, expiry, and audit metadata.
- [x] `P2-09` Implement `blindfold policy check` and a policy explanation command that
  shows the matched rule without raw input.
- [x] `P2-10` Add a policy matrix test covering every sensitivity/destination/mode
  combination.
- [x] `P2-11` Define fail-closed behavior for invalid, missing, or ambiguous policy.

**Exit criteria:**

- [x] Every supported destination has a deterministic default action.
- [x] No untrusted destination can request restoration.
- [ ] Rule precedence and overrides are documented and covered by tests.
- [x] SafeRefs are stable in scope, collision-resistant, and harmless when forged.

### Phase 3: Encrypted Local Vault and Audit

**Goal:** Store SafeRef mappings locally without exposing raw values through storage,
listing, logging, backup, or audit interfaces.

**Depends on:** P2

**Required tasks:**

- [x] `P3-01` Write an architecture decision comparing OS keychain-backed encryption
  and encrypted SQLite.
- [x] `P3-02` Implement the vault interface and selected portable encrypted backend.
- [!] `P3-03` Obtain or wrap the encryption key through an OS-protected mechanism; do
  not store the key beside ciphertext.
- [x] `P3-04` Bind records to project and session scopes.
- [x] `P3-05` Implement TTL, expiry cleanup, and explicit clear operations.
- [~] `P3-06` Store only required metadata: SafeRef, kind, label, keyed fingerprint,
  source identifier, scope, timestamps, and policy metadata.
- [x] `P3-07` Prevent unsafe debug/serialization implementations for raw-value types.
- [x] `P3-08` Implement `blindfold vault list` and `vault clear`; listing must never
  reveal raw values.
- [x] `P3-09` Implement append-only, audit-safe events with rotation and restrictive
  filesystem permissions.
- [~] `P3-10` Implement `blindfold audit` with filters and JSON output. JSON-lines output
  exists; filters remain.
- [x] `P3-11` Test wrong-key, corrupt-record, concurrent-access, crash-recovery, and
  permission scenarios.
- [x] `P3-13` Reject symlinked vault, lock, audit, and rotation paths; preserve external
  targets in regression tests. Descriptor-relative race hardening remains deferred.
- [x] `P3-12` Document deletion semantics and what encrypted artifacts may remain in
  filesystem backups.

**Exit criteria:**

- [x] Secret values are encrypted at rest and decrypted only for an authorized local
  operation.
- [x] Vault and audit files use restrictive permissions.
- [~] Corruption and unavailable key states fail closed; OS keychain states await the
  keychain adapter.
- [x] Vault list, audit output, logs, and errors pass the no-raw-secret tests.

### Phase 4: Local LLM Proxy

**Goal:** Sanitize supported LLM traffic before it leaves the machine and before it
returns to the agent.

**Depends on:** P1-P3

**Required tasks:**

- [~] `P4-01` Bind to loopback by default. Non-loopback authentication is not
  implemented; release behavior must reject non-loopback exposure.
- [x] `P4-02` Implement upstream allowlisting and reject proxy loops.
- [x] `P4-03` Implement OpenAI-compatible request normalization and sanitization.
- [x] `P4-04` Implement Anthropic-compatible request normalization and sanitization.
- [x] `P4-05` Scan supported text-bearing fields, including nested messages,
  OpenAI function/tool arguments, Anthropic tool inputs/JSON deltas, and system prompts.
- [x] `P4-06` Strip or redact sensitive headers and query parameters from logs and
  errors.
- [x] `P4-07` Sanitize non-streaming upstream responses.
- [~] `P4-08` Implement streaming sanitization with bounded buffering and overlap
  sufficient for the longest supported detector.
- [~] `P4-09` Define behavior for undecidable streaming fragments and upstream
  disconnects; prefer withholding data to leaking it.
- [x] `P4-10` Preserve status codes and safe error context without forwarding raw
  upstream bodies blindly.
- [x] `P4-11` Implement timeouts, body limits, cancellation, graceful shutdown, and
  backpressure.
- [x] `P4-12` Implement `blindfold proxy --listen 127.0.0.1:8787`.
- [x] `P4-13` Add fake upstream servers and packet-capture-style assertions proving
  known raw values never reach the upstream.
- [x] `P4-14` Test secrets split across every possible streaming chunk boundary.
- [x] `P4-15` Document TLS trust assumptions and why Blindfold is an application-level
  proxy rather than a transparent TLS interceptor.
- [x] `P4-16` Add explicit payload-free command/session/request tracing with request
  IDs, closed activity/route labels, coverage, byte counts, detector categories,
  sanitized structural pointers, outcomes, and closed issue codes. Persist only bounded
  owner-only metadata; never payloads, headers, query strings, or raw spans.

**Exit criteria:**

- [x] OpenAI-compatible and Anthropic-compatible request/response fixtures pass.
- [x] No known fixture reaches the fake upstream in raw form.
- [x] Streaming split-boundary tests pass.
- [x] Proxy errors, access logs, tracing, and metrics contain no raw request/response
  bodies.
- [x] Unsupported payloads fail with a clear, safe error rather than bypassing scans.

### Phase 4B: Egress Network Guard

**Goal:** Make guard mode control outbound destinations so direct known-provider calls
do not bypass the LLM redaction proxy.

**Depends on:** P4

**Required tasks:**

- [ ] `P4B-01` Implement an explicit local egress proxy on `127.0.0.1:8789`.
- [ ] `P4B-02` Set `HTTP_PROXY`, `HTTPS_PROXY`, compatible proxy variables, and
  `NO_PROXY` for guarded agent processes.
- [ ] `P4B-03` Block direct `CONNECT` traffic to known LLM providers, including
  OpenAI, Anthropic, OpenRouter, Gemini, Mistral, and Groq.
- [ ] `P4B-04` Allow common package and development registries by default policy.
- [ ] `P4B-05` Implement unknown-domain ask/block behavior with project-scoped allow
  and deny decisions.
- [ ] `P4B-06` Add `bf allow domain ...`, `bf deny domain ...`, and `bf status`
  commands or equivalent policy subcommands.
- [ ] `P4B-07` Log/audit destination decisions without request bodies, headers, query
  strings, or raw secrets.
- [ ] `P4B-08` Document that v1 does not install a root CA and does not inspect
  arbitrary encrypted HTTPS bodies.

**Exit criteria:**

- [ ] Direct `CONNECT api.openai.com:443`, `api.anthropic.com:443`, and
  `openrouter.ai:443` are blocked outside the Blindfold LLM proxy path.
- [ ] `registry.npmjs.org`, `pypi.org`, `crates.io`, GitHub, and Go module mirrors
  are allowed by default policy.
- [ ] Unknown domains ask or block according to `.blindfold.yaml`.
- [ ] Egress guard logs and traces contain no raw payloads.
- [ ] Startup output for guard mode clearly reports direct-provider blocking status.

### Phase 5: Secret Execution Runtime

**Goal:** Run a local process with selected secrets while returning only sanitized
output to the caller.

**Depends on:** P1-P3

**Required tasks:**

- [x] `P5-01` Implement `blindfold exec --secret NAME -- COMMAND`.
- [~] `P5-02` Resolve values from the process environment without displaying them.
  CLI vault resolution is not integrated.
- [x] `P5-03` Require explicit secret names; do not inherit the entire parent
  environment by default.
- [x] `P5-04` Define a minimal baseline environment and allow explicit passthrough
  variables.
- [x] `P5-05` Inject selected values only into the child process.
- [~] `P5-06` Concurrently capture and sanitize bounded stdout/stderr without deadlocks.
  Output is returned after completion rather than streamed interactively.
- [x] `P5-07` Preserve exit code and propagate termination signals.
- [x] `P5-08` Redact values written without a trailing newline and values split across
  stdout/stderr chunks.
- [~] `P5-09` Produce in-memory safe execution metadata. CLI audit-log integration is
  not implemented.
- [~] `P5-10` Add policy controls for executable, working directory, network use, and
  allowed secret labels.
- [x] `P5-11` Document the limitation that a hostile child process can exfiltrate any
  secret intentionally provided to it.
- [x] `P5-12` Test child crashes, signals, timeouts, binary output, large output, and
  output containing all injected values.

**Exit criteria:**

- [x] A test child can authenticate to a fake local service with an injected secret.
- [x] The same secret is absent from parent-visible stdout, stderr, logs, audit, and
  process arguments.
- [x] Exit codes and signals behave like direct command execution.
- [x] Only explicitly approved secrets and environment variables reach the child.

### Phase 6: Guard Mode Agent Runner

**Goal:** Provide one-command `bf run --guard claude|codex|opencode` experience with
managed LLM proxy routing, egress guard configuration, and an accurately described
protection boundary.

**Depends on:** P4 and P5. Full guard mode depends on P4B.

**Required tasks:**

- [~] `P6-01` Spike Claude Code's supported proxy/base-URL, hook, MCP, and environment
  integration points; record exact protected and unprotected paths.
- [x] `P6-02` Implement `blindfold run --guard claude|codex|opencode` with native
  trailing arguments and per-run opt-out. Current shorthand remains as a compatibility
  path.
- [x] `P6-03` Start and health-check the local proxy, configure the child agent, and
  clean up on exit.
- [x] `P6-03B` Configure OpenRouter/OpenAI-compatible routing for OpenCode through
  Blindfold's local proxy.
- [ ] `P6-03C` Start and configure the egress guard once P4B exists.
- [!] `P6-04` Sanitize wrapper-managed stdout/stderr.
- [!] `P6-05` Protect supported file/tool reads through documented hooks or broker
  integration only in strict/future modes; do not claim guard-mode local file-read
  interception.
- [~] `P6-06` Detect common bypass conditions such as direct provider configuration,
  unsupported agent version, or unavailable hooks. Managed children now use an
  environment allowlist; credential brokering and version/hook checks remain.
- [x] `P6-07` Show startup status listing what is protected, degraded, or unprotected.
- [x] `P6-08` Add `--strict` startup checks that refuse to run when required protections
  cannot be established.
- [~] `P6-09` Add an end-to-end fake-agent test for `.env` SafeRefs, proxy sanitization,
  `blindfold exec`, and sanitized command output.
- [x] `P6-10` Write the Claude Code quickstart, limitations, troubleshooting, and demo.

**Exit criteria:**

- [~] `blindfold run --guard claude|codex|opencode` launches installed agents and
  routes configured provider traffic; full clean-project provider demos remain.
- [ ] Guard mode blocks direct known-provider egress once P4B lands.
- [x] Startup output accurately reports the active boundary.
- [x] Managed agents do not inherit the vault master key or unrelated parent secrets.
- [x] Global `--trace` is explicit per invocation and produces independently clearable,
  schema-validated command/session/request metadata through
  `trace list|show|tail|export|clear`.
- [x] Traced agent sessions report `degraded` with `direct_filesystem_unmediated` while
  direct project-file reads remain outside Blindfold mediation.
- [ ] Strict mode filesystem mediation or sandboxing prevents direct reads of sensitive
  project files without changing normal agent Git/worktree behavior inside the managed
  workspace.
- [ ] The full demo passes without a raw fixture appearing in agent-visible output or
  fake provider requests.
- [x] Strict mode refuses known unsafe/degraded configurations.

### Phase 7: Release Hardening and `v0.1.0`

**Goal:** Turn the working vertical slice into a reproducible, reviewable public
release.

**Depends on:** P0-P6

**Required tasks:**

- [~] `P7-01` Complete the MVP verification matrix in Section 14.
- [x] `P7-02` Run dependency, license, unsafe-code, and supply-chain review.
- [~] `P7-03` Perform a focused security review of detector bypasses, SafeRef forgery,
  vault permissions, proxy exposure, and subprocess leakage. 2026-06-11 review fixed
  surrogate predictability, partial contextual matches, tool payload gaps, unsupported
  media pass-through, diff evasions, SDK token forgery, and vault symlinks; audit
  integrity, TOCTOU hardening, and process-tree controls remain.
- [ ] `P7-04` Test clean installation and upgrade on supported macOS and Linux versions.
- [ ] `P7-05` Produce checksummed release artifacts and document verification.
- [x] `P7-06` Complete README quickstart, guarantees, limitations, and security contact.
- [x] `P7-07` Publish known limitations and deferred threats without marketing
  overclaims.
- [ ] `P7-08` Tag `v0.1.0` and archive the release evidence.

**Exit criteria:**

- [ ] Every `v0.1.0` release gate passes.
- [ ] No open critical/high security issue is accepted without a written decision.
- [ ] Installation and demo instructions have been followed successfully from a clean
  machine/account.
- [ ] Release artifacts, checksums, changelog, and documentation agree on the version.

### Phase 8: Generated Diff Scanner

**Goal:** Prevent generated changes from introducing credentials or unsafe secret use.

**Depends on:** P2; may run in parallel with P3-P6

- [~] `P8-01` Parse staged, working-tree, and supplied patch input without requiring a
  Git repository for supplied patches.
- [x] `P8-02` Scan added lines while retaining enough context for useful findings;
  exact valid SafeRefs are masked without exempting the rest of the line.
- [x] `P8-03` Add elevated rules for frontend/public files, fixtures, CI config, and
  `.env` files.
- [~] `P8-04` Implement `blindfold diff-check` with stable JSON/SARIF output and
  meaningful exit codes.
- [x] `P8-05` Provide actionable remediation without echoing the detected value.
- [~] `P8-06` Add CI documentation and tests for staged, unstaged, renamed, binary, and
  untracked files.

**Exit criteria:**

- [x] Known hardcoded-secret patches fail with location and safe remediation.
- [x] Clean and explicitly allowed fake fixtures pass.
- [x] CI output contains no raw detected values.

### Phase 9: MCP Proxy

**Goal:** Resolve approved SafeRefs inside trusted MCP calls and sanitize tool results.

**Depends on:** P2-P4

- [x] `P9-01` Define the supported MCP transports and protocol version.
- [~] `P9-02` Intercept tool calls, resources, prompts, notifications, and errors where
  sensitive content can occur.
- [~] `P9-03` Validate SafeRefs and resolve them only for an allowed server/tool/input
  field.
- [x] `P9-04` Add least-privilege per-tool and per-secret scopes.
- [x] `P9-05` Sanitize responses before returning them to the agent.
- [x] `P9-06` Protect against malicious tool descriptions and errors attempting to
  solicit or reflect secrets.
- [x] `P9-07` Audit tool identity, requested SafeRefs, policy result, and redaction
  counts.
- [~] `P9-08` Add a fake MCP server and end-to-end tests.
- [x] `P9-09` Bound CLI stdio input per JSON-RPC message and reject unresolved
  plaintext in credential-named tool argument fields.

**Exit criteria:**

- [x] Unauthorized SafeRef resolution is denied.
- [x] Approved tools receive raw values only in approved fields.
- [x] Agent-visible results, logs, and audit remain sanitized.

### Phase 10: App SDK Preview

**Goal:** Offer destination-aware PII tokenization to application developers without
delaying the coding-agent product.

**Depends on:** Stable SafeRef, policy, and vault contracts

- [x] `P10-01` Write the SDK threat model and restoration rules.
- [x] `P10-02` Stabilize a language-neutral boundary API.
- [x] `P10-03` Implement a TypeScript preview SDK.
- [x] `P10-04` Add end-user-only PII restoration and prohibit secret restoration to
  LLM, log, or memory destinations.
- [x] `P10-05` Add compatibility, migration, and audit tests, including unpredictable
  tokens, forged-token inertness, collision avoidance, and longest-first overlap
  handling.

This phase is explicitly outside `v0.1.0`.

---

## 10. Threat Model

`THREAT_MODEL.md` must define assets, actors, trust boundaries, entry points,
assumptions, threats, mitigations, residual risks, and out-of-scope threats.

### Protected Assets

- Raw credentials, tokens, private keys, certificates, and credential-bearing URLs
- Caller-identified PII supplied to the preview SDK; automatic PII discovery remains
  outside the implemented detector boundary
- Vault encryption keys and SafeRef mappings
- Policy and audit integrity
- The user's expectation of which paths are protected

### In-Scope Protections

- Accidental secrets in managed LLM prompts and responses
- Direct known-provider LLM calls in guard mode once the egress guard is active
- Secrets and PII in managed shell output
- Raw values entering Blindfold logs or audit events
- Model or tool responses reflecting known secrets
- Secrets introduced in generated diffs
- Supported MCP tool arguments and results
- Basic splitting, encoding, and chunk-boundary bypass attempts

### Out of Scope for `v0.1.0`

- A compromised operating system, kernel, shell, or user account
- A malicious process running with the user's permissions
- A child process intentionally exfiltrating a secret explicitly granted to it
- Agent network or filesystem access that bypasses Blindfold
- Provider traffic sent directly rather than through the configured proxy before the
  egress guard is active, or from clients that ignore proxy settings
- Memory scraping, swap inspection, hardware attacks, and side-channel attacks
- Guaranteed detection of every unknown or transformed secret

### Future Strict-Sandbox Work

- Container or OS sandbox
- Brokered project filesystem mounts
- Sanitized process environment
- Process-tree monitoring and child egress controls

The product must not imply that future sandbox protections exist in `v0.1.0`.

---

## 11. Security Invariants

These are non-negotiable implementation requirements:

1. Raw values must be redacted before logging, tracing, metrics labels, audit, error
   formatting, or user-visible diagnostics.
2. Raw secret types must not implement unsafe default `Debug`, `Display`, or
   serialization behavior.
3. Telemetry is disabled by default. Any future telemetry is opt-in and excludes
   payloads, paths, labels, SafeRefs, and high-cardinality sensitive metadata.
4. Audit records contain SafeRefs or keyed fingerprints, never raw values.
5. Restoration is denied unless both the destination and operation are trusted by
   policy.
6. Unsupported or malformed security-sensitive input fails closed.
7. Proxy listeners bind to loopback by default.
8. Child processes receive only explicitly approved secrets and environment variables.
9. Test fixtures are fake, isolated, and mechanically checked not to be live.
10. Tests search every captured output and artifact for every raw fixture value.
11. Error handling must not fall back to dumping request bodies, subprocess
    environments, vault records, or upstream responses.
12. Overrides are narrow, visible, attributable, auditable, and optionally expiring.

Required regression tests should include:

- `no_raw_secret_leaks_in_output`
- `no_raw_secret_leaks_in_logs`
- `no_raw_secret_leaks_in_audit`
- `no_raw_secret_reaches_fake_upstream`
- `no_unapproved_env_reaches_child`
- `forged_saferef_does_not_restore`
- `stream_split_secret_is_redacted`

---

## 12. Documentation Deliverables

The documentation set for `v0.1.0` must include:

- `README.md`: promise, quickstart, demo, supported boundary, limitations, install,
  modes, roadmap, security contact, and license
- `SECURITY.md`: supported versions, private reporting process, expected response, and
  safe testing guidance
- `THREAT_MODEL.md`: the requirements in Section 10
- `docs/architecture.md`: data flow and trust boundaries
- `docs/guarantees.md`: precise guarantees and non-guarantees
- `docs/policy.md`: schema, precedence, destinations, actions, and examples
- `docs/claude-code.md`: setup, protected paths, bypass risks, and troubleshooting
- `docs/development.md`: build, test, lint, fixture, and release commands

Suggested README opening:

````markdown
# Blindfold

**Let AI agents use secrets without leaking secrets.**

Blindfold is a local privacy and secrets boundary for AI coding agents.

```text
Guard mode:
  Agent can read the repo.
  Managed LLM/provider traffic is redacted before leaving the machine.

Strict mode:
  Agent runs in a managed workspace where raw secrets are absent.
```

```sh
blindfold init
blindfold run --guard opencode
```
````

Avoid unqualified wording such as "your secrets can never leak." State the managed
boundary in the first screenful.

---

## 13. MVP Scope and Acceptance Criteria

### Included in `v0.1.0`

- Rust CLI and versioned configuration schema; full runtime configuration enforcement
  remains incomplete
- Secret scanning and redaction for files and stdin
- SafeRefs, destination-aware policy, encrypted vault, and safe audit
- OpenAI-compatible and Anthropic-compatible local proxy
- OpenRouter support through OpenAI-compatible proxy configuration
- Bounded request/response collection with JSON/SSE sanitization; true progressive
  streaming remains incomplete
- Guard mode runner that configures supported coding agents to use Blindfold-managed
  provider traffic
- Egress guard direct-provider blocking if P4B lands before release
- Secret execution runtime
- Claude Code, Codex, and OpenCode wrapper docs and one end-to-end demo
- macOS and Linux development targets; release support is gated on installation and key
  management evidence

### Excluded from `v0.1.0`

- Transparent OS-wide interception
- Strict container/network sandbox
- Agent local file-read mediation in guard mode
- MCP proxy
- Generated diff scanner, unless it completes without delaying the critical path
- PII restoration SDK
- Windows production support
- Dashboard, SSO, cloud sync, central policy, and compliance exports

### User-Facing Acceptance Checklist

- [x] `blindfold init` creates a safe, documented default configuration schema.
- [x] `blindfold doctor` identifies readiness and degraded protection without revealing
  values.
- [~] `blindfold scan .` detects the current corpus, reports safe locations and
  completeness; corpus thresholds remain.
- [x] `blindfold redact .env` produces useful key-preserving output.
- [x] Piped stdin can be redacted.
- [ ] `blindfold proxy` sanitizes OpenAI-compatible and Anthropic-compatible requests
  and responses.
- [x] OpenRouter/OpenAI-compatible routed traffic is sanitized when configured for
  OpenCode.
- [ ] Streaming sanitization catches a secret across every tested chunk boundary.
- [ ] `blindfold exec --secret NAME -- COMMAND` injects only approved values.
- [ ] Command stdout/stderr is sanitized while exit behavior is preserved.
- [ ] `blindfold run --guard opencode|claude|codex` completes the documented
  end-to-end demo without raw secrets reaching the fake provider.
- [ ] Guard mode blocks direct known-provider egress when the egress guard is enabled.
- [x] Startup output distinguishes protected, degraded, and unprotected paths.
- [x] Strict mode refuses to start when its required controls are unavailable.
- [x] Vault list and audit output are useful without revealing raw values.
- [x] README and threat model accurately describe current guarantees and limitations.
- [x] Apache License 2.0 is present.

---

## 14. Verification Matrix

Use this table as the release evidence index. Replace `TBD` with the actual command,
test, report, or artifact path when implementation begins.

| ID | Area | Verification | Pass condition | Evidence |
|---|---|---|---|---|
| `V-01` | Build | Clean debug and release builds | No warnings designated as errors; artifacts produced | TBD |
| `V-02` | Formatting/lint | Formatter and linter | No failures | TBD |
| `V-03` | Unit tests | Full unit suite | All tests pass | TBD |
| `V-04` | Integration | CLI/config/vault/proxy/exec suites | All tests pass | TBD |
| `V-05` | End to end | Claude wrapper demo with fake provider | Demo succeeds; no raw fixture escapes | TBD |
| `V-06` | Leak regression | Search captured output, logs, audit, temp artifacts, and fake upstream traffic | Zero raw fixture matches | TBD |
| `V-07` | Streaming | Split each fixture at every byte boundary supported by the detector | Every reconstruction is withheld/redacted | TBD |
| `V-08` | Detector quality | Positive and false-positive corpora | Meets documented recall/false-positive budget | TBD |
| `V-09` | Structured data | Parse redacted `.env`, JSON, YAML, TOML, and URLs | Output remains valid/useful or is safely blocked | TBD |
| `V-10` | Vault | Wrong key, corruption, permissions, concurrency, recovery, and audit read validation | Fails closed; no raw output | `cargo test -p blindfold-vault`; symlink and malformed audit tests |
| `V-11` | Proxy security | Loopback, upstream allowlist, loop prevention, limits, malformed payloads | Unsafe cases rejected safely | TBD |
| `V-11A` | Trace safety | Explicit enablement, closed schema, no payload/header/query retention, rotation, symlink rejection, clear | Trace JSON contains metadata only and modified records fail closed | `cargo test -p blindfold-trace -p blindfold-proxy -p blindfold-cli` |
| `V-12` | Exec isolation | Inspect child env and process args | Only approved values present; secret absent from argv | `cargo test -p blindfold-cli managed_wrapper_does_not_inherit_parent_secrets` |
| `V-13` | Policy | Complete mode/destination/sensitivity matrix | Every case has expected deterministic action | TBD |
| `V-14` | SafeRef abuse | Forged, malformed, replayed, expired, and cross-project references | No unauthorized restoration | TBD |
| `V-15` | Performance | Large repository, large file, and high-volume stream benchmarks | Meets recorded budgets without unbounded memory | TBD |
| `V-16` | Dependencies | Vulnerability, license, and supply-chain checks | No unapproved critical/high issue or incompatible license | TBD |
| `V-17` | Platforms | Clean install and demo on supported macOS/Linux matrix | All required platforms pass | TBD |
| `V-18` | Documentation | Follow quickstart from a clean environment | Commands and stated behavior match release | TBD |

### Initial Performance Budgets

Confirm or revise these during P1 and record the decision:

- CLI startup: target under 150 ms on a typical developer machine
- Text scanning: target at least 50 MB/s for regex/structured scanning
- Proxy non-streaming overhead: target p95 under 25 ms excluding upstream latency
- Streaming sanitizer: bounded memory with a documented maximum buffer
- Vault lookup: target p95 under 10 ms for a warm local store

Security correctness takes priority over these targets. A missed performance budget is
visible release debt; it is never a reason to bypass scanning.

---

## 15. Release Gates

`v0.1.0` may be released only when:

- [ ] All P0-P7 required tasks and phase exit criteria are complete.
- [ ] All Verification Matrix rows required for `v0.1.0` pass with linked evidence.
- [ ] The end-to-end demo uses only fake local secrets and a fake or isolated upstream.
- [ ] No raw fixture value appears in captured output or artifacts.
- [ ] No open critical/high security issue lacks a documented resolution.
- [ ] Known limitations are published and visible from the README.
- [ ] Install, uninstall, upgrade, and rollback instructions are tested.
- [ ] Release binaries are reproducible where practical, checksummed, and signed if
  release infrastructure supports it.
- [ ] The version, changelog, docs, artifacts, and Git tag agree.

### Definition of Done for Every Task

A task is done only when:

- [ ] Implementation is complete and formatted.
- [ ] Positive, negative, and leak-regression tests are added where relevant.
- [ ] Errors are safe and actionable.
- [ ] Documentation/config examples are updated.
- [ ] Compatibility or migration impact is addressed.
- [ ] Verification evidence is linked from the task or matrix.
- [ ] No unrelated scope or generated artifacts are included.

---

## 16. Risks and Open Decisions

Track these explicitly; unresolved high-impact decisions block the affected phase.

| ID | Type | Question or risk | Needed by | Status |
|---|---|---|---|---|
| `D-01` | Decision | Confirm Rust after a short proxy/streaming/keychain spike | P0 | Open |
| `D-02` | Decision | Select encrypted vault backend and key management model | P3 | Open |
| `D-03` | Decision | Define the exact SafeRef grammar and anti-forgery model | P2 | Open |
| `D-04` | Decision | Define supported macOS/Linux versions and Windows stance | P0 | Open |
| `D-05` | Decision | Confirm Claude Code integration surfaces and bypass limitations | P6 | Open |
| `D-06` | Decision | Set measurable detector recall and false-positive budgets | P1 | Open |
| `R-01` | Risk | Wrapper cannot mediate every Claude Code file/tool/network path | P6 | Open |
| `R-02` | Risk | Streaming output leaks a value before enough context is buffered | P4 | Open |
| `R-03` | Risk | Local child process intentionally exfiltrates an injected secret | P5 | Accepted limitation |
| `R-04` | Risk | Vault/keychain behavior differs significantly by platform | P3 | Open |
| `R-05` | Risk | Detector false positives make the default workflow unusable | P1 | Open |
| `R-06` | Risk | Dependencies log or serialize sensitive payloads unexpectedly | P0-P7 | Open |
| `R-07` | Risk | Automatic PII discovery is absent while older design examples imply it exists | P1/P10 | Open: claims narrowed; scope decision required |
| `R-08` | Risk | Managed agents using environment-only provider credentials cannot authenticate without bypass | P6 | Open: implement a credential broker |

For each open item, add an owner, target date, decision link, and mitigation when the
project moves into active implementation.

---

## 17. Priorities and Backlog Boundaries

Prioritize:

1. Correct and accurately described security boundaries
2. No-raw-secret regression coverage
3. Simple first-run UX
4. Low false positives and useful redaction
5. Streaming correctness
6. Clear failure and degraded-mode behavior
7. Agent-agnostic core interfaces
8. Performance and packaging

Do not prioritize before `v0.1.0`:

- Dashboard or desktop UI
- Enterprise SSO/SAML
- Cloud sync or hosted policy
- Centralized audit collection
- Multiple application SDKs
- Broad agent integrations
- Compliance reports
- Transparent system-wide network interception

---

## 18. Product Principles

- Simple outside, serious inside.
- Redact by default; block when the risk cannot be safely transformed.
- Agents should remain useful while raw values remain invisible.
- Safe references are useful context; raw values are not.
- Local-first with no cloud dependency for the core.
- Explain every block and degraded protection state.
- Make overrides narrow, safe, visible, and auditable.
- Never claim protection outside the controlled boundary.
- Prefer a smaller verifiable guarantee over a broader unprovable claim.

---

## 19. Target Demo

The first release demo is:

```sh
blindfold init
blindfold run --guard opencode
```

Within a sample project, OpenCode may read local files normally, including fake secret
fixtures. Its configured LLM traffic goes through Blindfold. A fake upstream capture
proves that raw `.env` values, API keys, and private-key fixtures are redacted before
the provider sees them. The demo also invokes tests through `blindfold exec` with a
realistic fake credential and verifies sanitized command output.

That vertical slice is the core product and the `v0.1.0` release target.
