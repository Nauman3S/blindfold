# Architecture Decisions

Architecture decision records retain their original rationale once accepted. Status and
supersession notes may be updated so historical commands are not mistaken for the
current contract; a later decision owns the new direction.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-rust-baseline.md) | Rust 1.96, edition 2024, minimal dependencies | Accepted |
| [0002](0002-vault-backend.md) | Encrypted local database with OS-protected key | Accepted direction |
| [0003](0003-saferef-format.md) | Versioned opaque SafeRef envelope | Accepted |
| [0004](0004-managed-boundary-and-platforms.md) | Managed boundary; macOS/Linux support | Partly superseded by 0008 |
| [0005](0005-proxy-fail-closed-compatibility.md) | Proxy fail-closed compatibility gates | Updated by 0008 |
| [0006](0006-mitm-proxy-library-evaluation.md) | MITM proxy library evaluation | Deferred |
| [0007](0007-detector-dependencies.md) | Detector dependency selection | Accepted |
| [0008](0008-constrained-noninteractive-runner.md) | One constrained noninteractive runner | Accepted |
| [0009](0009-harness-adapter-security-boundary.md) | Declarative, explicitly installed harness adapters | Manifest host and built-in gates implemented |
| [0010](0010-locked-container-egress-boundary.md) | Locked model-only container boundary | Preview implemented |
