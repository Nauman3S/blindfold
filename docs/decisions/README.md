# Architecture Decisions

Architecture decision records are immutable once accepted, except for typo or link
fixes. A later decision should supersede an earlier one when direction changes.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-rust-baseline.md) | Rust 1.96, edition 2024, minimal dependencies | Accepted |
| [0002](0002-vault-backend.md) | Encrypted local database with OS-protected key | Accepted direction |
| [0003](0003-saferef-format.md) | Versioned opaque SafeRef envelope | Accepted |
| [0004](0004-managed-boundary-and-platforms.md) | Managed boundary; macOS/Linux support | Accepted |
| [0005](0005-proxy-fail-closed-compatibility.md) | Proxy fail-closed compatibility gates | Accepted |
| [0006](0006-mitm-proxy-library-evaluation.md) | MITM proxy library evaluation | Proposed spike |
