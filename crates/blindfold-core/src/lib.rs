//! Security-domain types and invariants for Blindfold.
//!
//! This crate deliberately keeps raw secret values in a small, auditable type and
//! separates syntactic `SafeRef` validation from authorization. Higher-level crates
//! remain responsible for policy evaluation and vault-backed reference resolution.

#![forbid(unsafe_code)]

mod error;
mod finding;
mod safe_log;
mod safe_ref;
mod secret_value;
mod types;

pub use error::{ErrorCode, RedactedError};
pub use finding::{Finding, FindingError};
pub use safe_log::{EventLevel, SafeEvent, SafeEventSink, SafeField};
pub use safe_ref::{SafeRef, SafeRefError, SafeRefKind};
pub use secret_value::SecretValue;
pub use types::{Action, Destination, SecretKind, Sensitivity, Source};
