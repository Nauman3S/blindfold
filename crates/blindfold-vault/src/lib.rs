//! Portable encrypted storage and safe audit primitives for Blindfold.
//!
//! This crate implements an authenticated encrypted file store using a
//! caller-supplied 32-byte master key. It does **not** integrate with an OS
//! keychain; callers are responsible for obtaining and protecting the key.
//! Vault values are scoped to a project and session and are never exposed by
//! metadata listing APIs. Audit events accept only closed, reviewed fields.

#![forbid(unsafe_code)]

mod audit;
mod error;
mod fs;
mod vault;

pub use audit::{AuditAction, AuditEvent, AuditLog, AuditOutcome, RotationPolicy};
pub use error::{VaultError, VaultResult};
pub use vault::{EntryMetadata, MasterKey, Scope, Vault};
