# ADR 0002: Vault Backend Direction

- Status: Accepted direction; implementation spike required
- Date: 2026-06-11

## Context

SafeRef mappings require local persistence, scoped lookup, expiry, concurrency, and
crash recovery. Storing each value directly in an OS credential store complicates
queries and portability, while storing a database encryption key beside its ciphertext
does not provide a meaningful boundary.

## Decision

Use a local authenticated-encrypted record store, expected to be SQLite, with a random
master key stored or wrapped by:

- macOS Keychain on macOS; and
- a Secret Service implementation on Linux.

The database stores ciphertext and safe metadata only. The master key is never stored in
the database directory. Unavailable or locked key services, corrupt records, wrong keys,
or unsupported platforms fail closed.

Use established authenticated-encryption and key-derivation crates or OS primitives. Do
not implement cryptographic algorithms. The implementation spike must confirm crate
maintenance, file permissions, atomicity, concurrent access, backup behavior, and
headless Linux operation before this direction becomes final.

## Consequences

This supports structured expiry and audit-safe metadata while keeping key material
separate. It adds OS integration and SQLite dependencies and requires platform-specific
testing.

Encrypted database files may remain in backups after deletion. Blindfold can delete
local records and key references but cannot guarantee erasure from external backups.
