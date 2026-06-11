# ADR 0002: Vault Backend Direction

- Status: Portable encrypted-file implementation accepted; OS adapter spike required
- Date: 2026-06-11

## Context

SafeRef mappings require local persistence, scoped lookup, expiry, concurrency, and
crash recovery. Storing each value directly in an OS credential store complicates
queries and portability, while storing a database encryption key beside its ciphertext
does not provide a meaningful boundary.

## Decision

The first implementation uses a local authenticated-encrypted file store with atomic
replacement and a caller-supplied random master key. The planned production adapters
will store or wrap that key with:

- macOS Keychain on macOS; and
- a Secret Service implementation on Linux.

The vault file stores ciphertext and safe metadata only. The master key is never stored
in the vault directory by Blindfold. Corrupt records and wrong keys fail closed.

Use established authenticated-encryption and key-derivation crates or OS primitives. Do
not implement cryptographic algorithms. The implementation spike must confirm crate
maintenance, file permissions, atomicity, concurrent access, backup behavior, and
headless Linux operation before this direction becomes final.

## Consequences

This supports structured expiry and audit-safe metadata while keeping key material
separate. Until OS adapters exist, callers must supply the key out of band and production
use is not recommended.

Encrypted database files may remain in backups after deletion. Blindfold can delete
local records and key references but cannot guarantee erasure from external backups.
