# Supported Platforms

## v0.1.0 Policy

Blindfold `v0.1.0` targets macOS and Linux.

| Platform | Status | Notes |
|---|---|---|
| macOS | Supported | Maintained Apple releases; Apple silicon primary, Intel where CI/release testing remains available |
| Linux | Supported | Maintained x86_64 distributions with a usable Secret Service implementation |
| Windows | Unsupported | No artifact, support commitment, or security-boundary guarantee for `v0.1.0` |
| Other Unix | Unsupported | May compile, but is outside release and security validation |

The exact release matrix will name tested OS versions before `v0.1.0`. "Supported" means
the release installation and managed end-to-end demo pass on that matrix. It does not
mean every kernel, desktop environment, libc, shell, or package combination is covered.

## Platform Assumptions

macOS uses Keychain for protection of vault key material. Linux requires a functioning
Secret Service provider and user session where the selected backend depends on it.
Unavailable, locked, or incompatible key storage must fail closed rather than store a
key beside ciphertext or fall back to plaintext.

Headless Linux support depends on a documented secure key-storage configuration and must
not silently weaken the vault.

## Windows

Windows production support is deferred because process, credential-store, filesystem
permission, console, and release behavior require dedicated design and testing. A
successful local compilation does not change the unsupported status.

Adding Windows requires an ADR, CI and release coverage, a credential-storage decision,
threat-model review, and end-to-end security evidence.
