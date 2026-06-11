# Supported Platforms

## v0.1.0 Policy

Blindfold `v0.1.0` targets macOS and Linux.

| Platform | Status | Notes |
|---|---|---|
| macOS | Development target | Apple silicon is tested in development; release support evidence and Keychain integration remain |
| Linux | Development target | CI target; release installation evidence and Secret Service integration remain |
| Windows | Unsupported | No artifact, support commitment, or security-boundary guarantee for `v0.1.0` |
| Other Unix | Unsupported | May compile, but is outside release and security validation |

The exact release matrix will name tested OS versions before `v0.1.0`. "Supported" means
the release installation and managed end-to-end demo pass on that matrix. It does not
mean every kernel, desktop environment, libc, shell, or package combination is covered.

## Platform Assumptions

Production support is intended to use macOS Keychain and Linux Secret Service for vault
key material. Those adapters are not implemented. The preview vault requires a
caller-supplied key and must not be represented as release-ready key management.

Headless Linux support depends on a documented secure key-storage configuration and must
not silently weaken the vault.

## Windows

Windows production support is deferred because process, credential-store, filesystem
permission, console, and release behavior require dedicated design and testing. A
successful local compilation does not change the unsupported status.

Adding Windows requires an ADR, CI and release coverage, a credential-storage decision,
threat-model review, and end-to-end security evidence.
