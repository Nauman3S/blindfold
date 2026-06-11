# Release Policy

## Versioning

Blindfold uses Semantic Versioning.

Before `1.0.0`, a minor release may contain breaking changes to configuration, policy,
SafeRef, vault, or CLI contracts. Such changes must be documented in the changelog with
migration guidance. Patch releases must not intentionally break documented interfaces.

## Changelog

User-visible and security-relevant changes are added to `CHANGELOG.md` under
`[Unreleased]`. A release moves those entries into a dated heading:

```text
## [0.1.0] - YYYY-MM-DD
```

The version in source metadata, documentation, artifacts, checksums, and Git tag must
agree.

## Release Gates

A release requires:

- all scope and phase criteria for that version complete;
- formatting, Clippy, tests, release build, audit, deny, and secret scan passing;
- supported macOS and Linux installation and end-to-end evidence;
- no raw fixture value in captured output, logs, audit, temporary artifacts, or fake
  upstream traffic;
- no unresolved critical or high security issue without a written decision;
- published managed-boundary limitations;
- checksummed artifacts; and
- a changelog entry and annotated `vX.Y.Z` tag.

Windows artifacts must not be published for `v0.1.0`.

## Security Releases

Security fixes should minimize disclosure before users can update. The advisory,
changelog, and release notes should describe impact and affected versions without
including live secrets or unsafe reproduction data. Backports are considered for the
latest prior minor when they are low-risk and users cannot reasonably migrate
immediately.

## Pre-Releases

Tags such as `v0.1.0-rc.1` may be used for release candidates. Pre-releases carry no
production support commitment and must be clearly identified as such.

## Rollback

Release notes must identify configuration or storage migrations and whether rollback is
safe. A release requiring an irreversible vault migration must provide a tested backup
and recovery procedure before publication.
