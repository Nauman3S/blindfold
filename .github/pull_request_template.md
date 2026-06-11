## Summary

Describe the behavior and why it is needed.

## Security Boundary

State which managed path changes, its trusted destination, and its fail-closed behavior.
Write "No boundary change" when applicable.

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo audit`
- [ ] `cargo deny check`
- [ ] Gitleaks
- [ ] No live credentials or customer data included
- [ ] Documentation/ADR updated where required
