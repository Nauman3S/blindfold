## Summary

Describe the behavior and why it is needed.

## Security Boundary

State which managed path changes, its trusted destination, and its fail-closed behavior.
Write "No boundary change" when applicable.

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-targets --all-features`
- [ ] `npm --prefix sdk/typescript test`
- [ ] `PYTHONPATH=sdk/python/src python3 -m unittest discover -s sdk/python/tests -v`
- [ ] Managed runner smoke test when agent/proxy behavior changes
- [ ] Adapter manifest, capability, and bounded version tests when harness behavior changes
- [ ] `cargo audit`
- [ ] `cargo deny check`
- [ ] Gitleaks
- [ ] No live credentials or customer data included
- [ ] Documentation/ADR updated where required
- [ ] No unsupported interactive, opaque transport, or bypass path introduced
