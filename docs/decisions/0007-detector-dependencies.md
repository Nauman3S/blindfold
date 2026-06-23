# Detector Dependencies

Status: accepted, 2026-06-23

Blindfold's live proxy requires bounded, in-process detection with exact byte spans.

- `url` 2.5.8 parses and validates credential-bearing URLs. It was already present in
  the workspace dependency graph and is maintained by Servo under MIT/Apache-2.0.
- `email_address` 0.2.9 validates bounded email candidates under MIT. Default Serde
  support is disabled.
- `rlibphonenumber` 2.2.5 uses Google libphonenumber metadata to validate bounded
  international phone candidates under Apache-2.0. Google lists this Rust port from
  the upstream libphonenumber repository.

Gitleaks remains the pinned repository and CI scanner. It is not embedded in the live
proxy because it is a Go CLI rather than a stable Rust library API. Nosey Parker is
also CLI-oriented and datastore-heavy. Spawning either tool for every provider frame
would add latency, process availability, and raw-payload handoff risks.

Candidate extraction deliberately favors precision. Phone numbers must include a `+`
country code, and automatic PII support does not claim names, postal addresses,
national identifiers, or financial account numbers.

The initially evaluated `phonenumber` crate was rejected because its dependency graph
included the unmaintained `atomic-polyfill` crate. Dependency acceptance requires both
`cargo audit` and `cargo deny check` to pass.
