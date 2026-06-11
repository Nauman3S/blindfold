//! Secret detection, redaction, and bounded filesystem scanning.
//!
//! Findings intentionally contain only classifications and byte spans. They never
//! own matched bytes, so ordinary formatting cannot disclose a detected value.

#![forbid(unsafe_code)]

mod detector;
mod finding;
mod overlap;
mod redaction;
mod scanner;

pub use detector::{BuildError, Detector, DetectorSet};
pub use finding::{Confidence, Finding, SecretKind, Span, SpanError};
pub use overlap::resolve_overlaps;
pub use redaction::{
    DotenvCatalog, RedactionError, RedactionMode, RedactionOptions, RedactionOutput, Redactor,
};
pub use scanner::{
    BinaryHandling, FileScan, ScanError, ScanLimits, ScanReport, Scanner, ScannerBuilder,
};
