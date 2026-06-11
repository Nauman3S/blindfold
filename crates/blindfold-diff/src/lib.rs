//! Parse unified patches and scan added lines for likely secrets.
//!
//! Supplied patches are handled without invoking Git. Git-backed entry points use
//! fixed argument lists and return redacted errors that never include repository
//! output or patch contents.

#![forbid(unsafe_code)]

mod git;
mod patch;
mod scan;

pub use git::{GitDiff, GitError, read_git_patch, scan_git};
pub use patch::{
    FileChange, FilePatch, Hunk, Patch, PatchError, PatchLine, PatchLineKind, parse_patch,
};
pub use scan::{
    AddedLine, BuiltinDetector, Detection, Detector, Finding, FindingCategory, PathRisk, Report,
    ScanOutcome, Severity, scan, scan_patch, scan_with,
};
