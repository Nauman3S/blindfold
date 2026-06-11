use std::fmt;
use std::path::Path;
use std::process::Command;

use crate::{Patch, PatchError, Report, parse_patch, scan_patch};

/// Explicit Git diff source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GitDiff {
    /// Changes staged in the index.
    Staged,
    /// Tracked working-tree changes not staged in the index.
    WorkingTree,
}

/// Safe failure from a Git-backed scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GitError {
    /// Git could not be started.
    Spawn,
    /// Git rejected the repository or diff operation.
    CommandFailed,
    /// Git emitted non-UTF-8 patch output.
    NonUtf8Output,
    /// Git emitted a malformed patch.
    InvalidPatch(PatchError),
}

impl fmt::Display for GitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Spawn => "could not start git",
            Self::CommandFailed => "git diff failed",
            Self::NonUtf8Output => "git diff output is not valid UTF-8",
            Self::InvalidPatch(_) => "git produced an invalid patch",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for GitError {}

/// Runs a fixed-form Git diff and parses its patch.
///
/// The repository path is passed as one argument after `-C`; it is never parsed
/// as command text. External diff drivers, text conversion, and pagers are
/// disabled. Untracked files are not included by Git's working-tree diff.
///
/// # Errors
///
/// Returns a redacted [`GitError`] if Git cannot run, rejects the operation,
/// emits non-UTF-8 output, or emits a malformed patch.
pub fn read_git_patch(repository: &Path, source: GitDiff) -> Result<Patch, GitError> {
    let mut command = Command::new("git");
    command
        .arg("-c")
        .arg("diff.external=")
        .arg("-c")
        .arg("core.pager=cat")
        .arg("-C")
        .arg(repository)
        .arg("diff")
        .arg("--no-ext-diff")
        .arg("--no-textconv")
        .arg("--unified=3");
    if source == GitDiff::Staged {
        command.arg("--cached");
    }
    command
        .arg("--")
        .env_remove("GIT_EXTERNAL_DIFF")
        .env("GIT_PAGER", "cat");

    let output = command.output().map_err(|_| GitError::Spawn)?;
    if !output.status.success() {
        return Err(GitError::CommandFailed);
    }
    let patch = String::from_utf8(output.stdout).map_err(|_| GitError::NonUtf8Output)?;
    parse_patch(&patch).map_err(GitError::InvalidPatch)
}

/// Runs a fixed-form Git diff and scans its added lines with the built-in detector.
///
/// # Errors
///
/// Returns a redacted [`GitError`] if Git cannot run, rejects the operation,
/// emits non-UTF-8 output, or emits a malformed patch.
pub fn scan_git(repository: &Path, source: GitDiff) -> Result<Report, GitError> {
    read_git_patch(repository, source).map(|patch| scan_patch(&patch))
}
