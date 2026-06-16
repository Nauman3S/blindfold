use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::{DetectorSet, Finding};

/// Handling for files that appear binary or are not valid UTF-8.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BinaryHandling {
    /// Skip binary and invalid UTF-8 files.
    Skip,
    /// Scan a lossy UTF-8 representation.
    ScanLossy,
}

/// Hard traversal and resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanLimits {
    /// Maximum directory depth below the root.
    pub max_depth: usize,
    /// Maximum number of regular files considered.
    pub max_files: usize,
    /// Maximum bytes read from any one file.
    pub max_file_bytes: u64,
    /// Maximum aggregate bytes read.
    pub max_total_bytes: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_depth: 16,
            max_files: 10_000,
            max_file_bytes: 2 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Safe metadata for findings in one file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileScan {
    path: PathBuf,
    findings: Vec<Finding>,
}

impl FileScan {
    /// Returns the scanned path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns safe finding metadata.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
}

/// Result of a bounded scan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanReport {
    files: Vec<FileScan>,
    files_considered: usize,
    bytes_read: u64,
    skipped_binary: usize,
    skipped_too_large: usize,
    skipped_ignored: usize,
    skipped_symlinks: usize,
    io_errors: usize,
    limit_reached: bool,
}

impl ScanReport {
    /// Returns files that contained findings.
    #[must_use]
    pub fn files(&self) -> &[FileScan] {
        &self.files
    }

    /// Returns the number of regular files considered.
    #[must_use]
    pub const fn files_considered(&self) -> usize {
        self.files_considered
    }

    /// Returns aggregate bytes read.
    #[must_use]
    pub const fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Returns the number of skipped binary or invalid UTF-8 files.
    #[must_use]
    pub const fn skipped_binary(&self) -> usize {
        self.skipped_binary
    }

    /// Returns the number of files skipped due to the per-file size limit.
    #[must_use]
    pub const fn skipped_too_large(&self) -> usize {
        self.skipped_too_large
    }

    /// Returns the number of ignored entries.
    #[must_use]
    pub const fn skipped_ignored(&self) -> usize {
        self.skipped_ignored
    }

    /// Returns the number of skipped symlinks.
    #[must_use]
    pub const fn skipped_symlinks(&self) -> usize {
        self.skipped_symlinks
    }

    /// Returns the number of recoverable filesystem errors.
    #[must_use]
    pub const fn io_errors(&self) -> usize {
        self.io_errors
    }

    /// Returns whether a file-count or aggregate-byte budget stopped traversal.
    #[must_use]
    pub const fn limit_reached(&self) -> bool {
        self.limit_reached
    }
}

/// Builder for a bounded scanner.
pub struct ScannerBuilder {
    detectors: DetectorSet,
    limits: ScanLimits,
    binary: BinaryHandling,
    follow_symlinks: bool,
    ignored_names: HashSet<String>,
    ignored_extensions: HashSet<String>,
    ignored_paths: Vec<PathBuf>,
}

impl ScannerBuilder {
    /// Starts a builder with conservative defaults and common repository ignores.
    #[must_use]
    pub fn new(detectors: DetectorSet) -> Self {
        Self {
            detectors,
            limits: ScanLimits::default(),
            binary: BinaryHandling::Skip,
            follow_symlinks: false,
            ignored_names: [".git", "node_modules", "target"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            ignored_extensions: HashSet::new(),
            ignored_paths: Vec::new(),
        }
    }

    /// Sets hard scan limits.
    #[must_use]
    pub const fn limits(mut self, limits: ScanLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets binary-file handling.
    #[must_use]
    pub const fn binary_handling(mut self, handling: BinaryHandling) -> Self {
        self.binary = handling;
        self
    }

    /// Enables or disables symlink traversal.
    #[must_use]
    pub const fn follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }

    /// Adds an ignored file or directory basename.
    #[must_use]
    pub fn ignore_name(mut self, name: impl Into<String>) -> Self {
        self.ignored_names.insert(name.into());
        self
    }

    /// Adds an ignored extension without a leading dot.
    #[must_use]
    pub fn ignore_extension(mut self, extension: impl Into<String>) -> Self {
        self.ignored_extensions.insert(extension.into());
        self
    }

    /// Adds an exact path or directory prefix to ignore.
    #[must_use]
    pub fn ignore_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ignored_paths.push(path.into());
        self
    }

    /// Builds the scanner.
    #[must_use]
    pub fn build(self) -> Scanner {
        Scanner {
            detectors: self.detectors,
            limits: self.limits,
            binary: self.binary,
            follow_symlinks: self.follow_symlinks,
            ignored_names: self.ignored_names,
            ignored_extensions: self.ignored_extensions,
            ignored_paths: self.ignored_paths,
        }
    }
}

/// Bounded recursive filesystem scanner.
pub struct Scanner {
    detectors: DetectorSet,
    limits: ScanLimits,
    binary: BinaryHandling,
    follow_symlinks: bool,
    ignored_names: HashSet<String>,
    ignored_extensions: HashSet<String>,
    ignored_paths: Vec<PathBuf>,
}

impl Scanner {
    /// Scans a file or directory recursively within configured budgets.
    ///
    /// Recoverable per-entry I/O failures are counted in the report without
    /// embedding paths or operating-system messages in errors.
    ///
    /// # Errors
    ///
    /// Returns [`ScanError`] if the root cannot be inspected.
    pub fn scan(&self, root: impl AsRef<Path>) -> Result<ScanReport, ScanError> {
        let root = root.as_ref();
        fs::symlink_metadata(root).map_err(|_| ScanError::RootUnavailable)?;
        let mut report = ScanReport::default();
        let mut stack = vec![(root.to_path_buf(), 0_usize)];
        let mut visited = HashSet::new();

        while let Some((path, depth)) = stack.pop() {
            if report.limit_reached {
                break;
            }
            if self.is_ignored(&path) {
                report.skipped_ignored += 1;
                continue;
            }
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                report.io_errors += 1;
                continue;
            };
            if metadata.file_type().is_symlink() {
                if !self.follow_symlinks {
                    report.skipped_symlinks += 1;
                    continue;
                }
                let Ok(canonical) = fs::canonicalize(&path) else {
                    report.io_errors += 1;
                    continue;
                };
                stack.push((canonical, depth));
                continue;
            }
            if metadata.is_dir() {
                if self.follow_symlinks {
                    let Ok(canonical) = fs::canonicalize(&path) else {
                        report.io_errors += 1;
                        continue;
                    };
                    if !visited.insert(canonical) {
                        continue;
                    }
                }
                if depth >= self.limits.max_depth {
                    continue;
                }
                let Ok(entries) = fs::read_dir(&path) else {
                    report.io_errors += 1;
                    continue;
                };
                let mut children = Vec::new();
                for entry in entries {
                    match entry {
                        Ok(entry) => children.push(entry.path()),
                        Err(_) => report.io_errors += 1,
                    }
                }
                children.sort_unstable();
                for child in children.into_iter().rev() {
                    stack.push((child, depth + 1));
                }
            } else if metadata.is_file() {
                self.scan_file(&path, &metadata, &mut report);
            }
        }
        Ok(report)
    }

    fn scan_file(&self, path: &Path, metadata: &fs::Metadata, report: &mut ScanReport) {
        if report.files_considered >= self.limits.max_files {
            report.limit_reached = true;
            return;
        }
        report.files_considered += 1;
        if metadata.len() > self.limits.max_file_bytes {
            report.skipped_too_large += 1;
            return;
        }
        if report.bytes_read.saturating_add(metadata.len()) > self.limits.max_total_bytes {
            report.limit_reached = true;
            return;
        }

        let remaining_total = self
            .limits
            .max_total_bytes
            .saturating_sub(report.bytes_read);
        let read_limit = self.limits.max_file_bytes.min(remaining_total);
        let Ok(capacity) = usize::try_from(metadata.len().min(read_limit)) else {
            report.skipped_too_large += 1;
            return;
        };
        let mut bytes = Vec::with_capacity(capacity);
        let read_result = fs::File::open(path).and_then(|file| {
            file.take(read_limit.saturating_add(1))
                .read_to_end(&mut bytes)
        });
        if read_result.is_err() {
            report.io_errors += 1;
            return;
        }
        if bytes.len() as u64 > read_limit {
            if read_limit < self.limits.max_file_bytes {
                report.limit_reached = true;
            } else {
                report.skipped_too_large += 1;
            }
            return;
        }
        report.bytes_read = report.bytes_read.saturating_add(bytes.len() as u64);
        let likely_binary = bytes.iter().take(8_192).any(|byte| *byte == 0);

        let findings = if likely_binary && self.binary == BinaryHandling::Skip {
            report.skipped_binary += 1;
            return;
        } else {
            match String::from_utf8(bytes) {
                Ok(text) => self.detectors.detect(&text),
                Err(error) if self.binary == BinaryHandling::ScanLossy => self
                    .detectors
                    .detect(&String::from_utf8_lossy(error.as_bytes())),
                Err(_) => {
                    report.skipped_binary += 1;
                    return;
                }
            }
        };
        if !findings.is_empty() {
            report.files.push(FileScan {
                path: path.to_path_buf(),
                findings,
            });
        }
    }

    fn is_ignored(&self, path: &Path) -> bool {
        if self
            .ignored_paths
            .iter()
            .any(|ignored| path == ignored || path.starts_with(ignored))
        {
            return true;
        }
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| self.ignored_names.contains(name))
        {
            return true;
        }
        path.extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| self.ignored_extensions.contains(extension))
    }
}

/// Safe root-level scan failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanError {
    /// The requested root cannot be inspected.
    RootUnavailable,
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("scan root is unavailable")
    }
}

impl std::error::Error for ScanError {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{BinaryHandling, DetectorSet, ScanLimits, SecretKind};

    use super::ScannerBuilder;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "blindfold-detectors-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| unreachable!("temporary directory must be created: {error}"));
        path
    }

    fn detectors() -> DetectorSet {
        DetectorSet::new().unwrap_or_else(|error| unreachable!("patterns must compile: {error}"))
    }

    #[test]
    fn scans_recursively_and_honors_ignores_and_binary_policy() {
        let root = temporary_directory();
        fs::create_dir_all(root.join("nested"))
            .unwrap_or_else(|error| unreachable!("fixture directory must be created: {error}"));
        fs::create_dir_all(root.join("target"))
            .unwrap_or_else(|error| unreachable!("fixture directory must be created: {error}"));
        let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
        fs::write(root.join("nested/config.txt"), secret)
            .unwrap_or_else(|error| unreachable!("fixture must be written: {error}"));
        fs::write(root.join("target/ignored.txt"), secret)
            .unwrap_or_else(|error| unreachable!("fixture must be written: {error}"));
        fs::write(root.join("binary.bin"), [0, 1, 2, 3])
            .unwrap_or_else(|error| unreachable!("fixture must be written: {error}"));

        let report = ScannerBuilder::new(detectors())
            .binary_handling(BinaryHandling::Skip)
            .build()
            .scan(&root)
            .unwrap_or_else(|error| unreachable!("scan must succeed: {error}"));

        assert_eq!(report.files().len(), 1);
        assert_eq!(
            report.files()[0].findings()[0].kind(),
            SecretKind::OpenAiApiKey
        );
        assert_eq!(report.skipped_binary(), 1);
        assert_eq!(report.skipped_ignored(), 1);
        fs::remove_dir_all(root)
            .unwrap_or_else(|error| unreachable!("fixture must be removed: {error}"));
    }

    #[test]
    fn enforces_file_and_byte_budgets() {
        let root = temporary_directory();
        fs::write(root.join("a.txt"), "plain")
            .unwrap_or_else(|error| unreachable!("fixture must be written: {error}"));
        fs::write(root.join("b.txt"), "plain")
            .unwrap_or_else(|error| unreachable!("fixture must be written: {error}"));
        let report = ScannerBuilder::new(detectors())
            .limits(ScanLimits {
                max_depth: 4,
                max_files: 1,
                max_file_bytes: 100,
                max_total_bytes: 100,
            })
            .build()
            .scan(&root)
            .unwrap_or_else(|error| unreachable!("scan must succeed: {error}"));

        assert_eq!(report.files_considered(), 1);
        assert!(report.limit_reached());
        fs::remove_dir_all(root)
            .unwrap_or_else(|error| unreachable!("fixture must be removed: {error}"));
    }

    #[cfg(unix)]
    #[test]
    fn followed_symlink_cycles_do_not_duplicate_scans() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory();
        let nested = root.join("nested");
        fs::create_dir_all(&nested)
            .unwrap_or_else(|error| unreachable!("fixture directory must be created: {error}"));
        fs::write(
            nested.join("secret.txt"),
            "sk-proj-abcdefghijklmnopqrstuvwxyz012345",
        )
        .unwrap_or_else(|error| unreachable!("fixture must be written: {error}"));
        symlink(&root, nested.join("cycle"))
            .unwrap_or_else(|error| unreachable!("fixture symlink must be created: {error}"));

        let report = ScannerBuilder::new(detectors())
            .follow_symlinks(true)
            .build()
            .scan(&root)
            .unwrap_or_else(|error| unreachable!("scan must succeed: {error}"));

        assert_eq!(report.files_considered(), 1);
        assert_eq!(report.files().len(), 1);
        fs::remove_dir_all(root)
            .unwrap_or_else(|error| unreachable!("fixture must be removed: {error}"));
    }
}
