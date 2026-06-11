use std::fmt::Write as _;

use crate::{FileChange, Patch, PatchError, PatchLineKind, parse_patch};

/// Overall result of scanning a patch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScanOutcome {
    /// At least one likely secret was found.
    Findings,
    /// Added text was scanned and no likely secret was found.
    Clean,
    /// The patch had no added text to scan.
    NoTextChanges,
}

impl ScanOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Findings => "findings",
            Self::Clean => "clean",
            Self::NoTextChanges => "no_text_changes",
        }
    }
}

/// Severity assigned to a diff finding.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Severity {
    /// Suspicious secret use requiring review.
    Medium,
    /// A likely hardcoded credential.
    High,
    /// A likely credential in an especially exposed or sensitive path.
    Critical,
}

impl Severity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Stable category for a detected secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FindingCategory {
    /// A credential-like assignment.
    CredentialAssignment,
    /// A provider-shaped API key or token.
    ProviderToken,
    /// Private key material.
    PrivateKey,
    /// A URL with embedded credentials.
    CredentialUrl,
    /// A sensitive value in an environment file.
    EnvironmentSecret,
}

impl FindingCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialAssignment => "credential_assignment",
            Self::ProviderToken => "provider_token",
            Self::PrivateKey => "private_key",
            Self::CredentialUrl => "credential_url",
            Self::EnvironmentSecret => "environment_secret",
        }
    }
}

/// Why a path receives elevated handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PathRisk {
    /// The path has no special exposure classification.
    Normal,
    /// Browser-delivered or publicly served source.
    FrontendPublic,
    /// An environment file likely to contain runtime credentials.
    EnvironmentFile,
    /// Continuous-integration configuration.
    ContinuousIntegration,
    /// Test fixture or snapshot content.
    Fixture,
}

impl PathRisk {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::FrontendPublic => "frontend_public",
            Self::EnvironmentFile => "environment_file",
            Self::ContinuousIntegration => "continuous_integration",
            Self::Fixture => "fixture",
        }
    }
}

/// Safe detector output that deliberately contains no matched value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Detection {
    rule_id: &'static str,
    category: FindingCategory,
    severity: Severity,
    column: usize,
    message: &'static str,
    remediation: &'static str,
}

impl Detection {
    /// Creates a redaction-safe detector result.
    #[must_use]
    pub const fn new(
        rule_id: &'static str,
        category: FindingCategory,
        severity: Severity,
        column: usize,
        message: &'static str,
        remediation: &'static str,
    ) -> Self {
        Self {
            rule_id,
            category,
            severity,
            column,
            message,
            remediation,
        }
    }
}

/// Added-line content and nearby hunk context supplied to a detector.
///
/// Implementations must not retain or print `content`, `before`, or `after`.
#[derive(Clone, Copy)]
pub struct AddedLine<'a> {
    /// New-file path.
    pub path: &'a str,
    /// New-file line number.
    pub line: usize,
    /// Added content without its diff prefix.
    pub content: &'a str,
    /// Up to two preceding hunk lines, nearest last.
    pub before: &'a [&'a str],
    /// Up to two following hunk lines, nearest first.
    pub after: &'a [&'a str],
    /// Path-specific risk classification.
    pub path_risk: PathRisk,
}

impl std::fmt::Debug for AddedLine<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AddedLine")
            .field("path", &self.path)
            .field("line", &self.line)
            .field("content", &"[REDACTED]")
            .field("before", &"[REDACTED]")
            .field("after", &"[REDACTED]")
            .field("path_risk", &self.path_risk)
            .finish()
    }
}

/// Adapter interface for secret detectors.
///
/// This keeps the diff parser independent from a particular detector crate.
pub trait Detector {
    /// Inspects one added line and returns safe metadata only.
    fn detect(&self, line: AddedLine<'_>) -> Vec<Detection>;
}

/// Dependency-free detector for common hardcoded-secret forms.
#[derive(Clone, Copy, Debug, Default)]
pub struct BuiltinDetector;

impl Detector for BuiltinDetector {
    fn detect(&self, line: AddedLine<'_>) -> Vec<Detection> {
        detect_builtin(line).into_iter().collect()
    }
}

/// A redaction-safe finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    rule_id: &'static str,
    category: FindingCategory,
    severity: Severity,
    path: String,
    line: usize,
    column: usize,
    context_start: usize,
    context_end: usize,
    path_risk: PathRisk,
    message: &'static str,
    remediation: &'static str,
}

impl Finding {
    /// Returns the stable detector rule identifier.
    #[must_use]
    pub const fn rule_id(&self) -> &'static str {
        self.rule_id
    }

    /// Returns the finding category.
    #[must_use]
    pub const fn category(&self) -> FindingCategory {
        self.category
    }

    /// Returns the severity after path-risk elevation.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Returns the new-file path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the one-based new-file line number.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// Returns the one-based byte column reported by the detector.
    #[must_use]
    pub const fn column(&self) -> usize {
        self.column
    }

    /// Returns the first line number in the retained context window.
    #[must_use]
    pub const fn context_start(&self) -> usize {
        self.context_start
    }

    /// Returns the last line number in the retained context window.
    #[must_use]
    pub const fn context_end(&self) -> usize {
        self.context_end
    }

    /// Returns the path-specific risk classification.
    #[must_use]
    pub const fn path_risk(&self) -> PathRisk {
        self.path_risk
    }

    /// Returns a safe explanation that does not contain the detected value.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// Returns actionable remediation without the detected value.
    #[must_use]
    pub const fn remediation(&self) -> &'static str {
        self.remediation
    }
}

/// Complete result of scanning one patch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    outcome: ScanOutcome,
    files_examined: usize,
    added_lines_scanned: usize,
    binary_files_skipped: usize,
    findings: Vec<Finding>,
}

impl Report {
    /// Returns the overall scan outcome.
    #[must_use]
    pub const fn outcome(&self) -> ScanOutcome {
        self.outcome
    }

    /// Returns the number of file sections examined.
    #[must_use]
    pub const fn files_examined(&self) -> usize {
        self.files_examined
    }

    /// Returns the number of added text lines scanned.
    #[must_use]
    pub const fn added_lines_scanned(&self) -> usize {
        self.added_lines_scanned
    }

    /// Returns the number of binary file sections skipped.
    #[must_use]
    pub const fn binary_files_skipped(&self) -> usize {
        self.binary_files_skipped
    }

    /// Returns findings in patch and line order.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Renders stable, human-readable output without detected values.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut output = format!(
            "outcome={} files={} added_lines={} binary_files_skipped={}\n",
            self.outcome.as_str(),
            self.files_examined,
            self.added_lines_scanned,
            self.binary_files_skipped
        );
        for finding in &self.findings {
            let _ = writeln!(
                output,
                "{}:{}:{} [{}] {}: {} Remediation: {}",
                finding.path,
                finding.line,
                finding.column,
                finding.severity.as_str(),
                finding.rule_id,
                finding.message,
                finding.remediation
            );
        }
        output
    }

    /// Renders stable JSON without detected values.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut output = format!(
            "{{\"schema_version\":1,\"outcome\":\"{}\",\"files_examined\":{},\
             \"added_lines_scanned\":{},\"binary_files_skipped\":{},\"findings\":[",
            self.outcome.as_str(),
            self.files_examined,
            self.added_lines_scanned,
            self.binary_files_skipped
        );
        for (index, finding) in self.findings.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            output.push_str("{\"rule_id\":\"");
            escape_json(&mut output, finding.rule_id);
            output.push_str("\",\"category\":\"");
            output.push_str(finding.category.as_str());
            output.push_str("\",\"severity\":\"");
            output.push_str(finding.severity.as_str());
            output.push_str("\",\"path\":\"");
            escape_json(&mut output, &finding.path);
            let _ = write!(
                output,
                "\",\"line\":{},\"column\":{},\"context_start\":{},\"context_end\":{},\
                 \"path_risk\":\"{}\",\"message\":\"",
                finding.line,
                finding.column,
                finding.context_start,
                finding.context_end,
                finding.path_risk.as_str()
            );
            escape_json(&mut output, finding.message);
            output.push_str("\",\"remediation\":\"");
            escape_json(&mut output, finding.remediation);
            output.push_str("\"}");
        }
        output.push_str("]}");
        output
    }
}

/// Scans a parsed patch with the built-in detector.
#[must_use]
pub fn scan_patch(patch: &Patch) -> Report {
    scan_with(patch, &BuiltinDetector)
}

/// Parses and scans supplied unified patch text with the built-in detector.
///
/// This entry point does not invoke Git or require a repository.
///
/// # Errors
///
/// Returns [`PatchError`] when the supplied patch is malformed.
pub fn scan(input: &str) -> Result<Report, PatchError> {
    parse_patch(input).map(|patch| scan_patch(&patch))
}

/// Scans a parsed patch with an injected detector implementation.
#[must_use]
pub fn scan_with<D: Detector + ?Sized>(parsed_patch: &Patch, detector: &D) -> Report {
    let mut findings = Vec::new();
    let mut added_lines_scanned = 0;
    let mut binary_files_skipped = 0;

    for file in parsed_patch.files() {
        if file.change() == FileChange::Binary {
            binary_files_skipped += 1;
            continue;
        }
        let Some(path) = file.new_path() else {
            continue;
        };
        let path_risk = classify_path(path);
        for hunk in file.hunks() {
            let lines = hunk.lines();
            for (index, patch_line) in lines.iter().enumerate() {
                if patch_line.kind() != PatchLineKind::Added {
                    continue;
                }
                let Some(line_number) = patch_line.new_line() else {
                    continue;
                };
                added_lines_scanned += 1;
                let before_storage = nearby_before(lines, index);
                let after_storage = nearby_after(lines, index);
                let input = AddedLine {
                    path,
                    line: line_number,
                    content: patch_line.content(),
                    before: &before_storage,
                    after: &after_storage,
                    path_risk,
                };
                for detection in detector.detect(input) {
                    findings.push(Finding {
                        rule_id: detection.rule_id,
                        category: detection.category,
                        severity: elevate(detection.severity, path_risk),
                        path: path.to_owned(),
                        line: line_number,
                        column: detection.column.max(1),
                        context_start: line_number.saturating_sub(before_storage.len()),
                        context_end: line_number + after_storage.len(),
                        path_risk,
                        message: detection.message,
                        remediation: detection.remediation,
                    });
                }
            }
        }
    }

    let outcome = if findings.is_empty() {
        if added_lines_scanned == 0 {
            ScanOutcome::NoTextChanges
        } else {
            ScanOutcome::Clean
        }
    } else {
        ScanOutcome::Findings
    };
    Report {
        outcome,
        files_examined: parsed_patch.files().len(),
        added_lines_scanned,
        binary_files_skipped,
        findings,
    }
}

fn nearby_before(lines: &[crate::PatchLine], index: usize) -> Vec<&str> {
    lines[index.saturating_sub(2)..index]
        .iter()
        .filter(|line| line.kind() != PatchLineKind::Removed)
        .map(crate::PatchLine::content)
        .collect()
}

fn nearby_after(lines: &[crate::PatchLine], index: usize) -> Vec<&str> {
    lines[index + 1..lines.len().min(index + 3)]
        .iter()
        .filter(|line| line.kind() != PatchLineKind::Removed)
        .map(crate::PatchLine::content)
        .collect()
}

fn classify_path(path: &str) -> PathRisk {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let file_name = normalized.rsplit('/').next().unwrap_or(&normalized);
    if file_name == ".env" || file_name.starts_with(".env.") {
        PathRisk::EnvironmentFile
    } else if normalized.starts_with(".github/workflows/")
        || normalized.contains("/.github/workflows/")
        || normalized.starts_with(".circleci/")
        || normalized.contains("/.circleci/")
        || normalized.starts_with(".gitlab-ci")
        || file_name == ".travis.yml"
        || file_name == "jenkinsfile"
        || file_name.starts_with("azure-pipelines")
        || normalized.contains("/buildkite/")
        || normalized.contains("/ci/")
    {
        PathRisk::ContinuousIntegration
    } else if normalized.contains("/fixtures/")
        || normalized.starts_with("fixtures/")
        || normalized.contains("/snapshots/")
        || normalized.contains("__snapshots__")
    {
        PathRisk::Fixture
    } else if normalized.starts_with("public/")
        || normalized.contains("/public/")
        || normalized.starts_with("frontend/")
        || normalized.contains("/frontend/")
        || normalized.starts_with("src/client/")
        || normalized.contains("/src/client/")
    {
        PathRisk::FrontendPublic
    } else {
        PathRisk::Normal
    }
}

const fn elevate(severity: Severity, risk: PathRisk) -> Severity {
    if matches!(risk, PathRisk::Normal) {
        severity
    } else {
        match severity {
            Severity::Medium => Severity::High,
            Severity::High | Severity::Critical => Severity::Critical,
        }
    }
}

fn detect_builtin(line: AddedLine<'_>) -> Option<Detection> {
    let content = line.content.trim();
    if content.is_empty() {
        return None;
    }
    let masked = mask_safe_refs(content);
    let content = masked.as_str();
    if let Some(column) = find_ascii_case_insensitive(content, "-----begin private key-----") {
        return Some(Detection::new(
            "BF-DIFF-PRIVATE-KEY",
            FindingCategory::PrivateKey,
            Severity::Critical,
            column + 1,
            "private key material appears in an added line",
            "Remove the key, rotate it if real, and load it from an approved secret store.",
        ));
    }
    if let Some(column) = credential_url_column(content) {
        return Some(Detection::new(
            "BF-DIFF-CREDENTIAL-URL",
            FindingCategory::CredentialUrl,
            Severity::High,
            column,
            "a URL appears to contain embedded credentials",
            "Remove URL credentials and inject authentication through an approved secret store.",
        ));
    }
    if let Some(column) = provider_token_column(content) {
        return Some(Detection::new(
            "BF-DIFF-PROVIDER-TOKEN",
            FindingCategory::ProviderToken,
            Severity::High,
            column,
            "a provider-shaped token appears in an added line",
            "Remove and rotate the token, then reference it through an approved secret store.",
        ));
    }
    if let Some((column, value)) = credential_assignment(content) {
        if is_placeholder(value) {
            return None;
        }
        let (rule_id, category, severity, message) = if line.path_risk == PathRisk::EnvironmentFile
        {
            (
                "BF-DIFF-ENV-SECRET",
                FindingCategory::EnvironmentSecret,
                Severity::High,
                "an environment file assigns a likely secret",
            )
        } else {
            (
                "BF-DIFF-CREDENTIAL-ASSIGNMENT",
                FindingCategory::CredentialAssignment,
                Severity::Medium,
                "a credential-like name is assigned a non-placeholder value",
            )
        };
        return Some(Detection::new(
            rule_id,
            category,
            severity,
            column,
            message,
            "Replace the literal with a secret reference or runtime environment lookup.",
        ));
    }
    None
}

fn mask_safe_refs(content: &str) -> String {
    const PREFIX: &str = "{{BLINDFOLD:v1:";
    let mut masked = content.to_owned();
    let mut cursor = 0;
    while let Some(relative_start) = content[cursor..].find(PREFIX) {
        let start = cursor + relative_start;
        let Some(relative_end) = content[start..].find("}}") else {
            break;
        };
        let end = start + relative_end + 2;
        let candidate = &content[start..end];
        if SafeRef::parse(candidate).is_ok() {
            masked.replace_range(start..end, &" ".repeat(end - start));
        }
        cursor = end;
    }
    masked
}

fn credential_assignment(content: &str) -> Option<(usize, &str)> {
    let separator = content.find('=').or_else(|| content.find(':'))?;
    let name = content[..separator]
        .trim_matches(|character: char| {
            character.is_ascii_whitespace()
                || matches!(character, '"' | '\'' | '{' | ',' | '-' | '_')
        })
        .to_ascii_lowercase();
    let sensitive_name = [
        "api_key",
        "apikey",
        "access_key",
        "secret",
        "token",
        "password",
        "passwd",
        "private_key",
        "client_secret",
        "auth",
    ]
    .iter()
    .any(|candidate| name.contains(candidate));
    if !sensitive_name {
        return None;
    }
    let value = content[separator + 1..]
        .trim()
        .trim_end_matches([',', ';'])
        .trim_matches(['"', '\'']);
    if value.is_empty() || looks_like_runtime_reference(value) {
        return None;
    }
    Some((separator + 2, value))
}

fn looks_like_runtime_reference(value: &str) -> bool {
    value.starts_with("${")
        || value.starts_with("env.")
        || value.starts_with("process.env")
        || value.starts_with("os.environ")
        || value.starts_with("std::env")
        || value.contains("secret_ref")
}

fn is_placeholder(value: &str) -> bool {
    let normalized: String = value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect();
    if normalized.is_empty() {
        return true;
    }
    [
        "example",
        "examplekey",
        "fakeexamplekey",
        "placeholder",
        "placeholdervalue",
        "dummy",
        "dummyvalue",
        "fake",
        "sample",
        "changeme",
        "notasecret",
        "redacted",
        "yourkeyhere",
        "testonly",
    ]
    .iter()
    .any(|marker| normalized == *marker)
        || normalized
            .chars()
            .all(|character| matches!(character, 'x' | '0'))
}

fn provider_token_column(content: &str) -> Option<usize> {
    for prefix in [
        "AKIA",
        "ASIA",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "sk-",
    ] {
        let Some(index) = content.find(prefix) else {
            continue;
        };
        let token = content[index..]
            .split(|character: char| {
                character.is_ascii_whitespace() || matches!(character, '"' | '\'' | ',' | ';')
            })
            .next()
            .unwrap_or_default();
        let minimum = match prefix {
            "AKIA" | "ASIA" | "sk-" => 20,
            _ => 16,
        };
        if token.len() >= minimum
            && token
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
        {
            return Some(index + 1);
        }
    }
    jwt_column(content)
}

fn jwt_column(content: &str) -> Option<usize> {
    let mut start = 0;
    for (index, character) in content.char_indices() {
        if character.is_ascii_whitespace() || matches!(character, '"' | '\'' | ',' | ';') {
            if is_jwt(&content[start..index]) {
                return Some(start + 1);
            }
            start = index + character.len_utf8();
        }
    }
    is_jwt(&content[start..]).then_some(start + 1)
}

fn is_jwt(candidate: &str) -> bool {
    let mut segments = candidate.split('.');
    let Some(header) = segments.next() else {
        return false;
    };
    let Some(payload) = segments.next() else {
        return false;
    };
    let Some(signature) = segments.next() else {
        return false;
    };
    segments.next().is_none()
        && header.starts_with("eyJ")
        && [header, payload, signature]
            .iter()
            .all(|segment| segment.len() >= 8)
}

fn credential_url_column(content: &str) -> Option<usize> {
    let scheme = content.find("://")?;
    let authority = &content[scheme + 3..];
    let at = authority.find('@')?;
    let credentials = &authority[..at];
    credentials.contains(':').then_some(scheme + 4)
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .to_ascii_lowercase()
        .find(&needle.to_ascii_lowercase())
}

fn escape_json(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{1f}' => {
                let _ = write!(output, "\\u{:04x}", u32::from(character));
            }
            character => output.push(character),
        }
    }
}
use blindfold_core::SafeRef;
