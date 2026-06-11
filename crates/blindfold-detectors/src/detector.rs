use std::fmt;

use regex::Regex;

use crate::{Confidence, Finding, SecretKind, Span, resolve_overlaps};

/// Detector that appends safe finding metadata for a UTF-8 input.
pub trait Detector: Send + Sync {
    /// Appends findings. Implementations must never retain input or place matched
    /// bytes in diagnostics.
    fn detect(&self, input: &str, findings: &mut Vec<Finding>);
}

struct Pattern {
    regex: Regex,
    capture: usize,
    kind: SecretKind,
    confidence: Confidence,
    name: &'static str,
}

impl Pattern {
    fn detect(&self, input: &str, findings: &mut Vec<Finding>) {
        for captures in self.regex.captures_iter(input) {
            let Some(matched) = captures.get(self.capture) else {
                continue;
            };
            let Ok(span) = Span::new(matched.start(), matched.end()) else {
                continue;
            };
            findings.push(Finding::new(self.kind, span, self.confidence, self.name));
        }
    }
}

struct KnownFormats {
    patterns: Vec<Pattern>,
}

impl KnownFormats {
    fn new() -> Result<Self, BuildError> {
        let specifications = [
            (
                r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,})\b",
                1,
                SecretKind::OpenAiApiKey,
                Confidence::Certain,
                "known.openai",
            ),
            (
                r"\b(sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,})\b",
                1,
                SecretKind::AnthropicApiKey,
                Confidence::Certain,
                "known.anthropic",
            ),
            (
                r"\b((?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}))\b",
                1,
                SecretKind::GitHubToken,
                Confidence::Certain,
                "known.github",
            ),
            (
                r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b",
                1,
                SecretKind::StripeKey,
                Confidence::Certain,
                "known.stripe",
            ),
            (
                r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b",
                1,
                SecretKind::SlackToken,
                Confidence::Certain,
                "known.slack",
            ),
            (
                r"\b((?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16})\b",
                1,
                SecretKind::AwsAccessKeyId,
                Confidence::Certain,
                "known.aws_access_key",
            ),
            (
                r"(?i)\bBearer[ \t]+([A-Za-z0-9._~+/-]{16,}={0,2})",
                1,
                SecretKind::BearerToken,
                Confidence::High,
                "known.bearer",
            ),
            (
                r"\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b",
                1,
                SecretKind::JsonWebToken,
                Confidence::Certain,
                "known.jwt",
            ),
            (
                r"\b((?:ya29\.[A-Za-z0-9_-]{20,}|1//[A-Za-z0-9_-]{20,}))\b",
                1,
                SecretKind::OAuthToken,
                Confidence::Certain,
                "known.oauth",
            ),
            (
                r"(?s)(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)",
                1,
                SecretKind::PemPrivateKey,
                Confidence::Certain,
                "known.pem_private_key",
            ),
            (
                r"(?i)\b[a-z][a-z0-9+.-]{1,20}://[^/\s:@]+:([^/@\s]+)@[^/\s]+",
                1,
                SecretKind::CredentialUrl,
                Confidence::Certain,
                "known.credential_url",
            ),
        ];

        let mut patterns = Vec::with_capacity(specifications.len());
        for (expression, capture, kind, confidence, name) in specifications {
            let regex = Regex::new(expression).map_err(|_| BuildError { detector: name })?;
            patterns.push(Pattern {
                regex,
                capture,
                kind,
                confidence,
                name,
            });
        }
        Ok(Self { patterns })
    }
}

impl Detector for KnownFormats {
    fn detect(&self, input: &str, findings: &mut Vec<Finding>) {
        for pattern in &self.patterns {
            pattern.detect(input, findings);
        }
    }
}

struct ContextualDetector {
    assignment: Regex,
}

impl ContextualDetector {
    fn new() -> Result<Self, BuildError> {
        let assignment = Regex::new(
            r#"(?im)(?:^|[,{;\s])([A-Za-z][A-Za-z0-9_.-]{1,63})[ \t]*(?:=|:)[ \t]*["']?([A-Za-z0-9+/_.~=-]{16,512})"#,
        )
        .map_err(|_| BuildError {
            detector: "context.assignment",
        })?;
        Ok(Self { assignment })
    }
}

impl Detector for ContextualDetector {
    fn detect(&self, input: &str, findings: &mut Vec<Finding>) {
        for captures in self.assignment.captures_iter(input) {
            let (Some(name), Some(value)) = (captures.get(1), captures.get(2)) else {
                continue;
            };
            let normalized = name.as_str().to_ascii_lowercase();
            let classification = classify_context(&normalized);
            let Some((kind, confidence)) = classification else {
                continue;
            };

            let candidate = value.as_str();
            if candidate.len() < minimum_context_length(kind)
                || !has_character_variety(candidate)
                || shannon_entropy(candidate) < 3.5
            {
                continue;
            }
            let Ok(span) = Span::new(value.start(), value.end()) else {
                continue;
            };
            findings.push(Finding::new(kind, span, confidence, "context.assignment"));
        }
    }
}

fn classify_context(name: &str) -> Option<(SecretKind, Confidence)> {
    if name.contains("aws_secret_access_key") || name == "aws.secretaccesskey" {
        return Some((SecretKind::AwsSecretAccessKey, Confidence::High));
    }
    if name.contains("password") || name.contains("passwd") || name.ends_with("_pwd") {
        return Some((SecretKind::Password, Confidence::Contextual));
    }
    if name.contains("api_key") || name.contains("apikey") || name.contains("secret_key") {
        return Some((SecretKind::ApiKey, Confidence::Contextual));
    }
    if name.contains("oauth")
        || name.contains("access_token")
        || name.contains("refresh_token")
        || name.ends_with("_token")
        || name == "token"
    {
        return Some((SecretKind::Token, Confidence::Contextual));
    }
    None
}

const fn minimum_context_length(kind: SecretKind) -> usize {
    match kind {
        SecretKind::Password => 16,
        SecretKind::AwsSecretAccessKey => 32,
        _ => 20,
    }
}

fn has_character_variety(value: &str) -> bool {
    let mut classes = [false; 4];
    for byte in value.bytes() {
        if byte.is_ascii_lowercase() {
            classes[0] = true;
        } else if byte.is_ascii_uppercase() {
            classes[1] = true;
        } else if byte.is_ascii_digit() {
            classes[2] = true;
        } else {
            classes[3] = true;
        }
    }
    classes.into_iter().filter(|present| *present).count() >= 3
}

fn shannon_entropy(value: &str) -> f64 {
    let mut counts = [0_u16; 256];
    for byte in value.bytes() {
        counts[usize::from(byte)] = counts[usize::from(byte)].saturating_add(1);
    }
    let length = value.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = f64::from(count) / length;
            -probability * probability.log2()
        })
        .sum()
}

/// Default collection of known-format and contextual detectors.
pub struct DetectorSet {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorSet {
    /// Compiles the built-in detector collection.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] if an embedded regular expression cannot compile.
    pub fn new() -> Result<Self, BuildError> {
        Ok(Self {
            detectors: vec![
                Box::new(KnownFormats::new()?),
                Box::new(ContextualDetector::new()?),
            ],
        })
    }

    /// Creates an empty collection for application-specific detectors.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Adds a detector to this collection.
    pub fn push<D>(&mut self, detector: D)
    where
        D: Detector + 'static,
    {
        self.detectors.push(Box::new(detector));
    }

    /// Detects and resolves overlapping findings.
    #[must_use]
    pub fn detect(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for detector in &self.detectors {
            detector.detect(input, &mut findings);
        }
        resolve_overlaps(findings)
    }
}

/// Failure to construct built-in detectors.
///
/// The error deliberately omits regex text and engine diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildError {
    detector: &'static str,
}

impl BuildError {
    /// Returns the static identifier of the detector that failed to initialize.
    #[must_use]
    pub const fn detector(self) -> &'static str {
        self.detector
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to initialize secret detector {}",
            self.detector
        )
    }
}

impl std::error::Error for BuildError {}

#[cfg(test)]
mod tests {
    use crate::{Confidence, SecretKind};

    use super::DetectorSet;

    fn detectors() -> DetectorSet {
        DetectorSet::new()
            .unwrap_or_else(|error| unreachable!("embedded patterns must compile: {error}"))
    }

    #[test]
    fn recognizes_provider_and_protocol_formats() {
        let cases = [
            (
                "sk-proj-abcdefghijklmnopqrstuvwxyz012345",
                SecretKind::OpenAiApiKey,
            ),
            (
                "sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345",
                SecretKind::AnthropicApiKey,
            ),
            (
                "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
                SecretKind::GitHubToken,
            ),
            ("sk_live_abcdefghijklmnop1234", SecretKind::StripeKey),
            ("xoxb-1234567890-abcdefghijkl", SecretKind::SlackToken),
            ("AKIAIOSFODNN7EXAMPLE", SecretKind::AwsAccessKeyId),
            (
                "Bearer abcdefghijklmnop.QRSTUVWXYZ012345",
                SecretKind::BearerToken,
            ),
            (
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureABCDE",
                SecretKind::JsonWebToken,
            ),
            (
                "ya29.abcdefghijklmnopqrstuvwxyz012345",
                SecretKind::OAuthToken,
            ),
        ];

        for (input, expected) in cases {
            let findings = detectors().detect(input);
            assert!(
                findings.iter().any(|finding| finding.kind() == expected),
                "missing kind {expected:?}"
            );
        }
    }

    #[test]
    fn detects_pem_and_only_password_part_of_url() {
        let pem = "-----BEGIN PRIVATE KEY-----\nabc123+/=\n-----END PRIVATE KEY-----";
        let findings = detectors().detect(pem);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind(), SecretKind::PemPrivateKey);
        assert_eq!(&pem[findings[0].span().as_range()], pem);

        let url = "postgres://service:s3cr3t-value@db.internal/app";
        let findings = detectors().detect(url);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind(), SecretKind::CredentialUrl);
        assert_eq!(&url[findings[0].span().as_range()], "s3cr3t-value");
    }

    #[test]
    fn entropy_never_triggers_without_secret_context() {
        let random = "artifact_id=Az9+/bcDEF0123_ghIJK4567";
        assert!(detectors().detect(random).is_empty());

        let contextual = "refresh_token=Az9+/bcDEF0123_ghIJK4567";
        let findings = detectors().detect(contextual);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence(), Confidence::Contextual);
    }

    #[test]
    fn low_variety_context_values_are_ignored() {
        assert!(
            detectors()
                .detect("password=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .is_empty()
        );
    }

    #[test]
    fn findings_debug_never_contains_input_value() {
        let raw = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
        let findings = detectors().detect(raw);
        let debug = format!("{findings:?}");
        assert!(!debug.contains(raw));
        assert!(debug.contains("OpenAiApiKey"));
    }
}
