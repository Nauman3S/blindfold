use std::fmt;
use std::str::FromStr;

use email_address::EmailAddress;
use regex::Regex;
use url::Url;

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
                r"\b(sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,}))\b",
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
                r"(?:^|[^A-Za-z0-9_])[Bb][Ee][Aa][Rr][Ee][Rr][ \t]+([-A-Za-z0-9._~+/=]{16,})",
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

struct StructuredDetector {
    url: Regex,
    email: Regex,
    phone: Regex,
}

impl StructuredDetector {
    fn new() -> Result<Self, BuildError> {
        Ok(Self {
            url: Regex::new(
                r#"(?i)\b[A-Z][A-Z0-9+.-]{1,31}://[^\s<>"'`]+"#,
            )
            .map_err(|_| BuildError {
                detector: "structured.credential_url",
            })?,
            email: Regex::new(
                r"(?i)(?:^|[^A-Z0-9.!#$%&'*+?^_`{|}~-])([A-Z0-9.!#$%&'*+?^_`{|}~-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63})(?:$|[^A-Z0-9.-])",
            )
            .map_err(|_| BuildError {
                detector: "structured.email_address",
            })?,
            phone: Regex::new(r"(?:^|[^0-9+])((?:\+[1-9][0-9 .()-]{7,24}[0-9]))(?:$|[^0-9])")
                .map_err(|_| BuildError {
                    detector: "structured.phone_number",
                })?,
        })
    }

    fn detect_credential_urls(&self, input: &str, findings: &mut Vec<Finding>) {
        for candidate in self.url.find_iter(input) {
            let raw = candidate.as_str();
            let Ok(parsed) = Url::parse(raw) else {
                continue;
            };
            if parsed.password().is_none() {
                continue;
            }
            let Some(authority_start) = raw.find("://").map(|index| index + 3) else {
                continue;
            };
            let authority_end = raw[authority_start..]
                .find(['/', '?', '#'])
                .map_or(raw.len(), |index| authority_start + index);
            let authority = &raw[authority_start..authority_end];
            let Some(at) = authority.rfind('@') else {
                continue;
            };
            let user_info = &authority[..at];
            let Some(colon) = user_info.find(':') else {
                continue;
            };
            if colon + 1 == user_info.len() {
                continue;
            }
            let start = candidate.start() + authority_start + colon + 1;
            let end = candidate.start() + authority_start + user_info.len();
            let Ok(span) = Span::new(start, end) else {
                continue;
            };
            findings.push(Finding::new(
                SecretKind::CredentialUrl,
                span,
                Confidence::Certain,
                "structured.credential_url",
            ));
        }
    }

    fn detect_emails(&self, input: &str, findings: &mut Vec<Finding>) {
        for captures in self.email.captures_iter(input) {
            let Some(candidate) = captures.get(1) else {
                continue;
            };
            if EmailAddress::from_str(candidate.as_str()).is_err() {
                continue;
            }
            let Ok(span) = Span::new(candidate.start(), candidate.end()) else {
                continue;
            };
            findings.push(Finding::new(
                SecretKind::EmailAddress,
                span,
                Confidence::High,
                "structured.email_address",
            ));
        }
    }

    fn detect_phone_numbers(&self, input: &str, findings: &mut Vec<Finding>) {
        for captures in self.phone.captures_iter(input) {
            let Some(candidate) = captures.get(1) else {
                continue;
            };
            let Ok(number) = rlibphonenumber::PhoneNumber::parse(candidate.as_str(), None) else {
                continue;
            };
            if !number.is_valid() {
                continue;
            }
            let Ok(span) = Span::new(candidate.start(), candidate.end()) else {
                continue;
            };
            findings.push(Finding::new(
                SecretKind::PhoneNumber,
                span,
                Confidence::High,
                "structured.phone_number",
            ));
        }
    }
}

impl Detector for StructuredDetector {
    fn detect(&self, input: &str, findings: &mut Vec<Finding>) {
        self.detect_credential_urls(input, findings);
        self.detect_emails(input, findings);
        self.detect_phone_numbers(input, findings);
    }
}

struct ContextualDetector {
    assignment: Regex,
}

impl ContextualDetector {
    fn new() -> Result<Self, BuildError> {
        let assignment =
            Regex::new(r"(?m)(?:^|[,{;\s])([A-Za-z][-A-Za-z0-9_.]{1,63})[ \t]*(?:=|:)[ \t]*")
                .map_err(|_| BuildError {
                    detector: "context.assignment",
                })?;
        Ok(Self { assignment })
    }
}

impl Detector for ContextualDetector {
    fn detect(&self, input: &str, findings: &mut Vec<Finding>) {
        for captures in self.assignment.captures_iter(input) {
            let (Some(assignment), Some(name)) = (captures.get(0), captures.get(1)) else {
                continue;
            };
            let normalized = name.as_str().to_ascii_lowercase();
            let classification = classify_context(&normalized);
            let Some((kind, confidence)) = classification else {
                continue;
            };

            let Some((start, end)) = assignment_value_span(input, assignment.end()) else {
                continue;
            };
            let Some(candidate) = input.get(start..end) else {
                continue;
            };
            if candidate.len() > 512 {
                continue;
            }
            if candidate.len() < minimum_context_length(kind)
                || !has_character_variety(candidate)
                || shannon_entropy(candidate) < 3.5
            {
                continue;
            }
            let Ok(span) = Span::new(start, end) else {
                continue;
            };
            findings.push(Finding::new(kind, span, confidence, "context.assignment"));
        }
    }
}

fn assignment_value_span(input: &str, start: usize) -> Option<(usize, usize)> {
    let suffix = input.get(start..)?;
    let first = suffix.chars().next()?;
    if matches!(first, '"' | '\'') {
        let content_start = start + first.len_utf8();
        let mut escaped = false;
        for (offset, character) in input.get(content_start..)?.char_indices() {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == first {
                return (offset > 0).then_some((content_start, content_start + offset));
            } else if matches!(character, '\r' | '\n') {
                return None;
            }
        }
        return None;
    }

    let end = suffix
        .char_indices()
        .find_map(|(offset, character)| {
            (character.is_ascii_whitespace() || matches!(character, ',' | ';' | '}' | ']'))
                .then_some(start + offset)
        })
        .unwrap_or(input.len());
    (end > start).then_some((start, end))
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
    let Ok(length) = u32::try_from(value.len()) else {
        return 0.0;
    };
    let length = f64::from(length);
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
                Box::new(StructuredDetector::new()?),
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
    fn detects_passwords_in_database_cache_and_mail_urls() {
        let input = concat!(
            "DATABASE_URL=postgresql://service:db-pass@127.0.0.1/app\n",
            "REDIS_URL=redis://:cache-pass@127.0.0.1/0\n",
            "SMTP_URL=smtps://fixture@example.com:mail-pass@mail.example.com:465\n",
        );
        let findings = detectors().detect(input);
        let values = findings
            .iter()
            .filter(|finding| finding.kind() == SecretKind::CredentialUrl)
            .map(|finding| &input[finding.span().as_range()])
            .collect::<Vec<_>>();
        assert_eq!(values, ["db-pass", "cache-pass", "mail-pass"]);
    }

    #[test]
    fn detects_valid_email_and_international_phone_number() {
        let input = "CUSTOMER_EMAIL=ada.fixture@example.com\nCUSTOMER_PHONE=+1-202-555-0142";
        let findings = detectors().detect(input);
        assert!(findings.iter().any(|finding| {
            finding.kind() == SecretKind::EmailAddress
                && &input[finding.span().as_range()] == "ada.fixture@example.com"
        }));
        assert!(findings.iter().any(|finding| {
            finding.kind() == SecretKind::PhoneNumber
                && &input[finding.span().as_range()] == "+1-202-555-0142"
        }));
    }

    #[test]
    fn email_span_does_not_consume_url_delimiters() {
        let input = "smtps://fixture@example.com:mail-pass@mail.example.com:465";
        let findings = detectors().detect(input);
        assert!(findings.iter().any(|finding| {
            finding.kind() == SecretKind::EmailAddress
                && &input[finding.span().as_range()] == "fixture@example.com"
        }));
    }

    #[test]
    fn structured_detectors_reject_near_misses() {
        let input = "docs@example localhost user@localhost +1-000-000-0000 build-2026-06-23";
        assert!(detectors().detect(input).is_empty());
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
    fn contextual_values_cover_complete_quoted_punctuation() {
        let input = r#"password="Long! Password$ Value_1234""#;
        let findings = detectors().detect(input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind(), SecretKind::Password);
        assert_eq!(
            &input[findings[0].span().as_range()],
            "Long! Password$ Value_1234"
        );
    }

    #[test]
    fn oversized_contextual_values_are_not_partially_redacted() {
        let value = format!("Aa1!{}", "z".repeat(600));
        let input = format!("password=\"{value}\"");
        assert!(detectors().detect(&input).is_empty());
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
