use std::collections::{BTreeMap, HashMap};
use std::fmt;

use crate::{DetectorSet, Finding, SecretKind};

/// Redaction behavior for detected values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RedactionMode {
    /// Replace a value known from a dotenv catalog with `${NAME}`.
    EnvRef,
    /// Replace values with their non-sensitive schema labels.
    SchemaOnly,
    /// Replace values with an explicit redaction marker and schema label.
    Placeholder,
    /// Replace equal values with equal opaque, operation-local surrogates.
    Surrogate,
    /// Refuse inputs containing any finding.
    Block,
}

/// Options controlling one redaction operation.
#[derive(Clone, Copy, Debug)]
pub struct RedactionOptions<'a> {
    /// Redaction behavior.
    pub mode: RedactionMode,
    /// Optional dotenv catalog used by [`RedactionMode::EnvRef`].
    pub dotenv: Option<&'a DotenvCatalog>,
}

impl<'a> RedactionOptions<'a> {
    /// Creates options for a mode without a dotenv catalog.
    #[must_use]
    pub const fn new(mode: RedactionMode) -> Self {
        Self { mode, dotenv: None }
    }

    /// Attaches a dotenv catalog.
    #[must_use]
    pub const fn with_dotenv(mut self, dotenv: &'a DotenvCatalog) -> Self {
        self.dotenv = Some(dotenv);
        self
    }
}

/// Parsed dotenv values for environment-reference redaction.
///
/// Debug output exposes variable names and entry count only, never values.
#[derive(Clone, Default)]
pub struct DotenvCatalog {
    by_value: HashMap<String, String>,
}

impl DotenvCatalog {
    /// Parses dotenv assignments.
    ///
    /// Blank lines, comments, optional `export`, and single or double quoted
    /// values are supported. Duplicate values deterministically use the
    /// lexicographically smallest valid variable name.
    #[must_use]
    pub fn parse(input: &str) -> Self {
        let mut sorted = BTreeMap::<String, String>::new();
        for line in input.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let assignment = trimmed.strip_prefix("export ").unwrap_or(trimmed);
            let Some((name, raw_value)) = assignment.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if !valid_env_name(name) {
                continue;
            }
            let value = parse_dotenv_value(raw_value.trim());
            if value.is_empty() {
                continue;
            }
            sorted
                .entry(value)
                .and_modify(|existing| {
                    if name < existing.as_str() {
                        name.clone_into(existing);
                    }
                })
                .or_insert_with(|| name.to_owned());
        }
        Self {
            by_value: sorted.into_iter().collect(),
        }
    }

    /// Returns the number of distinct cataloged values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_value.len()
    }

    /// Returns whether the catalog has no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_value.is_empty()
    }

    fn name_for(&self, value: &str) -> Option<&str> {
        self.by_value.get(value).map(String::as_str)
    }
}

impl fmt::Debug for DotenvCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut names: Vec<&str> = self.by_value.values().map(String::as_str).collect();
        names.sort_unstable();
        formatter
            .debug_struct("DotenvCatalog")
            .field("names", &names)
            .field("entries", &self.by_value.len())
            .finish()
    }
}

fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn parse_dotenv_value(value: &str) -> String {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value
        .split_once(" #")
        .map_or(value, |(before_comment, _)| before_comment)
        .trim_end()
        .to_owned()
}

/// Redacted text plus safe finding metadata.
///
/// This type intentionally implements neither `Debug` nor `Display`, because
/// unmatched input remains caller-controlled and may still be sensitive.
pub struct RedactionOutput {
    text: String,
    findings: Vec<Finding>,
}

impl RedactionOutput {
    /// Returns the transformed text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns safe finding metadata.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Consumes the output and returns transformed text.
    #[must_use]
    pub fn into_text(self) -> String {
        self.text
    }
}

/// Detector-backed redaction service.
pub struct Redactor {
    detectors: DetectorSet,
}

impl Redactor {
    /// Creates a redactor from a detector collection.
    #[must_use]
    pub const fn new(detectors: DetectorSet) -> Self {
        Self { detectors }
    }

    /// Detects and transforms secrets.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionError::Blocked`] in block mode when a finding exists,
    /// or [`RedactionError::InvalidSpan`] if a custom detector returned a span
    /// outside UTF-8 boundaries.
    pub fn redact(
        &self,
        input: &str,
        options: RedactionOptions<'_>,
    ) -> Result<RedactionOutput, RedactionError> {
        let findings = self.detectors.detect(input);
        if options.mode == RedactionMode::Block && !findings.is_empty() {
            return Err(RedactionError::Blocked);
        }

        let mut output = String::with_capacity(input.len());
        let mut cursor = 0;
        let mut surrogates: HashMap<String, usize> = HashMap::new();
        for finding in &findings {
            let span = finding.span();
            let Some(prefix) = input.get(cursor..span.start()) else {
                return Err(RedactionError::InvalidSpan);
            };
            let Some(raw) = input.get(span.as_range()) else {
                return Err(RedactionError::InvalidSpan);
            };
            output.push_str(prefix);
            write_replacement(&mut output, raw, *finding, options, &mut surrogates);
            cursor = span.end();
        }
        let Some(suffix) = input.get(cursor..) else {
            return Err(RedactionError::InvalidSpan);
        };
        output.push_str(suffix);
        Ok(RedactionOutput {
            text: output,
            findings,
        })
    }
}

fn write_replacement(
    output: &mut String,
    raw: &str,
    finding: Finding,
    options: RedactionOptions<'_>,
    surrogates: &mut HashMap<String, usize>,
) {
    match options.mode {
        RedactionMode::EnvRef => {
            if let Some(name) = options.dotenv.and_then(|dotenv| dotenv.name_for(raw)) {
                output.push_str("${");
                output.push_str(name);
                output.push('}');
            } else {
                write_placeholder(output, finding.kind());
            }
        }
        RedactionMode::SchemaOnly => {
            output.push('<');
            output.push_str(finding.kind().label());
            output.push('>');
        }
        RedactionMode::Placeholder => write_placeholder(output, finding.kind()),
        RedactionMode::Surrogate => {
            let next = surrogates.len() + 1;
            let index = *surrogates.entry(raw.to_owned()).or_insert(next);
            output.push_str("{{BLINDFOLD:SURROGATE:");
            push_padded_index(output, index);
            output.push_str("}}");
        }
        RedactionMode::Block => output.push_str(raw),
    }
}

fn push_padded_index(output: &mut String, index: usize) {
    let digits = index.to_string();
    for _ in digits.len()..4 {
        output.push('0');
    }
    output.push_str(&digits);
}

fn write_placeholder(output: &mut String, kind: SecretKind) {
    output.push_str("[REDACTED:");
    output.push_str(kind.label());
    output.push(']');
}

/// Safe redaction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RedactionError {
    /// Block mode rejected an input containing a finding.
    Blocked,
    /// A custom detector returned a span outside the input or UTF-8 boundaries.
    InvalidSpan,
}

impl fmt::Display for RedactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Blocked => "input blocked because sensitive content was detected",
            Self::InvalidSpan => "detector returned an invalid input span",
        })
    }
}

impl std::error::Error for RedactionError {}

#[cfg(test)]
mod tests {
    use crate::{DetectorSet, RedactionMode, RedactionOptions};

    use super::{DotenvCatalog, RedactionError, Redactor};

    fn redactor() -> Redactor {
        Redactor::new(
            DetectorSet::new()
                .unwrap_or_else(|error| unreachable!("patterns must compile: {error}")),
        )
    }

    #[test]
    fn dotenv_catalog_never_debugs_values() {
        let raw = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
        let catalog = DotenvCatalog::parse(&format!("OPENAI_API_KEY='{raw}'"));
        let debug = format!("{catalog:?}");
        assert!(debug.contains("OPENAI_API_KEY"));
        assert!(!debug.contains(raw));
    }

    #[test]
    fn supports_all_non_blocking_modes() {
        let raw = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
        let catalog = DotenvCatalog::parse(&format!("OPENAI_API_KEY={raw}"));
        let cases = [
            (
                RedactionOptions::new(RedactionMode::EnvRef).with_dotenv(&catalog),
                "${OPENAI_API_KEY}",
            ),
            (
                RedactionOptions::new(RedactionMode::SchemaOnly),
                "<openai_api_key>",
            ),
            (
                RedactionOptions::new(RedactionMode::Placeholder),
                "[REDACTED:openai_api_key]",
            ),
            (
                RedactionOptions::new(RedactionMode::Surrogate),
                "{{BLINDFOLD:SURROGATE:0001}}",
            ),
        ];
        for (options, expected) in cases {
            let output = redactor()
                .redact(raw, options)
                .unwrap_or_else(|error| unreachable!("redaction must succeed: {error}"));
            assert_eq!(output.text(), expected);
        }
    }

    #[test]
    fn equal_values_receive_equal_surrogates() {
        let raw = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
        let input = format!("{raw} then {raw}");
        let output = redactor()
            .redact(&input, RedactionOptions::new(RedactionMode::Surrogate))
            .unwrap_or_else(|error| unreachable!("redaction must succeed: {error}"));
        assert_eq!(
            output.text(),
            "{{BLINDFOLD:SURROGATE:0001}} then {{BLINDFOLD:SURROGATE:0001}}"
        );
    }

    #[test]
    fn block_error_contains_no_input() {
        let raw = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
        let result = redactor().redact(raw, RedactionOptions::new(RedactionMode::Block));
        assert!(matches!(result, Err(RedactionError::Blocked)));
        let Err(error) = result else {
            unreachable!("block mode must reject");
        };
        assert!(!format!("{error:?}").contains(raw));
        assert!(!format!("{error}").contains(raw));
    }
}
