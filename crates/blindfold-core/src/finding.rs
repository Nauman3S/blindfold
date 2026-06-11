use std::fmt;
use std::ops::Range;

use crate::{SecretKind, SecretValue, Sensitivity, Source};

/// A classified occurrence of sensitive content.
///
/// The byte range is relative to the scanned input. Formatting a finding is safe
/// because [`SecretValue`] always redacts itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    kind: SecretKind,
    sensitivity: Sensitivity,
    source: Source,
    byte_range: Range<usize>,
    value: SecretValue,
}

impl Finding {
    /// Creates a finding after validating its byte range and captured value.
    ///
    /// # Errors
    ///
    /// Returns [`FindingError::EmptyRange`] when `byte_range` is empty, or
    /// [`FindingError::EmptyValue`] when `value` is empty.
    pub fn new(
        kind: SecretKind,
        sensitivity: Sensitivity,
        source: Source,
        byte_range: Range<usize>,
        value: SecretValue,
    ) -> Result<Self, FindingError> {
        if byte_range.is_empty() {
            return Err(FindingError::EmptyRange);
        }
        if value.is_empty() {
            return Err(FindingError::EmptyValue);
        }

        Ok(Self {
            kind,
            sensitivity,
            source,
            byte_range,
            value,
        })
    }

    /// Returns the secret classification.
    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    /// Returns the disclosure sensitivity.
    #[must_use]
    pub const fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }

    /// Returns the source metadata.
    #[must_use]
    pub const fn source(&self) -> &Source {
        &self.source
    }

    /// Returns the byte range in the scanned input.
    #[must_use]
    pub const fn byte_range(&self) -> &Range<usize> {
        &self.byte_range
    }

    /// Returns the protected value wrapper.
    #[must_use]
    pub const fn value(&self) -> &SecretValue {
        &self.value
    }

    /// Consumes the finding and returns its protected value wrapper.
    #[must_use]
    pub fn into_value(self) -> SecretValue {
        self.value
    }
}

/// Reason a finding could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FindingError {
    /// A finding must cover at least one input byte.
    EmptyRange,
    /// A finding must contain a non-empty protected value.
    EmptyValue,
}

impl fmt::Display for FindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyRange => "finding byte range is empty",
            Self::EmptyValue => "finding value is empty",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for FindingError {}

#[cfg(test)]
mod tests {
    use crate::{SecretKind, SecretValue, Sensitivity, Source};

    use super::{Finding, FindingError};

    #[test]
    fn debug_output_redacts_finding_value() {
        let raw = "sk-test-super-secret";
        let finding = Finding::new(
            SecretKind::ApiKey,
            Sensitivity::Secret,
            Source::EnvironmentVariable("OPENAI_API_KEY".to_owned()),
            4..24,
            SecretValue::new(raw),
        )
        .unwrap_or_else(|error| unreachable!("test finding must be valid: {error}"));

        let debug = format!("{finding:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(raw));
    }

    #[test]
    fn rejects_empty_ranges_and_values() {
        let empty_range = Finding::new(
            SecretKind::Token,
            Sensitivity::Secret,
            Source::StandardInput,
            3..3,
            SecretValue::new("value"),
        );
        let empty_value = Finding::new(
            SecretKind::Token,
            Sensitivity::Secret,
            Source::StandardInput,
            0..1,
            SecretValue::new(""),
        );

        assert_eq!(empty_range, Err(FindingError::EmptyRange));
        assert_eq!(empty_value, Err(FindingError::EmptyValue));
    }
}
