use std::fmt;
use std::str::FromStr;

const PREFIX: &str = "{{BLINDFOLD:v1:";
const SUFFIX: &str = "}}";
const ID_LENGTH: usize = 32;

/// Non-sensitive category carried by a [`SafeRef`].
///
/// The category helps an agent reason about protected data. It is not an
/// authorization claim and must never contain user-provided labels.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SafeRefKind {
    /// A credential or authentication secret.
    Secret,
    /// An environment-variable value.
    Environment,
    /// Personally identifiable information.
    PersonallyIdentifiableInformation,
    /// Private key material.
    PrivateKey,
    /// Certificate material.
    Certificate,
}

impl SafeRefKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "SECRET",
            Self::Environment => "ENV",
            Self::PersonallyIdentifiableInformation => "PII",
            Self::PrivateKey => "PRIVATE_KEY",
            Self::Certificate => "CERT",
        }
    }

    fn parse(value: &str) -> Result<Self, SafeRefError> {
        match value {
            "SECRET" => Ok(Self::Secret),
            "ENV" => Ok(Self::Environment),
            "PII" => Ok(Self::PersonallyIdentifiableInformation),
            "PRIVATE_KEY" => Ok(Self::PrivateKey),
            "CERT" => Ok(Self::Certificate),
            _ => Err(SafeRefError::InvalidKind),
        }
    }
}

/// An opaque, syntactically valid reference to protected data.
///
/// A `SafeRef` is not proof that a vault record exists and is not authorization
/// to restore a value. Every resolution attempt must independently verify scope,
/// lifetime, destination, operation, and vault authenticity. Consequently, a
/// forged string may parse successfully but remains harmless without a matching,
/// authorized vault record.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SafeRef {
    kind: SafeRefKind,
    encoded: String,
}

impl SafeRef {
    /// Constructs a reference from a non-sensitive category and 128-bit identifier
    /// encoded as 32 lowercase hexadecimal characters.
    ///
    /// The identifier must be generated independently of secret contents.
    ///
    /// # Errors
    ///
    /// Returns [`SafeRefError::InvalidLength`] for an identifier of the wrong
    /// length, or [`SafeRefError::InvalidIdentifier`] for non-lowercase-hex input.
    pub fn from_id(kind: SafeRefKind, id: &str) -> Result<Self, SafeRefError> {
        validate_id(id)?;
        Ok(Self {
            kind,
            encoded: format!("{PREFIX}{}:{id}{SUFFIX}", kind.as_str()),
        })
    }

    /// Parses and validates an untrusted reference.
    ///
    /// Successful parsing validates syntax only; it does not authenticate or
    /// authorize the reference.
    ///
    /// # Errors
    ///
    /// Returns a [`SafeRefError`] when the envelope, version, category, or
    /// identifier is invalid.
    pub fn parse(value: &str) -> Result<Self, SafeRefError> {
        let body = value
            .strip_prefix(PREFIX)
            .and_then(|rest| rest.strip_suffix(SUFFIX))
            .ok_or(SafeRefError::InvalidFormat)?;
        let (kind, id) = body.split_once(':').ok_or(SafeRefError::InvalidFormat)?;
        let kind = SafeRefKind::parse(kind)?;
        validate_id(id)?;

        let expected_length = PREFIX.len() + kind.as_str().len() + 1 + ID_LENGTH + SUFFIX.len();
        if value.len() != expected_length {
            return Err(SafeRefError::InvalidLength);
        }

        Ok(Self {
            kind,
            encoded: value.to_owned(),
        })
    }

    /// Returns the non-sensitive reference category.
    #[must_use]
    pub const fn kind(&self) -> SafeRefKind {
        self.kind
    }

    /// Returns the safe, opaque textual representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    /// Returns the format version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        1
    }
}

fn validate_id(id: &str) -> Result<(), SafeRefError> {
    if id.len() != ID_LENGTH {
        return Err(SafeRefError::InvalidLength);
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SafeRefError::InvalidIdentifier);
    }
    Ok(())
}

impl fmt::Debug for SafeRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SafeRef")
            .field(&self.encoded)
            .finish()
    }
}

impl fmt::Display for SafeRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.encoded)
    }
}

impl FromStr for SafeRef {
    type Err = SafeRefError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Reason a candidate safe reference was rejected.
///
/// Variants intentionally contain no rejected input, so formatting this error
/// cannot reflect attacker-controlled or sensitive text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SafeRefError {
    /// The candidate has an unexpected total or identifier length.
    InvalidLength,
    /// The candidate has an unsupported envelope or version.
    InvalidFormat,
    /// The candidate contains an unknown category.
    InvalidKind,
    /// The identifier contains characters outside lowercase hexadecimal.
    InvalidIdentifier,
}

impl fmt::Display for SafeRefError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidLength => "safe reference has an invalid length",
            Self::InvalidFormat => "safe reference has an invalid format",
            Self::InvalidKind => "safe reference has an invalid kind",
            Self::InvalidIdentifier => "safe reference has an invalid identifier",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SafeRefError {}

#[cfg(test)]
mod tests {
    use super::{SafeRef, SafeRefError, SafeRefKind};

    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn round_trips_valid_reference() {
        let safe_ref = SafeRef::from_id(SafeRefKind::Secret, ID).unwrap_or_else(|error| {
            unreachable!("test ID must be valid: {error}");
        });

        assert_eq!(
            safe_ref.as_str(),
            "{{BLINDFOLD:v1:SECRET:0123456789abcdef0123456789abcdef}}"
        );
        assert_eq!(safe_ref.kind(), SafeRefKind::Secret);
        assert_eq!(SafeRef::parse(safe_ref.as_str()), Ok(safe_ref));
    }

    #[test]
    fn rejects_malformed_or_secret_bearing_candidates() {
        let cases = [
            "{{BLINDFOLD:v1:SECRET:short}}",
            "{{BLINDFOLD:v2:SECRET:0123456789abcdef0123456789abcdef}}",
            "{{BLINDFOLD:v1:UNKNOWN:0123456789abcdef0123456789abcdef}}",
            "{{BLINDFOLD:v1:SECRET:0123456789ABCDEF0123456789ABCDEF}}",
            "{{BLINDFOLD:v1:SECRET:sk-test-super-secret-value-here}}",
            "prefix{{BLINDFOLD:v1:SECRET:0123456789abcdef0123456789abcdef}}",
        ];

        for candidate in cases {
            assert!(SafeRef::parse(candidate).is_err());
        }
    }

    #[test]
    fn forged_but_well_formed_reference_is_only_syntax_valid() {
        let forged = "{{BLINDFOLD:v1:SECRET:ffffffffffffffffffffffffffffffff}}";
        let parsed = SafeRef::parse(forged).unwrap_or_else(|error| {
            unreachable!("well-formed forged references parse syntactically: {error}");
        });

        assert_eq!(parsed.as_str(), forged);
    }

    #[test]
    fn parse_errors_do_not_echo_rejected_input() {
        let raw = "{{BLINDFOLD:v1:SECRET:sk-test-super-secret-value-here}}";
        let Err(error) = SafeRef::parse(raw) else {
            unreachable!("secret-bearing test input must be rejected");
        };

        assert_eq!(error, SafeRefError::InvalidLength);
        assert!(!format!("{error}").contains(raw));
        assert!(!format!("{error:?}").contains(raw));
    }
}
