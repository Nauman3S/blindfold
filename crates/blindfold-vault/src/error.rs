use std::fmt;

/// Result type returned by vault and audit operations.
pub type VaultResult<T> = Result<T, VaultError>;

/// Safely printable failure returned by this crate.
///
/// Variants deliberately contain no paths, payloads, keys, identifiers, or
/// wrapped I/O errors because those values may be sensitive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VaultError {
    /// A caller-provided option or identifier was invalid.
    InvalidInput,
    /// A filesystem operation failed.
    StorageUnavailable,
    /// Randomness could not be obtained from the operating system.
    RandomnessUnavailable,
    /// The vault could not be authenticated or decoded.
    ///
    /// Corruption and a wrong key intentionally produce the same error.
    CorruptOrWrongKey,
    /// A reference was absent, expired, or outside the requested scope.
    ReferenceRejected,
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidInput => "vault input is invalid",
            Self::StorageUnavailable => "protected storage is unavailable",
            Self::RandomnessUnavailable => "secure randomness is unavailable",
            Self::CorruptOrWrongKey => "vault authentication failed",
            Self::ReferenceRejected => "safe reference was rejected",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for VaultError {}
