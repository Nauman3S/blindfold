use std::fmt;

/// Stable category for a safely reportable failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Input was malformed or unsupported.
    InvalidInput,
    /// Policy denied the operation.
    PolicyDenied,
    /// A safe reference was invalid, unknown, expired, or unauthorized.
    SafeRefRejected,
    /// Protected storage was unavailable or rejected an operation.
    VaultUnavailable,
    /// An internal invariant failed without safe details to expose.
    Internal,
}

/// An error whose printable state cannot contain raw runtime values.
///
/// Messages are restricted to `'static` strings. Dynamic context, raw payloads,
/// and wrapped source errors are deliberately unsupported because their formatting
/// may expose sensitive values. Record additional diagnostics only through
/// separately reviewed, typed safe fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedactedError {
    code: ErrorCode,
    message: &'static str,
}

impl RedactedError {
    /// Creates an error from a stable code and compile-time message.
    #[must_use]
    pub const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    /// Returns the stable error category.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        self.code
    }

    /// Returns the safe, static diagnostic message.
    #[must_use]
    pub const fn message(self) -> &'static str {
        self.message
    }
}

impl fmt::Display for RedactedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for RedactedError {}

#[cfg(test)]
mod tests {
    use super::{ErrorCode, RedactedError};

    #[test]
    fn formatting_contains_only_static_safe_state() {
        let error = RedactedError::new(ErrorCode::PolicyDenied, "operation denied by policy");

        assert_eq!(format!("{error}"), "operation denied by policy");
        assert_eq!(
            format!("{error:?}"),
            "RedactedError { code: PolicyDenied, message: \"operation denied by policy\" }"
        );
    }
}
