use std::fmt;

const REDACTED: &str = "[REDACTED]";

/// A raw secret whose ordinary formatting is always redacted.
///
/// Access to the contents is intentionally explicit through
/// [`SecretValue::expose_secret`]. This type does not attempt memory zeroization;
/// adding that guarantee requires a separately reviewed storage strategy.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretValue(String);

impl SecretValue {
    /// Wraps a raw secret value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the raw value for an explicitly authorized operation.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Returns whether the wrapped value is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the byte length without exposing the value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<String> for SecretValue {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::SecretValue;

    #[test]
    fn formatting_never_reveals_contents() {
        let raw = "sk-test-super-secret";
        let value = SecretValue::new(raw);

        let debug = format!("{value:?}");
        let display = format!("{value}");

        assert_eq!(debug, "[REDACTED]");
        assert_eq!(display, "[REDACTED]");
        assert!(!debug.contains(raw));
        assert!(!display.contains(raw));
    }
}
