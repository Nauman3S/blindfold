use std::fmt;
use std::ops::Range;

/// Half-open byte span within a scanned UTF-8 input.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Span {
    start: usize,
    end: usize,
}

impl Span {
    /// Creates a non-empty span.
    ///
    /// # Errors
    ///
    /// Returns [`SpanError`] if `start >= end`.
    pub const fn new(start: usize, end: usize) -> Result<Self, SpanError> {
        if start >= end {
            return Err(SpanError);
        }
        Ok(Self { start, end })
    }

    /// Returns the first covered byte offset.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Returns the exclusive ending byte offset.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }

    /// Returns the number of covered bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end - self.start
    }

    /// Returns whether the span has no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        false
    }

    /// Returns whether two spans share at least one byte.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Converts this span to a standard range.
    #[must_use]
    pub const fn as_range(self) -> Range<usize> {
        self.start..self.end
    }
}

/// Error returned when a byte span is empty or reversed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanError;

impl fmt::Display for SpanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("span must be non-empty and ordered")
    }
}

impl std::error::Error for SpanError {}

/// Confidence assigned by a detector.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Confidence {
    /// Context suggests a secret, but the syntax is not provider-specific.
    Contextual,
    /// Syntax and context provide a strong signal.
    High,
    /// The value has a provider-specific or cryptographic envelope.
    Certain,
}

/// Classification of a detected credential.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SecretKind {
    /// OpenAI API key.
    OpenAiApiKey,
    /// Anthropic API key.
    AnthropicApiKey,
    /// GitHub token.
    GitHubToken,
    /// Stripe secret or restricted key.
    StripeKey,
    /// Slack token.
    SlackToken,
    /// AWS access-key identifier.
    AwsAccessKeyId,
    /// AWS secret access key found in an assignment context.
    AwsSecretAccessKey,
    /// Authorization bearer token.
    BearerToken,
    /// JSON Web Token.
    JsonWebToken,
    /// OAuth access or refresh token.
    OAuthToken,
    /// PEM-encoded private key.
    PemPrivateKey,
    /// URL containing user information with a password.
    CredentialUrl,
    /// Password-like assignment.
    Password,
    /// API-key-like assignment not recognized as a known provider format.
    ApiKey,
    /// Token-like assignment not recognized as a known provider format.
    Token,
}

impl SecretKind {
    /// Returns a stable, non-sensitive schema label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OpenAiApiKey => "openai_api_key",
            Self::AnthropicApiKey => "anthropic_api_key",
            Self::GitHubToken => "github_token",
            Self::StripeKey => "stripe_key",
            Self::SlackToken => "slack_token",
            Self::AwsAccessKeyId => "aws_access_key_id",
            Self::AwsSecretAccessKey => "aws_secret_access_key",
            Self::BearerToken => "bearer_token",
            Self::JsonWebToken => "jwt",
            Self::OAuthToken => "oauth_token",
            Self::PemPrivateKey => "pem_private_key",
            Self::CredentialUrl => "credential_url",
            Self::Password => "password",
            Self::ApiKey => "api_key",
            Self::Token => "token",
        }
    }
}

/// Safe metadata describing a detected secret occurrence.
///
/// A finding does not contain the matched bytes. The detector name is static and
/// cannot be influenced by scanned input.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Finding {
    kind: SecretKind,
    span: Span,
    confidence: Confidence,
    detector: &'static str,
}

impl Finding {
    /// Creates finding metadata.
    #[must_use]
    pub const fn new(
        kind: SecretKind,
        span: Span,
        confidence: Confidence,
        detector: &'static str,
    ) -> Self {
        Self {
            kind,
            span,
            confidence,
            detector,
        }
    }

    /// Returns the secret classification.
    #[must_use]
    pub const fn kind(self) -> SecretKind {
        self.kind
    }

    /// Returns the byte span.
    #[must_use]
    pub const fn span(self) -> Span {
        self.span
    }

    /// Returns detector confidence.
    #[must_use]
    pub const fn confidence(self) -> Confidence {
        self.confidence
    }

    /// Returns the static detector identifier.
    #[must_use]
    pub const fn detector(self) -> &'static str {
        self.detector
    }
}
