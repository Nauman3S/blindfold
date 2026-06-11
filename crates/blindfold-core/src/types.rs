use std::path::PathBuf;

/// Classification assigned to a detected secret.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SecretKind {
    /// A provider or service API key.
    ApiKey,
    /// A bearer, session, refresh, or other access token.
    Token,
    /// A password or passphrase.
    Password,
    /// Private key material.
    PrivateKey,
    /// A certificate that policy treats as sensitive.
    Certificate,
    /// A URL containing embedded credentials.
    CredentialUrl,
    /// Personally identifiable information.
    PersonallyIdentifiableInformation,
    /// Sensitive material that has not received a narrower classification.
    Other,
}

/// Boundary to which data is about to be sent.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Destination {
    /// A remote or local language-model provider.
    ModelProvider,
    /// The coding agent or other model-controlled process.
    Agent,
    /// A tool invoked by an agent.
    Tool,
    /// A locally spawned child process.
    ChildProcess,
    /// A file or other persistent user content.
    File,
    /// Operational logs or tracing output.
    Log,
    /// Security audit records.
    Audit,
    /// Human-facing terminal or user-interface output.
    User,
    /// A trusted local component performing an explicitly authorized operation.
    TrustedLocal,
}

/// Policy result for sensitive data at a destination.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Action {
    /// Permit the original value to cross the boundary.
    Allow,
    /// Replace the value with a non-restorable redaction marker.
    Redact,
    /// Replace the value with a restorable safe reference.
    ReplaceWithSafeRef,
    /// Permit the operation while surfacing a safe warning.
    Warn,
    /// Refuse the operation.
    Block,
}

/// Origin from which content was obtained.
///
/// Source metadata must describe origin only. Callers must not place raw secret
/// values in names or paths.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Source {
    /// An environment variable, identified by variable name.
    EnvironmentVariable(String),
    /// A file, identified by its path.
    File(PathBuf),
    /// Standard input.
    StandardInput,
    /// Output captured from a child process.
    ProcessOutput,
    /// An inbound request.
    Request,
    /// An outbound or upstream response.
    Response,
    /// A tool boundary, identified by a safe tool name.
    Tool(String),
    /// An origin that cannot be classified more precisely.
    Unknown,
}

/// Severity of disclosure if a value crosses an unauthorized boundary.
///
/// The variant order is intentional and may be used for threshold comparisons.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Sensitivity {
    /// Safe for public disclosure.
    Public,
    /// Intended for local or organizational use.
    Internal,
    /// Disclosure would expose private information.
    Confidential,
    /// Authentication material or equivalently sensitive data.
    Secret,
    /// Material requiring the strongest handling and explicit authorization.
    Restricted,
}
