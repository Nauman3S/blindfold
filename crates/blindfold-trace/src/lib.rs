//! Safe, bounded, payload-free request tracing for Blindfold.
//!
//! Trace records use a closed schema and contain only route, coverage, outcome,
//! byte counts, and sanitized replacement metadata. Payloads, headers, query
//! strings, detector spans, and free-form messages are not representable.

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Result type for trace operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Safe trace operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// An input violates the closed trace schema.
    InvalidInput,
    /// Trace storage could not be accessed safely.
    StorageUnavailable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "trace metadata is invalid",
            Self::StorageUnavailable => "trace storage is unavailable",
        })
    }
}

impl std::error::Error for Error {}

/// Closed command activity or provider route for one trace record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    /// OpenAI-compatible traffic.
    OpenAi,
    /// Anthropic-compatible traffic.
    Anthropic,
    /// A request did not match an allowlisted provider route.
    Unknown,
    /// A local file/stdin redaction operation.
    Redact,
    /// A repository or file scan operation.
    Scan,
    /// A local explicit-secret execution operation.
    Exec,
    /// A policy inspection operation.
    Policy,
    /// A generated-diff inspection operation.
    DiffCheck,
    /// A vault operation.
    Vault,
    /// An audit inspection operation.
    Audit,
    /// A standalone proxy operation.
    Proxy,
    /// A guarded outbound destination decision.
    Egress,
    /// An MCP stdio operation.
    Mcp,
    /// A Claude Code wrapper session.
    RunClaude,
    /// A Codex wrapper session.
    RunCodex,
    /// An `OpenCode` wrapper session.
    RunOpencode,
    /// A project initialization operation.
    Init,
    /// A local diagnostic operation.
    Doctor,
    /// A shell wrapper generation operation.
    ShellInit,
}

/// How completely Blindfold inspected one exchange.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// Supported content was inspected in both directions.
    Protected,
    /// Some supported metadata exists, but inspection was incomplete.
    Degraded,
    /// The exchange was rejected before a protected boundary was established.
    Unprotected,
}

/// Safe result of one exchange.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Blindfold observed a local command invocation.
    Observed,
    /// Request and response completed through the managed proxy.
    Succeeded,
    /// Blindfold rejected the exchange.
    Rejected,
    /// The allowlisted upstream failed.
    Failed,
    /// The exchange exceeded its configured deadline.
    TimedOut,
}

/// Prominent, closed reason for degraded or failed coverage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Issue {
    /// Request media type or method was unsupported.
    UnsupportedRequest,
    /// Upstream response media type was unsupported.
    UnsupportedResponse,
    /// Request exceeded its configured limit.
    RequestTooLarge,
    /// Response exceeded its configured limit.
    ResponseTooLarge,
    /// JSON or SSE content was malformed.
    InvalidPayload,
    /// The request attempted to loop through Blindfold.
    ProxyLoop,
    /// The route was not allowlisted.
    RouteNotAllowed,
    /// The upstream failed.
    UpstreamFailure,
    /// The request timed out.
    Timeout,
    /// The managed agent can still read project files without Blindfold mediation.
    DirectFilesystemUnmediated,
}

/// Closed detector category retained for correlation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// `OpenAI` API key.
    OpenAiApiKey,
    /// Anthropic API key.
    AnthropicApiKey,
    /// GitHub token.
    GitHubToken,
    /// Stripe key.
    StripeKey,
    /// Slack token.
    SlackToken,
    /// AWS access-key identifier.
    AwsAccessKeyId,
    /// AWS secret access key.
    AwsSecretAccessKey,
    /// Bearer token.
    BearerToken,
    /// JSON Web Token.
    Jwt,
    /// OAuth token.
    OAuthToken,
    /// PEM private key.
    PemPrivateKey,
    /// Credential-bearing URL password.
    CredentialUrl,
    /// Password-like value.
    Password,
    /// API-key-like value.
    ApiKey,
    /// Token-like value.
    Token,
    /// Replacement reported by a sanitizer without a more specific category.
    Sensitive,
}

impl Category {
    /// Returns the stable display label.
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
            Self::Jwt => "jwt",
            Self::OAuthToken => "oauth_token",
            Self::PemPrivateKey => "pem_private_key",
            Self::CredentialUrl => "credential_url",
            Self::Password => "password",
            Self::ApiKey => "api_key",
            Self::Token => "token",
            Self::Sensitive => "sensitive",
        }
    }
}

/// Safe replacement summary for one structural location and category.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Replacement {
    id: String,
    category: Category,
    pointer: String,
    occurrences: u32,
}

impl Replacement {
    /// Creates validated replacement metadata.
    ///
    /// # Errors
    ///
    /// Rejects invalid operation-local IDs, pointers, or zero occurrence counts.
    pub fn new(
        id: impl Into<String>,
        category: Category,
        pointer: impl Into<String>,
        occurrences: u32,
    ) -> Result<Self> {
        let replacement = Self {
            id: id.into(),
            category,
            pointer: pointer.into(),
            occurrences,
        };
        replacement.validate()?;
        Ok(replacement)
    }

    /// Returns the operation-local replacement identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the detector category.
    #[must_use]
    pub const fn category(&self) -> Category {
        self.category
    }

    /// Returns the sanitized structural JSON pointer.
    #[must_use]
    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    /// Returns the number of replacements at this location.
    #[must_use]
    pub const fn occurrences(&self) -> u32 {
        self.occurrences
    }

    fn validate(&self) -> Result<()> {
        let valid_id = self
            .id
            .strip_prefix('S')
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()));
        let valid_pointer = self.pointer.len() <= 256
            && self.pointer.starts_with('/')
            && self.pointer.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'~' | b'*')
            });
        if valid_id && valid_pointer && self.occurrences > 0 {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
    }
}

/// One payload-free command, session, or provider-request trace record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    version: u8,
    timestamp: u64,
    request_id: String,
    route: Route,
    coverage: Coverage,
    outcome: Outcome,
    request_bytes_before: u64,
    request_bytes_after: u64,
    response_bytes_before: u64,
    response_bytes_after: u64,
    replacements: Vec<Replacement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issue: Option<Issue>,
}

impl Record {
    /// Creates a trace record timestamped with the current system time.
    ///
    /// # Errors
    ///
    /// Rejects invalid IDs, replacement metadata, byte counts, or issue states.
    #[allow(clippy::too_many_arguments)]
    pub fn now(
        request_id: impl Into<String>,
        route: Route,
        coverage: Coverage,
        outcome: Outcome,
        request_bytes: (u64, u64),
        response_bytes: (u64, u64),
        replacements: Vec<Replacement>,
        issue: Option<Issue>,
    ) -> Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidInput)?
            .as_secs();
        let record = Self {
            version: 1,
            timestamp,
            request_id: request_id.into(),
            route,
            coverage,
            outcome,
            request_bytes_before: request_bytes.0,
            request_bytes_after: request_bytes.1,
            response_bytes_before: response_bytes.0,
            response_bytes_after: response_bytes.1,
            replacements,
            issue,
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the request identifier.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the event timestamp as Unix seconds.
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Returns the command activity or provider route.
    #[must_use]
    pub const fn route(&self) -> Route {
        self.route
    }

    /// Returns the coverage state.
    #[must_use]
    pub const fn coverage(&self) -> Coverage {
        self.coverage
    }

    /// Returns the exchange outcome.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// Returns request bytes before and after sanitization.
    #[must_use]
    pub const fn request_bytes(&self) -> (u64, u64) {
        (self.request_bytes_before, self.request_bytes_after)
    }

    /// Returns response bytes before and after sanitization.
    #[must_use]
    pub const fn response_bytes(&self) -> (u64, u64) {
        (self.response_bytes_before, self.response_bytes_after)
    }

    /// Returns replacement summaries.
    #[must_use]
    pub fn replacements(&self) -> &[Replacement] {
        &self.replacements
    }

    /// Returns a closed issue when coverage was not fully protected.
    #[must_use]
    pub const fn issue(&self) -> Option<Issue> {
        self.issue
    }

    /// Serializes the record using the versioned closed schema.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization unexpectedly fails.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|_| Error::StorageUnavailable)
    }

    fn validate(&self) -> Result<()> {
        let valid_id = self.request_id.len() <= 80
            && self.request_id.strip_prefix("req_").is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() || byte == b'_')
            });
        let valid_state = (self.coverage == Coverage::Protected && self.issue.is_none())
            || (self.coverage != Coverage::Protected && self.issue.is_some());
        if self.version != 1 || !valid_id || !valid_state || self.replacements.len() > 1024 {
            return Err(Error::InvalidInput);
        }
        self.replacements.iter().try_for_each(Replacement::validate)
    }
}

/// Owner-only, bounded, rotating JSON-lines trace store.
pub struct Store {
    path: PathBuf,
    lock_path: PathBuf,
    max_bytes: u64,
    retained_files: usize,
}

impl Store {
    /// Opens trace storage with non-zero limits.
    ///
    /// # Errors
    ///
    /// Rejects symlinks, unsafe existing directory modes, and invalid limits.
    pub fn open(path: impl AsRef<Path>, max_bytes: u64, retained_files: usize) -> Result<Self> {
        if max_bytes == 0 || retained_files == 0 {
            return Err(Error::InvalidInput);
        }
        let path = path.as_ref().to_path_buf();
        prepare_parent(&path)?;
        reject_symlink(&path)?;
        let lock_path = adjacent_path(&path, "lock")?;
        drop(open_lock(&lock_path)?);
        restrict_file(&path)?;
        Ok(Self {
            path,
            lock_path,
            max_bytes,
            retained_files,
        })
    }

    /// Appends one complete trace record and rotates when needed.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, serialization, locking, or storage fails.
    pub fn append(&self, record: &Record) -> Result<()> {
        record.validate()?;
        let line = record.to_json()?.into_bytes();
        let line_len = u64::try_from(line.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or(Error::InvalidInput)?;
        if line_len > self.max_bytes {
            return Err(Error::InvalidInput);
        }
        let _lock = open_lock(&self.lock_path)?;
        let current_len = match reject_symlink(&self.path)? {
            PathState::Missing => 0,
            PathState::Present => fs::metadata(&self.path)
                .map_err(|_| Error::StorageUnavailable)?
                .len(),
        };
        if current_len != 0 && current_len.saturating_add(line_len) > self.max_bytes {
            self.rotate()?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true).read(true);
        set_file_mode(&mut options);
        reject_symlink(&self.path)?;
        let mut file = options
            .open(&self.path)
            .map_err(|_| Error::StorageUnavailable)?;
        reject_symlink(&self.path)?;
        restrict_file(&self.path)?;
        file.write_all(&line)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_data())
            .map_err(|_| Error::StorageUnavailable)
    }

    /// Reads all retained records from oldest to newest and validates every line.
    ///
    /// # Errors
    ///
    /// Rejects symlinks, oversized files, malformed records, and unknown fields.
    pub fn read_all(&self) -> Result<Vec<Record>> {
        let _lock = open_lock(&self.lock_path)?;
        let mut records = Vec::new();
        for generation in (1..=self.retained_files).rev() {
            self.read_path(&rotated_path(&self.path, generation)?, &mut records)?;
        }
        self.read_path(&self.path, &mut records)?;
        Ok(records)
    }

    /// Removes active and rotated trace records while preserving the lock file.
    ///
    /// # Errors
    ///
    /// Rejects symlinks or filesystem failures.
    pub fn clear(&self) -> Result<usize> {
        let _lock = open_lock(&self.lock_path)?;
        let mut removed = 0;
        for generation in 0..=self.retained_files {
            let path = if generation == 0 {
                self.path.clone()
            } else {
                rotated_path(&self.path, generation)?
            };
            reject_symlink(&path)?;
            match fs::remove_file(path) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::StorageUnavailable),
            }
        }
        Ok(removed)
    }

    fn read_path(&self, path: &Path, records: &mut Vec<Record>) -> Result<()> {
        if reject_symlink(path)? == PathState::Missing {
            return Ok(());
        }
        let metadata = fs::metadata(path).map_err(|_| Error::StorageUnavailable)?;
        if metadata.len() > self.max_bytes {
            return Err(Error::StorageUnavailable);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        let file = options.open(path).map_err(|_| Error::StorageUnavailable)?;
        reject_symlink(path)?;
        let mut contents = Vec::with_capacity(
            usize::try_from(metadata.len()).map_err(|_| Error::StorageUnavailable)?,
        );
        file.take(self.max_bytes.saturating_add(1))
            .read_to_end(&mut contents)
            .map_err(|_| Error::StorageUnavailable)?;
        if u64::try_from(contents.len()).map_or(true, |length| length > self.max_bytes) {
            return Err(Error::StorageUnavailable);
        }
        for line in contents
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let record: Record =
                serde_json::from_slice(line).map_err(|_| Error::StorageUnavailable)?;
            record.validate().map_err(|_| Error::StorageUnavailable)?;
            records.push(record);
        }
        Ok(())
    }

    fn rotate(&self) -> Result<()> {
        let oldest = rotated_path(&self.path, self.retained_files)?;
        reject_symlink(&oldest)?;
        match fs::remove_file(oldest) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::StorageUnavailable),
        }
        for generation in (1..self.retained_files).rev() {
            let source = rotated_path(&self.path, generation)?;
            let destination = rotated_path(&self.path, generation + 1)?;
            reject_symlink(&source)?;
            reject_symlink(&destination)?;
            match fs::rename(source, destination) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::StorageUnavailable),
            }
        }
        let destination = rotated_path(&self.path, 1)?;
        reject_symlink(&self.path)?;
        reject_symlink(&destination)?;
        fs::rename(&self.path, destination).map_err(|_| Error::StorageUnavailable)
    }
}

fn prepare_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or(Error::InvalidInput)?;
    let missing = reject_symlink(parent)? == PathState::Missing;
    fs::create_dir_all(parent).map_err(|_| Error::StorageUnavailable)?;
    reject_symlink(parent)?;
    if missing {
        restrict_dir(parent)?;
    } else {
        reject_unsafe_dir(parent)?;
    }
    Ok(())
}

fn adjacent_path(path: &Path, suffix: &str) -> Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::InvalidInput)?;
    Ok(path.with_file_name(format!("{name}.{suffix}")))
}

fn rotated_path(path: &Path, generation: usize) -> Result<PathBuf> {
    adjacent_path(path, &generation.to_string())
}

fn open_lock(path: &Path) -> Result<File> {
    reject_symlink(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_file_mode(&mut options);
    let file = options.open(path).map_err(|_| Error::StorageUnavailable)?;
    reject_symlink(path)?;
    restrict_file(path)?;
    file.lock().map_err(|_| Error::StorageUnavailable)?;
    Ok(file)
}

fn restrict_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if reject_symlink(path)? == PathState::Present {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|_| Error::StorageUnavailable)?;
        }
    }
    Ok(())
}

fn restrict_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        reject_symlink(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::StorageUnavailable)?;
    }
    Ok(())
}

fn reject_unsafe_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|_| Error::StorageUnavailable)?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(Error::StorageUnavailable);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PathState {
    Missing,
    Present,
}

fn reject_symlink(path: &Path) -> Result<PathState> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::StorageUnavailable),
        Ok(_) => Ok(PathState::Present),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(PathState::Missing),
        Err(_) => Err(Error::StorageUnavailable),
    }
}

fn set_file_mode(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{Category, Coverage, Error, Issue, Outcome, Record, Replacement, Route, Store};

    fn record(id: &str) -> super::Result<Record> {
        Record::now(
            id,
            Route::Anthropic,
            Coverage::Protected,
            Outcome::Succeeded,
            (120, 110),
            (80, 70),
            vec![Replacement::new(
                "S1",
                Category::BearerToken,
                "/messages/0/content",
                2,
            )?],
            None,
        )
    }

    #[test]
    fn round_trips_closed_records_and_clears_independently()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let private = directory.path().join(".blindfold");
        fs::create_dir(&private)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
        }
        let store = Store::open(private.join("trace.jsonl"), 4096, 2)?;
        let expected = record("req_abcd_1")?;
        store.append(&expected)?;
        assert_eq!(store.read_all()?, vec![expected]);
        assert_eq!(store.clear()?, 1);
        assert!(store.read_all()?.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_free_form_or_inconsistent_records() {
        assert_eq!(
            Record::now(
                "request-secret",
                Route::OpenAi,
                Coverage::Protected,
                Outcome::Rejected,
                (0, 0),
                (0, 0),
                Vec::new(),
                Some(Issue::InvalidPayload),
            ),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            Replacement::new("S1", Category::Password, "/unsafe key", 1),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn rejects_modified_trace_files_with_payload_fields()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let private = directory.path().join(".blindfold");
        fs::create_dir(&private)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
        }
        let path = private.join("trace.jsonl");
        let store = Store::open(&path, 4096, 2)?;
        fs::write(
            path,
            "{\"version\":1,\"timestamp\":1,\"request_id\":\"req_abcd\",\"route\":\"open_ai\",\"coverage\":\"protected\",\"outcome\":\"succeeded\",\"request_bytes_before\":1,\"request_bytes_after\":1,\"response_bytes_before\":1,\"response_bytes_after\":1,\"replacements\":[],\"payload\":\"raw secret\"}\n",
        )?;
        assert_eq!(store.read_all(), Err(Error::StorageUnavailable));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_storage_without_reading_target()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempdir()?;
        let private = directory.path().join("private");
        fs::create_dir(&private)?;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
        let target = directory.path().join("target");
        fs::write(&target, b"raw target secret")?;
        symlink(&target, private.join("trace.jsonl"))?;
        assert!(matches!(
            Store::open(private.join("trace.jsonl"), 4096, 2),
            Err(Error::StorageUnavailable)
        ));
        assert_eq!(fs::read(&target)?, b"raw target secret");
        Ok(())
    }
}
