//! Isolated process execution with explicit secret injection and sanitized output.
//!
//! The runtime starts children with an empty environment unless the caller adds
//! baseline values, named parent-environment passthrough, or explicit secret
//! bindings. It prevents exact injected secret values from appearing in the
//! executable or argument vector and removes those values from captured output.
//!
//! This is an execution boundary, not a process sandbox. A child intentionally
//! given a secret can still transform or exfiltrate that value through unmanaged
//! files, processes, or network connections.

#![forbid(unsafe_code)]

mod redactor;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use blindfold_core::SecretValue;

use crate::redactor::{RedactionSummary, StreamingRedactor};

const DEFAULT_OUTPUT_LIMIT: usize = 1024 * 1024;
const READ_BUFFER_SIZE: usize = 8 * 1024;

/// A validated environment-variable name safe to retain in audit metadata.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentName(String);

impl EnvironmentName {
    /// Validates an environment-variable name.
    ///
    /// Names are restricted to portable ASCII identifiers so audit labels cannot
    /// contain control characters, values, or platform-specific separators.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError::InvalidEnvironmentName`] when `name` is empty,
    /// longer than 128 bytes, starts with a digit, or contains characters other
    /// than ASCII letters, digits, and underscores.
    pub fn new(name: impl Into<String>) -> Result<Self, ExecutionError> {
        let name = name.into();
        let mut bytes = name.bytes();
        let first = bytes.next().ok_or(ExecutionError::InvalidEnvironmentName)?;
        if name.len() > 128
            || !(first.is_ascii_alphabetic() || first == b'_')
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(ExecutionError::InvalidEnvironmentName);
        }
        Ok(Self(name))
    }

    /// Returns the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EnvironmentName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("EnvironmentName")
            .field(&self.0)
            .finish()
    }
}

/// An explicitly named secret to inject into a child environment.
pub struct SecretBinding {
    name: EnvironmentName,
    value: SecretValue,
}

impl SecretBinding {
    /// Creates a named secret binding.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError::EmptySecret`] for an empty value.
    pub fn new(name: EnvironmentName, value: SecretValue) -> Result<Self, ExecutionError> {
        if value.is_empty() {
            return Err(ExecutionError::EmptySecret);
        }
        Ok(Self { name, value })
    }

    /// Returns the environment-variable name.
    #[must_use]
    pub const fn name(&self) -> &EnvironmentName {
        &self.name
    }
}

impl fmt::Debug for SecretBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBinding")
            .field("name", &"[OMITTED]")
            .field("value", &self.value)
            .finish()
    }
}

/// Environment configuration for a child process.
#[derive(Clone, Default)]
pub struct EnvironmentPolicy {
    baseline: BTreeMap<EnvironmentName, OsString>,
    passthrough: BTreeSet<EnvironmentName>,
}

impl fmt::Debug for EnvironmentPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentPolicy")
            .field("baseline_names", &self.baseline.keys().collect::<Vec<_>>())
            .field("passthrough", &self.passthrough)
            .finish()
    }
}

impl EnvironmentPolicy {
    /// Creates an empty environment policy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            baseline: BTreeMap::new(),
            passthrough: BTreeSet::new(),
        }
    }

    /// Adds a fixed non-secret baseline value.
    ///
    /// Baseline values should be limited to values required for child startup.
    /// They are not treated as secrets by the exact-value output redactor.
    pub fn set_baseline(&mut self, name: EnvironmentName, value: impl Into<OsString>) {
        self.baseline.insert(name, value.into());
    }

    /// Allows one named value to be copied from the parent environment when present.
    pub fn allow_passthrough(&mut self, name: EnvironmentName) {
        self.passthrough.insert(name);
    }

    /// Returns the configured baseline names.
    pub fn baseline_names(&self) -> impl Iterator<Item = &EnvironmentName> {
        self.baseline.keys()
    }

    /// Returns the configured passthrough names.
    pub fn passthrough_names(&self) -> impl Iterator<Item = &EnvironmentName> {
        self.passthrough.iter()
    }
}

/// A command and its non-secret process settings.
pub struct CommandSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
    working_directory: Option<PathBuf>,
}

impl CommandSpec {
    /// Creates a command specification.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            working_directory: None,
        }
    }

    /// Appends one non-secret argument.
    pub fn arg(&mut self, argument: impl Into<OsString>) {
        self.arguments.push(argument.into());
    }

    /// Appends non-secret arguments.
    pub fn args(&mut self, arguments: impl IntoIterator<Item = impl Into<OsString>>) {
        self.arguments.extend(arguments.into_iter().map(Into::into));
    }

    /// Sets the child working directory.
    pub fn set_working_directory(&mut self, path: impl Into<PathBuf>) {
        self.working_directory = Some(path.into());
    }

    /// Returns the executable path.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Returns the argument vector, excluding the executable.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
}

impl fmt::Debug for CommandSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandSpec")
            .field("program", &"[OMITTED]")
            .field("argument_count", &self.arguments.len())
            .field(
                "working_directory",
                &self.working_directory.as_ref().map(|_| "[OMITTED]"),
            )
            .finish()
    }
}

/// Runtime limits for process execution.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionLimits {
    output_bytes_per_stream: usize,
    timeout: Option<Duration>,
}

impl ExecutionLimits {
    /// Creates limits with a one MiB sanitized-output cap per stream and no timeout.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            output_bytes_per_stream: DEFAULT_OUTPUT_LIMIT,
            timeout: None,
        }
    }

    /// Sets the maximum retained sanitized bytes for each output stream.
    pub fn set_output_bytes_per_stream(&mut self, limit: usize) {
        self.output_bytes_per_stream = limit;
    }

    /// Sets an optional wall-clock timeout.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    /// Returns the per-stream output limit.
    #[must_use]
    pub const fn output_bytes_per_stream(self) -> usize {
        self.output_bytes_per_stream
    }

    /// Returns the wall-clock timeout.
    #[must_use]
    pub const fn timeout(self) -> Option<Duration> {
        self.timeout
    }
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete input for one managed child execution.
pub struct ExecutionRequest {
    command: CommandSpec,
    environment: EnvironmentPolicy,
    secrets: Vec<SecretBinding>,
    limits: ExecutionLimits,
}

impl ExecutionRequest {
    /// Creates a request with an empty child environment and default limits.
    #[must_use]
    pub fn new(command: CommandSpec) -> Self {
        Self {
            command,
            environment: EnvironmentPolicy::new(),
            secrets: Vec::new(),
            limits: ExecutionLimits::new(),
        }
    }

    /// Replaces the child environment policy.
    pub fn set_environment(&mut self, environment: EnvironmentPolicy) {
        self.environment = environment;
    }

    /// Adds an explicit secret binding.
    pub fn add_secret(&mut self, secret: SecretBinding) {
        self.secrets.push(secret);
    }

    /// Replaces the execution limits.
    pub fn set_limits(&mut self, limits: ExecutionLimits) {
        self.limits = limits;
    }
}

impl fmt::Debug for ExecutionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionRequest")
            .field("command", &self.command)
            .field("baseline_count", &self.environment.baseline.len())
            .field("passthrough_count", &self.environment.passthrough.len())
            .field("secret_count", &self.secrets.len())
            .field("limits", &self.limits)
            .finish()
    }
}

/// Portable process termination metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitMetadata {
    code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
}

impl ExitMetadata {
    /// Returns the normal process exit code, if one was available.
    #[must_use]
    pub const fn code(self) -> Option<i32> {
        self.code
    }

    /// Returns the terminating signal number on supported Unix platforms.
    #[must_use]
    pub const fn signal(self) -> Option<i32> {
        self.signal
    }

    /// Returns whether the runtime killed the child after its timeout.
    #[must_use]
    pub const fn timed_out(self) -> bool {
        self.timed_out
    }

    /// Returns whether the process exited successfully without timing out.
    #[must_use]
    pub fn success(self) -> bool {
        self.code == Some(0) && !self.timed_out
    }
}

/// Safe metadata suitable for an execution audit record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionAudit {
    argument_count: usize,
    working_directory_set: bool,
    secret_names: Vec<EnvironmentName>,
    baseline_names: Vec<EnvironmentName>,
    passthrough_names: Vec<EnvironmentName>,
    duration: Duration,
    exit: ExitMetadata,
    stdout_bytes_read: u64,
    stderr_bytes_read: u64,
    stdout_redactions: u64,
    stderr_redactions: u64,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

impl ExecutionAudit {
    /// Returns the number of command arguments, excluding the executable.
    #[must_use]
    pub const fn argument_count(&self) -> usize {
        self.argument_count
    }

    /// Returns whether a working directory was explicitly configured.
    #[must_use]
    pub const fn working_directory_set(&self) -> bool {
        self.working_directory_set
    }

    /// Returns explicitly injected secret labels.
    #[must_use]
    pub fn secret_names(&self) -> &[EnvironmentName] {
        &self.secret_names
    }

    /// Returns fixed baseline environment labels.
    #[must_use]
    pub fn baseline_names(&self) -> &[EnvironmentName] {
        &self.baseline_names
    }

    /// Returns allowed parent-environment passthrough labels.
    #[must_use]
    pub fn passthrough_names(&self) -> &[EnvironmentName] {
        &self.passthrough_names
    }

    /// Returns wall-clock execution duration.
    #[must_use]
    pub const fn duration(&self) -> Duration {
        self.duration
    }

    /// Returns process termination metadata.
    #[must_use]
    pub const fn exit(&self) -> ExitMetadata {
        self.exit
    }

    /// Returns bytes drained from stdout before sanitization.
    #[must_use]
    pub const fn stdout_bytes_read(&self) -> u64 {
        self.stdout_bytes_read
    }

    /// Returns bytes drained from stderr before sanitization.
    #[must_use]
    pub const fn stderr_bytes_read(&self) -> u64 {
        self.stderr_bytes_read
    }

    /// Returns exact-value replacements made in stdout.
    #[must_use]
    pub const fn stdout_redactions(&self) -> u64 {
        self.stdout_redactions
    }

    /// Returns exact-value replacements made in stderr.
    #[must_use]
    pub const fn stderr_redactions(&self) -> u64 {
        self.stderr_redactions
    }

    /// Returns whether sanitized stdout exceeded its retention limit.
    #[must_use]
    pub const fn stdout_truncated(&self) -> bool {
        self.stdout_truncated
    }

    /// Returns whether sanitized stderr exceeded its retention limit.
    #[must_use]
    pub const fn stderr_truncated(&self) -> bool {
        self.stderr_truncated
    }
}

/// Sanitized output and safe metadata from a completed child.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionResult {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    audit: ExecutionAudit,
}

impl ExecutionResult {
    /// Returns bounded, sanitized stdout bytes.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns bounded, sanitized stderr bytes.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Returns safe execution metadata.
    #[must_use]
    pub const fn audit(&self) -> &ExecutionAudit {
        &self.audit
    }
}

/// Safely reportable runtime failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExecutionError {
    /// An environment name was not a portable identifier.
    InvalidEnvironmentName,
    /// Empty secret values cannot be safely used as redaction patterns.
    EmptySecret,
    /// An environment label was configured more than once.
    DuplicateEnvironmentName,
    /// An exact injected secret was found in the executable or arguments.
    SecretInArguments,
    /// An exact injected secret overlaps metadata retained for audit.
    SecretInMetadata,
    /// The child process could not be started.
    SpawnFailed,
    /// The child process could not be observed or terminated.
    ProcessControlFailed,
    /// Captured child output could not be read.
    OutputReadFailed,
    /// An internal output-reader thread failed.
    OutputWorkerFailed,
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEnvironmentName => "invalid environment variable name",
            Self::EmptySecret => "empty secrets cannot be injected",
            Self::DuplicateEnvironmentName => "environment variable configured more than once",
            Self::SecretInArguments => "an injected secret is present in process arguments",
            Self::SecretInMetadata => "an injected secret is present in audit metadata",
            Self::SpawnFailed => "child process could not be started",
            Self::ProcessControlFailed => "child process could not be controlled",
            Self::OutputReadFailed => "child process output could not be read",
            Self::OutputWorkerFailed => "child output worker failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ExecutionError {}

/// Executes one child with an isolated environment and sanitized output.
///
/// # Errors
///
/// Returns a safe [`ExecutionError`] when request validation, process startup,
/// process control, or output capture fails.
pub fn execute(request: &ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
    validate_request(request)?;

    let patterns = Arc::new(
        request
            .secrets
            .iter()
            .map(|secret| secret.value.expose_secret().as_bytes().to_vec())
            .collect::<Vec<_>>(),
    );
    let mut command = build_command(request);
    let started = Instant::now();
    let mut child = command.spawn().map_err(|_| ExecutionError::SpawnFailed)?;
    let Some(stdout) = child.stdout.take() else {
        terminate_child(&mut child);
        return Err(ExecutionError::SpawnFailed);
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_child(&mut child);
        return Err(ExecutionError::SpawnFailed);
    };
    let output_limit = request.limits.output_bytes_per_stream;

    let stdout_patterns = Arc::clone(&patterns);
    let Ok(stdout_worker) = thread::Builder::new()
        .name("blindfold-stdout".to_owned())
        .spawn(move || capture_stream(stdout, &stdout_patterns, output_limit))
    else {
        terminate_child(&mut child);
        return Err(ExecutionError::OutputWorkerFailed);
    };
    let Ok(stderr_worker) = thread::Builder::new()
        .name("blindfold-stderr".to_owned())
        .spawn(move || capture_stream(stderr, &patterns, output_limit))
    else {
        terminate_child(&mut child);
        let _ = join_capture(stdout_worker);
        return Err(ExecutionError::OutputWorkerFailed);
    };

    let (status, timed_out) = match wait_for_child(&mut child, request.limits.timeout) {
        Ok(outcome) => outcome,
        Err(error) => {
            terminate_child(&mut child);
            let _ = join_capture(stdout_worker);
            let _ = join_capture(stderr_worker);
            return Err(error);
        }
    };
    let stdout = join_capture(stdout_worker)?;
    let stderr = join_capture(stderr_worker)?;
    let exit = exit_metadata(status, timed_out);
    let duration = started.elapsed();

    Ok(ExecutionResult {
        stdout: stdout.output,
        stderr: stderr.output,
        audit: ExecutionAudit {
            argument_count: request.command.arguments.len(),
            working_directory_set: request.command.working_directory.is_some(),
            secret_names: request
                .secrets
                .iter()
                .map(|secret| secret.name.clone())
                .collect(),
            baseline_names: request.environment.baseline.keys().cloned().collect(),
            passthrough_names: request.environment.passthrough.iter().cloned().collect(),
            duration,
            exit,
            stdout_bytes_read: stdout.bytes_read,
            stderr_bytes_read: stderr.bytes_read,
            stdout_redactions: stdout.redactions,
            stderr_redactions: stderr.redactions,
            stdout_truncated: stdout.truncated,
            stderr_truncated: stderr.truncated,
        },
    })
}

fn validate_request(request: &ExecutionRequest) -> Result<(), ExecutionError> {
    let mut names = BTreeSet::new();
    for name in request
        .environment
        .baseline
        .keys()
        .chain(&request.environment.passthrough)
        .chain(request.secrets.iter().map(|secret| &secret.name))
    {
        if !names.insert(name) {
            return Err(ExecutionError::DuplicateEnvironmentName);
        }
    }

    for secret in &request.secrets {
        let value = secret.value.expose_secret();
        if os_str_contains(request.command.program.as_os_str(), value)
            || request
                .command
                .arguments
                .iter()
                .any(|argument| os_str_contains(argument, value))
        {
            return Err(ExecutionError::SecretInArguments);
        }
        if names
            .iter()
            .any(|name| contains_bytes(name.as_str().as_bytes(), value.as_bytes()))
        {
            return Err(ExecutionError::SecretInMetadata);
        }
    }
    Ok(())
}

fn build_command(request: &ExecutionRequest) -> Command {
    let mut command = Command::new(&request.command.program);
    command
        .args(&request.command.arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        command.process_group(0);
    }

    if let Some(path) = &request.command.working_directory {
        command.current_dir(path);
    }
    for (name, value) in &request.environment.baseline {
        command.env(name.as_str(), value);
    }
    for name in &request.environment.passthrough {
        if let Some(value) = std::env::var_os(name.as_str()) {
            command.env(name.as_str(), value);
        }
    }
    for secret in &request.secrets {
        command.env(secret.name.as_str(), secret.value.expose_secret());
    }
    command
}

fn wait_for_child(
    child: &mut std::process::Child,
    timeout: Option<Duration>,
) -> Result<(ExitStatus, bool), ExecutionError> {
    let Some(timeout) = timeout else {
        return child
            .wait()
            .map(|status| (status, false))
            .map_err(|_| ExecutionError::ProcessControlFailed);
    };

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ExecutionError::ProcessControlFailed)?;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| ExecutionError::ProcessControlFailed)?
        {
            terminate_descendants(child);
            return Ok((status, false));
        }
        if Instant::now() >= deadline {
            terminate_process_group(child)?;
            let status = child
                .wait()
                .map_err(|_| ExecutionError::ProcessControlFailed)?;
            return Ok((status, true));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn terminate_child(child: &mut std::process::Child) {
    let _ = terminate_process_group(child);
    let _ = child.wait();
}

#[cfg(unix)]
fn terminate_process_group(child: &mut std::process::Child) -> Result<(), ExecutionError> {
    use nix::{
        sys::signal::{Signal, killpg},
        unistd::Pid,
    };

    let process_group = i32::try_from(child.id())
        .map(Pid::from_raw)
        .map_err(|_| ExecutionError::ProcessControlFailed)?;
    killpg(process_group, Signal::SIGKILL).map_err(|_| ExecutionError::ProcessControlFailed)
}

#[cfg(not(unix))]
fn terminate_process_group(child: &mut std::process::Child) -> Result<(), ExecutionError> {
    child
        .kill()
        .map_err(|_| ExecutionError::ProcessControlFailed)
}

#[cfg(unix)]
fn terminate_descendants(child: &mut std::process::Child) {
    let _ = terminate_process_group(child);
}

#[cfg(not(unix))]
const fn terminate_descendants(_child: &mut std::process::Child) {}

fn capture_stream(
    mut stream: impl Read,
    patterns: &[Vec<u8>],
    limit: usize,
) -> Result<RedactionSummary, io::Error> {
    let mut redactor = StreamingRedactor::new(patterns, limit);
    let mut buffer = [0_u8; READ_BUFFER_SIZE];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        redactor.push(&buffer[..read]);
    }
    Ok(redactor.finish())
}

fn join_capture(
    worker: thread::JoinHandle<Result<RedactionSummary, io::Error>>,
) -> Result<RedactionSummary, ExecutionError> {
    worker
        .join()
        .map_err(|_| ExecutionError::OutputWorkerFailed)?
        .map_err(|_| ExecutionError::OutputReadFailed)
}

#[cfg(unix)]
fn os_str_contains(value: &OsStr, needle: &str) -> bool {
    use std::os::unix::ffi::OsStrExt;

    contains_bytes(value.as_bytes(), needle.as_bytes())
}

#[cfg(not(unix))]
fn os_str_contains(value: &OsStr, needle: &str) -> bool {
    value.to_string_lossy().contains(needle)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|candidate| candidate == needle)
}

fn exit_metadata(status: ExitStatus, timed_out: bool) -> ExitMetadata {
    ExitMetadata {
        code: status.code(),
        signal: exit_signal(status),
        timed_out,
    }
}

#[cfg(unix)]
fn exit_signal(status: ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    status.signal()
}

#[cfg(not(unix))]
const fn exit_signal(_status: ExitStatus) -> Option<i32> {
    None
}
