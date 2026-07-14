//! Fail-closed host services for explicitly installed agent plugins.
//!
//! This crate never searches the current directory or project tree. Callers provide exact
//! installed plugin directories and an explicit executable search path. Executable probes
//! are host-owned and run with null stdin, bounded output, a timeout, and an otherwise
//! empty environment containing only a validated explicit `PATH`.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fmt, fs,
    io::Read,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use blindfold_exec::{
    CommandSpec, EnvironmentName, EnvironmentPolicy, ExecutionLimits, ExecutionRequest, execute,
};
use blindfold_plugin_api::{MANIFEST_FILE_NAME, MAX_MANIFEST_BYTES, PluginManifest};
use semver::{Version, VersionReq};

const DEFAULT_OUTPUT_BYTES_PER_STREAM: usize = 16 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_OUTPUT_BYTES_PER_STREAM: usize = 1024 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_EXPECTED_MARKER_BYTES: usize = 128;

/// One validated, explicitly configured plugin installation directory.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct InstalledPluginDir {
    path: PathBuf,
}

impl InstalledPluginDir {
    /// Returns the canonical absolute installation directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for InstalledPluginDir {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstalledPluginDir")
            .field("path", &"[OMITTED]")
            .finish()
    }
}

/// One validated installed plugin, its manifest, and contained executable entrypoint.
pub struct InstalledPlugin {
    directory: InstalledPluginDir,
    manifest: PluginManifest,
    entrypoint: PathBuf,
}

impl InstalledPlugin {
    /// Returns the canonical installed plugin directory.
    #[must_use]
    pub const fn directory(&self) -> &InstalledPluginDir {
        &self.directory
    }

    /// Returns the strictly parsed plugin manifest.
    #[must_use]
    pub const fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// Returns the canonical executable entrypoint contained by the plugin directory.
    #[must_use]
    pub fn entrypoint(&self) -> &Path {
        &self.entrypoint
    }
}

impl fmt::Debug for InstalledPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstalledPlugin")
            .field("directory", &"[OMITTED]")
            .field("plugin_id", &self.manifest.id())
            .field("plugin_version", &self.manifest.version())
            .field("entrypoint", &"[OMITTED]")
            .finish()
    }
}

/// Validated resource limits for an executable version probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeLimits {
    timeout: Duration,
    output_bytes_per_stream: usize,
}

impl ProbeLimits {
    /// Creates bounded probe limits.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::InvalidProbeLimits`] when the timeout or output limit is zero,
    /// the timeout exceeds 30 seconds, or either retained stream could exceed one MiB.
    pub fn new(timeout: Duration, output_bytes_per_stream: usize) -> Result<Self, HostError> {
        if timeout.is_zero()
            || timeout > MAX_TIMEOUT
            || output_bytes_per_stream == 0
            || output_bytes_per_stream > MAX_OUTPUT_BYTES_PER_STREAM
        {
            return Err(HostError::InvalidProbeLimits);
        }
        Ok(Self {
            timeout,
            output_bytes_per_stream,
        })
    }

    /// Returns the probe wall-clock timeout.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    /// Returns the retained byte limit applied independently to stdout and stderr.
    #[must_use]
    pub const fn output_bytes_per_stream(self) -> usize {
        self.output_bytes_per_stream
    }
}

impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            output_bytes_per_stream: DEFAULT_OUTPUT_BYTES_PER_STREAM,
        }
    }
}

/// A successful and compatible executable version probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionProbe {
    version: Version,
}

impl VersionProbe {
    /// Returns the parsed compatible version.
    #[must_use]
    pub const fn version(&self) -> &Version {
        &self.version
    }
}

/// Safe, payload-free plugin host failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HostError {
    /// An explicit plugin path was relative, unavailable, a symlink, or not a directory.
    InvalidPluginDirectory,
    /// The same canonical plugin directory was configured more than once.
    DuplicatePluginDirectory,
    /// An installed plugin manifest was missing, unsafe, oversized, or invalid.
    InvalidPluginManifest,
    /// Two installed plugin manifests declared the same plugin identifier.
    DuplicatePluginId,
    /// A plugin entrypoint was missing, non-executable, or escaped its installation.
    InvalidPluginEntrypoint,
    /// The command or explicit search path was malformed or unsafe.
    InvalidExecutablePath,
    /// No executable could be resolved from the explicit command and search path.
    ExecutableNotFound,
    /// The resolved target was not a regular executable file.
    ExecutableNotRunnable,
    /// Probe limits were zero or exceeded the host's hard bounds.
    InvalidProbeLimits,
    /// A supplied output marker was empty, too long, or contained unsafe characters.
    InvalidExpectedMarker,
    /// The executable could not be spawned or controlled.
    ProbeFailed,
    /// The executable exceeded its probe timeout.
    ProbeTimedOut,
    /// The executable exceeded a retained output limit.
    ProbeOutputTooLarge,
    /// The executable returned an unsuccessful status.
    ProbeUnsuccessful,
    /// Probe output was not valid UTF-8.
    InvalidProbeOutput,
    /// Probe output did not identify the expected executable.
    ExpectedMarkerMissing,
    /// Probe output did not contain a semantic version.
    VersionMissing,
    /// Probe output contained more than one distinct semantic version.
    VersionAmbiguous,
    /// The discovered semantic version did not satisfy the required range.
    VersionIncompatible,
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPluginDirectory => "an explicit plugin directory is invalid",
            Self::DuplicatePluginDirectory => "an explicit plugin directory is duplicated",
            Self::InvalidPluginManifest => "an installed plugin manifest is invalid",
            Self::DuplicatePluginId => "an installed plugin identifier is duplicated",
            Self::InvalidPluginEntrypoint => "an installed plugin entrypoint is invalid",
            Self::InvalidExecutablePath => "the executable path policy rejected the command",
            Self::ExecutableNotFound => "the executable was not found in the explicit search path",
            Self::ExecutableNotRunnable => "the resolved executable is not runnable",
            Self::InvalidProbeLimits => "the executable probe limits are invalid",
            Self::InvalidExpectedMarker => "the executable marker is invalid",
            Self::ProbeFailed => "the executable version probe failed",
            Self::ProbeTimedOut => "the executable version probe timed out",
            Self::ProbeOutputTooLarge => "the executable version probe output was too large",
            Self::ProbeUnsuccessful => "the executable version probe was unsuccessful",
            Self::InvalidProbeOutput => "the executable version output is invalid",
            Self::ExpectedMarkerMissing => "the executable version marker is missing",
            Self::VersionMissing => "the executable semantic version is missing",
            Self::VersionAmbiguous => "the executable semantic version is ambiguous",
            Self::VersionIncompatible => "the executable version is incompatible",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for HostError {}

/// Validates exact installed plugin directories without searching the project tree.
///
/// The returned paths are canonical, sorted, and unique. Final-component directory
/// symlinks are rejected so a configured installation cannot silently retarget later.
/// Manifest parsing is intentionally left to the plugin API layer.
///
/// # Errors
///
/// Returns a safe [`HostError`] when any path is relative, unavailable, a symlink, not a
/// directory, or resolves to the same directory as another entry.
pub fn discover_explicit_plugin_dirs<I, P>(
    directories: I,
) -> Result<Vec<InstalledPluginDir>, HostError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut discovered = BTreeSet::new();
    for directory in directories {
        let directory = directory.as_ref();
        if !directory.is_absolute() {
            return Err(HostError::InvalidPluginDirectory);
        }
        let metadata =
            fs::symlink_metadata(directory).map_err(|_| HostError::InvalidPluginDirectory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(HostError::InvalidPluginDirectory);
        }
        let canonical =
            fs::canonicalize(directory).map_err(|_| HostError::InvalidPluginDirectory)?;
        if !discovered.insert(canonical) {
            return Err(HostError::DuplicatePluginDirectory);
        }
    }
    Ok(discovered
        .into_iter()
        .map(|path| InstalledPluginDir { path })
        .collect())
}

/// Loads strict manifests and contained entrypoints from exact installed directories.
///
/// Only [`MANIFEST_FILE_NAME`] is read beneath each already validated directory. The host
/// reads at most [`MAX_MANIFEST_BYTES`] plus one sentinel byte, rejects manifest symlinks,
/// delegates parsing to [`PluginManifest::parse_toml`], rejects duplicate plugin IDs, and
/// requires every canonical executable entrypoint to remain inside its installation.
///
/// # Errors
///
/// Returns a payload-free [`HostError`] when directory discovery, bounded manifest loading,
/// strict parsing, plugin identity uniqueness, or entrypoint containment fails.
pub fn load_explicit_plugins<I, P>(directories: I) -> Result<Vec<InstalledPlugin>, HostError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let directories = discover_explicit_plugin_dirs(directories)?;
    let mut plugin_ids = BTreeSet::new();
    let mut plugins = Vec::with_capacity(directories.len());
    for directory in directories {
        let manifest_path = directory.path.join(MANIFEST_FILE_NAME);
        let metadata =
            fs::symlink_metadata(&manifest_path).map_err(|_| HostError::InvalidPluginManifest)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(HostError::InvalidPluginManifest);
        }
        let mut file =
            fs::File::open(&manifest_path).map_err(|_| HostError::InvalidPluginManifest)?;
        let mut encoded = Vec::with_capacity(MAX_MANIFEST_BYTES.min(4096));
        file.by_ref()
            .take((MAX_MANIFEST_BYTES as u64).saturating_add(1))
            .read_to_end(&mut encoded)
            .map_err(|_| HostError::InvalidPluginManifest)?;
        let manifest =
            PluginManifest::parse_toml(&encoded).map_err(|_| HostError::InvalidPluginManifest)?;
        if !plugin_ids.insert(manifest.id().as_str().to_owned()) {
            return Err(HostError::DuplicatePluginId);
        }
        let entrypoint = validate_executable(&directory.path.join(manifest.entrypoint().as_str()))
            .map_err(|_| HostError::InvalidPluginEntrypoint)?;
        if !entrypoint.starts_with(&directory.path) {
            return Err(HostError::InvalidPluginEntrypoint);
        }
        plugins.push(InstalledPlugin {
            directory,
            manifest,
            entrypoint,
        });
    }
    Ok(plugins)
}

/// Resolves a command without consulting the current working directory.
///
/// Absolute commands are validated directly. Bare commands require an explicit `PATH`
/// value. Every search entry must be non-empty and absolute; relative entries are rejected
/// instead of being interpreted against the project. Executable symlinks are allowed but
/// canonicalized, and the returned target is always an absolute regular executable file.
///
/// # Errors
///
/// Returns a safe [`HostError`] for malformed commands or search paths, missing commands,
/// broken symlinks, non-files, and non-executable targets.
pub fn resolve_executable(command: &OsStr, path: Option<&OsStr>) -> Result<PathBuf, HostError> {
    let command_path = Path::new(command);
    if command_path.is_absolute() {
        return validate_executable(command_path);
    }
    if !is_bare_command(command_path) {
        return Err(HostError::InvalidExecutablePath);
    }
    let path = validate_search_path(path.ok_or(HostError::ExecutableNotFound)?)?;
    let entries = std::env::split_paths(&path).collect::<Vec<_>>();
    let mut found_non_runnable = false;
    for entry in entries {
        let candidate = entry.join(command_path);
        match validate_executable(&candidate) {
            Ok(executable) => return Ok(executable),
            Err(HostError::ExecutableNotRunnable) => found_non_runnable = true,
            Err(HostError::ExecutableNotFound) => {}
            Err(error) => return Err(error),
        }
    }
    if found_non_runnable {
        Err(HostError::ExecutableNotRunnable)
    } else {
        Err(HostError::ExecutableNotFound)
    }
}

/// Runs a bounded executable version probe and enforces its compatibility requirement.
///
/// The executable must already be resolved by [`resolve_executable`]. The child receives
/// null stdin and an otherwise empty environment containing only the supplied, revalidated
/// absolute-only `PATH` and an ephemeral `HOME` equal to the probe working directory.
/// `expected_marker` may be `None` for version-only output such as `OpenCode`'s `1.18.0`;
/// identity-bearing Claude and Codex manifests should supply a marker.
/// Neither captured output nor configured paths are returned in errors or `Debug` output.
///
/// # Errors
///
/// Returns a safe [`HostError`] when validation, process execution, output parsing, or the
/// compatibility requirement fails. No partially successful probe is returned.
pub fn probe_version<I, S>(
    program: &Path,
    arguments: I,
    expected_marker: Option<&str>,
    requirement: &VersionReq,
    limits: ProbeLimits,
    search_path: &OsStr,
) -> Result<VersionProbe, HostError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    if let Some(marker) = expected_marker {
        validate_marker(marker)?;
    }
    let program = validate_executable(program)?;
    let search_path = validate_search_path(search_path)?;
    let probe_directory = tempfile::Builder::new()
        .prefix("blindfold-probe-")
        .tempdir()
        .map_err(|_| HostError::ProbeFailed)?;
    let probe_path =
        fs::canonicalize(probe_directory.path()).map_err(|_| HostError::ProbeFailed)?;
    let mut command = CommandSpec::new(program);
    command.set_working_directory(&probe_path);
    command.args(
        arguments
            .into_iter()
            .map(|argument| OsString::from(argument.as_ref())),
    );
    let mut execution_limits = ExecutionLimits::new();
    execution_limits.set_timeout(Some(limits.timeout));
    execution_limits.set_output_bytes_per_stream(limits.output_bytes_per_stream);
    let mut request = ExecutionRequest::new(command);
    let mut environment = EnvironmentPolicy::new();
    let path_name = EnvironmentName::new("PATH").map_err(|_| HostError::ProbeFailed)?;
    environment.set_baseline(path_name, search_path);
    let home_name = EnvironmentName::new("HOME").map_err(|_| HostError::ProbeFailed)?;
    environment.set_baseline(home_name, probe_path.as_os_str());
    request.set_environment(environment);
    request.set_limits(execution_limits);
    let result = execute(&request).map_err(|_| HostError::ProbeFailed)?;
    if result.audit().exit().timed_out() {
        return Err(HostError::ProbeTimedOut);
    }
    if result.audit().stdout_truncated() || result.audit().stderr_truncated() {
        return Err(HostError::ProbeOutputTooLarge);
    }
    if !result.audit().exit().success() {
        return Err(HostError::ProbeUnsuccessful);
    }
    let stdout = std::str::from_utf8(result.stdout()).map_err(|_| HostError::InvalidProbeOutput)?;
    let stderr = std::str::from_utf8(result.stderr()).map_err(|_| HostError::InvalidProbeOutput)?;
    let output = format!("{stdout}\n{stderr}");
    let version = parse_version_output(&output, expected_marker)?;
    if !requirement.matches(&version) {
        return Err(HostError::VersionIncompatible);
    }
    Ok(VersionProbe { version })
}

fn parse_version_output(output: &str, expected_marker: Option<&str>) -> Result<Version, HostError> {
    if let Some(marker) = expected_marker
        && !contains_marker(output, marker)
    {
        return Err(HostError::ExpectedMarkerMissing);
    }
    let mut versions = BTreeSet::new();
    for token in output.split(is_version_separator) {
        let candidate = token
            .strip_prefix('v')
            .or_else(|| token.strip_prefix('V'))
            .unwrap_or(token);
        if let Ok(version) = Version::parse(candidate) {
            versions.insert(version);
        }
    }
    match versions.len() {
        0 => Err(HostError::VersionMissing),
        1 => versions.into_iter().next().ok_or(HostError::VersionMissing),
        _ => Err(HostError::VersionAmbiguous),
    }
}

fn contains_marker(output: &str, marker: &str) -> bool {
    let output = output.to_ascii_lowercase();
    let marker = marker.to_ascii_lowercase();
    output.match_indices(&marker).any(|(start, _)| {
        let end = start + marker.len();
        let starts_at_boundary =
            start == 0 || !output.as_bytes()[start - 1].is_ascii_alphanumeric();
        let ends_at_boundary =
            end == output.len() || !output.as_bytes()[end].is_ascii_alphanumeric();
        starts_at_boundary && ends_at_boundary
    })
}

fn is_version_separator(character: char) -> bool {
    character.is_ascii_whitespace()
        || matches!(
            character,
            ',' | ';' | ':' | '=' | '/' | '(' | ')' | '[' | ']' | '{' | '}' | '"' | '\''
        )
}

fn validate_marker(marker: &str) -> Result<(), HostError> {
    if marker.is_empty()
        || marker.len() > MAX_EXPECTED_MARKER_BYTES
        || !marker
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'_' | b'.'))
    {
        return Err(HostError::InvalidExpectedMarker);
    }
    Ok(())
}

fn is_bare_command(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn validate_search_path(path: &OsStr) -> Result<OsString, HostError> {
    let entries = std::env::split_paths(path).collect::<Vec<_>>();
    if entries.is_empty()
        || entries
            .iter()
            .any(|entry| entry.as_os_str().is_empty() || !entry.is_absolute())
    {
        return Err(HostError::InvalidExecutablePath);
    }
    std::env::join_paths(entries).map_err(|_| HostError::InvalidExecutablePath)
}

fn validate_executable(path: &Path) -> Result<PathBuf, HostError> {
    if !path.is_absolute() {
        return Err(HostError::InvalidExecutablePath);
    }
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            HostError::ExecutableNotFound
        } else {
            HostError::ExecutableNotRunnable
        }
    })?;
    if !metadata.is_file() {
        return Err(HostError::ExecutableNotRunnable);
    }
    let canonical = fs::canonicalize(path).map_err(|_| HostError::ExecutableNotRunnable)?;
    if !canonical.is_absolute() || !is_executable(&metadata) {
        return Err(HostError::ExecutableNotRunnable);
    }
    Ok(canonical)
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
const fn is_executable(_metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::{HostError, parse_version_output};

    #[test]
    fn parses_common_agent_version_outputs() -> Result<(), HostError> {
        let cases = [
            ("2.1.17 (Claude Code)", "Claude Code", "2.1.17"),
            ("codex-cli 0.141.0", "codex", "0.141.0"),
            ("opencode version v1.2.3-beta.1", "opencode", "1.2.3-beta.1"),
        ];
        for (output, marker, expected) in cases {
            let version = parse_version_output(output, Some(marker))?;
            assert_eq!(version.to_string(), expected);
        }
        Ok(())
    }

    #[test]
    fn rejects_ambiguous_versions() {
        assert_eq!(
            parse_version_output("codex 1.2.3 runtime 4.5.6", Some("codex")),
            Err(HostError::VersionAmbiguous)
        );
    }

    #[test]
    fn marker_matching_requires_identifier_boundaries() {
        assert_eq!(
            parse_version_output("notcodex 1.2.3", Some("codex")),
            Err(HostError::ExpectedMarkerMissing)
        );
    }

    #[test]
    fn parses_markerless_opencode_version_output() -> Result<(), HostError> {
        let version = parse_version_output("1.17.3", None)?;
        assert_eq!(version.to_string(), "1.17.3");
        Ok(())
    }
}
