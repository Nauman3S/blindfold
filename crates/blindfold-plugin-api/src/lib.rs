//! Strict, bounded manifest types for Blindfold harness-adapter plugins.
//!
//! Manifests describe compatibility and least-privilege requirements. They do
//! not contain shell snippets, command arguments, secrets, or authorization.
//! A host must still enforce every declared permission and reject capabilities
//! it does not support.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use semver::{Op, Version, VersionReq};
use serde::Deserialize;

/// The only manifest schema version understood by this crate.
pub const CURRENT_MANIFEST_VERSION: u16 = 1;
/// Fixed manifest filename within an installed plugin directory.
pub const MANIFEST_FILE_NAME: &str = "blindfold-plugin.toml";
/// Maximum accepted encoded manifest size.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

const MAX_PLUGIN_ID_BYTES: usize = 64;
const MAX_ENTRYPOINT_BYTES: usize = 240;
const MAX_COMMAND_BYTES: usize = 64;
const MAX_DECLARATIONS: usize = 16;

/// A validated harness-adapter plugin manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginManifest {
    manifest_version: u16,
    id: PluginId,
    version: Version,
    kind: PluginKind,
    protocol: Protocol,
    entrypoint: Entrypoint,
    harness: Harness,
    capabilities: Capabilities,
    permissions: Permissions,
}

impl PluginManifest {
    /// Parses and semantically validates a bounded UTF-8 TOML manifest.
    ///
    /// Parse failures are deliberately collapsed into a redacted error; parser
    /// diagnostics can echo attacker-controlled manifest contents.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] for oversized, malformed, unsupported, or
    /// semantically invalid input.
    pub fn parse_toml(input: &[u8]) -> Result<Self, ManifestError> {
        if input.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge);
        }
        let text = std::str::from_utf8(input).map_err(|_| ManifestError::InvalidEncoding)?;
        let raw: RawManifest = toml::from_str(text).map_err(|_| ManifestError::InvalidDocument)?;
        let manifest = Self {
            manifest_version: raw.manifest_version,
            id: PluginId(raw.id),
            version: raw.version,
            kind: raw.kind,
            protocol: raw.protocol,
            entrypoint: Entrypoint(raw.entrypoint),
            harness: Harness {
                command: raw.harness.command,
                version_requirement: raw.harness.version,
                noninteractive_modes: raw.harness.noninteractive_modes,
            },
            capabilities: Capabilities {
                providers: raw.capabilities.providers,
                transports: raw.capabilities.transports,
                events: raw.capabilities.events,
            },
            permissions: Permissions {
                filesystem: raw.permissions.filesystem,
                network: raw.permissions.network,
                environment: raw.permissions.environment,
                spawn_harness: raw.permissions.spawn_harness,
                spawn_tools: raw.permissions.spawn_tools,
            },
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Revalidates all cross-field and bounded-value invariants.
    ///
    /// # Errors
    ///
    /// Returns a redacted [`ManifestError`] when an invariant is not met.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.manifest_version != CURRENT_MANIFEST_VERSION {
            return Err(ManifestError::UnsupportedManifestVersion);
        }
        validate_plugin_id(self.id.as_str())?;
        validate_entrypoint(self.entrypoint.as_str())?;
        validate_command(self.harness.command())?;
        if !has_finite_version_bounds(&self.harness.version_requirement) {
            return Err(ManifestError::UnboundedHarnessVersion);
        }
        validate_nonempty_unique(&self.harness.noninteractive_modes)?;
        validate_nonempty_unique(&self.capabilities.providers)?;
        validate_nonempty_unique(&self.capabilities.transports)?;
        validate_nonempty_unique(&self.capabilities.events)?;
        validate_unique(&self.permissions.filesystem)?;
        validate_unique(&self.permissions.network)?;
        validate_unique(&self.permissions.environment)?;
        if !self.capabilities.events.contains(&Event::ModelRequest)
            || !self.capabilities.events.contains(&Event::ModelResponse)
        {
            return Err(ManifestError::MissingBoundaryEvents);
        }
        if !self.permissions.spawn_harness
            || !self
                .permissions
                .network
                .contains(&NetworkPermission::ModelProxy)
        {
            return Err(ManifestError::InsufficientBoundaryPermissions);
        }
        if self
            .permissions
            .filesystem
            .contains(&FilesystemPermission::WorkspaceWrite)
            && !self
                .permissions
                .filesystem
                .contains(&FilesystemPermission::WorkspaceRead)
        {
            return Err(ManifestError::InvalidPermissionCombination);
        }
        Ok(())
    }

    /// Returns the manifest schema version.
    #[must_use]
    pub const fn manifest_version(&self) -> u16 {
        self.manifest_version
    }

    /// Returns the validated plugin identifier.
    #[must_use]
    pub const fn id(&self) -> &PluginId {
        &self.id
    }

    /// Returns the plugin's semantic version.
    #[must_use]
    pub const fn version(&self) -> &Version {
        &self.version
    }

    /// Returns the plugin kind.
    #[must_use]
    pub const fn kind(&self) -> PluginKind {
        self.kind
    }

    /// Returns the host/plugin protocol.
    #[must_use]
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns the validated relative executable path.
    #[must_use]
    pub const fn entrypoint(&self) -> &Entrypoint {
        &self.entrypoint
    }

    /// Returns the harness compatibility declaration.
    #[must_use]
    pub const fn harness(&self) -> &Harness {
        &self.harness
    }

    /// Returns provider and event capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// Returns requested least-privilege permissions.
    #[must_use]
    pub const fn permissions(&self) -> &Permissions {
        &self.permissions
    }
}

/// A validated, non-secret plugin identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PluginId(String);

impl PluginId {
    /// Returns the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A validated plugin-directory-relative executable path.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Entrypoint(String);

impl Entrypoint {
    /// Returns the relative path text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Entrypoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Supported plugin category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum PluginKind {
    /// An adapter for one noninteractive AI harness CLI.
    HarnessAdapter,
}

/// Supported host/plugin wire protocol.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// Core-owned built-in adapter selection with no external entrypoint execution.
    BuiltinV1,
    /// Framed JSON messages over inherited standard input and output.
    StdioJsonV1,
}

/// Harness executable and version compatibility declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Harness {
    command: String,
    version_requirement: VersionReq,
    noninteractive_modes: Vec<NonInteractiveMode>,
}

impl Harness {
    /// Returns the executable basename. It is never a shell command string.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Returns the supported harness semantic-version requirement.
    #[must_use]
    pub const fn version_requirement(&self) -> &VersionReq {
        &self.version_requirement
    }

    /// Returns the supported noninteractive invocation modes.
    #[must_use]
    pub fn noninteractive_modes(&self) -> &[NonInteractiveMode] {
        &self.noninteractive_modes
    }
}

/// Closed noninteractive harness modes supported by the initial protocol.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum NonInteractiveMode {
    /// Claude-style print mode.
    Print,
    /// Codex-style execution mode.
    Exec,
    /// Codex-style review mode.
    Review,
    /// `OpenCode`-style run mode.
    Run,
}

/// Declared provider, transport, and event capabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    providers: Vec<Provider>,
    transports: Vec<Transport>,
    events: Vec<Event>,
}

impl Capabilities {
    /// Returns provider families the adapter can mediate.
    #[must_use]
    pub fn providers(&self) -> &[Provider] {
        &self.providers
    }

    /// Returns provider transports the adapter can mediate.
    #[must_use]
    pub fn transports(&self) -> &[Transport] {
        &self.transports
    }

    /// Returns lifecycle events the adapter emits to the host.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }
}

/// Closed provider families.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// OpenAI-compatible APIs.
    OpenAi,
    /// Anthropic APIs.
    Anthropic,
    /// `OpenRouter`'s OpenAI-compatible API.
    OpenRouter,
}

/// Closed model-traffic transports.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    /// One request and response using JSON over HTTP.
    HttpJson,
    /// Server-sent event response streaming.
    ServerSentEvents,
    /// WebSocket message streaming.
    WebSocket,
}

/// Closed adapter lifecycle events.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum Event {
    /// A request about to cross the model boundary.
    ModelRequest,
    /// A response received from the model boundary.
    ModelResponse,
    /// A tool request emitted by the harness.
    ToolRequest,
    /// A tool result about to re-enter model context.
    ToolResult,
    /// Final noninteractive command output.
    CommandOutput,
}

/// Explicit least-privilege requirements requested by an adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Permissions {
    filesystem: Vec<FilesystemPermission>,
    network: Vec<NetworkPermission>,
    environment: Vec<EnvironmentPermission>,
    spawn_harness: bool,
    spawn_tools: bool,
}

impl Permissions {
    /// Returns requested filesystem grants.
    #[must_use]
    pub fn filesystem(&self) -> &[FilesystemPermission] {
        &self.filesystem
    }

    /// Returns requested network grants.
    #[must_use]
    pub fn network(&self) -> &[NetworkPermission] {
        &self.network
    }

    /// Returns requested non-secret environment categories.
    #[must_use]
    pub fn environment(&self) -> &[EnvironmentPermission] {
        &self.environment
    }

    /// Returns whether the adapter requests permission to spawn its harness.
    #[must_use]
    pub const fn spawn_harness(&self) -> bool {
        self.spawn_harness
    }

    /// Returns whether the adapter requests permission to spawn tool processes.
    #[must_use]
    pub const fn spawn_tools(&self) -> bool {
        self.spawn_tools
    }
}

/// Closed filesystem grants. Arbitrary host paths are intentionally absent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemPermission {
    /// Read immutable files shipped inside the installed plugin directory.
    PluginRead,
    /// Read the selected workspace.
    WorkspaceRead,
    /// Write the selected workspace.
    WorkspaceWrite,
    /// Read and write the configured session temporary directory.
    SessionTemp,
}

/// Closed network grants. Arbitrary destinations are intentionally absent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPermission {
    /// Connect to Blindfold's local managed model proxy.
    ModelProxy,
    /// Connect through Blindfold's project-policy egress proxy.
    PolicyEgress,
    /// Connect to Blindfold's local secret-operation broker.
    LocalBroker,
}

/// Closed non-secret environment categories.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum EnvironmentPermission {
    /// Receive the sanitized executable search path.
    Path,
    /// Receive the configured user home directory.
    Home,
    /// Receive the configured temporary directory.
    Temp,
    /// Receive locale variables.
    Locale,
    /// Receive terminal capability variables for child compatibility.
    Terminal,
    /// Receive non-secret user identity variables such as `USER` and `LOGNAME`.
    UserIdentity,
    /// Receive the configured shell path.
    Shell,
    /// Receive host XDG configuration, data, and cache locations.
    HostConfig,
}

/// Safe, redacted manifest failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ManifestError {
    /// Encoded input exceeded [`MAX_MANIFEST_BYTES`].
    TooLarge,
    /// Input was not UTF-8.
    InvalidEncoding,
    /// TOML structure, types, enums, or semantic versions were invalid.
    InvalidDocument,
    /// `manifest_version` is not supported.
    UnsupportedManifestVersion,
    /// The plugin ID was invalid.
    InvalidPluginId,
    /// The executable entrypoint path was unsafe or invalid.
    InvalidEntrypoint,
    /// The harness executable basename was unsafe or invalid.
    InvalidHarnessCommand,
    /// The harness semantic-version requirement matched every version.
    UnboundedHarnessVersion,
    /// A required declaration list was empty.
    EmptyDeclaration,
    /// A declaration list exceeded its bound.
    TooManyDeclarations,
    /// A declaration occurred more than once.
    DuplicateDeclaration,
    /// Required model request/response events were absent.
    MissingBoundaryEvents,
    /// Required model-proxy or harness-spawn permission was absent.
    InsufficientBoundaryPermissions,
    /// Declared permissions were internally inconsistent.
    InvalidPermissionCombination,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "plugin manifest exceeds the size limit",
            Self::InvalidEncoding => "plugin manifest encoding is invalid",
            Self::InvalidDocument => "plugin manifest document is invalid",
            Self::UnsupportedManifestVersion => "plugin manifest version is unsupported",
            Self::InvalidPluginId => "plugin identifier is invalid",
            Self::InvalidEntrypoint => "plugin entrypoint is invalid",
            Self::InvalidHarnessCommand => "plugin harness command is invalid",
            Self::UnboundedHarnessVersion => "plugin harness version requirement is unbounded",
            Self::EmptyDeclaration => "plugin capability declaration is empty",
            Self::TooManyDeclarations => "plugin has too many capability declarations",
            Self::DuplicateDeclaration => "plugin capability declaration is duplicated",
            Self::MissingBoundaryEvents => "plugin omits required boundary events",
            Self::InsufficientBoundaryPermissions => "plugin omits required boundary permissions",
            Self::InvalidPermissionCombination => "plugin permission combination is invalid",
        })
    }
}

impl std::error::Error for ManifestError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    manifest_version: u16,
    id: String,
    version: Version,
    kind: PluginKind,
    protocol: Protocol,
    entrypoint: String,
    harness: RawHarness,
    capabilities: RawCapabilities,
    permissions: RawPermissions,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHarness {
    command: String,
    version: VersionReq,
    noninteractive_modes: Vec<NonInteractiveMode>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapabilities {
    providers: Vec<Provider>,
    transports: Vec<Transport>,
    events: Vec<Event>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPermissions {
    filesystem: Vec<FilesystemPermission>,
    network: Vec<NetworkPermission>,
    environment: Vec<EnvironmentPermission>,
    spawn_harness: bool,
    spawn_tools: bool,
}

fn validate_plugin_id(value: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > MAX_PLUGIN_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        || value.split(['.', '-']).any(|component| {
            let mut bytes = component.bytes();
            !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
                || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
    {
        return Err(ManifestError::InvalidPluginId);
    }
    Ok(())
}

fn validate_entrypoint(value: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > MAX_ENTRYPOINT_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(ManifestError::InvalidEntrypoint);
    }
    Ok(())
}

fn validate_command(value: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > MAX_COMMAND_BYTES
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(ManifestError::InvalidHarnessCommand);
    }
    Ok(())
}

fn validate_nonempty_unique<T>(values: &[T]) -> Result<(), ManifestError>
where
    T: Copy + Ord,
{
    if values.is_empty() {
        return Err(ManifestError::EmptyDeclaration);
    }
    validate_unique(values)
}

fn has_finite_version_bounds(requirement: &VersionReq) -> bool {
    let mut lower = false;
    let mut upper = false;
    for comparator in &requirement.comparators {
        match comparator.op {
            Op::Exact | Op::Tilde | Op::Caret => {
                lower = true;
                upper = true;
            }
            Op::Wildcard => return false,
            Op::Greater | Op::GreaterEq => lower = true,
            Op::Less | Op::LessEq => upper = true,
            _ => {}
        }
    }
    lower && upper
}

fn validate_unique<T>(values: &[T]) -> Result<(), ManifestError>
where
    T: Copy + Ord,
{
    if values.len() > MAX_DECLARATIONS {
        return Err(ManifestError::TooManyDeclarations);
    }
    let unique = values.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(ManifestError::DuplicateDeclaration);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use semver::VersionReq;

    use super::{
        ManifestError, has_finite_version_bounds, validate_command, validate_entrypoint,
        validate_plugin_id,
    };

    #[test]
    fn finite_version_analysis_distinguishes_one_sided_ranges()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(!has_finite_version_bounds(&VersionReq::parse("*")?));
        assert!(!has_finite_version_bounds(&VersionReq::parse(">=1.2.3")?));
        assert!(!has_finite_version_bounds(&VersionReq::parse("<2.0.0")?));
        assert!(has_finite_version_bounds(&VersionReq::parse(
            ">=1.2.3, <2.0.0"
        )?));
        assert!(has_finite_version_bounds(&VersionReq::parse("~1.2.3")?));
        Ok(())
    }

    #[test]
    fn token_validators_reject_shell_and_path_ambiguity() {
        assert_eq!(
            validate_command("codex --flag"),
            Err(ManifestError::InvalidHarnessCommand)
        );
        assert_eq!(
            validate_entrypoint("../adapter"),
            Err(ManifestError::InvalidEntrypoint)
        );
        assert_eq!(
            validate_plugin_id("acme.-adapter"),
            Err(ManifestError::InvalidPluginId)
        );
    }
}
