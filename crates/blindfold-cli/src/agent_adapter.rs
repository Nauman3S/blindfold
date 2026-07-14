//! Built-in harness adapters backed by the same strict manifest contract used by plugins.

use std::{collections::BTreeSet, env, ffi::OsStr, fmt, path::PathBuf};

use blindfold_plugin_api::{
    EnvironmentPermission, Event, FilesystemPermission, NetworkPermission, NonInteractiveMode,
    PluginKind, PluginManifest, Protocol, Provider, Transport,
};
use blindfold_plugin_host::{HostError, ProbeLimits, probe_version, resolve_executable};
use semver::{Version, VersionReq};

const CLAUDE_MANIFEST: &[u8] = include_bytes!("../plugins/claude-code.toml");
const CODEX_MANIFEST: &[u8] = include_bytes!("../plugins/codex-cli.toml");
const OPENCODE_MANIFEST: &[u8] = include_bytes!("../plugins/opencode.toml");

/// Closed built-in adapter implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HarnessKind {
    Claude,
    Codex,
    OpenCode,
}

/// One validated built-in adapter manifest and its host-owned probe policy.
pub(crate) struct HarnessAdapter {
    kind: HarnessKind,
    manifest: PluginManifest,
    version_marker: Option<&'static str>,
}

impl HarnessAdapter {
    /// Resolves a user-facing harness name to a validated built-in adapter.
    pub(crate) fn load(name: &str) -> Result<Self, AdapterError> {
        let (kind, bytes, version_marker) = match name {
            "claude" => (HarnessKind::Claude, CLAUDE_MANIFEST, Some("Claude Code")),
            "codex" => (HarnessKind::Codex, CODEX_MANIFEST, Some("codex-cli")),
            "opencode" => (HarnessKind::OpenCode, OPENCODE_MANIFEST, None),
            _ => return Err(AdapterError::UnsupportedHarness),
        };
        let manifest =
            PluginManifest::parse_toml(bytes).map_err(|_| AdapterError::InvalidBuiltinManifest)?;
        validate_builtin_contract(kind, &manifest)?;
        Ok(Self {
            kind,
            manifest,
            version_marker,
        })
    }

    pub(crate) const fn kind(&self) -> HarnessKind {
        self.kind
    }

    pub(crate) fn id(&self) -> &str {
        self.manifest.id().as_str()
    }

    pub(crate) const fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    pub(crate) fn command(&self) -> &str {
        self.manifest.harness().command()
    }

    pub(crate) fn supports_mode(&self, mode: NonInteractiveMode) -> bool {
        self.manifest
            .harness()
            .noninteractive_modes()
            .contains(&mode)
    }

    /// Resolves and probes the exact executable that will later be launched.
    pub(crate) fn resolve_compatible_executable(&self) -> Result<PathBuf, AdapterError> {
        let path = env::var_os("PATH").ok_or(AdapterError::SearchPathUnavailable)?;
        let executable = resolve_executable(OsStr::new(self.command()), Some(&path))
            .map_err(AdapterError::Host)?;
        probe_version(
            &executable,
            ["--version"],
            self.version_marker,
            self.manifest.harness().version_requirement(),
            ProbeLimits::default(),
            &path,
        )
        .map_err(AdapterError::Host)?;
        Ok(executable)
    }
}

fn validate_builtin_contract(
    kind: HarnessKind,
    manifest: &PluginManifest,
) -> Result<(), AdapterError> {
    let (id, entrypoint, command, version_requirement, providers, transports, modes) = match kind {
        HarnessKind::Claude => (
            "dev.blindfold.claude-code",
            "builtin/claude-code",
            "claude",
            "=2.1.202",
            &[Provider::Anthropic][..],
            &[Transport::HttpJson, Transport::ServerSentEvents][..],
            &[NonInteractiveMode::Print][..],
        ),
        HarnessKind::Codex => (
            "dev.blindfold.codex-cli",
            "builtin/codex-cli",
            "codex",
            "=0.144.4",
            &[Provider::OpenAi][..],
            &[Transport::HttpJson, Transport::WebSocket][..],
            &[NonInteractiveMode::Exec, NonInteractiveMode::Review][..],
        ),
        HarnessKind::OpenCode => (
            "dev.blindfold.opencode",
            "builtin/opencode",
            "opencode",
            "=1.18.0",
            &[Provider::OpenAi, Provider::Anthropic, Provider::OpenRouter][..],
            &[Transport::HttpJson, Transport::ServerSentEvents][..],
            &[NonInteractiveMode::Run][..],
        ),
    };
    let expected_requirement =
        VersionReq::parse(version_requirement).map_err(|_| AdapterError::InvalidBuiltinManifest)?;
    let permissions = manifest.permissions();
    let valid = manifest.id().as_str() == id
        && manifest.version() == &Version::new(0, 1, 0)
        && manifest.entrypoint().as_str() == entrypoint
        && manifest.harness().command() == command
        && manifest.harness().version_requirement() == &expected_requirement
        && manifest.kind() == PluginKind::HarnessAdapter
        && manifest.protocol() == Protocol::BuiltinV1
        && same_members(manifest.harness().noninteractive_modes(), modes)
        && same_members(manifest.capabilities().providers(), providers)
        && same_members(manifest.capabilities().transports(), transports)
        && same_members(
            manifest.capabilities().events(),
            &[
                Event::ModelRequest,
                Event::ModelResponse,
                Event::CommandOutput,
            ],
        )
        && same_members(
            permissions.filesystem(),
            &[
                FilesystemPermission::WorkspaceRead,
                FilesystemPermission::WorkspaceWrite,
                FilesystemPermission::SessionTemp,
            ],
        )
        && same_members(
            permissions.network(),
            &[
                NetworkPermission::ModelProxy,
                NetworkPermission::PolicyEgress,
            ],
        )
        && same_members(
            permissions.environment(),
            &[
                EnvironmentPermission::Path,
                EnvironmentPermission::Home,
                EnvironmentPermission::Temp,
                EnvironmentPermission::Locale,
                EnvironmentPermission::Terminal,
                EnvironmentPermission::UserIdentity,
                EnvironmentPermission::Shell,
                EnvironmentPermission::HostConfig,
            ],
        )
        && permissions.spawn_harness()
        && permissions.spawn_tools();
    if !valid {
        return Err(AdapterError::UnsupportedBuiltinCapabilities);
    }
    Ok(())
}

fn same_members<T>(actual: &[T], expected: &[T]) -> bool
where
    T: Copy + Ord,
{
    actual.iter().copied().collect::<BTreeSet<_>>()
        == expected.iter().copied().collect::<BTreeSet<_>>()
}

/// Safe adapter startup failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdapterError {
    UnsupportedHarness,
    InvalidBuiltinManifest,
    UnsupportedBuiltinCapabilities,
    SearchPathUnavailable,
    Host(HostError),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHarness => formatter.write_str("unsupported coding agent"),
            Self::InvalidBuiltinManifest => {
                formatter.write_str("built-in harness adapter manifest is invalid")
            }
            Self::UnsupportedBuiltinCapabilities => {
                formatter.write_str("built-in harness adapter requests unsupported capabilities")
            }
            Self::SearchPathUnavailable => {
                formatter.write_str("harness executable search path is unavailable")
            }
            Self::Host(error) => write!(formatter, "harness compatibility check failed: {error}"),
        }
    }
}

impl std::error::Error for AdapterError {}

#[cfg(test)]
mod tests {
    use blindfold_plugin_api::{NonInteractiveMode, PluginManifest};

    use super::{
        AdapterError, CODEX_MANIFEST, HarnessAdapter, HarnessKind, validate_builtin_contract,
    };

    #[test]
    fn built_in_manifests_are_valid_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            ("claude", NonInteractiveMode::Print),
            ("codex", NonInteractiveMode::Exec),
            ("codex", NonInteractiveMode::Review),
            ("opencode", NonInteractiveMode::Run),
        ];
        for (name, mode) in cases {
            let adapter = HarnessAdapter::load(name)?;
            assert!(adapter.supports_mode(mode));
            assert!(
                !adapter
                    .manifest
                    .harness()
                    .version_requirement()
                    .to_string()
                    .is_empty()
            );
        }
        Ok(())
    }

    #[test]
    fn built_in_contract_binds_every_identity_field() -> Result<(), Box<dyn std::error::Error>> {
        let original = std::str::from_utf8(CODEX_MANIFEST)?;
        for (expected, replacement) in [
            ("dev.blindfold.codex-cli", "dev.blindfold.other-cli"),
            ("builtin/codex-cli", "builtin/other-cli"),
            ("command = \"codex\"", "command = \"other\""),
            ("version = \"=0.144.4\"", "version = \"=0.144.5\""),
        ] {
            let changed = original.replacen(expected, replacement, 1);
            let manifest = PluginManifest::parse_toml(changed.as_bytes())?;
            assert_eq!(
                validate_builtin_contract(HarnessKind::Codex, &manifest),
                Err(AdapterError::UnsupportedBuiltinCapabilities)
            );
        }
        Ok(())
    }
}
