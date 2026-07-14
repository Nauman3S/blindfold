//! Public manifest contract tests.

use blindfold_plugin_api::{
    CURRENT_MANIFEST_VERSION, Event, FilesystemPermission, MANIFEST_FILE_NAME, MAX_MANIFEST_BYTES,
    ManifestError, NetworkPermission, NonInteractiveMode, PluginKind, PluginManifest, Protocol,
    Provider, Transport,
};
use semver::Version;

const VALID: &str = r#"
manifest_version = 1
id = "acme.codex"
version = "1.2.3"
kind = "harness-adapter"
protocol = "stdio-json-v1"
entrypoint = "bin/acme-codex"

[harness]
command = "codex"
version = ">=2.1.152, <2.2.0"
noninteractive_modes = ["exec", "review"]

[capabilities]
providers = ["open-ai"]
transports = ["http-json"]
events = ["model-request", "model-response", "tool-result", "command-output"]

[permissions]
filesystem = ["plugin-read", "workspace-read", "workspace-write"]
network = ["model-proxy", "local-broker"]
environment = ["path", "home", "temp"]
spawn_harness = true
spawn_tools = false
"#;

fn parse(text: &str) -> Result<PluginManifest, ManifestError> {
    PluginManifest::parse_toml(text.as_bytes())
}

fn with_requirement(requirement: &str) -> String {
    VALID.replace(">=2.1.152, <2.2.0", requirement)
}

#[test]
fn parses_the_complete_versioned_contract() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = parse(VALID)?;

    assert_eq!(MANIFEST_FILE_NAME, "blindfold-plugin.toml");
    assert_eq!(manifest.manifest_version(), CURRENT_MANIFEST_VERSION);
    assert_eq!(manifest.id().as_str(), "acme.codex");
    assert_eq!(manifest.version(), &Version::new(1, 2, 3));
    assert_eq!(manifest.kind(), PluginKind::HarnessAdapter);
    assert_eq!(manifest.protocol(), Protocol::StdioJsonV1);
    assert_eq!(manifest.entrypoint().as_str(), "bin/acme-codex");
    assert_eq!(manifest.harness().command(), "codex");
    assert!(
        manifest
            .harness()
            .version_requirement()
            .matches(&Version::new(2, 1, 200))
    );
    assert_eq!(
        manifest.harness().noninteractive_modes(),
        [NonInteractiveMode::Exec, NonInteractiveMode::Review]
    );
    assert_eq!(manifest.capabilities().providers(), [Provider::OpenAi]);
    assert_eq!(manifest.capabilities().transports(), [Transport::HttpJson]);
    assert!(
        manifest
            .capabilities()
            .events()
            .contains(&Event::ToolResult)
    );
    assert!(
        manifest
            .permissions()
            .filesystem()
            .contains(&FilesystemPermission::WorkspaceWrite)
    );
    assert!(
        manifest
            .permissions()
            .network()
            .contains(&NetworkPermission::ModelProxy)
    );
    assert!(manifest.permissions().spawn_harness());
    assert!(!manifest.permissions().spawn_tools());
    manifest.validate()?;
    Ok(())
}

#[test]
fn requires_finite_lower_and_upper_harness_version_bounds() {
    for invalid in ["*", "1.*", "1.2.*", ">=2.1.152", "<2.2.0"] {
        assert_eq!(
            parse(&with_requirement(invalid)),
            Err(ManifestError::UnboundedHarnessVersion),
            "requirement {invalid} should be rejected"
        );
    }
    for valid in [">=2.1.152, <2.2.0", "=2.1.152", "~2.1.152", "^2.1.152"] {
        assert!(
            parse(&with_requirement(valid)).is_ok(),
            "requirement {valid} should be accepted"
        );
    }
}

#[test]
fn rejects_unknown_fields_at_every_level() {
    for invalid in [
        VALID.replace("manifest_version = 1", "manifest_version = 1\nextra = true"),
        VALID.replace("command = \"codex\"", "command = \"codex\"\nextra = true"),
        VALID.replace(
            "providers = [\"open-ai\"]",
            "providers = [\"open-ai\"]\nextra = true",
        ),
        VALID.replace("spawn_tools = false", "spawn_tools = false\nextra = true"),
    ] {
        assert_eq!(parse(&invalid), Err(ManifestError::InvalidDocument));
    }
}

#[test]
fn rejects_oversized_non_utf8_and_malformed_documents() {
    assert_eq!(
        PluginManifest::parse_toml(&vec![b'x'; MAX_MANIFEST_BYTES + 1]),
        Err(ManifestError::TooLarge)
    );
    assert_eq!(
        PluginManifest::parse_toml(&[0xff]),
        Err(ManifestError::InvalidEncoding)
    );
    assert_eq!(parse("not = [valid"), Err(ManifestError::InvalidDocument));
    assert_eq!(
        parse(&VALID.replace("version = \"1.2.3\"", "version = \"latest\"")),
        Err(ManifestError::InvalidDocument)
    );
}

#[test]
fn errors_never_echo_manifest_content() {
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
    let invalid = format!("{VALID}\nunknown = \"{secret}\"\n");
    let error = parse(&invalid)
        .err()
        .unwrap_or(ManifestError::InvalidDocument);
    let display = error.to_string();
    let debug = format!("{error:?}");

    assert!(!display.contains(secret));
    assert!(!debug.contains(secret));
    assert_eq!(error, ManifestError::InvalidDocument);
}

#[test]
fn rejects_shell_commands_and_unsafe_entrypoints() {
    for command in [
        "codex --flag",
        "sh -c",
        "/usr/bin/codex",
        "-codex",
        "codex;echo",
    ] {
        let invalid = VALID.replace("command = \"codex\"", &format!("command = \"{command}\""));
        assert_eq!(parse(&invalid), Err(ManifestError::InvalidHarnessCommand));
    }
    for entrypoint in ["../bin/adapter", "/bin/adapter", "bin//adapter", "bin/a;id"] {
        let invalid = VALID.replace(
            "entrypoint = \"bin/acme-codex\"",
            &format!("entrypoint = \"{entrypoint}\""),
        );
        assert_eq!(parse(&invalid), Err(ManifestError::InvalidEntrypoint));
    }
    let command_arguments = VALID.replace(
        "command = \"codex\"",
        "command = \"codex\"\narguments = [\"exec\"]",
    );
    assert_eq!(
        parse(&command_arguments),
        Err(ManifestError::InvalidDocument)
    );
}

#[test]
fn validates_identifier_schema_and_manifest_version() {
    for id in [
        "",
        "123.codex",
        "Acme.codex",
        ".acme",
        "acme..codex",
        "acme.-codex",
        "acme/codex",
    ] {
        let invalid = VALID.replace("id = \"acme.codex\"", &format!("id = \"{id}\""));
        assert_eq!(parse(&invalid), Err(ManifestError::InvalidPluginId));
    }
    assert_eq!(
        parse(&VALID.replace("manifest_version = 1", "manifest_version = 2")),
        Err(ManifestError::UnsupportedManifestVersion)
    );
}

#[test]
fn validates_nonempty_bounded_unique_declarations() {
    assert_eq!(
        parse(&VALID.replace(
            "noninteractive_modes = [\"exec\", \"review\"]",
            "noninteractive_modes = []",
        )),
        Err(ManifestError::EmptyDeclaration)
    );
    assert_eq!(
        parse(&VALID.replace(
            "providers = [\"open-ai\"]",
            "providers = [\"open-ai\", \"open-ai\"]",
        )),
        Err(ManifestError::DuplicateDeclaration)
    );
    let too_many = std::iter::repeat_n("\"exec\"", 17)
        .collect::<Vec<_>>()
        .join(", ");
    assert_eq!(
        parse(&VALID.replace(
            "noninteractive_modes = [\"exec\", \"review\"]",
            &format!("noninteractive_modes = [{too_many}]"),
        )),
        Err(ManifestError::TooManyDeclarations)
    );
}

#[test]
fn requires_complete_model_boundary_events() {
    for events in [
        "events = [\"model-response\"]",
        "events = [\"model-request\"]",
    ] {
        let invalid = VALID.replace(
            "events = [\"model-request\", \"model-response\", \"tool-result\", \"command-output\"]",
            events,
        );
        assert_eq!(parse(&invalid), Err(ManifestError::MissingBoundaryEvents));
    }
}

#[test]
fn enforces_minimum_and_consistent_permissions() {
    assert_eq!(
        parse(&VALID.replace("spawn_harness = true", "spawn_harness = false")),
        Err(ManifestError::InsufficientBoundaryPermissions)
    );
    assert_eq!(
        parse(&VALID.replace(
            "network = [\"model-proxy\", \"local-broker\"]",
            "network = [\"local-broker\"]",
        )),
        Err(ManifestError::InsufficientBoundaryPermissions)
    );
    assert_eq!(
        parse(&VALID.replace(
            "filesystem = [\"plugin-read\", \"workspace-read\", \"workspace-write\"]",
            "filesystem = [\"plugin-read\", \"workspace-write\"]",
        )),
        Err(ManifestError::InvalidPermissionCombination)
    );
    assert_eq!(
        parse(&VALID.replace(
            "network = [\"model-proxy\", \"local-broker\"]",
            "network = [\"model-proxy\", \"model-proxy\"]",
        )),
        Err(ManifestError::DuplicateDeclaration)
    );
}

#[test]
fn rejects_undeclared_capability_values() {
    for invalid in [
        VALID.replace("providers = [\"open-ai\"]", "providers = [\"custom\"]"),
        VALID.replace("transports = [\"http-json\"]", "transports = [\"tcp\"]"),
        VALID.replace(
            "environment = [\"path\", \"home\", \"temp\"]",
            "environment = [\"api-key\"]",
        ),
    ] {
        assert_eq!(parse(&invalid), Err(ManifestError::InvalidDocument));
    }
}
