//! Installed-directory, executable-resolution, and process-probe boundary tests.

#![cfg(unix)]

use std::{
    ffi::{OsStr, OsString},
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    time::Duration,
};

use blindfold_plugin_host::{
    HostError, ProbeLimits, discover_explicit_plugin_dirs, load_explicit_plugins, probe_version,
    resolve_executable,
};
use semver::{Version, VersionReq};
use tempfile::TempDir;

const VALID_MANIFEST: &str = r#"
manifest_version = 1
id = "test.codex"
version = "1.0.0"
kind = "harness-adapter"
protocol = "stdio-json-v1"
entrypoint = "bin/adapter"

[harness]
command = "codex"
version = ">=0.141.0, <0.142.0"
noninteractive_modes = ["exec", "review"]

[capabilities]
providers = ["open-ai"]
transports = ["http-json"]
events = ["model-request", "model-response"]

[permissions]
filesystem = ["plugin-read", "workspace-read"]
network = ["model-proxy"]
environment = ["path"]
spawn_harness = true
spawn_tools = false
"#;

#[test]
fn discovery_uses_only_exact_explicit_directories() -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let installed = root.path().join("installed");
    let project_plugin = root.path().join("project").join("plugin");
    fs::create_dir_all(&installed)?;
    fs::create_dir_all(&project_plugin)?;

    let discovered = discover_explicit_plugin_dirs([&installed])?;

    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].path(), fs::canonicalize(installed)?);
    assert_ne!(discovered[0].path(), fs::canonicalize(project_plugin)?);
    Ok(())
}

#[test]
fn discovery_rejects_relative_symlink_and_duplicate_directories()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let installed = root.path().join("installed");
    let linked = root.path().join("linked");
    fs::create_dir(&installed)?;
    symlink(&installed, &linked)?;

    assert_eq!(
        discover_explicit_plugin_dirs([Path::new("relative-plugin")]),
        Err(HostError::InvalidPluginDirectory)
    );
    assert_eq!(
        discover_explicit_plugin_dirs([&linked]),
        Err(HostError::InvalidPluginDirectory)
    );
    assert_eq!(
        discover_explicit_plugin_dirs([&installed, &installed]),
        Err(HostError::DuplicatePluginDirectory)
    );
    Ok(())
}

#[test]
fn loads_only_fixed_manifest_and_contained_executable() -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let installed = root.path().join("installed");
    fs::create_dir_all(installed.join("bin"))?;
    fs::write(installed.join("blindfold-plugin.toml"), VALID_MANIFEST)?;
    let _entrypoint = write_script(&installed.join("bin"), "adapter", "exit 0")?;

    let plugins = load_explicit_plugins([&installed])?;

    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].manifest().id().as_str(), "test.codex");
    assert!(
        plugins[0]
            .entrypoint()
            .starts_with(plugins[0].directory().path())
    );
    Ok(())
}

#[test]
fn rejects_manifest_symlink_and_escaping_entrypoint() -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let manifest_target = root.path().join("manifest-target");
    fs::write(&manifest_target, VALID_MANIFEST)?;
    let linked_install = root.path().join("linked-install");
    fs::create_dir_all(linked_install.join("bin"))?;
    symlink(
        &manifest_target,
        linked_install.join("blindfold-plugin.toml"),
    )?;
    let _entrypoint = write_script(&linked_install.join("bin"), "adapter", "exit 0")?;
    assert!(matches!(
        load_explicit_plugins([&linked_install]),
        Err(HostError::InvalidPluginManifest)
    ));

    let escaped_install = root.path().join("escaped-install");
    fs::create_dir_all(escaped_install.join("bin"))?;
    fs::write(
        escaped_install.join("blindfold-plugin.toml"),
        VALID_MANIFEST,
    )?;
    let outside = write_script(root.path(), "outside-adapter", "exit 0")?;
    symlink(&outside, escaped_install.join("bin").join("adapter"))?;
    assert!(matches!(
        load_explicit_plugins([&escaped_install]),
        Err(HostError::InvalidPluginEntrypoint)
    ));
    Ok(())
}

#[test]
fn resolver_requires_an_explicit_safe_search_path() -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let executable = write_script(root.path(), "agent", "printf 'agent 1.2.3\\n'")?;
    let search = std::env::join_paths([root.path()])?;

    assert_eq!(
        resolve_executable(OsStr::new("agent"), Some(&search))?,
        fs::canonicalize(executable)?
    );
    assert_eq!(
        resolve_executable(OsStr::new("agent"), None),
        Err(HostError::ExecutableNotFound)
    );
    assert_eq!(
        resolve_executable(OsStr::new("./agent"), Some(&search)),
        Err(HostError::InvalidExecutablePath)
    );
    let unsafe_search = std::env::join_paths([Path::new("relative")])?;
    assert_eq!(
        resolve_executable(OsStr::new("agent"), Some(&unsafe_search)),
        Err(HostError::InvalidExecutablePath)
    );
    Ok(())
}

#[test]
fn resolver_canonicalizes_executable_symlinks() -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let target = write_script(root.path(), "agent-real", "printf 'agent 1.2.3\\n'")?;
    let linked = root.path().join("agent");
    symlink(&target, &linked)?;
    let search = std::env::join_paths([root.path()])?;

    assert_eq!(
        resolve_executable(OsStr::new("agent"), Some(&search))?,
        fs::canonicalize(target)?
    );
    Ok(())
}

#[test]
fn probe_uses_ephemeral_home_and_accepts_compatible_stderr_version()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let program = write_script(
        root.path(),
        "codex",
        "[ \"$HOME\" = \"$PWD\" ] || exit 9\nprintf 'codex-cli 0.141.2\\n' >&2",
    )?;
    let requirement = VersionReq::parse(">=0.141.0, <0.142.0")?;
    let search_path = probe_search_path(root.path())?;

    let result = probe_version(
        &program,
        ["--version"],
        Some("codex"),
        &requirement,
        ProbeLimits::default(),
        &search_path,
    )?;

    assert_eq!(result.version(), &Version::parse("0.141.2")?);
    Ok(())
}

#[test]
fn probe_rejects_marker_mismatch_and_incompatible_version() -> Result<(), Box<dyn std::error::Error>>
{
    let root = TempDir::new()?;
    let program = write_script(root.path(), "agent", "printf 'other 1.2.3\\n'")?;
    let any = VersionReq::STAR;
    let search_path = probe_search_path(root.path())?;
    assert_eq!(
        probe_version(
            &program,
            ["--version"],
            Some("codex"),
            &any,
            ProbeLimits::default(),
            &search_path
        ),
        Err(HostError::ExpectedMarkerMissing)
    );

    let program = write_script(root.path(), "codex", "printf 'codex 1.2.3\\n'")?;
    let requirement = VersionReq::parse(">=2.0.0")?;
    assert_eq!(
        probe_version(
            &program,
            ["--version"],
            Some("codex"),
            &requirement,
            ProbeLimits::default(),
            &search_path
        ),
        Err(HostError::VersionIncompatible)
    );
    Ok(())
}

#[test]
fn probe_rejects_timeout_and_oversize_output() -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let search_path = probe_search_path(root.path())?;
    let sleeper = write_script(root.path(), "sleeper", "exec /bin/sleep 2")?;
    let limits = ProbeLimits::new(Duration::from_millis(25), 1024)?;
    assert_eq!(
        probe_version(
            &sleeper,
            ["--version"],
            Some("agent"),
            &VersionReq::STAR,
            limits,
            &search_path
        ),
        Err(HostError::ProbeTimedOut)
    );

    let noisy = write_script(
        root.path(),
        "noisy",
        "i=0; while [ \"$i\" -lt 128 ]; do printf x; i=$((i + 1)); done; printf ' codex 1.2.3\\n'",
    )?;
    let limits = ProbeLimits::new(Duration::from_secs(3), 32)?;
    assert_eq!(
        probe_version(
            &noisy,
            ["--version"],
            Some("codex"),
            &VersionReq::STAR,
            limits,
            &search_path
        ),
        Err(HostError::ProbeOutputTooLarge)
    );
    Ok(())
}

#[test]
fn probe_accepts_exact_markerless_opencode_output() -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let program = write_script(
        root.path(),
        "opencode",
        "[ \"$HOME\" = \"$PWD\" ] || exit 12; printf '1.18.0\\n'",
    )?;
    let search_path = probe_search_path(root.path())?;

    let result = probe_version(
        &program,
        ["--version"],
        None,
        &VersionReq::parse("^1.18")?,
        ProbeLimits::default(),
        &search_path,
    )?;

    assert_eq!(result.version(), &Version::parse("1.18.0")?);
    Ok(())
}

#[test]
fn probe_supports_env_node_launcher_with_only_validated_path()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let _node = write_script(root.path(), "node", "printf 'codex-cli 0.141.2\\n'")?;
    let launcher = write_executable(root.path(), "codex", "#!/usr/bin/env node\n")?;
    let search_path = probe_search_path(root.path())?;

    let result = probe_version(
        &launcher,
        ["--version"],
        Some("codex"),
        &VersionReq::parse("^0.141")?,
        ProbeLimits::default(),
        &search_path,
    )?;

    assert_eq!(result.version(), &Version::parse("0.141.2")?);
    Ok(())
}

fn write_script(
    directory: &Path,
    name: &str,
    body: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    write_executable(directory, name, &format!("#!/bin/sh\n{body}\n"))
}

fn write_executable(
    directory: &Path,
    name: &str,
    contents: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = directory.join(name);
    fs::write(&path, contents)?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

fn probe_search_path(directory: &Path) -> Result<OsString, std::env::JoinPathsError> {
    std::env::join_paths([directory, Path::new("/usr/bin"), Path::new("/bin")])
}
