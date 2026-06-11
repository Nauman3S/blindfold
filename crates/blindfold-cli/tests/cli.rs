//! End-to-end tests for the `blindfold` binary.

use std::{
    error::Error,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "blindfold-cli-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.0);
    }
}

fn blindfold(directory: &Path, arguments: &[&str]) -> Result<Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_blindfold"))
        .args(arguments)
        .current_dir(directory)
        .output()
}

fn blindfold_with_input(
    directory: &Path,
    arguments: &[&str],
    input: &str,
) -> Result<Output, std::io::Error> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_blindfold"))
        .args(arguments)
        .current_dir(directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(input.as_bytes())?;
    }
    child.wait_with_output()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn help_and_version_are_available() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let help = blindfold(directory.path(), &["--help"])?;
    let version = blindfold(directory.path(), &["--version"])?;

    assert!(help.status.success());
    assert!(stdout(&help).contains("doctor"));
    assert!(version.status.success());
    assert_eq!(
        stdout(&version).trim(),
        format!("blindfold {}", env!("CARGO_PKG_VERSION"))
    );
    Ok(())
}

#[test]
fn init_creates_defaults_and_never_overwrites() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let first = blindfold(directory.path(), &["init"])?;
    assert!(first.status.success(), "{}", stderr(&first));

    let config_path = directory.path().join(".blindfold.yaml");
    let initial = fs::read_to_string(&config_path)?;
    assert!(initial.contains("version: 1"));

    fs::write(&config_path, "sentinel: do-not-overwrite\n")?;
    let second = blindfold(directory.path(), &["init"])?;
    assert!(!second.status.success());
    assert_eq!(
        fs::read_to_string(config_path)?,
        "sentinel: do-not-overwrite\n"
    );
    Ok(())
}

#[test]
fn doctor_reports_all_required_checks() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let init = blindfold(directory.path(), &["init"])?;
    assert!(init.status.success());

    let doctor = blindfold(directory.path(), &["doctor"])?;
    let output = stdout(&doctor);
    assert!(output.contains("config presence"));
    assert!(output.contains("config validity"));
    assert!(output.contains("storage directory"));
    assert!(output.contains("loopback port"));
    assert!(output.contains("Claude command"));
    Ok(())
}

#[test]
fn doctor_recognizes_local_override_without_printing_values() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let init = blindfold(directory.path(), &["init"])?;
    assert!(init.status.success());
    let secret_like_value = "claude-with-sensitive-suffix";
    fs::write(
        directory.path().join(".blindfold.local.yaml"),
        format!("claude:\n  command: {secret_like_value}\n"),
    )?;

    let doctor = blindfold(directory.path(), &["doctor"])?;
    let combined = format!("{}{}", stdout(&doctor), stderr(&doctor));
    assert!(combined.contains("local override"));
    assert!(!combined.contains(secret_like_value));
    Ok(())
}

#[test]
fn invalid_config_error_does_not_echo_values() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let sensitive_value = "highly-sensitive.invalid.example";
    fs::write(
        directory.path().join(".blindfold.yaml"),
        format!("version: 1\nproxy:\n  host: {sensitive_value}\n"),
    )?;

    let doctor = blindfold(directory.path(), &["doctor"])?;
    let combined = format!("{}{}", stdout(&doctor), stderr(&doctor));
    assert!(!doctor.status.success());
    assert!(combined.contains("proxy.host"));
    assert!(!combined.contains(sensitive_value));
    Ok(())
}

#[test]
fn scan_and_redact_never_print_the_raw_value() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let raw = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
    fs::write(
        directory.path().join("config.txt"),
        format!("api_key={raw}\n"),
    )?;

    let scan = blindfold(directory.path(), &["scan", ".", "--json"])?;
    assert_eq!(scan.status.code(), Some(2));
    assert!(stdout(&scan).contains("openai_api_key"));
    assert!(!stdout(&scan).contains(raw));

    let redact = blindfold(directory.path(), &["redact", "config.txt"])?;
    assert!(redact.status.success());
    assert!(stdout(&redact).contains("[REDACTED:openai_api_key]"));
    assert!(!stdout(&redact).contains(raw));
    Ok(())
}

#[test]
fn exec_injects_then_redacts_selected_secret() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let raw = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
    let output = Command::new(env!("CARGO_BIN_EXE_blindfold"))
        .args([
            "exec",
            "--secret",
            "DEMO_API_KEY",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$DEMO_API_KEY\"",
        ])
        .env("DEMO_API_KEY", raw)
        .current_dir(directory.path())
        .output()?;

    let combined = format!("{}{}", stdout(&output), stderr(&output));
    assert!(output.status.success());
    assert!(!combined.contains(raw));
    assert!(combined.contains("[REDACTED]"));
    Ok(())
}

#[test]
fn policy_diff_and_mcp_commands_are_safe() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let policy = blindfold(
        directory.path(),
        &[
            "policy",
            "check",
            "--mode",
            "balanced",
            "--destination",
            "model",
            "--sensitivity",
            "secret",
        ],
    )?;
    assert_eq!(policy.status.code(), Some(2));
    assert!(stdout(&policy).contains("action=Block"));

    let raw = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
    let patch = format!(
        "diff --git a/app.js b/app.js\n--- a/app.js\n+++ b/app.js\n@@ -0,0 +1 @@\n+const key = \"{raw}\";\n"
    );
    fs::write(directory.path().join("change.diff"), patch)?;
    let diff = blindfold(
        directory.path(),
        &["diff-check", "--patch", "change.diff", "--json"],
    )?;
    assert_eq!(diff.status.code(), Some(2));
    assert!(!stdout(&diff).contains(raw));

    let message =
        format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{{\"message\":\"failed {raw}\"}}}}\n");
    let mcp = blindfold_with_input(
        directory.path(),
        &["mcp", "--direction", "to-agent"],
        &message,
    )?;
    assert!(mcp.status.success());
    assert!(!stdout(&mcp).contains(raw));
    assert!(stdout(&mcp).contains("[REDACTED:openai_api_key]"));
    Ok(())
}

#[test]
fn vault_lists_only_safe_references() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let raw = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
    let key = "11".repeat(32);
    let put = Command::new(env!("CARGO_BIN_EXE_blindfold"))
        .args(["vault", "put-env", "DEMO_API_KEY"])
        .env("BLINDFOLD_MASTER_KEY", &key)
        .env("DEMO_API_KEY", raw)
        .current_dir(directory.path())
        .output()?;
    assert!(put.status.success(), "{}", stderr(&put));
    assert!(stdout(&put).contains("{{BLINDFOLD:v1:ENV:"));
    assert!(!stdout(&put).contains(raw));

    let list = Command::new(env!("CARGO_BIN_EXE_blindfold"))
        .args(["vault", "list"])
        .env("BLINDFOLD_MASTER_KEY", key)
        .current_dir(directory.path())
        .output()?;
    assert!(list.status.success(), "{}", stderr(&list));
    assert!(!stdout(&list).contains(raw));
    assert!(stdout(&list).contains("{{BLINDFOLD:v1:ENV:"));
    Ok(())
}
