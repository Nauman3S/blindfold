//! Integration coverage for supplied patches and explicit Git diff inputs.

use blindfold_diff::{
    FileChange, GitDiff, PathRisk, ScanOutcome, Severity, parse_patch, scan, scan_git, scan_patch,
};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const RAW_SECRET: &str = "sk-live-1234567890abcdefghijklmnop";

#[test]
fn scans_staged_like_patch_and_never_renders_raw_value() -> Result<(), Box<dyn std::error::Error>> {
    let patch = format!(
        "diff --git a/src/config.rs b/src/config.rs\n--- a/src/config.rs\n\
         +++ b/src/config.rs\n@@ -10,2 +10,3 @@\n let mode = \"safe\";\n\
         +let api_key = \"{RAW_SECRET}\";\n run();\n"
    );

    let report = scan_patch(&parse_patch(&patch)?);

    assert_eq!(report.outcome(), ScanOutcome::Findings);
    assert_eq!(report.added_lines_scanned(), 1);
    assert_eq!(report.findings()[0].line(), 11);
    assert_eq!(report.findings()[0].context_start(), 10);
    assert_eq!(report.findings()[0].context_end(), 12);
    assert!(!report.to_text().contains(RAW_SECRET));
    assert!(!report.to_json().contains(RAW_SECRET));
    assert!(!format!("{report:?}").contains(RAW_SECRET));
    Ok(())
}

#[test]
fn elevates_frontend_env_ci_and_fixture_findings() -> Result<(), Box<dyn std::error::Error>> {
    for path in [
        "frontend/src/config.ts",
        "public/config.js",
        ".env.production",
        ".github/workflows/release.yml",
        "tests/fixtures/account.json",
    ] {
        let patch = single_added_line(path, &format!("token = \"{RAW_SECRET}\""));
        let report = scan_patch(&parse_patch(&patch)?);
        let finding = &report.findings()[0];

        assert_ne!(finding.path_risk(), PathRisk::Normal, "{path}");
        assert!(
            finding.severity() >= Severity::High,
            "expected elevated severity for {path}"
        );
    }
    Ok(())
}

#[test]
fn accepts_unstaged_like_clean_patch_and_fake_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let clean = single_added_line("src/lib.rs", "let timeout_seconds = 30;");
    let fake = single_added_line(
        "tests/fixtures/config.json",
        r#""api_key": "fake-example-key""#,
    );

    for input in [clean, fake] {
        let report = scan(&input)?;
        assert_eq!(report.outcome(), ScanOutcome::Clean);
        assert!(report.findings().is_empty());
    }
    Ok(())
}

#[test]
fn valid_safe_ref_does_not_hide_another_secret_on_the_same_line()
-> Result<(), Box<dyn std::error::Error>> {
    let safe_ref = "{{BLINDFOLD:v1:ENV:00112233445566778899aabbccddeeff}}";
    let patch = single_added_line(
        "src/config.rs",
        &format!("reference = \"{safe_ref}\"; api_key = \"{RAW_SECRET}\";"),
    );

    let report = scan(&patch)?;

    assert_eq!(report.outcome(), ScanOutcome::Findings);
    assert!(!report.to_text().contains(RAW_SECRET));
    assert!(!report.to_json().contains(RAW_SECRET));
    Ok(())
}

#[test]
fn placeholder_markers_inside_real_values_do_not_bypass_detection()
-> Result<(), Box<dyn std::error::Error>> {
    for marker in ["fake", "sample", "notasecret", "example"] {
        let value = format!("{marker}-real-looking-password-123456");
        let patch = single_added_line("src/config.rs", &format!("password = \"{value}\""));
        let report = scan(&patch)?;
        assert_eq!(report.outcome(), ScanOutcome::Findings, "{marker}");
    }
    Ok(())
}

#[test]
fn handles_renames_and_binary_markers() -> Result<(), Box<dyn std::error::Error>> {
    let patch = "diff --git a/old.txt b/new.txt\n\
                 similarity index 100%\n\
                 rename from old.txt\n\
                 rename to new.txt\n\
                 diff --git a/logo.png b/logo.png\n\
                 index 1111111..2222222 100644\n\
                 Binary files a/logo.png and b/logo.png differ\n";

    let parsed = parse_patch(patch)?;
    assert_eq!(parsed.files()[0].change(), FileChange::Renamed);
    assert_eq!(parsed.files()[0].old_path(), Some("old.txt"));
    assert_eq!(parsed.files()[0].new_path(), Some("new.txt"));
    assert_eq!(parsed.files()[1].change(), FileChange::Binary);

    let report = scan_patch(&parsed);
    assert_eq!(report.outcome(), ScanOutcome::NoTextChanges);
    assert_eq!(report.binary_files_skipped(), 1);
    Ok(())
}

#[test]
fn rejects_malformed_patches_with_safe_errors() {
    let malformed = "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n\
                     @@ -1,1 +1,2 @@\n unchanged\n";
    let Err(error) = parse_patch(malformed) else {
        unreachable!("count mismatch must fail");
    };

    assert_eq!(
        error.to_string(),
        "patch hunk line counts do not match its header"
    );
    assert!(!format!("{error:?}").contains("unchanged"));
}

#[test]
fn scans_actual_staged_and_working_tree_diffs_through_explicit_apis()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = temporary_directory()?;
    run_git(&directory, &["init", "-q"])?;
    run_git(
        &directory,
        &["config", "user.email", "test@example.invalid"],
    )?;
    run_git(&directory, &["config", "user.name", "Blindfold Test"])?;
    fs::write(directory.join("config.txt"), "mode=safe\n")?;
    run_git(&directory, &["add", "config.txt"])?;
    run_git(&directory, &["commit", "-qm", "initial"])?;

    fs::write(
        directory.join("config.txt"),
        format!("mode=safe\napi_key={RAW_SECRET}\n"),
    )?;
    run_git(&directory, &["add", "config.txt"])?;
    let staged = scan_git(&directory, GitDiff::Staged)?;
    assert_eq!(staged.outcome(), ScanOutcome::Findings);

    fs::write(
        directory.join("config.txt"),
        format!("mode=unsafe\napi_key={RAW_SECRET}\n"),
    )?;
    let working = scan_git(&directory, GitDiff::WorkingTree)?;
    assert_eq!(working.outcome(), ScanOutcome::Clean);

    fs::remove_dir_all(directory)?;
    Ok(())
}

fn single_added_line(path: &str, content: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         new file mode 100644\n\
         --- /dev/null\n\
         +++ b/{path}\n\
         @@ -0,0 +1,1 @@\n\
         +{content}\n"
    )
}

fn temporary_directory() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "blindfold-diff-test-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    Ok(directory)
}

fn run_git(directory: &Path, arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .status()?;
    assert!(status.success(), "git command failed");
    Ok(())
}
