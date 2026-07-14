//! Integration tests for isolated process execution and output sanitization.

use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::process;
use std::thread;
use std::time::Duration;

use blindfold_core::SecretValue;
use blindfold_exec::{
    CommandSpec, EnvironmentName, EnvironmentPolicy, ExecutionError, ExecutionLimits,
    ExecutionRequest, SecretBinding, execute,
};

const MODE_NAME: &str = "BLINDFOLD_CHILD_MODE";
const SECRET_NAME: &str = "BLINDFOLD_TEST_SECRET";
const SECRET: &str = "bf-test-secret-3f6d8c1a";
const SECOND_SECRET_NAME: &str = "BLINDFOLD_SECOND_SECRET";
const SECOND_SECRET: &str = "bf-second-secret-72ca";

#[test]
fn child_helper() {
    let Ok(mode) = env::var(MODE_NAME) else {
        return;
    };

    match mode.as_str() {
        "environment" => {
            let mut variables = env::vars_os().collect::<Vec<_>>();
            variables.sort_unstable();
            let stdout = io::stdout();
            let mut output = stdout.lock();
            for (name, value) in variables {
                write!(output, "{}=", name.to_string_lossy())
                    .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
                output
                    .write_all(value.as_encoded_bytes())
                    .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
                writeln!(output)
                    .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
            }
        }
        "leak" => {
            let secret = required_secret();
            let midpoint = secret.len() / 2;
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            stdout
                .write_all(&secret.as_bytes()[..midpoint])
                .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
            stdout
                .flush()
                .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
            thread::sleep(Duration::from_millis(20));
            stdout
                .write_all(&secret.as_bytes()[midpoint..])
                .unwrap_or_else(|error| unreachable!("test output must work: {error}"));

            let stderr = io::stderr();
            let mut stderr = stderr.lock();
            stderr
                .write_all(&secret.as_bytes()[..midpoint])
                .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
            stderr
                .flush()
                .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
            thread::sleep(Duration::from_millis(20));
            stderr
                .write_all(&secret.as_bytes()[midpoint..])
                .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
        }
        "large" => {
            let stdout_worker =
                thread::spawn(|| write_repeated(io::stdout(), b'o', 2 * 1024 * 1024));
            let stderr_worker =
                thread::spawn(|| write_repeated(io::stderr(), b'e', 2 * 1024 * 1024));
            stdout_worker
                .join()
                .unwrap_or_else(|_| unreachable!("stdout test writer must not panic"));
            stderr_worker
                .join()
                .unwrap_or_else(|_| unreachable!("stderr test writer must not panic"));
        }
        "argv" => {
            let secret = required_secret();
            let found = env::args_os().any(|argument| os_string_contains(&argument, &secret));
            println!("ARGV_CONTAINS_SECRET={found}");
            print!("{secret}");
        }
        "multiple" => {
            print!(
                "{}:{}",
                required_secret(),
                env::var(SECOND_SECRET_NAME).unwrap_or_else(|error| {
                    unreachable!("second child fixture secret must be present: {error}")
                })
            );
        }
        "binary" => {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            output
                .write_all(&[0xff])
                .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
            output
                .write_all(required_secret().as_bytes())
                .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
            output
                .write_all(&[0xfe])
                .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
        }
        "sleep" => thread::sleep(Duration::from_secs(5)),
        "failure" => process::exit(37),
        other => unreachable!("unknown child helper mode: {other}"),
    }
}

#[test]
fn child_receives_only_explicit_environment() {
    let mut environment = EnvironmentPolicy::new();
    environment.set_baseline(name(MODE_NAME), "environment");
    environment.allow_passthrough(name("PATH"));
    let result = execute_child("environment", environment, true, ExecutionLimits::new());
    let output = String::from_utf8_lossy(result.stdout());

    assert!(output.contains("BLINDFOLD_CHILD_MODE=environment"));
    assert!(output.contains("BLINDFOLD_TEST_SECRET=[REDACTED]"));
    assert!(output.contains("PATH="));
    assert!(!output.contains("HOME="));
    assert!(!output.contains("USER="));
    assert!(!output.contains(SECRET));
    assert_eq!(
        result
            .audit()
            .secret_names()
            .iter()
            .map(EnvironmentName::as_str)
            .collect::<Vec<_>>(),
        [SECRET_NAME]
    );
}

#[test]
fn redacts_split_values_without_trailing_newlines_on_both_streams() {
    let result = execute_child("leak", helper_environment(), true, ExecutionLimits::new());

    assert!(!contains(result.stdout(), SECRET.as_bytes()));
    assert!(!contains(result.stderr(), SECRET.as_bytes()));
    assert!(contains(result.stdout(), b"[REDACTED]"));
    assert!(contains(result.stderr(), b"[REDACTED]"));
    assert_eq!(result.audit().stdout_redactions(), 1);
    assert_eq!(result.audit().stderr_redactions(), 1);
}

#[test]
fn redacts_every_explicitly_injected_value() {
    let mut request = child_request("multiple", helper_environment(), ExecutionLimits::new());
    request.add_secret(secret_binding());
    request.add_secret(
        SecretBinding::new(name(SECOND_SECRET_NAME), SecretValue::new(SECOND_SECRET))
            .unwrap_or_else(|error| unreachable!("fixture secret must be valid: {error}")),
    );
    let result = execute(&request).unwrap_or_else(|error| unreachable!("child must run: {error}"));

    assert!(contains(result.stdout(), b"[REDACTED]:[REDACTED]"));
    assert!(!contains(result.stdout(), SECRET.as_bytes()));
    assert!(!contains(result.stdout(), SECOND_SECRET.as_bytes()));
    assert_eq!(result.audit().stdout_redactions(), 2);
}

#[test]
fn sanitizes_secrets_inside_binary_output() {
    let result = execute_child("binary", helper_environment(), true, ExecutionLimits::new());

    let expected = [b"\xff".as_slice(), b"[REDACTED]", b"\xfe".as_slice()].concat();
    assert!(contains(result.stdout(), &expected));
    assert!(!contains(result.stdout(), SECRET.as_bytes()));
}

#[test]
fn drains_large_stdout_and_stderr_concurrently_and_bounds_results() {
    let mut limits = ExecutionLimits::new();
    limits.set_output_bytes_per_stream(4096);
    let result = execute_child("large", helper_environment(), false, limits);

    assert_eq!(result.stdout().len(), 4096);
    assert_eq!(result.stderr().len(), 4096);
    assert!(result.audit().stdout_truncated());
    assert!(result.audit().stderr_truncated());
    assert!(result.audit().stdout_bytes_read() >= 2 * 1024 * 1024);
    assert!(result.audit().stderr_bytes_read() >= 2 * 1024 * 1024);
    assert!(result.audit().exit().success());
}

#[test]
fn preserves_nonzero_exit_codes() {
    let result = execute_child(
        "failure",
        helper_environment(),
        false,
        ExecutionLimits::new(),
    );

    assert_eq!(result.audit().exit().code(), Some(37));
    assert_eq!(result.audit().exit().signal(), None);
    assert!(!result.audit().exit().success());
}

#[test]
fn reports_timeout_termination() {
    let mut limits = ExecutionLimits::new();
    limits.set_timeout(Some(Duration::from_millis(20)));
    let result = execute_child("sleep", helper_environment(), false, limits);

    assert!(result.audit().exit().timed_out());
    assert!(!result.audit().exit().success());
}

#[cfg(unix)]
#[test]
fn terminates_pipe_holding_descendants_after_the_child_exits() -> Result<(), ExecutionError> {
    let mut command = CommandSpec::new("/bin/sh");
    command.args(["-c", "/bin/sleep 10 & exit 0"]);
    let mut request = ExecutionRequest::new(command);
    let mut limits = ExecutionLimits::new();
    limits.set_timeout(Some(Duration::from_millis(250)));
    request.set_limits(limits);

    let started = std::time::Instant::now();
    let result = execute(&request)?;

    assert!(result.audit().exit().success());
    assert!(started.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[test]
fn secret_is_not_present_in_child_argv_or_safe_metadata() {
    let result = execute_child("argv", helper_environment(), true, ExecutionLimits::new());
    let output = String::from_utf8_lossy(result.stdout());
    let debug = format!("{result:?}");

    assert!(output.contains("ARGV_CONTAINS_SECRET=false"));
    assert!(!output.contains(SECRET));
    assert!(!debug.contains(SECRET));
    assert!(
        !debug.contains(
            env::current_exe()
                .unwrap_or_default()
                .to_string_lossy()
                .as_ref()
        )
    );
}

#[test]
fn rejects_a_secret_embedded_in_an_argument_before_spawn() {
    let mut command = CommandSpec::new(env::current_exe().unwrap_or_default());
    command.arg(format!("prefix-{SECRET}-suffix"));
    let mut request = ExecutionRequest::new(command);
    request.add_secret(secret_binding());

    assert_eq!(execute(&request), Err(ExecutionError::SecretInArguments));
}

#[test]
fn rejects_a_secret_overlapping_audited_labels() {
    let command = CommandSpec::new(
        env::current_exe()
            .unwrap_or_else(|error| unreachable!("test executable must be known: {error}")),
    );
    let mut request = ExecutionRequest::new(command);
    request.add_secret(
        SecretBinding::new(name("API_TOKEN"), SecretValue::new("TOKEN"))
            .unwrap_or_else(|error| unreachable!("fixture secret must be valid: {error}")),
    );

    assert_eq!(execute(&request), Err(ExecutionError::SecretInMetadata));
}

#[cfg(unix)]
#[test]
fn preserves_unix_signal_status() {
    let mut command = CommandSpec::new("/bin/sh");
    command.args(["-c", "kill -TERM $$"]);
    let request = ExecutionRequest::new(command);
    let result =
        execute(&request).unwrap_or_else(|error| unreachable!("signal child must run: {error}"));

    assert_eq!(result.audit().exit().code(), None);
    assert_eq!(result.audit().exit().signal(), Some(15));
}

fn execute_child(
    mode: &str,
    environment: EnvironmentPolicy,
    with_secret: bool,
    limits: ExecutionLimits,
) -> blindfold_exec::ExecutionResult {
    let mut request = child_request(mode, environment, limits);
    if with_secret {
        request.add_secret(secret_binding());
    }
    execute(&request).unwrap_or_else(|error| unreachable!("child execution must succeed: {error}"))
}

fn child_request(
    mode: &str,
    mut environment: EnvironmentPolicy,
    limits: ExecutionLimits,
) -> ExecutionRequest {
    environment.set_baseline(name(MODE_NAME), mode);
    let mut command = CommandSpec::new(
        env::current_exe()
            .unwrap_or_else(|error| unreachable!("test executable must be known: {error}")),
    );
    command.args(["--exact", "child_helper", "--nocapture"]);
    let mut request = ExecutionRequest::new(command);
    request.set_environment(environment);
    request.set_limits(limits);
    request
}

fn helper_environment() -> EnvironmentPolicy {
    EnvironmentPolicy::new()
}

fn secret_binding() -> SecretBinding {
    SecretBinding::new(name(SECRET_NAME), SecretValue::new(SECRET))
        .unwrap_or_else(|error| unreachable!("fixture secret must be valid: {error}"))
}

fn name(value: &str) -> EnvironmentName {
    EnvironmentName::new(value)
        .unwrap_or_else(|error| unreachable!("fixture environment name must be valid: {error}"))
}

fn required_secret() -> String {
    env::var(SECRET_NAME)
        .unwrap_or_else(|error| unreachable!("child fixture secret must be present: {error}"))
}

fn write_repeated(writer: impl Write, byte: u8, count: usize) {
    let mut writer = io::BufWriter::new(writer);
    let block = [byte; 8192];
    for _ in 0..(count / block.len()) {
        writer
            .write_all(&block)
            .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
    }
    writer
        .flush()
        .unwrap_or_else(|error| unreachable!("test output must work: {error}"));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn os_string_contains(value: &OsString, needle: &str) -> bool {
    value.to_string_lossy().contains(needle)
}
