//! End-to-end tests for the `blindfold` binary.

use std::{
    error::Error,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
const PROVIDER_FIXTURE: &str = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";

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

fn fake_agent(directory: &Path) -> Result<PathBuf, std::io::Error> {
    let path = directory.join("fake-agent");
    fs::write(
        &path,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > agent-args\nprintf '%s' \"${ANTHROPIC_BASE_URL-}\" > anthropic-base\nprintf '%s' \"${OPENCODE_CONFIG_CONTENT-}\" > opencode-config\nprintf '%s' \"${HTTPS_PROXY-}\" > https-proxy\nprintf '%s' \"${BLINDFOLD_MASTER_KEY-}\" > inherited-master-key\nprintf '%s' \"${UNRELATED_PARENT_SECRET-}\" > inherited-parent-secret\n",
    )?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

fn fake_connect_agent(directory: &Path) -> Result<PathBuf, std::io::Error> {
    let path = directory.join("fake-connect-agent");
    fs::write(
        &path,
        r#"#!/bin/sh
ruby -rsocket -ruri -e '
proxy = URI(ENV.fetch("HTTPS_PROXY"))
socket = TCPSocket.new(proxy.host, proxy.port)
socket.write("CONNECT unknown.example:443 HTTP/1.1\r\nHost: unknown.example:443\r\n\r\n")
response = socket.readpartial(256)
File.write("connect-response", response)
socket.close
'
"#,
    )?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

fn fake_provider_agent(directory: &Path, mode: &str) -> Result<PathBuf, std::io::Error> {
    let path = directory.join(format!("fake-provider-agent-{mode}"));
    let script = format!(
        r#"#!/bin/sh
ruby -rjson -rnet/http -ruri -e '
mode = "{mode}"
secret = "{PROVIDER_FIXTURE}"
case mode
when "claude"
  base = ENV.fetch("ANTHROPIC_BASE_URL")
  uri = URI(base + "/v1/messages")
  body = {{"messages"=>[{{"role"=>"user","content"=>[{{"type"=>"text","text"=>"send #{{secret}}"}}]}}]}}
when "codex"
  config = ARGV.join(" ")
  raise "missing codex openai_base_url: #{{ARGV.inspect}}" unless config =~ /openai_base_url="?([^"\s]+)"?/
  uri = URI($1 + "/responses")
  body = {{"input"=>"send #{{secret}}"}}
when "opencode"
  config = JSON.parse(ENV.fetch("OPENCODE_CONFIG_CONTENT"))
  uri = URI(config.fetch("provider").fetch("openai").fetch("options").fetch("baseURL") + "/chat/completions")
  body = {{"messages"=>[{{"role"=>"user","content"=>"send #{{secret}}"}}]}}
else
  raise "unknown fake mode"
end
request = Net::HTTP::Post.new(uri)
request["content-type"] = "application/json"
request.body = JSON.generate(body)
response = Net::HTTP.start(uri.host, uri.port, nil, nil) {{ |http| http.request(request) }}
File.write("agent-response", response.body)
puts response.body
' -- "$@"
"#,
    );
    fs::write(&path, script)?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

struct FakeProvider {
    upstream: String,
    request: mpsc::Receiver<CapturedProviderRequest>,
    done: thread::JoinHandle<()>,
}

#[derive(Debug)]
struct CapturedProviderRequest {
    request_line: String,
    body: String,
}

fn spawn_fake_provider(mode: &str) -> Result<FakeProvider, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let upstream = format!("http://{}", listener.local_addr()?);
    let (tx, rx) = mpsc::channel();
    let response = match mode {
        "claude" => {
            format!(r#"{{"content":[{{"type":"text","text":"echo {PROVIDER_FIXTURE}"}}]}}"#)
        }
        "codex" => format!(r#"{{"output_text":"echo {PROVIDER_FIXTURE}"}}"#),
        "opencode" => {
            format!(r#"{{"choices":[{{"message":{{"content":"echo {PROVIDER_FIXTURE}"}}}}]}}"#)
        }
        _ => return Err("unknown fake provider mode".into()),
    };
    let done = thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let Ok(request) = read_provider_request(&mut stream) else {
            return;
        };
        let _ = tx.send(request);
        let reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response.len(),
            response
        );
        let _ = stream.write_all(reply.as_bytes());
    });
    Ok(FakeProvider {
        upstream,
        request: rx,
        done,
    })
}

fn read_provider_request(
    stream: &mut TcpStream,
) -> Result<CapturedProviderRequest, Box<dyn Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = find_header_end(&buffer) {
            let header = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
            let content_length = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            let body_start = header_end + 4;
            while buffer.len().saturating_sub(body_start) < content_length {
                let read = stream.read(&mut chunk)?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let request_line = header.lines().next().unwrap_or_default().to_owned();
            let body = String::from_utf8_lossy(
                &buffer[body_start..body_start.saturating_add(content_length)],
            )
            .into_owned();
            return Ok(CapturedProviderRequest { request_line, body });
        }
    }
    Err("provider request was incomplete".into())
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
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
    let short = Command::new(env!("CARGO_BIN_EXE_bf"))
        .arg("--version")
        .current_dir(directory.path())
        .output()?;
    assert!(short.status.success());
    assert_eq!(
        stdout(&short).trim(),
        format!("blindfold {}", env!("CARGO_PKG_VERSION"))
    );
    Ok(())
}

#[test]
fn trace_commands_render_only_closed_metadata_and_clear_explicitly() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let blindfold_directory = directory.path().join(".blindfold");
    fs::create_dir(&blindfold_directory)?;
    fs::set_permissions(&blindfold_directory, fs::Permissions::from_mode(0o700))?;
    let raw = "raw-secret-must-not-appear";
    fs::write(
        blindfold_directory.join("trace.jsonl"),
        "{\"version\":1,\"timestamp\":1,\"request_id\":\"req_abcd_1\",\"route\":\"anthropic\",\"coverage\":\"protected\",\"outcome\":\"succeeded\",\"request_bytes_before\":120,\"request_bytes_after\":90,\"response_bytes_before\":80,\"response_bytes_after\":70,\"replacements\":[{\"id\":\"S1\",\"category\":\"bearer_token\",\"pointer\":\"/messages/0/content\",\"occurrences\":2}]}\n",
    )?;

    let list = blindfold(directory.path(), &["trace", "list"])?;
    assert!(list.status.success(), "{}", stderr(&list));
    assert!(stdout(&list).contains("req_abcd_1"));

    let show = blindfold(directory.path(), &["trace", "show", "req_abcd_1"])?;
    let show_output = stdout(&show);
    assert!(show.status.success(), "{}", stderr(&show));
    assert!(show_output.contains("coverage: protected"));
    assert!(show_output.contains("S1  bearer_token  /messages/0/content"));
    assert!(!show_output.contains(raw));

    let export = blindfold(
        directory.path(),
        &["trace", "export", "req_abcd_1", "--redacted"],
    )?;
    assert!(export.status.success(), "{}", stderr(&export));
    assert!(stdout(&export).contains("\"version\":1"));
    assert!(!stdout(&export).contains(raw));

    let unconfirmed = blindfold(directory.path(), &["trace", "clear"])?;
    assert!(!unconfirmed.status.success());
    assert!(blindfold_directory.join("trace.jsonl").exists());
    let cleared = blindfold(directory.path(), &["trace", "clear", "--yes"])?;
    assert!(cleared.status.success(), "{}", stderr(&cleared));
    assert!(!blindfold_directory.join("trace.jsonl").exists());
    Ok(())
}

#[test]
fn redact_trace_populates_trace_list_and_tail() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let raw = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
    fs::write(
        directory.path().join("config.txt"),
        format!("OPENAI_API_KEY={raw}\n"),
    )?;

    let redact = blindfold(directory.path(), &["redact", "config.txt", "--trace"])?;
    assert!(redact.status.success(), "{}", stderr(&redact));
    assert!(!stdout(&redact).contains(raw));

    let list = blindfold(directory.path(), &["trace", "list"])?;
    assert!(list.status.success(), "{}", stderr(&list));
    assert!(stdout(&list).contains("route=redact"));

    let tail = blindfold(directory.path(), &["trace", "tail"])?;
    let output = stdout(&tail);
    assert!(tail.status.success(), "{}", stderr(&tail));
    assert!(output.contains("activity: redact"));
    assert!(output.contains("openai_api_key"));
    assert!(output.contains("/env/OPENAI_API_KEY"));
    assert!(!output.contains(raw));
    Ok(())
}

#[test]
fn redact_trace_names_dotenv_variable_without_value() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let raw = "postgresql://blindfold_fake:BLINDFOLD_FAKE_FIXTURE@127.0.0.1:55432/blindfold_test";
    fs::write(
        directory.path().join("application.env"),
        format!("APP_ENV=test\nDATABASE_URL={raw}\n"),
    )?;

    let redact = blindfold(directory.path(), &["redact", "--trace", "application.env"])?;
    assert!(redact.status.success(), "{}", stderr(&redact));
    assert!(!stdout(&redact).contains(raw));

    let show_without_id = blindfold(directory.path(), &["trace", "show"])?;
    assert!(!show_without_id.status.success());
    let tail = blindfold(directory.path(), &["trace", "tail"])?;
    let output = stdout(&tail);
    assert!(tail.status.success(), "{}", stderr(&tail));
    assert!(output.contains("credential_url"));
    assert!(output.contains("/env/DATABASE_URL"));
    assert!(!output.contains(raw));
    assert!(!output.contains("BLINDFOLD_FAKE_FIXTURE@"));
    Ok(())
}

#[test]
fn global_trace_flag_can_appear_before_or_after_subcommand() -> Result<(), Box<dyn Error>> {
    let first = TestDirectory::new()?;
    let output = blindfold(first.path(), &["--trace", "doctor"])?;
    assert!(!output.status.success());
    let trace = blindfold(first.path(), &["trace", "tail"])?;
    assert!(stdout(&trace).contains("doctor"));

    let second = TestDirectory::new()?;
    fs::write(
        second.path().join("config.txt"),
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345\n",
    )?;
    let output = blindfold(second.path(), &["redact", "--trace", "config.txt"])?;
    assert!(output.status.success(), "{}", stderr(&output));
    let trace = blindfold(second.path(), &["trace", "tail"])?;
    assert!(stdout(&trace).contains("redact"));
    Ok(())
}

#[test]
fn traced_agent_session_reports_unmediated_file_reads() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let agent = fake_agent(directory.path())?;
    let output = Command::new(env!("CARGO_BIN_EXE_blindfold"))
        .args([
            "run",
            "opencode",
            "--trace",
            "--agent-command",
            agent.to_str().ok_or("non-UTF-8 agent path")?,
            "--",
            "exec",
            "--version",
        ])
        .current_dir(directory.path())
        .output()?;

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("agent file reads: unmediated"));
    let trace = blindfold(directory.path(), &["trace", "tail"])?;
    let output = stdout(&trace);
    assert!(trace.status.success(), "{}", stderr(&trace));
    assert!(output.contains("activity: run:opencode"));
    assert!(output.contains("coverage: degraded"));
    assert!(output.contains("issue: direct_filesystem_unmediated"));
    Ok(())
}

#[test]
fn traced_guard_records_payload_free_egress_decisions() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let agent = fake_connect_agent(directory.path())?;
    let output = Command::new(env!("CARGO_BIN_EXE_blindfold"))
        .args([
            "run",
            "--guard",
            "opencode",
            "--trace",
            "--agent-command",
            agent.to_str().ok_or("non-UTF-8 agent path")?,
        ])
        .current_dir(directory.path())
        .output()?;

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        fs::read_to_string(directory.path().join("connect-response"))?
            .starts_with("HTTP/1.1 403 Forbidden")
    );
    let trace = blindfold(directory.path(), &["trace", "list"])?;
    let output = stdout(&trace);
    assert!(trace.status.success(), "{}", stderr(&trace));
    assert!(output.contains("route=egress"));
    assert!(output.contains("outcome=rejected"));
    assert!(!output.contains("unknown.example"));

    let trace = blindfold(directory.path(), &["trace", "tail"])?;
    let output = stdout(&trace);
    assert!(trace.status.success(), "{}", stderr(&trace));
    assert!(output.contains("activity: run:opencode"));
    assert!(!output.contains("unknown.example"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn trace_rejects_symlinked_storage_without_printing_target() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let directory = TestDirectory::new()?;
    let blindfold_directory = directory.path().join(".blindfold");
    fs::create_dir(&blindfold_directory)?;
    fs::set_permissions(&blindfold_directory, fs::Permissions::from_mode(0o700))?;
    let raw = "trace target raw secret";
    let target = directory.path().join("target");
    fs::write(&target, raw)?;
    symlink(&target, blindfold_directory.join("trace.jsonl"))?;

    let output = blindfold(directory.path(), &["trace", "list"])?;
    let combined = format!("{}{}", stdout(&output), stderr(&output));
    assert!(!output.status.success());
    assert!(!combined.contains(raw));
    assert_eq!(fs::read_to_string(target)?, raw);
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
fn scan_reports_policy_skips_without_calling_the_scan_incomplete() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    fs::write(directory.path().join("binary.dat"), b"prefix\0suffix")?;

    let text = blindfold(directory.path(), &["scan", "."])?;
    assert!(text.status.success());
    assert!(stdout(&text).contains("complete=true"));
    assert!(stdout(&text).contains("skipped_binary=1"));
    assert!(stdout(&text).contains("io_errors=0"));
    assert!(stdout(&text).contains("limit_reached=false"));

    let json = blindfold(directory.path(), &["scan", ".", "--json"])?;
    assert!(json.status.success());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout)?;
    assert_eq!(report["complete"], true);
    assert_eq!(report["skipped"]["binary"], 1);
    assert_eq!(report["skipped"]["too_large"], 0);
    assert_eq!(report["skipped"]["ignored"], 0);
    assert_eq!(report["skipped"]["symlinks"], 0);
    assert_eq!(report["io_errors"], 0);
    assert_eq!(report["limit_reached"], false);
    Ok(())
}

#[test]
fn incomplete_scan_exit_code_takes_precedence_over_findings() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    fs::write(
        directory.path().join("config.txt"),
        "api_key=sk-proj-abcdefghijklmnopqrstuvwxyz012345\n",
    )?;
    fs::File::create(directory.path().join("large.dat"))?.set_len(2 * 1024 * 1024 + 1)?;

    let scan = blindfold(directory.path(), &["scan", ".", "--json"])?;
    assert_eq!(scan.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&scan.stdout)?;
    assert_eq!(report["complete"], false);
    assert_eq!(report["findings"].as_array().map(Vec::len), Some(1));
    assert_eq!(report["skipped"]["too_large"], 1);
    Ok(())
}

#[test]
fn scan_reports_when_a_hard_limit_stops_traversal() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    for index in 0..33 {
        fs::File::create(directory.path().join(format!("{index:02}.dat")))?
            .set_len(2 * 1024 * 1024)?;
    }

    let scan = blindfold(directory.path(), &["scan", ".", "--json"])?;
    assert_eq!(scan.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&scan.stdout)?;
    assert_eq!(report["complete"], false);
    assert_eq!(report["limit_reached"], true);
    Ok(())
}

#[test]
fn redact_output_refuses_overwrite_without_force() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let raw = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";
    fs::write(directory.path().join("input.txt"), raw)?;

    let first = blindfold(
        directory.path(),
        &["redact", "input.txt", "--output", "safe.txt"],
    )?;
    assert!(first.status.success(), "{}", stderr(&first));
    let safe = fs::read_to_string(directory.path().join("safe.txt"))?;
    assert!(!safe.contains(raw));
    assert!(safe.contains("[REDACTED:openai_api_key]"));

    fs::write(directory.path().join("safe.txt"), "keep-me")?;
    let refused = blindfold(
        directory.path(),
        &["redact", "input.txt", "--output", "safe.txt"],
    )?;
    assert!(!refused.status.success());
    assert!(stderr(&refused).contains("already exists"));
    assert_eq!(
        fs::read_to_string(directory.path().join("safe.txt"))?,
        "keep-me"
    );

    let forced = blindfold(
        directory.path(),
        &["redact", "input.txt", "--output", "safe.txt", "--force"],
    )?;
    assert!(forced.status.success(), "{}", stderr(&forced));
    assert!(!fs::read_to_string(directory.path().join("safe.txt"))?.contains(raw));
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
fn network_policy_commands_are_project_scoped() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;

    let allow = blindfold(directory.path(), &["allow", "domain", "API.EXAMPLE.COM."])?;
    assert!(allow.status.success(), "{}", stderr(&allow));
    assert!(stdout(&allow).contains("api.example.com"));

    let deny = blindfold(directory.path(), &["deny", "domain", "blocked.example.com"])?;
    assert!(deny.status.success(), "{}", stderr(&deny));
    assert!(stdout(&deny).contains("blocked.example.com"));

    let status = blindfold(directory.path(), &["status"])?;
    let status_stdout = stdout(&status);
    assert!(status.status.success(), "{}", stderr(&status));
    assert!(status_stdout.contains("allow api.example.com"));
    assert!(status_stdout.contains("deny blocked.example.com"));
    assert!(status_stdout.contains("unknown domains: block"));

    let policy = fs::read_to_string(directory.path().join(".blindfold/network-policy.json"))?;
    assert!(policy.contains("api.example.com"));
    assert!(policy.contains("blocked.example.com"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn audit_rejects_a_symlink_without_printing_its_target() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let directory = TestDirectory::new()?;
    let private = "raw audit target secret";
    let external = directory.path().join("external.txt");
    fs::write(&external, private)?;
    fs::create_dir(directory.path().join(".blindfold"))?;
    symlink(&external, directory.path().join(".blindfold/audit.jsonl"))?;

    let output = blindfold(directory.path(), &["audit"])?;
    let combined = format!("{}{}", stdout(&output), stderr(&output));
    assert!(!output.status.success());
    assert!(!combined.contains(private));
    assert_eq!(fs::read_to_string(external)?, private);
    Ok(())
}

#[test]
fn mcp_rejects_plaintext_in_credential_named_arguments() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let message = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"demo\",\"arguments\":{\"api_key\":\"AbCdEf0123456789+/xyZQ==\"}}}\n";
    let output = blindfold_with_input(
        directory.path(),
        &["mcp", "--direction", "to-server"],
        message,
    )?;

    assert!(!output.status.success());
    assert!(!stdout(&output).contains("AbCdEf0123456789+/xyZQ=="));
    assert!(stderr(&output).contains("credential-bearing"));
    Ok(())
}

#[test]
fn mcp_rejects_an_oversized_message_without_buffering_all_stdin() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let oversized = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{}\"}}\n",
        "x".repeat(1024 * 1024)
    );
    let output = blindfold_with_input(
        directory.path(),
        &["mcp", "--direction", "to-agent"],
        &oversized,
    )?;

    assert!(!output.status.success());
    assert!(stderr(&output).contains("size limit"));
    assert!(output.stdout.is_empty());
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

#[test]
fn destructive_and_ambiguous_cli_inputs_are_rejected() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let invalid_ttl = blindfold(
        directory.path(),
        &["vault", "put-env", "DEMO_API_KEY", "--ttl-seconds", "nope"],
    )?;
    assert!(!invalid_ttl.status.success());

    let key = "11".repeat(32);
    let clear = Command::new(env!("CARGO_BIN_EXE_blindfold"))
        .args(["vault", "clear"])
        .env("BLINDFOLD_MASTER_KEY", key)
        .current_dir(directory.path())
        .output()?;
    assert!(!clear.status.success());
    assert!(stderr(&clear).contains("--yes"));

    let conflicting_diff = blindfold(
        directory.path(),
        &["diff-check", "--patch", "change.diff", "--staged"],
    )?;
    assert!(!conflicting_diff.status.success());
    Ok(())
}

#[test]
fn strict_agent_preview_refuses_degraded_boundary() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let output = blindfold(directory.path(), &["run", "claude", "--strict"])?;

    assert!(!output.status.success());
    assert!(stderr(&output).contains("strict agent mode is unavailable"));
    Ok(())
}

#[test]
fn claude_wrapper_routes_through_anthropic_proxy() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let agent = fake_agent(directory.path())?;
    let output = blindfold(
        directory.path(),
        &[
            "run",
            "--guard",
            "claude",
            "--agent-command",
            agent.to_str().ok_or("non-UTF-8 agent path")?,
            "--",
            "--version",
        ],
    )?;

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("Blindfold Guard active"));
    assert_eq!(
        fs::read_to_string(directory.path().join("agent-args"))?,
        "--version\n"
    );
    let base = fs::read_to_string(directory.path().join("anthropic-base"))?;
    assert!(base.starts_with("http://127.0.0.1:"));
    assert!(base.ends_with("/anthropic"));
    let egress = fs::read_to_string(directory.path().join("https-proxy"))?;
    assert!(egress.starts_with("http://127.0.0.1:"));
    Ok(())
}

#[test]
fn codex_wrapper_injects_one_run_base_url_override() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let agent = fake_agent(directory.path())?;
    let output = blindfold(
        directory.path(),
        &[
            "run",
            "--guard",
            "codex",
            "--agent-command",
            agent.to_str().ok_or("non-UTF-8 agent path")?,
            "--",
            "review",
        ],
    )?;

    assert!(output.status.success(), "{}", stderr(&output));
    let arguments = fs::read_to_string(directory.path().join("agent-args"))?;
    assert!(arguments.contains("-c\nopenai_base_url=\"http://127.0.0.1:"));
    assert!(arguments.contains("/openai/v1\"\nreview\n"));
    Ok(())
}

#[test]
fn interactive_codex_guard_refuses_unsupported_websocket_transport() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let agent = fake_agent(directory.path())?;
    let output = blindfold(
        directory.path(),
        &[
            "run",
            "--guard",
            "codex",
            "--agent-command",
            agent.to_str().ok_or("non-UTF-8 agent path")?,
        ],
    )?;

    assert!(!output.status.success());
    assert!(stderr(&output).contains("WebSocket transport"));
    assert!(!directory.path().join("agent-args").exists());
    Ok(())
}

#[test]
fn opencode_wrapper_merges_inline_config_and_routes_both_providers() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let agent = fake_agent(directory.path())?;
    let output = Command::new(env!("CARGO_BIN_EXE_blindfold"))
        .args([
            "run",
            "--guard",
            "opencode",
            "--agent-command",
            agent.to_str().ok_or("non-UTF-8 agent path")?,
            "--",
            "run",
            "hello",
        ])
        .env(
            "OPENCODE_CONFIG_CONTENT",
            r#"{"theme":"system","provider":{"openai":{"options":{"timeout":1000}}}}"#,
        )
        .current_dir(directory.path())
        .output()?;

    assert!(output.status.success(), "{}", stderr(&output));
    let config: serde_json::Value = serde_json::from_str(&fs::read_to_string(
        directory.path().join("opencode-config"),
    )?)?;
    assert_eq!(config["theme"], "system");
    assert_eq!(config["provider"]["openai"]["options"]["timeout"], 1000);
    assert!(
        config["provider"]["openai"]["options"]["baseURL"]
            .as_str()
            .is_some_and(|url| url.ends_with("/openai/v1"))
    );
    assert!(
        config["provider"]["anthropic"]["options"]["baseURL"]
            .as_str()
            .is_some_and(|url| url.ends_with("/anthropic/v1"))
    );
    assert!(
        config["provider"]["openrouter"]["options"]["baseURL"]
            .as_str()
            .is_some_and(|url| url.ends_with("/openrouter/v1"))
    );
    Ok(())
}

#[test]
fn guarded_agent_modes_redact_requests_and_responses_to_fake_providers()
-> Result<(), Box<dyn Error>> {
    for mode in ["claude", "codex", "opencode"] {
        run_guarded_fake_provider_mode(mode)?;
    }
    Ok(())
}

fn run_guarded_fake_provider_mode(mode: &str) -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let provider = spawn_fake_provider(mode)?;
    let agent = fake_provider_agent(directory.path(), mode)?;
    let agent_path = agent.to_str().ok_or("non-UTF-8 agent path")?;
    let output = match mode {
        "claude" => Command::new(env!("CARGO_BIN_EXE_blindfold"))
            .args([
                "run",
                "--guard",
                "claude",
                "--anthropic-upstream",
                &provider.upstream,
                "--agent-command",
                agent_path,
            ])
            .current_dir(directory.path())
            .output()?,
        "codex" => Command::new(env!("CARGO_BIN_EXE_blindfold"))
            .args([
                "run",
                "--guard",
                "codex",
                "--openai-upstream",
                &provider.upstream,
                "--agent-command",
                agent_path,
                "--",
                "exec",
                "hello",
            ])
            .current_dir(directory.path())
            .output()?,
        "opencode" => Command::new(env!("CARGO_BIN_EXE_blindfold"))
            .args([
                "run",
                "--guard",
                "opencode",
                "--openai-upstream",
                &provider.upstream,
                "--agent-command",
                agent_path,
                "--",
                "run",
                "hello",
            ])
            .current_dir(directory.path())
            .output()?,
        _ => unreachable!("fixed test modes"),
    };

    assert!(output.status.success(), "{mode}: {}", stderr(&output));
    let request = provider
        .request
        .recv_timeout(Duration::from_secs(5))
        .map_err(|error| {
            let agent_response =
                fs::read_to_string(directory.path().join("agent-response")).unwrap_or_default();
            format!(
                "{mode}: fake provider did not receive request: {error}; stdout={}; stderr={}; agent_response={agent_response}",
                stdout(&output),
                stderr(&output)
            )
        })?;
    provider
        .done
        .join()
        .map_err(|_| "provider thread panicked")?;
    assert!(
        request.request_line.contains("/v1/"),
        "{mode}: unexpected upstream request line {}",
        request.request_line
    );
    assert!(
        !request.request_line.contains("/v1/v1/"),
        "{mode}: duplicate upstream version path {}",
        request.request_line
    );
    assert!(
        !request.body.contains(PROVIDER_FIXTURE),
        "{mode}: upstream body leaked raw fixture: {}",
        request.body
    );
    assert!(
        request.body.contains("[REDACTED:openai_api_key]"),
        "{mode}: upstream body was not redacted: {}",
        request.body
    );
    let response = fs::read_to_string(directory.path().join("agent-response"))?;
    assert!(
        !response.contains(PROVIDER_FIXTURE),
        "{mode}: agent response leaked raw fixture: {response}"
    );
    assert!(
        response.contains("[REDACTED:openai_api_key]"),
        "{mode}: agent response was not redacted: {response}"
    );
    assert!(
        !stdout(&output).contains(PROVIDER_FIXTURE),
        "{mode}: stdout leaked raw fixture"
    );
    Ok(())
}

#[test]
fn wrapper_bypass_does_not_inject_proxy_configuration() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let agent = fake_agent(directory.path())?;
    let output = blindfold(
        directory.path(),
        &[
            "run",
            "codex",
            "--no-proxy",
            "--agent-command",
            agent.to_str().ok_or("non-UTF-8 agent path")?,
            "--",
            "--version",
        ],
    )?;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        fs::read_to_string(directory.path().join("agent-args"))?,
        "--version\n"
    );
    assert!(stderr(&output).contains("bypass requested"));
    Ok(())
}

#[test]
fn managed_wrapper_does_not_inherit_parent_secrets() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let agent = fake_agent(directory.path())?;
    let output = Command::new(env!("CARGO_BIN_EXE_blindfold"))
        .args([
            "run",
            "codex",
            "--agent-command",
            agent.to_str().ok_or("non-UTF-8 agent path")?,
            "--",
            "exec",
            "--version",
        ])
        .env("BLINDFOLD_MASTER_KEY", "11".repeat(32))
        .env("UNRELATED_PARENT_SECRET", "fake-parent-secret")
        .current_dir(directory.path())
        .output()?;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        fs::read_to_string(directory.path().join("inherited-master-key"))?,
        ""
    );
    assert_eq!(
        fs::read_to_string(directory.path().join("inherited-parent-secret"))?,
        ""
    );
    Ok(())
}

#[test]
fn shell_init_wraps_all_agents_and_exposes_bypass_helper() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let output = blindfold(directory.path(), &["shell-init", "zsh"])?;
    let script = stdout(&output);

    assert!(output.status.success());
    assert!(script.contains("blindfold run --guard claude"));
    assert!(script.contains("blindfold run --guard codex"));
    assert!(script.contains("blindfold run --guard opencode"));
    assert!(script.contains("bf-off()"));
    Ok(())
}
