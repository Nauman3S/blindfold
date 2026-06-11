use std::env;
use std::fs;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use blindfold_core::{
    Destination, SafeRef, SafeRefKind, SecretKind as CoreSecretKind, SecretValue, Sensitivity,
};
use blindfold_detectors::{
    DetectorSet, DotenvCatalog, RedactionMode, RedactionOptions, Redactor, ScannerBuilder,
};
use blindfold_diff::{GitDiff, ScanOutcome, scan, scan_git};
use blindfold_exec::{
    CommandSpec, EnvironmentName, EnvironmentPolicy, ExecutionRequest, SecretBinding, execute,
};
use blindfold_mcp::{
    Direction as McpDirection, Resolver as McpResolver, Sanitizer as McpSanitizer,
    Transformer as McpTransformer,
};
use blindfold_policy::{Operation, Policy, Preset, Request, SourceContext};
use blindfold_proxy::{
    Config as ProxyConfig, Provider, Proxy, Sanitizer as ProxySanitizer, Upstream,
};
use blindfold_vault::{
    AuditAction, AuditEvent, AuditLog, AuditOutcome, MasterKey, RotationPolicy, Scope, Vault,
};
use clap::{Arg, ArgAction, ArgMatches, Command};
use tokio_util::sync::CancellationToken;

use crate::{config, doctor};

const MASTER_KEY_ENV: &str = "BLINDFOLD_MASTER_KEY";

pub(crate) async fn run() -> ExitCode {
    let matches = cli().get_matches();
    let root = match env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            return fail(&format!(
                "could not determine current directory: {}",
                error.kind()
            ));
        }
    };

    match matches.subcommand() {
        Some(("init", _)) => init(&root),
        Some(("doctor", _)) => doctor_command(&root),
        Some(("scan", args)) => scan_command(args),
        Some(("redact", args)) => redact_command(args),
        Some(("exec", args)) => exec_command(args),
        Some(("policy", args)) => policy_command(args),
        Some(("diff-check", args)) => diff_command(&root, args),
        Some(("vault", args)) => vault_command(&root, args),
        Some(("audit", _)) => audit_command(&root),
        Some(("proxy", args)) => proxy_command(args).await,
        Some(("mcp", args)) => mcp_command(args),
        Some(("run", args)) => run_agent_command(args).await,
        _ => ExitCode::FAILURE,
    }
}

#[allow(clippy::too_many_lines)] // Declarative command schema is clearer kept together.
fn cli() -> Command {
    Command::new("blindfold")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Let agents use secrets without seeing secrets")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("init").about("Create a safe default .blindfold.yaml"))
        .subcommand(Command::new("doctor").about("Check local Blindfold prerequisites"))
        .subcommand(
            Command::new("scan")
                .about("Scan a file or directory without printing matched values")
                .arg(Arg::new("path").default_value("."))
                .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
        )
        .subcommand(
            Command::new("redact")
                .about("Redact a file or standard input")
                .arg(Arg::new("file").value_name("FILE"))
                .arg(
                    Arg::new("mode")
                        .long("mode")
                        .default_value("placeholder")
                        .value_parser([
                            "env-ref",
                            "schema-only",
                            "placeholder",
                            "surrogate",
                            "block",
                        ]),
                ),
        )
        .subcommand(
            Command::new("exec")
                .about("Run a command with explicitly selected environment secrets")
                .arg(
                    Arg::new("secret")
                        .long("secret")
                        .action(ArgAction::Append)
                        .num_args(1)
                        .required(true),
                )
                .arg(
                    Arg::new("command")
                        .num_args(1..)
                        .trailing_var_arg(true)
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("policy")
                .about("Inspect policy behavior")
                .subcommand(
                    Command::new("check")
                        .arg(
                            Arg::new("mode")
                                .long("mode")
                                .default_value("balanced")
                                .value_parser(["chill", "balanced", "strict", "ci"]),
                        )
                        .arg(
                            Arg::new("destination")
                                .long("destination")
                                .default_value("model")
                                .value_parser([
                                    "model",
                                    "agent",
                                    "tool",
                                    "child",
                                    "file",
                                    "log",
                                    "audit",
                                    "user",
                                    "trusted-local",
                                ]),
                        )
                        .arg(
                            Arg::new("sensitivity")
                                .long("sensitivity")
                                .default_value("secret")
                                .value_parser([
                                    "public",
                                    "internal",
                                    "confidential",
                                    "secret",
                                    "restricted",
                                ]),
                        ),
                ),
        )
        .subcommand(
            Command::new("diff-check")
                .about("Scan added lines in a patch or Git diff")
                .arg(Arg::new("patch").long("patch").value_name("FILE"))
                .arg(Arg::new("staged").long("staged").action(ArgAction::SetTrue))
                .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
        )
        .subcommand(
            Command::new("vault")
                .about("Manage encrypted local SafeRef mappings")
                .subcommand(
                    Command::new("put-env")
                        .arg(Arg::new("name").required(true))
                        .arg(Arg::new("ttl").long("ttl-seconds").default_value("3600")),
                )
                .subcommand(Command::new("list"))
                .subcommand(Command::new("clear")),
        )
        .subcommand(Command::new("audit").about("Print safe local audit JSON lines"))
        .subcommand(
            Command::new("proxy")
                .about("Run the loopback LLM proxy")
                .arg(
                    Arg::new("listen")
                        .long("listen")
                        .default_value("127.0.0.1:8787"),
                )
                .arg(Arg::new("openai").long("openai-upstream"))
                .arg(Arg::new("anthropic").long("anthropic-upstream")),
        )
        .subcommand(
            Command::new("mcp")
                .about("MCP stdio JSON-RPC sanitization preview")
                .arg(
                    Arg::new("direction")
                        .long("direction")
                        .default_value("to-agent")
                        .value_parser(["to-agent", "to-server"]),
                )
                .arg(Arg::new("server").long("server").default_value("preview")),
        )
        .subcommand(
            Command::new("run")
                .about("Run a supported coding agent through a declared boundary")
                .arg(Arg::new("agent").required(true).value_parser(["claude"]))
                .arg(Arg::new("strict").long("strict").action(ArgAction::SetTrue))
                .arg(
                    Arg::new("anthropic")
                        .long("anthropic-upstream")
                        .required(true),
                )
                .arg(Arg::new("agent_arg").num_args(0..).trailing_var_arg(true)),
        )
}

fn init(root: &Path) -> ExitCode {
    match config::init(root) {
        Ok(()) => {
            println!("Created {} with safe defaults.", config::CONFIG_FILE);
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error.to_string()),
    }
}

fn doctor_command(root: &Path) -> ExitCode {
    let report = doctor::run(root);
    report.print();
    if report.is_healthy() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn detectors() -> Result<DetectorSet, ExitCode> {
    DetectorSet::new().map_err(|error| fail(&error.to_string()))
}

fn scan_command(args: &ArgMatches) -> ExitCode {
    let path = args
        .get_one::<String>("path")
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    let scanner = match detectors() {
        Ok(detectors) => ScannerBuilder::new(detectors).build(),
        Err(code) => return code,
    };
    let report = match scanner.scan(path) {
        Ok(report) => report,
        Err(error) => return fail(&error.to_string()),
    };
    if args.get_flag("json") {
        print_scan_json(&report);
    } else {
        for file in report.files() {
            for finding in file.findings() {
                println!(
                    "{}:{}-{} {} {:?}",
                    file.path().display(),
                    finding.span().start(),
                    finding.span().end(),
                    finding.kind().label(),
                    finding.confidence()
                );
            }
        }
        println!(
            "Scanned {} files; {} files contained findings.",
            report.files_considered(),
            report.files().len()
        );
    }
    if report.files().is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn print_scan_json(report: &blindfold_detectors::ScanReport) {
    let findings = report
        .files()
        .iter()
        .flat_map(|file| {
            file.findings().iter().map(move |finding| {
                serde_json::json!({
                    "path": file.path(),
                    "start": finding.span().start(),
                    "end": finding.span().end(),
                    "kind": finding.kind().label(),
                    "detector": finding.detector(),
                    "confidence": format!("{:?}", finding.confidence()).to_lowercase(),
                })
            })
        })
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "files_considered": report.files_considered(),
            "bytes_read": report.bytes_read(),
            "findings": findings,
        })
    );
}

fn redact_command(args: &ArgMatches) -> ExitCode {
    let input = if let Some(path) = args.get_one::<String>("file") {
        match fs::read_to_string(path) {
            Ok(input) => input,
            Err(error) => return fail(&format!("could not read input: {}", error.kind())),
        }
    } else {
        let mut input = String::new();
        if let Err(error) = io::stdin().read_to_string(&mut input) {
            return fail(&format!("could not read standard input: {}", error.kind()));
        }
        input
    };
    let mode = match args.get_one::<String>("mode").map(String::as_str) {
        Some("env-ref") => RedactionMode::EnvRef,
        Some("schema-only") => RedactionMode::SchemaOnly,
        Some("surrogate") => RedactionMode::Surrogate,
        Some("block") => RedactionMode::Block,
        _ => RedactionMode::Placeholder,
    };
    let redactor = match detectors() {
        Ok(detectors) => Redactor::new(detectors),
        Err(code) => return code,
    };
    let dotenv = (mode == RedactionMode::EnvRef).then(|| DotenvCatalog::parse(&input));
    let options = dotenv.as_ref().map_or_else(
        || RedactionOptions::new(mode),
        |catalog| RedactionOptions::new(mode).with_dotenv(catalog),
    );
    match redactor.redact(&input, options) {
        Ok(output) => {
            print!("{}", output.text());
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error.to_string()),
    }
}

fn exec_command(args: &ArgMatches) -> ExitCode {
    let command = args
        .get_many::<String>("command")
        .map(|values| values.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let Some(program) = command.first() else {
        return fail("a command is required");
    };
    let mut spec = CommandSpec::new(program);
    spec.args(command.iter().skip(1));
    let mut request = ExecutionRequest::new(spec);
    let mut environment = EnvironmentPolicy::new();
    for name in ["PATH", "HOME", "USER", "SHELL", "TERM", "TMPDIR"] {
        let parsed = match EnvironmentName::new(name) {
            Ok(name) => name,
            Err(error) => return fail(&error.to_string()),
        };
        environment.allow_passthrough(parsed);
    }
    request.set_environment(environment);
    if let Some(names) = args.get_many::<String>("secret") {
        for name in names {
            let Ok(value) = env::var(name) else {
                return fail("a requested secret is unavailable in the parent environment");
            };
            let env_name = match EnvironmentName::new(name.clone()) {
                Ok(name) => name,
                Err(error) => return fail(&error.to_string()),
            };
            let binding = match SecretBinding::new(env_name, SecretValue::new(value)) {
                Ok(binding) => binding,
                Err(error) => return fail(&error.to_string()),
            };
            request.add_secret(binding);
        }
    }
    match execute(&request) {
        Ok(result) => {
            print!("{}", String::from_utf8_lossy(result.stdout()));
            eprint!("{}", String::from_utf8_lossy(result.stderr()));
            let audit = result.audit();
            eprintln!(
                "\nBlindfold: exit={:?} stdout_redactions={} stderr_redactions={}",
                audit.exit().code(),
                audit.stdout_redactions(),
                audit.stderr_redactions()
            );
            exit_from_code(audit.exit().code())
        }
        Err(error) => fail(&error.to_string()),
    }
}

fn policy_command(args: &ArgMatches) -> ExitCode {
    let Some(("check", check)) = args.subcommand() else {
        return fail("policy subcommand is required");
    };
    let preset = match check.get_one::<String>("mode").map(String::as_str) {
        Some("chill") => Preset::Chill,
        Some("strict") => Preset::Strict,
        Some("ci") => Preset::Ci,
        _ => Preset::Balanced,
    };
    let destination = parse_destination(check.get_one::<String>("destination").map(String::as_str));
    let sensitivity = parse_sensitivity(check.get_one::<String>("sensitivity").map(String::as_str));
    let request = Request::new(
        Operation::Disclose,
        CoreSecretKind::ApiKey,
        sensitivity,
        SourceContext::File,
        destination,
    );
    let decision = Policy::preset(preset).evaluate(request);
    println!(
        "action={:?} basis={:?} mode={:?} destination={:?} sensitivity={:?}",
        decision.action(),
        decision.explanation().basis(),
        preset,
        destination,
        sensitivity
    );
    if decision.permits_operation() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn diff_command(root: &Path, args: &ArgMatches) -> ExitCode {
    let report = if let Some(path) = args.get_one::<String>("patch") {
        match fs::read_to_string(path) {
            Ok(input) => match scan(&input) {
                Ok(report) => report,
                Err(error) => return fail(&error.to_string()),
            },
            Err(error) => return fail(&format!("could not read patch: {}", error.kind())),
        }
    } else {
        let source = if args.get_flag("staged") {
            GitDiff::Staged
        } else {
            GitDiff::WorkingTree
        };
        match scan_git(root, source) {
            Ok(report) => report,
            Err(error) => return fail(&error.to_string()),
        }
    };
    if args.get_flag("json") {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.to_text());
    }
    if report.outcome() == ScanOutcome::Findings {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn vault_command(root: &Path, args: &ArgMatches) -> ExitCode {
    let vault = match open_vault(root) {
        Ok(vault) => vault,
        Err(code) => return code,
    };
    let scope = match project_scope(root) {
        Ok(scope) => scope,
        Err(error) => return fail(&error.to_string()),
    };
    match args.subcommand() {
        Some(("put-env", put)) => {
            let Some(name) = put.get_one::<String>("name") else {
                return fail("environment variable name is required");
            };
            let Ok(value) = env::var(name) else {
                return fail("environment value is unavailable");
            };
            let ttl = put
                .get_one::<String>("ttl")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(3600);
            match vault.store(
                SafeRefKind::Environment,
                &scope,
                &SecretValue::new(value),
                Duration::from_secs(ttl),
            ) {
                Ok(safe_ref) => {
                    println!("{safe_ref}");
                    append_audit(
                        root,
                        AuditAction::Store,
                        AuditOutcome::Succeeded,
                        Some(safe_ref),
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error.to_string()),
            }
        }
        Some(("list", _)) => match vault.list(&scope) {
            Ok(entries) => {
                for entry in entries {
                    println!("{}", entry.safe_ref());
                }
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error.to_string()),
        },
        Some(("clear", _)) => match vault.clear(&scope) {
            Ok(count) => {
                println!("Removed {count} scoped vault entries.");
                append_audit(root, AuditAction::Clear, AuditOutcome::Succeeded, None);
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error.to_string()),
        },
        _ => fail("vault subcommand is required"),
    }
}

fn audit_command(root: &Path) -> ExitCode {
    let path = root.join(".blindfold/audit.jsonl");
    match fs::read_to_string(path) {
        Ok(contents) => {
            print!("{contents}");
            ExitCode::SUCCESS
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            println!("No audit events recorded.");
            ExitCode::SUCCESS
        }
        Err(error) => fail(&format!("could not read audit log: {}", error.kind())),
    }
}

async fn proxy_command(args: &ArgMatches) -> ExitCode {
    let Some(listen) = args
        .get_one::<String>("listen")
        .and_then(|value| value.parse::<SocketAddr>().ok())
    else {
        return fail("invalid proxy listen address");
    };
    let mut upstreams = Vec::new();
    if let Some(url) = args.get_one::<String>("openai") {
        match Upstream::new("openai", url, Provider::OpenAi) {
            Ok(upstream) => upstreams.push(upstream),
            Err(error) => return fail(&error.to_string()),
        }
    }
    if let Some(url) = args.get_one::<String>("anthropic") {
        match Upstream::new("anthropic", url, Provider::Anthropic) {
            Ok(upstream) => upstreams.push(upstream),
            Err(error) => return fail(&error.to_string()),
        }
    }
    if upstreams.is_empty() {
        return fail("at least one upstream must be configured");
    }
    let sanitizer = match DetectorSanitizer::new() {
        Ok(sanitizer) => Arc::new(sanitizer),
        Err(code) => return code,
    };
    let config = ProxyConfig {
        bind_addr: listen,
        upstreams,
        ..ProxyConfig::default()
    };
    let proxy = match Proxy::new(config, sanitizer) {
        Ok(proxy) => proxy,
        Err(error) => return fail(&error.to_string()),
    };
    let bound = match proxy.bind().await {
        Ok(bound) => bound,
        Err(error) => return fail(&error.to_string()),
    };
    println!("Blindfold proxy listening on http://{}", bound.local_addr());
    println!("Routes: /openai/... and /anthropic/...");
    let cancellation = CancellationToken::new();
    let signal = cancellation.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal.cancel();
    });
    match bound.serve(cancellation).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&format!("proxy stopped: {}", error.kind())),
    }
}

fn mcp_command(args: &ArgMatches) -> ExitCode {
    let mut input = String::new();
    if let Err(error) = io::stdin().read_to_string(&mut input) {
        return fail(&format!("could not read MCP message: {}", error.kind()));
    }
    let sanitizer = match DetectorSanitizer::new() {
        Ok(sanitizer) => sanitizer,
        Err(code) => return code,
    };
    let transformer = match McpTransformer::new(RejectResolver, sanitizer, 1024 * 1024) {
        Ok(transformer) => transformer,
        Err(error) => return fail(&error.to_string()),
    };
    let direction = if args
        .get_one::<String>("direction")
        .is_some_and(|value| value == "to-server")
    {
        McpDirection::ToServer
    } else {
        McpDirection::ToAgent
    };
    let server = args
        .get_one::<String>("server")
        .map_or("preview", String::as_str);
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        match transformer.transform(direction, server, line) {
            Ok((output, audit)) => {
                println!("{output}");
                eprintln!(
                    "Blindfold MCP: restored={} sanitized={} rejected={}",
                    audit.restored, audit.sanitized, audit.rejected
                );
            }
            Err(error) => return fail(&error.to_string()),
        }
    }
    ExitCode::SUCCESS
}

async fn run_agent_command(args: &ArgMatches) -> ExitCode {
    if args.get_flag("strict") {
        return fail(
            "strict Claude mode is unavailable because upstream credential injection is not yet isolated from the agent process",
        );
    }
    eprintln!("Blindfold degraded mode:");
    eprintln!("- managed Anthropic request/response proxy: available");
    eprintln!("- interactive terminal output sanitization: unavailable");
    eprintln!("- direct filesystem/network bypass prevention: unavailable");
    eprintln!("- provider credential isolation from the agent environment: unavailable");
    let Some(upstream) = args.get_one::<String>("anthropic") else {
        return fail("Anthropic upstream is required");
    };
    let listen: SocketAddr = match "127.0.0.1:0".parse() {
        Ok(address) => address,
        Err(_) => return fail("internal proxy address is invalid"),
    };
    let sanitizer = match DetectorSanitizer::new() {
        Ok(sanitizer) => Arc::new(sanitizer),
        Err(code) => return code,
    };
    let upstream = match Upstream::new("anthropic", upstream, Provider::Anthropic) {
        Ok(upstream) => upstream,
        Err(error) => return fail(&error.to_string()),
    };
    let proxy = match Proxy::new(
        ProxyConfig {
            bind_addr: listen,
            upstreams: vec![upstream],
            ..ProxyConfig::default()
        },
        sanitizer,
    ) {
        Ok(proxy) => proxy,
        Err(error) => return fail(&error.to_string()),
    };
    let bound = match proxy.bind().await {
        Ok(bound) => bound,
        Err(error) => return fail(&error.to_string()),
    };
    let base_url = format!("http://{}/anthropic", bound.local_addr());
    let cancellation = CancellationToken::new();
    let proxy_cancellation = cancellation.clone();
    let proxy_task = tokio::spawn(bound.serve(proxy_cancellation));

    let mut command = tokio::process::Command::new("claude");
    if let Some(values) = args.get_many::<String>("agent_arg") {
        command.args(values);
    }
    command.env("ANTHROPIC_BASE_URL", &base_url);
    let status = command.status().await;
    cancellation.cancel();
    let _ = proxy_task.await;
    match status {
        Ok(status) => exit_from_code(status.code()),
        Err(error) => fail(&format!("could not run Claude: {}", error.kind())),
    }
}

struct DetectorSanitizer {
    redactor: Redactor,
}

impl DetectorSanitizer {
    fn new() -> Result<Self, ExitCode> {
        detectors().map(|detectors| Self {
            redactor: Redactor::new(detectors),
        })
    }

    fn sanitize_text(&self, text: &str) -> String {
        self.redactor
            .redact(text, RedactionOptions::new(RedactionMode::Placeholder))
            .map_or_else(
                |_| "[BLOCKED]".to_owned(),
                blindfold_detectors::RedactionOutput::into_text,
            )
    }
}

impl ProxySanitizer for DetectorSanitizer {
    fn sanitize(&self, text: &str) -> String {
        self.sanitize_text(text)
    }

    fn required_overlap(&self) -> usize {
        512
    }
}

impl McpSanitizer for DetectorSanitizer {
    fn sanitize(&self, text: &str) -> (String, usize) {
        let output = self
            .redactor
            .redact(text, RedactionOptions::new(RedactionMode::Placeholder));
        match output {
            Ok(output) => {
                let count = output.findings().len();
                (output.into_text(), count)
            }
            Err(_) => ("[BLOCKED]".to_owned(), 1),
        }
    }
}

struct RejectResolver;

impl McpResolver for RejectResolver {
    fn allows(&self, _server: &str, _tool: &str, _pointer: &str) -> bool {
        false
    }

    fn resolve(&self, _safe_ref: &SafeRef) -> Option<SecretValue> {
        None
    }
}

fn open_vault(root: &Path) -> Result<Vault, ExitCode> {
    let raw = env::var(MASTER_KEY_ENV)
        .map_err(|_| fail("BLINDFOLD_MASTER_KEY must be 64 hexadecimal characters"))?;
    let key = decode_key(&raw)
        .ok_or_else(|| fail("BLINDFOLD_MASTER_KEY must be 64 hexadecimal characters"))?;
    Vault::open(root.join(".blindfold/vault.bin"), MasterKey::new(key))
        .map_err(|error| fail(&error.to_string()))
}

fn decode_key(input: &str) -> Option<[u8; 32]> {
    if input.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        output[index] = (high << 4) | low;
    }
    Some(output)
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn project_scope(root: &Path) -> Result<Scope, blindfold_vault::VaultError> {
    Scope::new(root.to_string_lossy(), "default")
}

fn append_audit(
    root: &Path,
    action: AuditAction,
    outcome: AuditOutcome,
    safe_ref: Option<SafeRef>,
) {
    let Ok(rotation) = RotationPolicy::new(1024 * 1024, 3) else {
        return;
    };
    let Ok(log) = AuditLog::open(root.join(".blindfold/audit.jsonl"), rotation) else {
        return;
    };
    let _ = log.append(&AuditEvent::now(action, outcome, safe_ref));
}

fn parse_destination(value: Option<&str>) -> Destination {
    match value {
        Some("agent") => Destination::Agent,
        Some("tool") => Destination::Tool,
        Some("child") => Destination::ChildProcess,
        Some("file") => Destination::File,
        Some("log") => Destination::Log,
        Some("audit") => Destination::Audit,
        Some("user") => Destination::User,
        Some("trusted-local") => Destination::TrustedLocal,
        _ => Destination::ModelProvider,
    }
}

fn parse_sensitivity(value: Option<&str>) -> Sensitivity {
    match value {
        Some("public") => Sensitivity::Public,
        Some("internal") => Sensitivity::Internal,
        Some("confidential") => Sensitivity::Confidential,
        Some("restricted") => Sensitivity::Restricted,
        _ => Sensitivity::Secret,
    }
}

fn exit_from_code(code: Option<i32>) -> ExitCode {
    code.and_then(|value| u8::try_from(value).ok())
        .map_or(ExitCode::FAILURE, ExitCode::from)
}

fn fail(message: &str) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}
