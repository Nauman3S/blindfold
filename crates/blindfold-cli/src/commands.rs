use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use atomic_write_file::AtomicWriteFile;
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
use blindfold_proxy::{SanitizedText as ProxySanitizedText, TraceSink as ProxyTraceSink};
use blindfold_trace::{
    Category as TraceCategory, Coverage as TraceCoverage, Issue as TraceIssue,
    Outcome as TraceOutcome, Record as TraceRecord, Replacement as TraceReplacement,
    Route as TraceRoute, Store as TraceStore,
};
use blindfold_vault::{
    AuditAction, AuditEvent, AuditLog, AuditOutcome, MasterKey, RotationPolicy, Scope, Vault,
};
use clap::{Arg, ArgAction, ArgMatches, Command};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::{config, doctor};

const MASTER_KEY_ENV: &str = "BLINDFOLD_MASTER_KEY";
const BYPASS_ENV: &str = "BLINDFOLD_BYPASS";
const DEFAULT_ALLOWED_DOMAINS: &[&str] = &[
    "github.com",
    "api.github.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "proxy.golang.org",
    "sum.golang.org",
];
static NEXT_CLI_TRACE_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) async fn run() -> ExitCode {
    let matches = cli().get_matches();
    let trace_enabled = matches.get_flag("trace");
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
        Some(("init", _)) => traced_command(&root, trace_enabled, TraceRoute::Init, || init(&root)),
        Some(("doctor", _)) => traced_command(&root, trace_enabled, TraceRoute::Doctor, || {
            doctor_command(&root)
        }),
        Some(("scan", args)) => scan_command(&root, args, trace_enabled),
        Some(("redact", args)) => redact_command(&root, args, trace_enabled),
        Some(("exec", args)) => traced_command(&root, trace_enabled, TraceRoute::Exec, || {
            exec_command(args)
        }),
        Some(("policy", args)) => traced_command(&root, trace_enabled, TraceRoute::Policy, || {
            policy_command(args)
        }),
        Some(("allow", args)) => traced_command(&root, trace_enabled, TraceRoute::Policy, || {
            allow_command(&root, args)
        }),
        Some(("deny", args)) => traced_command(&root, trace_enabled, TraceRoute::Policy, || {
            deny_command(&root, args)
        }),
        Some(("status", _)) => traced_command(&root, trace_enabled, TraceRoute::Policy, || {
            status_command(&root)
        }),
        Some(("diff-check", args)) => {
            traced_command(&root, trace_enabled, TraceRoute::DiffCheck, || {
                diff_command(&root, args)
            })
        }
        Some(("vault", args)) => traced_command(&root, trace_enabled, TraceRoute::Vault, || {
            vault_command(&root, args)
        }),
        Some(("audit", _)) => traced_command(&root, trace_enabled, TraceRoute::Audit, || {
            audit_command(&root)
        }),
        Some(("trace", args)) => trace_command(&root, args),
        Some(("proxy", args)) => {
            traced_async_command(&root, trace_enabled, TraceRoute::Proxy, proxy_command(args)).await
        }
        Some(("mcp", args)) => {
            traced_command(&root, trace_enabled, TraceRoute::Mcp, || mcp_command(args))
        }
        Some(("run", args)) => run_agent_command(&root, args, trace_enabled).await,
        Some(("shell-init", args)) => {
            traced_command(&root, trace_enabled, TraceRoute::ShellInit, || {
                shell_init_command(args)
            })
        }
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
        .arg(
            Arg::new("trace")
                .long("trace")
                .global(true)
                .help("Record payload-free trace metadata for this invocation")
                .action(ArgAction::SetTrue),
        )
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
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .value_name("FILE")
                        .help("Write redacted content to a new file instead of stdout"),
                )
                .arg(
                    Arg::new("force")
                        .long("force")
                        .help("Allow --output to replace an existing file")
                        .requires("output")
                        .action(ArgAction::SetTrue),
                )
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
            Command::new("allow")
                .about("Allow project-scoped network destinations")
                .subcommand(Command::new("domain").arg(Arg::new("domain").required(true)))
                .subcommand_required(true),
        )
        .subcommand(
            Command::new("deny")
                .about("Deny project-scoped network destinations")
                .subcommand(Command::new("domain").arg(Arg::new("domain").required(true)))
                .subcommand_required(true),
        )
        .subcommand(Command::new("status").about("Show safe Blindfold project status"))
        .subcommand(
            Command::new("diff-check")
                .about("Scan added lines in a patch or Git diff")
                .arg(
                    Arg::new("patch")
                        .long("patch")
                        .value_name("FILE")
                        .conflicts_with("staged"),
                )
                .arg(
                    Arg::new("staged")
                        .long("staged")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("patch"),
                )
                .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
        )
        .subcommand(
            Command::new("vault")
                .about("Manage encrypted local SafeRef mappings")
                .subcommand(
                    Command::new("put-env")
                        .arg(Arg::new("name").required(true))
                        .arg(
                            Arg::new("ttl")
                                .long("ttl-seconds")
                                .default_value("3600")
                                .value_parser(clap::value_parser!(u64).range(1..)),
                        ),
                )
                .subcommand(Command::new("list"))
                .subcommand(
                    Command::new("clear").arg(
                        Arg::new("yes")
                            .long("yes")
                            .help("Confirm deletion of all records in this scope")
                            .action(ArgAction::SetTrue),
                    ),
                ),
        )
        .subcommand(Command::new("audit").about("Print safe local audit JSON lines"))
        .subcommand(
            Command::new("trace")
                .about("Inspect explicitly enabled payload-free command/session/request traces")
                .subcommand(
                    Command::new("list")
                        .about("List retained trace records")
                        .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
                )
                .subcommand(
                    Command::new("show")
                        .about("Show one trace record")
                        .arg(Arg::new("request_id").required(true))
                        .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
                )
                .subcommand(
                    Command::new("tail")
                        .about("Show the most recent trace record")
                        .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
                )
                .subcommand(
                    Command::new("export")
                        .about("Export one trace using the closed redacted JSON schema")
                        .arg(Arg::new("request_id").required(true))
                        .arg(
                            Arg::new("redacted")
                                .long("redacted")
                                .required(true)
                                .action(ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("clear").about("Delete retained traces").arg(
                        Arg::new("yes")
                            .long("yes")
                            .help("Confirm deletion of all retained traces")
                            .action(ArgAction::SetTrue),
                    ),
                )
                .subcommand_required(true),
        )
        .subcommand(
            Command::new("proxy")
                .about("Run the loopback LLM proxy")
                .arg(
                    Arg::new("listen")
                        .long("listen")
                        .default_value("127.0.0.1:8787"),
                )
                .arg(Arg::new("openai").long("openai-upstream"))
                .arg(Arg::new("anthropic").long("anthropic-upstream"))
                .arg(Arg::new("openrouter").long("openrouter-upstream")),
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
                .arg(
                    Arg::new("agent")
                        .required(true)
                        .value_parser(["claude", "codex", "opencode"]),
                )
                .arg(
                    Arg::new("guard")
                        .long("guard")
                        .help("Run in guard mode: route managed provider traffic through Blindfold")
                        .action(ArgAction::SetTrue),
                )
                .arg(Arg::new("strict").long("strict").action(ArgAction::SetTrue))
                .arg(
                    Arg::new("anthropic")
                        .long("anthropic-upstream")
                        .default_value("https://api.anthropic.com"),
                )
                .arg(
                    Arg::new("openai")
                        .long("openai-upstream")
                        .default_value("https://api.openai.com/v1"),
                )
                .arg(
                    Arg::new("openrouter")
                        .long("openrouter-upstream")
                        .default_value("https://openrouter.ai/api/v1"),
                )
                .arg(
                    Arg::new("no_proxy")
                        .long("no-proxy")
                        .help("Run the native agent directly for this invocation")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("agent_command")
                        .long("agent-command")
                        .help("Override the native agent executable")
                        .value_name("PATH"),
                )
                .arg(Arg::new("agent_arg").num_args(0..).trailing_var_arg(true)),
        )
        .subcommand(
            Command::new("shell-init")
                .about("Print opt-out-friendly shell wrappers for coding agents")
                .arg(
                    Arg::new("shell")
                        .default_value("zsh")
                        .value_parser(["bash", "zsh"]),
                ),
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

fn traced_command(
    root: &Path,
    trace_enabled: bool,
    route: TraceRoute,
    command: impl FnOnce() -> ExitCode,
) -> ExitCode {
    let code = command();
    if trace_enabled && let Err(error) = append_command_trace(root, route, (0, 0), Vec::new()) {
        return fail(&error.to_string());
    }
    code
}

async fn traced_async_command(
    root: &Path,
    trace_enabled: bool,
    route: TraceRoute,
    future: impl std::future::Future<Output = ExitCode>,
) -> ExitCode {
    let code = future.await;
    if trace_enabled && let Err(error) = append_command_trace(root, route, (0, 0), Vec::new()) {
        return fail(&error.to_string());
    }
    code
}

fn scan_command(root: &Path, args: &ArgMatches, trace_enabled: bool) -> ExitCode {
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
        println!(
            "Completeness: complete={} skipped_binary={} skipped_too_large={} \
             skipped_ignored={} skipped_symlinks={} io_errors={} limit_reached={}.",
            !scan_is_incomplete(&report),
            report.skipped_binary(),
            report.skipped_too_large(),
            report.skipped_ignored(),
            report.skipped_symlinks(),
            report.io_errors(),
            report.limit_reached()
        );
    }
    let code = if scan_is_incomplete(&report) {
        ExitCode::from(3)
    } else if report.files().is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    };
    if trace_enabled
        && let Err(error) =
            append_command_trace(root, TraceRoute::Scan, (report.bytes_read(), 0), Vec::new())
    {
        return fail(&error.to_string());
    }
    code
}

fn scan_is_incomplete(report: &blindfold_detectors::ScanReport) -> bool {
    report.skipped_too_large() > 0 || report.io_errors() > 0 || report.limit_reached()
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
            "complete": !scan_is_incomplete(report),
            "skipped": {
                "binary": report.skipped_binary(),
                "too_large": report.skipped_too_large(),
                "ignored": report.skipped_ignored(),
                "symlinks": report.skipped_symlinks(),
            },
            "io_errors": report.io_errors(),
            "limit_reached": report.limit_reached(),
            "findings": findings,
        })
    );
}

fn redact_command(root: &Path, args: &ArgMatches, trace_enabled: bool) -> ExitCode {
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
            if trace_enabled
                && let Err(error) =
                    append_redact_trace(root, &input, output.text(), output.findings())
            {
                return fail(&error.to_string());
            }
            if let Some(path) = args.get_one::<String>("output") {
                write_redacted_output(Path::new(path), output.text(), args.get_flag("force"))
            } else {
                print!("{}", output.text());
                ExitCode::SUCCESS
            }
        }
        Err(error) => fail(&error.to_string()),
    }
}

fn append_redact_trace(
    root: &Path,
    input: &str,
    output: &str,
    findings: &[blindfold_detectors::Finding],
) -> blindfold_trace::Result<()> {
    let mut grouped = BTreeMap::<(TraceCategory, String), u32>::new();
    let dotenv_ranges = dotenv_value_ranges(input);
    for finding in findings {
        let pointer = dotenv_ranges
            .iter()
            .find(|field| field.range_contains(finding.span().start()))
            .map_or_else(|| "/input".to_owned(), DotenvFieldRange::pointer);
        *grouped
            .entry((trace_category(finding.kind()), pointer))
            .or_default() += 1;
    }
    let replacements = grouped
        .into_iter()
        .enumerate()
        .map(|(index, ((category, pointer), count))| {
            TraceReplacement::new(format!("S{}", index + 1), category, pointer, count)
        })
        .collect::<blindfold_trace::Result<Vec<_>>>()?;
    append_command_trace(
        root,
        TraceRoute::Redact,
        (
            u64::try_from(input.len()).unwrap_or(u64::MAX),
            u64::try_from(output.len()).unwrap_or(u64::MAX),
        ),
        replacements,
    )
}

struct DotenvFieldRange {
    name: String,
    value_start: usize,
    value_end: usize,
}

impl DotenvFieldRange {
    const fn range_contains(&self, offset: usize) -> bool {
        self.value_start <= offset && offset < self.value_end
    }

    fn pointer(&self) -> String {
        format!("/env/{}", self.name)
    }
}

fn dotenv_value_ranges(input: &str) -> Vec<DotenvFieldRange> {
    let mut ranges = Vec::new();
    let mut offset = 0;
    for line_with_ending in input.split_inclusive('\n') {
        let line = line_with_ending
            .strip_suffix('\n')
            .unwrap_or(line_with_ending);
        if let Some(range) = dotenv_value_range(line, offset) {
            ranges.push(range);
        }
        offset += line_with_ending.len();
    }
    ranges
}

fn dotenv_value_range(line: &str, line_offset: usize) -> Option<DotenvFieldRange> {
    let assignment_start = line.bytes().position(|byte| !byte.is_ascii_whitespace())?;
    let assignment = line[assignment_start..]
        .strip_prefix("export ")
        .unwrap_or(&line[assignment_start..]);
    let name_start = line.len() - assignment.len();
    let equals = assignment.find('=')?;
    let name = assignment[..equals].trim();
    if !valid_trace_env_name(name) {
        return None;
    }
    let raw_value = &assignment[equals + 1..];
    let leading_value_spaces = raw_value
        .bytes()
        .take_while(u8::is_ascii_whitespace)
        .count();
    let value_start = line_offset + name_start + equals + 1 + leading_value_spaces;
    let value_end = line_offset + line.len();
    Some(DotenvFieldRange {
        name: name.to_owned(),
        value_start,
        value_end,
    })
}

fn valid_trace_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn write_redacted_output(path: &Path, contents: &str, force: bool) -> ExitCode {
    if force {
        let mut file = match AtomicWriteFile::open(path) {
            Ok(file) => file,
            Err(error) => {
                return fail(&format!("could not create output file: {}", error.kind()));
            }
        };
        if let Err(error) = file
            .write_all(contents.as_bytes())
            .and_then(|()| file.commit())
        {
            return fail(&format!("could not write output file: {}", error.kind()));
        }
        eprintln!(
            "Blindfold atomically replaced {} with redacted content.",
            path.to_string_lossy()
        );
        return ExitCode::SUCCESS;
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return fail("output file already exists; choose another path or pass --force");
        }
        Err(error) => return fail(&format!("could not create output file: {}", error.kind())),
    };
    if let Err(error) = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
    {
        return fail(&format!("could not write output file: {}", error.kind()));
    }
    eprintln!(
        "Blindfold wrote redacted content to {}.",
        path.to_string_lossy()
    );
    ExitCode::SUCCESS
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

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
struct ProjectNetworkPolicy {
    allow: BTreeSet<String>,
    deny: BTreeSet<String>,
}

fn allow_command(root: &Path, args: &ArgMatches) -> ExitCode {
    let Some(("domain", domain)) = args.subcommand() else {
        return fail("allow subcommand is required");
    };
    let Some(domain) = domain.get_one::<String>("domain") else {
        return fail("a domain is required");
    };
    let domain = match normalize_policy_domain(domain) {
        Ok(domain) => domain,
        Err(message) => return fail(message),
    };
    let mut policy = match load_project_network_policy(root) {
        Ok(policy) => policy,
        Err(message) => return fail(message),
    };
    policy.deny.remove(&domain);
    policy.allow.insert(domain.clone());
    if let Err(message) = save_project_network_policy(root, &policy) {
        return fail(&message);
    }
    println!("Allowed domain for this project: {domain}");
    ExitCode::SUCCESS
}

fn deny_command(root: &Path, args: &ArgMatches) -> ExitCode {
    let Some(("domain", domain)) = args.subcommand() else {
        return fail("deny subcommand is required");
    };
    let Some(domain) = domain.get_one::<String>("domain") else {
        return fail("a domain is required");
    };
    let domain = match normalize_policy_domain(domain) {
        Ok(domain) => domain,
        Err(message) => return fail(message),
    };
    let mut policy = match load_project_network_policy(root) {
        Ok(policy) => policy,
        Err(message) => return fail(message),
    };
    policy.allow.remove(&domain);
    policy.deny.insert(domain.clone());
    if let Err(message) = save_project_network_policy(root, &policy) {
        return fail(&message);
    }
    println!("Denied domain for this project: {domain}");
    ExitCode::SUCCESS
}

fn status_command(root: &Path) -> ExitCode {
    let policy = match load_project_network_policy(root) {
        Ok(policy) => policy,
        Err(message) => return fail(message),
    };
    println!("Blindfold status");
    println!(
        "network default allow domains: {}",
        DEFAULT_ALLOWED_DOMAINS.len()
    );
    println!("project allowed domains: {}", policy.allow.len());
    for domain in &policy.allow {
        println!("  allow {domain}");
    }
    println!("project denied domains: {}", policy.deny.len());
    for domain in &policy.deny {
        println!("  deny {domain}");
    }
    println!("unknown domains: block");
    ExitCode::SUCCESS
}

fn normalize_policy_domain(input: &str) -> Result<String, &'static str> {
    let domain = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 253
        || domain.starts_with('-')
        || domain.ends_with('-')
        || domain.contains("..")
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err("domain must be a hostname using letters, digits, dots, or hyphens");
    }
    Ok(domain)
}

fn load_project_network_policy(root: &Path) -> Result<ProjectNetworkPolicy, &'static str> {
    let path = project_network_policy_path(root);
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ProjectNetworkPolicy::default());
        }
        Err(_) => return Err("could not read project network policy"),
    };
    if contents.len() > 1024 * 1024 {
        return Err("project network policy is too large");
    }
    serde_json::from_str(&contents).map_err(|_| "project network policy is invalid")
}

fn save_project_network_policy(root: &Path, policy: &ProjectNetworkPolicy) -> Result<(), String> {
    let path = project_network_policy_path(root);
    let Some(parent) = path.parent() else {
        return Err("project network policy path is invalid".to_owned());
    };
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create policy directory: {}", error.kind()))?;
    let contents = serde_json::to_string_pretty(policy)
        .map_err(|_| "could not serialize project network policy".to_owned())?;
    let mut file = AtomicWriteFile::open(&path)
        .map_err(|error| format!("could not write project network policy: {}", error.kind()))?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.commit())
        .map_err(|error| format!("could not write project network policy: {}", error.kind()))
}

fn project_network_policy_path(root: &Path) -> PathBuf {
    root.join(".blindfold/network-policy.json")
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
            let ttl = put.get_one::<u64>("ttl").copied().unwrap_or(3600);
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
        Some(("clear", clear)) if !clear.get_flag("yes") => {
            fail("vault clear is destructive; pass --yes to confirm this working-directory scope")
        }
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
    let rotation = match RotationPolicy::new(1024 * 1024, 5) {
        Ok(rotation) => rotation,
        Err(error) => return fail(&error.to_string()),
    };
    let audit = match AuditLog::open(path, rotation) {
        Ok(audit) => audit,
        Err(error) => return fail(&format!("could not open audit log: {error}")),
    };
    match audit.read_lines() {
        Ok(lines) if lines.is_empty() => {
            println!("No audit events recorded.");
            ExitCode::SUCCESS
        }
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => fail(&format!("could not read audit log: {error}")),
    }
}

fn trace_command(root: &Path, args: &ArgMatches) -> ExitCode {
    let store = match open_trace_store(root) {
        Ok(store) => store,
        Err(error) => return fail(&error.to_string()),
    };
    match args.subcommand() {
        Some(("clear", clear)) if !clear.get_flag("yes") => {
            fail("trace clear is destructive; pass --yes to confirm")
        }
        Some(("clear", _)) => match store.clear() {
            Ok(count) => {
                println!("Removed {count} trace files.");
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error.to_string()),
        },
        Some((command @ ("list" | "show" | "tail" | "export"), values)) => {
            let records = match store.read_all() {
                Ok(records) => records,
                Err(error) => return fail(&error.to_string()),
            };
            match command {
                "list" => {
                    if values.get_flag("json") {
                        print_trace_json_array(&records)
                    } else {
                        for record in &records {
                            print_trace_summary(record);
                        }
                        if records.is_empty() {
                            println!("No trace records recorded.");
                        }
                        ExitCode::SUCCESS
                    }
                }
                "tail" => match records.last() {
                    Some(record) => print_trace_record(record, values.get_flag("json")),
                    None => fail("no trace records recorded"),
                },
                "show" | "export" => {
                    let Some(request_id) = values.get_one::<String>("request_id") else {
                        return fail("request ID is required");
                    };
                    let Some(record) = records
                        .iter()
                        .find(|record| record.request_id() == request_id)
                    else {
                        return fail("request trace was not found");
                    };
                    print_trace_record(record, command == "export" || values.get_flag("json"))
                }
                _ => fail("trace subcommand is required"),
            }
        }
        _ => fail("trace subcommand is required"),
    }
}

fn open_trace_store(root: &Path) -> blindfold_trace::Result<TraceStore> {
    TraceStore::open(root.join(".blindfold/trace.jsonl"), 1024 * 1024, 3)
}

fn append_command_trace(
    root: &Path,
    route: TraceRoute,
    bytes: (u64, u64),
    replacements: Vec<TraceReplacement>,
) -> blindfold_trace::Result<()> {
    append_trace_record(
        root,
        route,
        TraceCoverage::Protected,
        TraceOutcome::Observed,
        bytes,
        replacements,
        None,
    )
}

fn append_degraded_run_trace(
    root: &Path,
    route: TraceRoute,
    issue: TraceIssue,
) -> blindfold_trace::Result<()> {
    append_trace_record(
        root,
        route,
        TraceCoverage::Degraded,
        TraceOutcome::Observed,
        (0, 0),
        Vec::new(),
        Some(issue),
    )
}

fn append_unprotected_run_trace(root: &Path, route: TraceRoute) -> blindfold_trace::Result<()> {
    append_trace_record(
        root,
        route,
        TraceCoverage::Unprotected,
        TraceOutcome::Observed,
        (0, 0),
        Vec::new(),
        Some(TraceIssue::DirectFilesystemUnmediated),
    )
}

fn append_trace_record(
    root: &Path,
    route: TraceRoute,
    coverage: TraceCoverage,
    outcome: TraceOutcome,
    bytes: (u64, u64),
    replacements: Vec<TraceReplacement>,
    issue: Option<TraceIssue>,
) -> blindfold_trace::Result<()> {
    let store = open_trace_store(root)?;
    let record = TraceRecord::now(
        next_trace_request_id(),
        route,
        coverage,
        outcome,
        bytes,
        (0, 0),
        replacements,
        issue,
    )?;
    store.append(&record)
}

fn next_trace_request_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let sequence = NEXT_CLI_TRACE_ID.fetch_add(1, Ordering::Relaxed);
    format!("req_{timestamp:x}_{sequence:x}")
}

fn print_trace_json_array(records: &[TraceRecord]) -> ExitCode {
    let mut output = String::from("[");
    for (index, record) in records.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        let Ok(json) = record.to_json() else {
            return fail("trace serialization failed");
        };
        output.push_str(&json);
    }
    output.push(']');
    println!("{output}");
    ExitCode::SUCCESS
}

fn print_trace_record(record: &TraceRecord, json: bool) -> ExitCode {
    if json {
        return match record.to_json() {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error.to_string()),
        };
    }
    println!("request: {}", record.request_id());
    if trace_is_provider_route(record.route()) {
        println!(
            "route: agent -> blindfold -> {}",
            trace_route_label(record.route())
        );
    } else {
        println!("activity: {}", trace_route_label(record.route()));
    }
    println!("coverage: {}", trace_coverage_label(record.coverage()));
    let request = record.request_bytes();
    let response = record.response_bytes();
    println!("request: {} bytes -> {} bytes", request.0, request.1);
    println!("response: {} bytes -> {} bytes", response.0, response.1);
    println!("outcome: {}", trace_outcome_label(record.outcome()));
    if let Some(issue) = record.issue() {
        println!("issue: {}", trace_issue_label(issue));
    }
    println!("replacements:");
    if record.replacements().is_empty() {
        println!("  none");
    } else {
        for replacement in record.replacements() {
            println!(
                "  {}  {}  {}  occurrences={}",
                replacement.id(),
                replacement.category().label(),
                replacement.pointer(),
                replacement.occurrences()
            );
        }
    }
    println!("retention: metadata only; original and sanitized payloads not retained");
    ExitCode::SUCCESS
}

fn print_trace_summary(record: &TraceRecord) {
    println!(
        "{}  route={} coverage={} outcome={} replacements={}",
        record.request_id(),
        trace_route_label(record.route()),
        trace_coverage_label(record.coverage()),
        trace_outcome_label(record.outcome()),
        record.replacements().len()
    );
}

const fn trace_route_label(route: TraceRoute) -> &'static str {
    match route {
        TraceRoute::OpenAi => "openai",
        TraceRoute::Anthropic => "anthropic",
        TraceRoute::Unknown => "unknown",
        TraceRoute::Redact => "redact",
        TraceRoute::Scan => "scan",
        TraceRoute::Exec => "exec",
        TraceRoute::Policy => "policy",
        TraceRoute::DiffCheck => "diff-check",
        TraceRoute::Vault => "vault",
        TraceRoute::Audit => "audit",
        TraceRoute::Proxy => "proxy",
        TraceRoute::Egress => "egress",
        TraceRoute::Mcp => "mcp",
        TraceRoute::RunClaude => "run:claude",
        TraceRoute::RunCodex => "run:codex",
        TraceRoute::RunOpencode => "run:opencode",
        TraceRoute::Init => "init",
        TraceRoute::Doctor => "doctor",
        TraceRoute::ShellInit => "shell-init",
    }
}

const fn trace_is_provider_route(route: TraceRoute) -> bool {
    matches!(
        route,
        TraceRoute::OpenAi | TraceRoute::Anthropic | TraceRoute::Unknown
    )
}

const fn trace_coverage_label(coverage: TraceCoverage) -> &'static str {
    match coverage {
        TraceCoverage::Protected => "protected",
        TraceCoverage::Degraded => "degraded",
        TraceCoverage::Unprotected => "unprotected",
    }
}

const fn trace_outcome_label(outcome: TraceOutcome) -> &'static str {
    match outcome {
        TraceOutcome::Observed => "observed",
        TraceOutcome::Succeeded => "succeeded",
        TraceOutcome::Rejected => "rejected",
        TraceOutcome::Failed => "failed",
        TraceOutcome::TimedOut => "timed_out",
    }
}

const fn trace_issue_label(issue: TraceIssue) -> &'static str {
    match issue {
        TraceIssue::UnsupportedRequest => "unsupported_request",
        TraceIssue::UnsupportedResponse => "unsupported_response",
        TraceIssue::RequestTooLarge => "request_too_large",
        TraceIssue::ResponseTooLarge => "response_too_large",
        TraceIssue::InvalidPayload => "invalid_payload",
        TraceIssue::ProxyLoop => "proxy_loop",
        TraceIssue::RouteNotAllowed => "route_not_allowed",
        TraceIssue::UpstreamFailure => "upstream_failure",
        TraceIssue::Timeout => "timeout",
        TraceIssue::DirectFilesystemUnmediated => "direct_filesystem_unmediated",
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
    if let Some(url) = args.get_one::<String>("openrouter") {
        match Upstream::new("openrouter", url, Provider::OpenAi) {
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
        stream_overlap: 512,
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
    println!("Routes: /openai/..., /anthropic/..., and /openrouter/...");
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
    const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
    let sanitizer = match DetectorSanitizer::new() {
        Ok(sanitizer) => sanitizer,
        Err(code) => return code,
    };
    let transformer = match McpTransformer::new(RejectResolver, sanitizer, MAX_MESSAGE_BYTES) {
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
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    loop {
        let line = match read_bounded_line(&mut reader, MAX_MESSAGE_BYTES) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => return fail(error),
        };
        if line.trim().is_empty() {
            continue;
        }
        match transformer.transform(direction, server, &line) {
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

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<String>, &'static str> {
    let mut line = Vec::new();
    loop {
        let buffer = reader
            .fill_buf()
            .map_err(|_| "could not read MCP message")?;
        if buffer.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return String::from_utf8(line)
                .map(Some)
                .map_err(|_| "invalid MCP JSON-RPC message");
        }
        let (consumed, complete) =
            if let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
                line.extend_from_slice(&buffer[..newline]);
                (newline + 1, true)
            } else {
                line.extend_from_slice(buffer);
                (buffer.len(), false)
            };
        reader.consume(consumed);
        if line.len() > max_bytes {
            return Err("MCP message exceeds the configured size limit");
        }
        if complete {
            return String::from_utf8(line)
                .map(Some)
                .map_err(|_| "invalid MCP JSON-RPC message");
        }
    }
}

struct BoundEgressGuard {
    listener: TcpListener,
    local_addr: SocketAddr,
    policy: Arc<EgressNetworkPolicy>,
    trace_sink: Option<Arc<CliTraceSink>>,
}

impl BoundEgressGuard {
    async fn bind(
        policy: EgressNetworkPolicy,
        trace_sink: Option<Arc<CliTraceSink>>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
            policy: Arc::new(policy),
            trace_sink,
        })
    }

    const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    async fn serve(self, cancellation: CancellationToken) -> io::Result<()> {
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    let policy = Arc::clone(&self.policy);
                    let trace_sink = self.trace_sink.clone();
                    tokio::spawn(async move {
                        let _ = handle_egress_connection(stream, policy, trace_sink).await;
                    });
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
struct EgressNetworkPolicy {
    allow: BTreeSet<String>,
    deny: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EgressDecision {
    Allow,
    BlockKnownProvider,
    BlockDenied,
    BlockUnknown,
}

impl EgressNetworkPolicy {
    fn load(root: &Path) -> Result<Self, &'static str> {
        load_project_network_policy(root).map(Self::from_project)
    }

    fn from_project(project: ProjectNetworkPolicy) -> Self {
        let mut allow = DEFAULT_ALLOWED_DOMAINS
            .iter()
            .map(|domain| (*domain).to_owned())
            .collect::<BTreeSet<_>>();
        allow.extend(project.allow);
        Self {
            allow,
            deny: project.deny,
        }
    }

    fn decision(&self, host: &str) -> EgressDecision {
        let host = normalize_connect_host(host);
        if is_blocked_llm_provider(&host) {
            return EgressDecision::BlockKnownProvider;
        }
        if self.deny.iter().any(|domain| domain_matches(&host, domain)) {
            return EgressDecision::BlockDenied;
        }
        if self
            .allow
            .iter()
            .any(|domain| domain_matches(&host, domain))
        {
            return EgressDecision::Allow;
        }
        EgressDecision::BlockUnknown
    }
}

impl Default for EgressNetworkPolicy {
    fn default() -> Self {
        Self::from_project(ProjectNetworkPolicy::default())
    }
}

async fn handle_egress_connection(
    mut client: TcpStream,
    policy: Arc<EgressNetworkPolicy>,
    trace_sink: Option<Arc<CliTraceSink>>,
) -> io::Result<()> {
    let header = read_http_header(&mut client).await?;
    let header_len = u64::try_from(header.len()).unwrap_or(u64::MAX);
    let Ok(header_text) = std::str::from_utf8(&header) else {
        write_http_response(&mut client, "400 Bad Request", "").await?;
        return Ok(());
    };
    let Some(first_line) = header_text.lines().next() else {
        write_http_response(&mut client, "400 Bad Request", "").await?;
        return Ok(());
    };
    let parts = first_line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 3 {
        write_http_response(&mut client, "400 Bad Request", "").await?;
        return Ok(());
    }
    if parts[0].eq_ignore_ascii_case("CONNECT") {
        return handle_connect(&mut client, parts[1], &policy, trace_sink, header_len).await;
    }
    write_http_response(
        &mut client,
        "501 Not Implemented",
        "Blindfold egress guard currently supports CONNECT only.\n",
    )
    .await?;
    Ok(())
}

async fn handle_connect(
    client: &mut TcpStream,
    authority: &str,
    policy: &EgressNetworkPolicy,
    trace_sink: Option<Arc<CliTraceSink>>,
    header_len: u64,
) -> io::Result<()> {
    let host = authority_host(authority);
    match policy.decision(host) {
        EgressDecision::Allow => {}
        EgressDecision::BlockKnownProvider => {
            emit_egress_trace(
                trace_sink.as_deref(),
                EgressDecision::BlockKnownProvider,
                header_len,
                TraceOutcome::Rejected,
                None,
            );
            write_http_response(
                client,
                "403 Forbidden",
                "Blocked direct LLM provider access; route provider traffic through Blindfold's LLM proxy.\n",
            )
            .await?;
            return Ok(());
        }
        EgressDecision::BlockDenied => {
            emit_egress_trace(
                trace_sink.as_deref(),
                EgressDecision::BlockDenied,
                header_len,
                TraceOutcome::Rejected,
                None,
            );
            write_http_response(
                client,
                "403 Forbidden",
                "Blocked by Blindfold egress policy: domain is denied for this project.\n",
            )
            .await?;
            return Ok(());
        }
        EgressDecision::BlockUnknown => {
            emit_egress_trace(
                trace_sink.as_deref(),
                EgressDecision::BlockUnknown,
                header_len,
                TraceOutcome::Rejected,
                None,
            );
            write_http_response(
                client,
                "403 Forbidden",
                "Blocked by Blindfold egress policy: unknown domains are blocked by default. Use `blindfold allow domain <host>` to allow this destination.\n",
            )
            .await?;
            return Ok(());
        }
    }
    let Ok(mut upstream) = TcpStream::connect(authority).await else {
        emit_egress_trace(
            trace_sink.as_deref(),
            EgressDecision::Allow,
            header_len,
            TraceOutcome::Failed,
            Some(TraceIssue::UpstreamFailure),
        );
        write_http_response(client, "502 Bad Gateway", "").await?;
        return Ok(());
    };
    emit_egress_trace(
        trace_sink.as_deref(),
        EgressDecision::Allow,
        header_len,
        TraceOutcome::Succeeded,
        None,
    );
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let _ = tokio::io::copy_bidirectional(client, &mut upstream).await;
    Ok(())
}

fn emit_egress_trace(
    sink: Option<&CliTraceSink>,
    decision: EgressDecision,
    request_bytes: u64,
    outcome: TraceOutcome,
    issue: Option<TraceIssue>,
) {
    let Some(sink) = sink else {
        return;
    };
    let issue = issue.or(match decision {
        EgressDecision::Allow => None,
        EgressDecision::BlockKnownProvider
        | EgressDecision::BlockDenied
        | EgressDecision::BlockUnknown => Some(TraceIssue::RouteNotAllowed),
    });
    let coverage = if issue.is_none() {
        TraceCoverage::Protected
    } else {
        TraceCoverage::Unprotected
    };
    let Ok(record) = TraceRecord::now(
        next_trace_request_id(),
        TraceRoute::Egress,
        coverage,
        outcome,
        (request_bytes, request_bytes),
        (0, 0),
        Vec::new(),
        issue,
    ) else {
        return;
    };
    sink.record(record);
}

async fn write_http_response(client: &mut TcpStream, status: &str, body: &str) -> io::Result<()> {
    client
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
}

async fn read_http_header(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    const MAX_HEADER_BYTES: usize = 8192;
    let mut header = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        header.extend_from_slice(&buffer[..read]);
        if header.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if header.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "egress header too large",
            ));
        }
    }
    Ok(header)
}

fn authority_host(authority: &str) -> &str {
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    host.trim_start_matches('[').split_once(']').map_or_else(
        || host.rsplit_once(':').map_or(host, |(host, _)| host),
        |(host, _)| host,
    )
}

fn normalize_connect_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn is_blocked_llm_provider(host: &str) -> bool {
    let host = normalize_connect_host(host);
    [
        "api.openai.com",
        "api.anthropic.com",
        "openrouter.ai",
        "generativelanguage.googleapis.com",
        "api.mistral.ai",
        "api.groq.com",
    ]
    .iter()
    .any(|domain| domain_matches(&host, domain))
}

#[allow(clippy::too_many_lines)] // Agent startup and shutdown sequence is clearest in order.
async fn run_agent_command(root: &Path, args: &ArgMatches, trace_enabled: bool) -> ExitCode {
    let agent = args
        .get_one::<String>("agent")
        .map_or("claude", String::as_str);
    let agent_command = args
        .get_one::<String>("agent_command")
        .map_or(agent, String::as_str);
    let agent_args = args
        .get_many::<String>("agent_arg")
        .map(|values| values.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let bypass = args.get_flag("no_proxy") || env_flag(BYPASS_ENV);

    if bypass {
        eprintln!("Blindfold bypass requested; launching {agent} without the managed proxy.");
        let code = run_native_agent(agent, agent_command, &agent_args).await;
        if trace_enabled
            && let Err(error) = append_unprotected_run_trace(root, run_trace_route(agent))
        {
            return fail(&error.to_string());
        }
        return code;
    }
    if args.get_flag("strict") {
        return fail(
            "strict agent mode is unavailable because direct filesystem and network bypass prevention is not yet established",
        );
    }

    let mode = if args.get_flag("guard") {
        "Blindfold Guard active:"
    } else {
        "Blindfold degraded compatibility mode:"
    };
    eprintln!("{mode}");
    eprintln!("- managed provider request/response proxy: available");
    eprintln!("- interactive terminal output sanitization: unavailable");
    eprintln!("- direct filesystem/network bypass prevention: unavailable");
    eprintln!(
        "- direct known-provider egress blocking: {}",
        if args.get_flag("guard") {
            "enabled for proxy-aware clients"
        } else {
            "unavailable without --guard"
        }
    );
    eprintln!(
        "- unknown egress domains: {}",
        if args.get_flag("guard") {
            "blocked unless allowed by project policy"
        } else {
            "unavailable without --guard"
        }
    );
    eprintln!(
        "- agent file reads: unmediated; if the agent opens .env directly, it can see raw contents"
    );
    eprintln!("- parent secret environment isolation: available");
    eprintln!("- provider credential broker: unavailable; use the agent credential store");
    eprintln!(
        "- payload-free request tracing: {}",
        if trace_enabled { "enabled" } else { "disabled" }
    );
    if trace_enabled {
        eprintln!(
            "- trace scope: command/session metadata and managed provider requests only; direct file reads are not observable"
        );
    }
    eprintln!("- one-run opt-out: --no-proxy or {BYPASS_ENV}=1");

    if agent == "codex" && codex_overrides_proxy(&agent_args) {
        return fail(
            "Codex arguments override the managed OpenAI base URL; remove that override or use --no-proxy",
        );
    }
    if agent == "codex" && codex_uses_interactive_websocket_transport(&agent_args) {
        return fail(
            "interactive Codex uses a WebSocket transport that Blindfold does not sanitize yet; use `blindfold run --guard codex -- exec ...`, `blindfold run --guard codex -- review`, or `--no-proxy`",
        );
    }

    let listen: SocketAddr = match "127.0.0.1:0".parse() {
        Ok(address) => address,
        Err(_) => return fail("internal proxy address is invalid"),
    };
    let sanitizer = match DetectorSanitizer::new() {
        Ok(sanitizer) => Arc::new(sanitizer),
        Err(code) => return code,
    };
    let upstreams = match agent_upstreams(agent, args) {
        Ok(upstreams) => upstreams,
        Err(code) => return code,
    };
    let proxy = match Proxy::new(
        ProxyConfig {
            bind_addr: listen,
            stream_overlap: 512,
            upstreams,
            ..ProxyConfig::default()
        },
        sanitizer,
    ) {
        Ok(proxy) => proxy,
        Err(error) => return fail(&error.to_string()),
    };
    let trace_sink = if trace_enabled {
        let store = match open_trace_store(root) {
            Ok(store) => store,
            Err(error) => return fail(&error.to_string()),
        };
        Some(Arc::new(CliTraceSink::new(store)))
    } else {
        None
    };
    let proxy = match &trace_sink {
        Some(sink) => proxy.with_trace_sink(Arc::clone(sink) as Arc<dyn ProxyTraceSink>),
        None => proxy,
    };
    let bound = match proxy.bind().await {
        Ok(bound) => bound,
        Err(error) => return fail(&error.to_string()),
    };
    let proxy_origin = format!("http://{}", bound.local_addr());
    let cancellation = CancellationToken::new();
    let proxy_cancellation = cancellation.clone();
    let proxy_task = tokio::spawn(bound.serve(proxy_cancellation));
    let egress = if args.get_flag("guard") {
        let policy = match EgressNetworkPolicy::load(root) {
            Ok(policy) => policy,
            Err(message) => {
                cancellation.cancel();
                let _ = proxy_task.await;
                return fail(message);
            }
        };
        match BoundEgressGuard::bind(policy, trace_sink.clone()).await {
            Ok(guard) => Some(guard),
            Err(error) => {
                cancellation.cancel();
                let _ = proxy_task.await;
                return fail(&format!("could not start egress guard: {}", error.kind()));
            }
        }
    } else {
        None
    };
    let egress_origin = egress
        .as_ref()
        .map(|guard| format!("http://{}", guard.local_addr()));
    if let Some(origin) = &egress_origin {
        eprintln!("- egress guard proxy: {origin}");
    }
    let egress_task = egress.map(|guard| {
        let cancellation = cancellation.clone();
        tokio::spawn(guard.serve(cancellation))
    });

    let mut command = tokio::process::Command::new(agent_command);
    configure_managed_agent_environment(&mut command);
    configure_agent_command(agent, &mut command, &agent_args, &proxy_origin);
    if let Some(origin) = &egress_origin {
        command.env("HTTP_PROXY", origin);
        command.env("HTTPS_PROXY", origin);
        command.env("ALL_PROXY", origin);
        command.env("NO_PROXY", "localhost,127.0.0.1,::1");
    }
    let status = command.status().await;
    cancellation.cancel();
    let _ = proxy_task.await;
    if let Some(task) = egress_task {
        let _ = task.await;
    }
    if trace_sink.is_some_and(|sink| sink.failed()) {
        return fail("one or more request traces could not be persisted safely");
    }
    if trace_enabled
        && let Err(error) = append_degraded_run_trace(
            root,
            run_trace_route(agent),
            TraceIssue::DirectFilesystemUnmediated,
        )
    {
        return fail(&error.to_string());
    }
    match status {
        Ok(status) => exit_from_code(status.code()),
        Err(error) => fail(&format!("could not run agent: {}", error.kind())),
    }
}

const fn run_trace_route(agent: &str) -> TraceRoute {
    match agent.as_bytes() {
        b"claude" => TraceRoute::RunClaude,
        b"codex" => TraceRoute::RunCodex,
        b"opencode" => TraceRoute::RunOpencode,
        _ => TraceRoute::Unknown,
    }
}

fn configure_managed_agent_environment(command: &mut tokio::process::Command) {
    command.env_clear();
    for name in [
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TERM",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "NO_COLOR",
        "COLORTERM",
    ] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
}

fn agent_upstreams(agent: &str, args: &ArgMatches) -> Result<Vec<Upstream>, ExitCode> {
    let anthropic = args
        .get_one::<String>("anthropic")
        .map_or("https://api.anthropic.com", String::as_str);
    let openai = args
        .get_one::<String>("openai")
        .map_or("https://api.openai.com/v1", String::as_str);
    let openrouter = args
        .get_one::<String>("openrouter")
        .map_or("https://openrouter.ai/api/v1", String::as_str);
    let upstream = |name, url, provider| {
        Upstream::new(name, url, provider).map_err(|error| fail(&error.to_string()))
    };
    match agent {
        "claude" => Ok(vec![upstream("anthropic", anthropic, Provider::Anthropic)?]),
        "codex" => Ok(vec![upstream("openai", openai, Provider::OpenAi)?]),
        "opencode" => Ok(vec![
            upstream("anthropic", anthropic, Provider::Anthropic)?,
            upstream("openai", openai, Provider::OpenAi)?,
            upstream("openrouter", openrouter, Provider::OpenAi)?,
        ]),
        _ => Err(fail("unsupported coding agent")),
    }
}

fn configure_agent_command(
    agent: &str,
    command: &mut tokio::process::Command,
    agent_args: &[String],
    proxy_origin: &str,
) {
    match agent {
        "claude" => {
            command.args(agent_args);
            command.env("ANTHROPIC_BASE_URL", format!("{proxy_origin}/anthropic"));
        }
        "codex" => {
            command.arg("-c");
            command.arg(format!("openai_base_url=\"{proxy_origin}/openai/v1\""));
            command.args(agent_args);
        }
        "opencode" => {
            command.args(agent_args);
            command.env(
                "OPENCODE_CONFIG_CONTENT",
                opencode_proxy_config(proxy_origin),
            );
        }
        _ => {}
    }
}

fn opencode_proxy_config(proxy_origin: &str) -> String {
    let mut config = env::var("OPENCODE_CONFIG_CONTENT")
        .ok()
        .and_then(|value| serde_json::from_str::<serde_json::Value>(&value).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}));
    merge_json(
        &mut config,
        serde_json::json!({
            "provider": {
                "anthropic": {
                    "options": {
                        "baseURL": format!("{proxy_origin}/anthropic/v1")
                    }
                },
                "openai": {
                    "options": {
                        "baseURL": format!("{proxy_origin}/openai/v1")
                    }
                },
                "openrouter": {
                    "options": {
                        "baseURL": format!("{proxy_origin}/openrouter/v1")
                    }
                }
            }
        }),
    );
    config.to_string()
}

fn merge_json(target: &mut serde_json::Value, overlay: serde_json::Value) {
    match (target, overlay) {
        (serde_json::Value::Object(target), serde_json::Value::Object(overlay)) => {
            for (key, value) in overlay {
                merge_json(target.entry(key).or_insert(serde_json::Value::Null), value);
            }
        }
        (target, overlay) => *target = overlay,
    }
}

fn codex_overrides_proxy(args: &[String]) -> bool {
    args.windows(2).any(|pair| {
        matches!(pair[0].as_str(), "-c" | "--config")
            && pair[1].trim_start().starts_with("openai_base_url")
    }) || args
        .iter()
        .any(|arg| arg.starts_with("--config=openai_base_url"))
}

fn codex_uses_interactive_websocket_transport(args: &[String]) -> bool {
    !matches!(
        args.first().map(String::as_str),
        Some("exec" | "e" | "review")
    )
}

async fn run_native_agent(agent: &str, command: &str, args: &[String]) -> ExitCode {
    match tokio::process::Command::new(command)
        .args(args)
        .status()
        .await
    {
        Ok(status) => exit_from_code(status.code()),
        Err(error) => fail(&format!("could not run {agent}: {}", error.kind())),
    }
}

fn env_flag(name: &str) -> bool {
    env::var(name).is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn shell_init_command(args: &ArgMatches) -> ExitCode {
    let shell = args
        .get_one::<String>("shell")
        .map_or("zsh", String::as_str);
    if !matches!(shell, "bash" | "zsh") {
        return fail("unsupported shell");
    }
    print!(
        r#"claude() {{
  if [[ "${{BLINDFOLD_BYPASS:-0}}" == "1" ]]; then command claude "$@"; else command blindfold run --guard claude -- "$@"; fi
}}
codex() {{
  if [[ "${{BLINDFOLD_BYPASS:-0}}" == "1" ]]; then command codex "$@"; else command blindfold run --guard codex -- "$@"; fi
}}
opencode() {{
  if [[ "${{BLINDFOLD_BYPASS:-0}}" == "1" ]]; then command opencode "$@"; else command blindfold run --guard opencode -- "$@"; fi
}}
bf-off() {{
  BLINDFOLD_BYPASS=1 "$@"
}}
"#
    );
    ExitCode::SUCCESS
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

    fn sanitize_traced(&self, text: &str) -> ProxySanitizedText {
        let output = self
            .redactor
            .redact(text, RedactionOptions::new(RedactionMode::Placeholder));
        match output {
            Ok(output) => {
                let categories = output
                    .findings()
                    .iter()
                    .map(|finding| trace_category(finding.kind()))
                    .collect();
                ProxySanitizedText::new(output.into_text(), categories)
            }
            Err(_) => {
                ProxySanitizedText::new("[BLOCKED]".to_owned(), vec![TraceCategory::Sensitive])
            }
        }
    }
}

struct CliTraceSink {
    store: TraceStore,
    failed: Mutex<bool>,
}

impl CliTraceSink {
    const fn new(store: TraceStore) -> Self {
        Self {
            store,
            failed: Mutex::new(false),
        }
    }

    fn failed(&self) -> bool {
        self.failed.lock().map_or(true, |failed| *failed)
    }
}

impl ProxyTraceSink for CliTraceSink {
    fn record(&self, record: TraceRecord) {
        if self.store.append(&record).is_err()
            && let Ok(mut failed) = self.failed.lock()
        {
            *failed = true;
        }
    }
}

const fn trace_category(kind: blindfold_detectors::SecretKind) -> TraceCategory {
    match kind {
        blindfold_detectors::SecretKind::OpenAiApiKey => TraceCategory::OpenAiApiKey,
        blindfold_detectors::SecretKind::AnthropicApiKey => TraceCategory::AnthropicApiKey,
        blindfold_detectors::SecretKind::GitHubToken => TraceCategory::GitHubToken,
        blindfold_detectors::SecretKind::StripeKey => TraceCategory::StripeKey,
        blindfold_detectors::SecretKind::SlackToken => TraceCategory::SlackToken,
        blindfold_detectors::SecretKind::AwsAccessKeyId => TraceCategory::AwsAccessKeyId,
        blindfold_detectors::SecretKind::AwsSecretAccessKey => TraceCategory::AwsSecretAccessKey,
        blindfold_detectors::SecretKind::BearerToken => TraceCategory::BearerToken,
        blindfold_detectors::SecretKind::JsonWebToken => TraceCategory::Jwt,
        blindfold_detectors::SecretKind::OAuthToken => TraceCategory::OAuthToken,
        blindfold_detectors::SecretKind::PemPrivateKey => TraceCategory::PemPrivateKey,
        blindfold_detectors::SecretKind::CredentialUrl => TraceCategory::CredentialUrl,
        blindfold_detectors::SecretKind::Password => TraceCategory::Password,
        blindfold_detectors::SecretKind::ApiKey => TraceCategory::ApiKey,
        blindfold_detectors::SecretKind::Token => TraceCategory::Token,
        _ => TraceCategory::Sensitive,
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

#[cfg(test)]
mod tests {
    use tokio_util::sync::CancellationToken;

    use super::{
        BoundEgressGuard, EgressDecision, EgressNetworkPolicy, ProjectNetworkPolicy,
        authority_host, is_blocked_llm_provider,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[test]
    fn egress_guard_identifies_blocked_llm_provider_hosts() {
        assert_eq!(authority_host("api.openai.com:443"), "api.openai.com");
        assert_eq!(
            authority_host("user@api.anthropic.com:443"),
            "api.anthropic.com"
        );
        assert_eq!(authority_host("[::1]:443"), "::1");
        assert!(is_blocked_llm_provider("api.openai.com"));
        assert!(is_blocked_llm_provider("sub.openrouter.ai"));
        assert!(is_blocked_llm_provider("generativelanguage.googleapis.com"));
        assert!(!is_blocked_llm_provider("registry.npmjs.org"));
        assert!(!is_blocked_llm_provider("example.com"));
    }

    #[test]
    fn egress_policy_decides_allow_deny_provider_and_unknown_domains() {
        let policy = EgressNetworkPolicy::from_project(ProjectNetworkPolicy {
            allow: ["api.example.com".to_owned()].into_iter().collect(),
            deny: ["blocked.example.com".to_owned()].into_iter().collect(),
        });

        assert_eq!(policy.decision("registry.npmjs.org"), EgressDecision::Allow);
        assert_eq!(policy.decision("api.example.com"), EgressDecision::Allow);
        assert_eq!(
            policy.decision("sub.api.example.com"),
            EgressDecision::Allow
        );
        assert_eq!(
            policy.decision("blocked.example.com"),
            EgressDecision::BlockDenied
        );
        assert_eq!(
            policy.decision("sub.blocked.example.com"),
            EgressDecision::BlockDenied
        );
        assert_eq!(
            policy.decision("api.openai.com"),
            EgressDecision::BlockKnownProvider
        );
        assert_eq!(
            policy.decision("unknown.example"),
            EgressDecision::BlockUnknown
        );
    }

    #[tokio::test]
    async fn egress_guard_blocks_direct_llm_connect() -> Result<(), Box<dyn std::error::Error>> {
        let guard = BoundEgressGuard::bind(EgressNetworkPolicy::default(), None).await?;
        let address = guard.local_addr();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(guard.serve(cancellation.clone()));

        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n")
            .await?;
        let mut response = vec![0_u8; 256];
        let read = stream.read(&mut response).await?;
        let response = String::from_utf8_lossy(&response[..read]);
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("Blocked direct LLM provider access"));

        cancellation.cancel();
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn egress_guard_blocks_unknown_connect() -> Result<(), Box<dyn std::error::Error>> {
        let guard = BoundEgressGuard::bind(EgressNetworkPolicy::default(), None).await?;
        let address = guard.local_addr();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(guard.serve(cancellation.clone()));

        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(b"CONNECT unknown.example:443 HTTP/1.1\r\nHost: unknown.example:443\r\n\r\n")
            .await?;
        let mut response = vec![0_u8; 512];
        let read = stream.read(&mut response).await?;
        let response = String::from_utf8_lossy(&response[..read]);
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("unknown domains are blocked"));

        cancellation.cancel();
        task.await??;
        Ok(())
    }
}
