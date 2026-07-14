use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
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
use blindfold_plugin_api::{NonInteractiveMode, Protocol};
use blindfold_plugin_host::load_explicit_plugins;
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

use crate::{
    agent_adapter::{HarnessAdapter, HarnessKind},
    boundary::{self, GatewayProvider},
    config,
    container_runner::{ContainerRunError, LockedRunSpec, run_locked},
    doctor,
    host_credential::HostCredential,
};

const MASTER_KEY_ENV: &str = "BLINDFOLD_MASTER_KEY";
const MANAGED_AGENT_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const MANAGED_AGENT_OUTPUT_TRUNCATION_OVERLAP: usize = 512;
const CALL_REQUEST_LIMIT: usize = 64 * 1024;
const CALL_RESPONSE_LIMIT: usize = 1024 * 1024;
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
        Some(("mask", args)) => mask_command(&root, args, trace_enabled),
        Some(("exec", args)) => traced_command(&root, trace_enabled, TraceRoute::Exec, || {
            exec_command(args)
        }),
        Some(("call", args)) => call_command(&root, args, trace_enabled).await,
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
        Some(("plugin", args)) => plugin_command(args),
        Some(("container", args)) => container_command(&root, args).await,
        Some(("boundary", args)) => boundary_command(args).await,
        Some(("run", args)) => run_agent_command(&root, args, trace_enabled).await,
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
            Command::new("mask")
                .about("Replace detected values with encrypted-vault SafeRefs")
                .arg(Arg::new("file").value_name("FILE"))
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .value_name("FILE")
                        .help("Write masked content to a new file instead of stdout"),
                )
                .arg(
                    Arg::new("force")
                        .long("force")
                        .help("Allow --output to replace an existing file")
                        .requires("output")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("ttl")
                        .long("ttl-seconds")
                        .default_value("3600")
                        .value_parser(clap::value_parser!(u64).range(1..)),
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
            Command::new("call")
                .about("Make one brokered HTTP call with an explicit bearer secret")
                .arg(Arg::new("url").long("url").required(true))
                .arg(Arg::new("secret").long("secret").required(true))
                .arg(
                    Arg::new("method")
                        .long("method")
                        .default_value("GET")
                        .value_parser(["GET", "POST"]),
                )
                .arg(
                    Arg::new("body")
                        .long("body")
                        .help("Optional non-secret request body"),
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
            Command::new("plugin")
                .about("Inspect embedded adapters or validate explicit plugin directories")
                .subcommand(Command::new("list").about("List embedded harness adapters"))
                .subcommand(
                    Command::new("validate")
                        .about("Validate absolute plugin directories without executing them")
                        .arg(
                            Arg::new("directory")
                                .value_name("ABSOLUTE_DIR")
                                .value_parser(clap::value_parser!(PathBuf))
                                .num_args(1..)
                                .required(true),
                        ),
                )
                .subcommand_required(true),
        )
        .subcommand(
            Command::new("container")
                .about("Run a coding agent in the locked model-only container boundary")
                .subcommand(
                    Command::new("run")
                        .arg(
                            Arg::new("agent")
                                .required(true)
                                .value_parser(["claude", "codex", "opencode"]),
                        )
                        .arg(
                            Arg::new("provider")
                                .long("provider")
                                .value_parser(["anthropic", "openai", "openrouter"])
                                .help("Required only to select an OpenCode provider"),
                        )
                        .arg(
                            Arg::new("credential_file")
                                .long("credential-file")
                                .value_parser(clap::value_parser!(PathBuf))
                                .conflicts_with("credential_env")
                                .help("Use a host credential file instead of the provider's standard environment variable"),
                        )
                        .arg(
                            Arg::new("credential_env")
                                .long("credential-env")
                                .conflicts_with("credential_file")
                                .help("Read the provider credential from this host environment variable"),
                        )
                        .arg(
                            Arg::new("image")
                                .long("image")
                                .default_value("blindfold-locked:local")
                                .help("Digest-pinned release image or explicit local evaluation image"),
                        )
                        .arg(Arg::new("agent_arg").num_args(0..).trailing_var_arg(true)),
                )
                .subcommand_required(true),
        )
        .subcommand(
            Command::new("boundary")
                .about("Internal transport for the locked container boundary")
                .hide(true)
                .subcommand(
                    Command::new("gateway")
                        .arg(
                            Arg::new("socket")
                                .long("socket")
                                .value_parser(clap::value_parser!(PathBuf))
                                .required(true),
                        )
                        .arg(
                            Arg::new("provider")
                                .long("provider")
                                .value_parser(["anthropic", "openai", "openrouter"])
                                .required(true),
                        )
                        .arg(Arg::new("upstream").long("upstream").required(true))
                        .arg(
                            Arg::new("credential_file")
                                .long("credential-file")
                                .value_parser(clap::value_parser!(PathBuf))
                                .required(true),
                        ),
                )
                .subcommand(
                    Command::new("agent")
                        .arg(
                            Arg::new("socket")
                                .long("socket")
                                .value_parser(clap::value_parser!(PathBuf))
                                .required(true),
                        )
                        .arg(
                            Arg::new("agent")
                                .required(true)
                                .value_parser(["claude", "codex", "opencode"]),
                        )
                        .arg(Arg::new("agent_arg").num_args(0..).trailing_var_arg(true)),
                )
                .subcommand_required(true),
        )
        .subcommand(
            Command::new("run")
                .about("Run a supported coding agent through a declared boundary")
                .arg(
                    Arg::new("agent")
                        .required(true)
                        .value_parser(["claude", "codex", "opencode"]),
                )
                .arg(Arg::new("anthropic").long("anthropic-upstream"))
                .arg(Arg::new("openai").long("openai-upstream"))
                .arg(Arg::new("openrouter").long("openrouter-upstream"))
                .arg(Arg::new("agent_arg").num_args(0..).trailing_var_arg(true)),
        )
}

async fn container_command(root: &Path, args: &ArgMatches) -> ExitCode {
    let Some(("run", args)) = args.subcommand() else {
        return ExitCode::FAILURE;
    };
    let Some(agent) = args.get_one::<String>("agent") else {
        return fail("container agent is required");
    };
    let provider = match container_provider(agent, args.get_one::<String>("provider")) {
        Ok(provider) => provider,
        Err(error) => return fail(error),
    };
    let credential = if let Some(path) = args.get_one::<PathBuf>("credential_file") {
        HostCredential::from_file(path)
    } else {
        let environment = args
            .get_one::<String>("credential_env")
            .map_or_else(|| provider_environment(provider), String::as_str);
        HostCredential::from_environment(environment)
    };
    let credential = match credential {
        Ok(credential) => credential,
        Err(error) => return fail(&error.to_string()),
    };
    let workspace = match fs::canonicalize(root) {
        Ok(path) => path,
        Err(error) => {
            return fail(&format!(
                "could not resolve the container workspace: {}",
                error.kind()
            ));
        }
    };
    let agent_args = args
        .get_many::<String>("agent_arg")
        .map(|values| values.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let image = args
        .get_one::<String>("image")
        .cloned()
        .unwrap_or_else(|| "blindfold-locked:local".to_owned());
    let local_evaluation_image = image == "blindfold-locked:local";
    let upstream = match (agent.as_str(), provider) {
        (_, "anthropic") => "https://api.anthropic.com",
        ("codex", "openai") => "https://api.openai.com/v1",
        ("opencode", "openai") => "https://api.openai.com",
        (_, "openrouter") => "https://openrouter.ai/api",
        _ => return fail("container provider is invalid"),
    };
    let spec = match LockedRunSpec::new(
        agent,
        agent_args,
        workspace,
        credential.path().to_path_buf(),
        upstream.to_owned(),
        provider.to_owned(),
        image,
    ) {
        Ok(spec) => spec,
        Err(error) => return fail(&error.to_string()),
    };
    eprintln!("Blindfold locked container run:");
    eprintln!("- agent network: none (loopback only)");
    eprintln!("- allowed egress: supported model traffic through the Blindfold gateway");
    eprintln!("- provider credential: gateway-only secret file");
    eprintln!("- generic web, package, Git, SSH, and CONNECT egress: disabled");
    if local_evaluation_image {
        eprintln!(
            "- image integrity: local evaluation image pinned to its current ID for this session"
        );
    }
    match run_locked(spec).await {
        Ok(status) => exit_from_code(status.code()),
        Err(ContainerRunError::Interrupted) => ExitCode::from(130),
        Err(error) => fail(&error.to_string()),
    }
}

fn provider_environment(provider: &str) -> &'static str {
    match provider {
        "anthropic" => "ANTHROPIC_API_KEY",
        "openrouter" => "OPENROUTER_API_KEY",
        _ => "OPENAI_API_KEY",
    }
}

fn container_provider<'a>(
    agent: &str,
    selected: Option<&'a String>,
) -> Result<&'a str, &'static str> {
    match (agent, selected.map(String::as_str)) {
        ("claude", None | Some("anthropic")) => Ok("anthropic"),
        ("codex", None | Some("openai")) => Ok("openai"),
        ("opencode", Some(provider)) => Ok(provider),
        ("opencode", None) => Err("OpenCode locked runs require --provider"),
        ("claude", Some(_)) => Err("Claude locked runs require the Anthropic provider"),
        ("codex", Some(_)) => Err("Codex locked runs require the OpenAI provider"),
        _ => Err("container agent is invalid"),
    }
}

async fn boundary_command(args: &ArgMatches) -> ExitCode {
    match args.subcommand() {
        Some(("gateway", args)) => {
            let Some(socket) = args.get_one::<PathBuf>("socket") else {
                return fail("gateway socket is required");
            };
            let Some(provider) = args
                .get_one::<String>("provider")
                .and_then(|value| GatewayProvider::parse(value))
            else {
                return fail("gateway provider is invalid");
            };
            let Some(upstream) = args.get_one::<String>("upstream") else {
                return fail("gateway upstream is required");
            };
            let Some(credential_file) = args.get_one::<PathBuf>("credential_file") else {
                return fail("gateway credential file is required");
            };
            match boundary::run_gateway(socket, provider, upstream, credential_file).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&error),
            }
        }
        Some(("agent", args)) => {
            let Some(socket) = args.get_one::<PathBuf>("socket") else {
                return fail("gateway socket is required");
            };
            let Some(agent) = args.get_one::<String>("agent") else {
                return fail("agent is required");
            };
            let agent_args = args
                .get_many::<String>("agent_arg")
                .map(|values| values.cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            match boundary::run_agent(socket, agent, &agent_args).await {
                Ok(code) => code,
                Err(error) => fail(&error),
            }
        }
        _ => ExitCode::FAILURE,
    }
}

fn plugin_command(args: &ArgMatches) -> ExitCode {
    match args.subcommand() {
        Some(("list", _)) => plugin_list_command(),
        Some(("validate", args)) => plugin_validate_command(args),
        _ => ExitCode::FAILURE,
    }
}

fn plugin_list_command() -> ExitCode {
    let adapters = ["claude", "codex", "opencode"]
        .into_iter()
        .map(HarnessAdapter::load)
        .collect::<Result<Vec<_>, _>>();
    let adapters = match adapters {
        Ok(adapters) => adapters,
        Err(error) => return fail(&error.to_string()),
    };
    for adapter in adapters {
        print_plugin_manifest(adapter.manifest());
    }
    ExitCode::SUCCESS
}

fn plugin_validate_command(args: &ArgMatches) -> ExitCode {
    let directories = args.get_many::<PathBuf>("directory").into_iter().flatten();
    let mut plugins = match load_explicit_plugins(directories) {
        Ok(plugins) => plugins,
        Err(error) => return fail(&format!("plugin validation failed: {error}")),
    };
    plugins.sort_by(|left, right| left.manifest().id().cmp(right.manifest().id()));
    for plugin in &plugins {
        print_plugin_manifest(plugin.manifest());
    }
    println!(
        "Validated {} explicit plugin director{}; no plugin was installed, activated, or executed.",
        plugins.len(),
        if plugins.len() == 1 { "y" } else { "ies" }
    );
    ExitCode::SUCCESS
}

fn print_plugin_manifest(manifest: &blindfold_plugin_api::PluginManifest) {
    let modes = manifest
        .harness()
        .noninteractive_modes()
        .iter()
        .map(|mode| match mode {
            NonInteractiveMode::Print => "print",
            NonInteractiveMode::Exec => "exec",
            NonInteractiveMode::Review => "review",
            NonInteractiveMode::Run => "run",
        })
        .collect::<Vec<_>>()
        .join(",");
    let protocol = match manifest.protocol() {
        Protocol::BuiltinV1 => "builtin-v1",
        Protocol::StdioJsonV1 => "stdio-json-v1",
    };
    println!(
        "{} plugin={} protocol={} command={} harness=\"{}\" modes={}",
        manifest.id(),
        manifest.version(),
        protocol,
        manifest.harness().command(),
        manifest.harness().version_requirement(),
        modes
    );
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
    let input = match read_text_input(args) {
        Ok(input) => input,
        Err(code) => return code,
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
                && let Err(error) = append_transform_trace(
                    root,
                    TraceRoute::Redact,
                    &input,
                    output.text(),
                    output.findings(),
                )
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

fn read_text_input(args: &ArgMatches) -> Result<String, ExitCode> {
    if let Some(path) = args.get_one::<String>("file") {
        fs::read_to_string(path)
            .map_err(|error| fail(&format!("could not read input: {}", error.kind())))
    } else {
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .map_err(|error| fail(&format!("could not read standard input: {}", error.kind())))?;
        Ok(input)
    }
}

fn mask_command(root: &Path, args: &ArgMatches, trace_enabled: bool) -> ExitCode {
    if let Some(path) = args.get_one::<String>("output")
        && !args.get_flag("force")
    {
        match Path::new(path).symlink_metadata() {
            Ok(_) => {
                return fail("output file already exists; choose another path or pass --force");
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return fail(&format!("could not inspect output file: {}", error.kind()));
            }
        }
    }
    let input = match read_text_input(args) {
        Ok(input) => input,
        Err(code) => return code,
    };
    let detector_set = match detectors() {
        Ok(detectors) => detectors,
        Err(code) => return code,
    };
    let findings = detector_set.detect(&input);
    if let Err(code) = validate_finding_spans(&input, &findings) {
        return code;
    }
    let vault = match open_vault(root) {
        Ok(vault) => vault,
        Err(code) => return code,
    };
    let scope = match project_scope(root) {
        Ok(scope) => scope,
        Err(error) => return fail(&error.to_string()),
    };
    let ttl = Duration::from_secs(args.get_one::<u64>("ttl").copied().unwrap_or(3600));
    let (output, stored_refs) = match mask_findings(&input, &findings, &vault, &scope, ttl) {
        Ok(output) => output,
        Err(code) => return code,
    };
    if let Err(error) = append_store_audit(root, &stored_refs) {
        return fail(&error.to_string());
    }
    if trace_enabled
        && let Err(error) =
            append_transform_trace(root, TraceRoute::Mask, &input, &output, &findings)
    {
        return fail(&error.to_string());
    }
    if let Some(path) = args.get_one::<String>("output") {
        write_transformed_output(Path::new(path), &output, args.get_flag("force"), "masked")
    } else {
        let mut stdout = io::stdout().lock();
        match stdout
            .write_all(output.as_bytes())
            .and_then(|()| stdout.flush())
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(&format!("could not write masked output: {}", error.kind())),
        }
    }
}

fn validate_finding_spans(
    input: &str,
    findings: &[blindfold_detectors::Finding],
) -> Result<(), ExitCode> {
    let mut cursor = 0;
    for finding in findings {
        let span = finding.span();
        if span.start() < cursor
            || input.get(cursor..span.start()).is_none()
            || input.get(span.as_range()).is_none()
        {
            return Err(fail("detector returned an invalid input span"));
        }
        cursor = span.end();
    }
    if input.get(cursor..).is_none() {
        return Err(fail("detector returned an invalid input span"));
    }
    Ok(())
}

fn mask_findings(
    input: &str,
    findings: &[blindfold_detectors::Finding],
    vault: &Vault,
    scope: &Scope,
    ttl: Duration,
) -> Result<(String, Vec<SafeRef>), ExitCode> {
    let mut references = Vec::<(SafeRefKind, &str, SafeRef)>::new();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    for finding in findings {
        let span = finding.span();
        let Some(prefix) = input.get(cursor..span.start()) else {
            return Err(fail("detector returned an invalid input span"));
        };
        let Some(raw) = input.get(span.as_range()) else {
            return Err(fail("detector returned an invalid input span"));
        };
        let kind = mask_safe_ref_kind(finding.kind());
        let safe_ref = if let Some((_, _, safe_ref)) = references
            .iter()
            .find(|(stored_kind, stored_raw, _)| *stored_kind == kind && *stored_raw == raw)
        {
            safe_ref.clone()
        } else {
            let safe_ref = vault
                .store(kind, scope, &SecretValue::new(raw), ttl)
                .map_err(|error| fail(&error.to_string()))?;
            references.push((kind, raw, safe_ref.clone()));
            safe_ref
        };
        output.push_str(prefix);
        output.push_str(safe_ref.as_str());
        cursor = span.end();
    }
    let Some(suffix) = input.get(cursor..) else {
        return Err(fail("detector returned an invalid input span"));
    };
    output.push_str(suffix);
    Ok((
        output,
        references
            .into_iter()
            .map(|(_, _, safe_ref)| safe_ref)
            .collect(),
    ))
}

const fn mask_safe_ref_kind(kind: blindfold_detectors::SecretKind) -> SafeRefKind {
    match kind {
        blindfold_detectors::SecretKind::EmailAddress
        | blindfold_detectors::SecretKind::PhoneNumber => {
            SafeRefKind::PersonallyIdentifiableInformation
        }
        blindfold_detectors::SecretKind::PemPrivateKey => SafeRefKind::PrivateKey,
        _ => SafeRefKind::Secret,
    }
}

fn append_store_audit(root: &Path, safe_refs: &[SafeRef]) -> blindfold_vault::VaultResult<()> {
    if safe_refs.is_empty() {
        return Ok(());
    }
    let rotation = RotationPolicy::new(1024 * 1024, 3)?;
    let log = AuditLog::open(root.join(".blindfold/audit.jsonl"), rotation)?;
    for safe_ref in safe_refs {
        log.append(&AuditEvent::now(
            AuditAction::Store,
            AuditOutcome::Succeeded,
            Some(safe_ref.clone()),
        ))?;
    }
    Ok(())
}

fn append_transform_trace(
    root: &Path,
    route: TraceRoute,
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
        route,
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
    write_transformed_output(path, contents, force, "redacted")
}

fn write_transformed_output(
    path: &Path,
    contents: &str,
    force: bool,
    content_kind: &'static str,
) -> ExitCode {
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
            "Blindfold atomically replaced {} with {content_kind} content.",
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
        "Blindfold wrote {content_kind} content to {}.",
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

async fn call_command(root: &Path, args: &ArgMatches, trace_enabled: bool) -> ExitCode {
    let trace_store = match optional_call_trace_store(root, trace_enabled) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let (env_name, secret) = match call_secret(args) {
        Ok(secret) => secret,
        Err(code) => return code,
    };
    let request_body_len = match validate_call_body(args, &secret, trace_store.as_ref()) {
        Ok(length) => length,
        Err(code) => return code,
    };
    let url = match allowed_call_url(root, args, trace_store.as_ref(), request_body_len) {
        Ok(url) => url,
        Err(code) => return code,
    };
    let method = match args.get_one::<String>("method").map(String::as_str) {
        Some("POST") => reqwest::Method::POST,
        _ => reqwest::Method::GET,
    };
    let Ok(auth_value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {secret}")) else {
        return fail("secret cannot be represented as an HTTP bearer token");
    };
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
    else {
        return fail("could not initialize HTTP client");
    };
    let mut request = client
        .request(method, url)
        .header(reqwest::header::AUTHORIZATION, auth_value);
    if let Some(body) = args.get_one::<String>("body") {
        request = request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.clone());
    }
    let Ok(response) = request.send().await else {
        return fail("brokered HTTP call failed");
    };
    let status = response.status();
    let body = match read_bounded_response(response).await {
        Ok(body) => body,
        Err(message) => return fail(message),
    };
    let sanitized = match sanitize_call_response(&body, &secret, &env_name) {
        Ok(sanitized) => sanitized,
        Err(code) => return code,
    };
    let trace_outcome = if status.is_success() {
        TraceOutcome::Succeeded
    } else {
        TraceOutcome::Failed
    };
    if let Some(store) = &trace_store
        && let Err(error) = append_trace_to_store(
            store,
            TraceRoute::Call,
            TraceCoverage::Protected,
            trace_outcome,
            (
                u64::try_from(request_body_len).unwrap_or(u64::MAX),
                u64::try_from(request_body_len).unwrap_or(u64::MAX),
            ),
            (
                u64::try_from(body.len()).unwrap_or(u64::MAX),
                u64::try_from(sanitized.text.len()).unwrap_or(u64::MAX),
            ),
            sanitized.replacements,
            None,
        )
    {
        return fail(&error.to_string());
    }
    println!("status: {}", status.as_u16());
    print!("{}", sanitized.text);
    if !sanitized.text.ends_with('\n') {
        println!();
    }
    eprintln!(
        "Blindfold: injected_secret={} response_bytes={} raw_secrets_exposed=0",
        env_name.as_str(),
        body.len()
    );
    if status.is_success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn optional_call_trace_store(root: &Path, enabled: bool) -> Result<Option<TraceStore>, ExitCode> {
    if !enabled {
        return Ok(None);
    }
    open_trace_store(root)
        .map(Some)
        .map_err(|error| fail(&error.to_string()))
}

fn call_secret(args: &ArgMatches) -> Result<(EnvironmentName, String), ExitCode> {
    let Some(secret_name) = args.get_one::<String>("secret") else {
        return Err(fail("a secret name is required"));
    };
    let env_name =
        EnvironmentName::new(secret_name.clone()).map_err(|error| fail(&error.to_string()))?;
    let secret = env::var(secret_name)
        .map_err(|_| fail("a requested secret is unavailable in the parent environment"))?;
    if secret.is_empty() {
        return Err(fail("a requested secret is empty"));
    }
    Ok((env_name, secret))
}

fn validate_call_body(
    args: &ArgMatches,
    secret: &str,
    trace_store: Option<&TraceStore>,
) -> Result<usize, ExitCode> {
    let Some(body) = args.get_one::<String>("body") else {
        return Ok(0);
    };
    if body.len() > CALL_REQUEST_LIMIT {
        return Err(reject_call(
            trace_store,
            body.len(),
            TraceIssue::RequestTooLarge,
            "brokered HTTP request body is too large",
        ));
    }
    let body_has_findings = detectors().map(|detectors| !detectors.detect(body).is_empty())?;
    if body.contains(secret) || body_has_findings {
        return Err(reject_call(
            trace_store,
            body.len(),
            TraceIssue::InvalidPayload,
            "brokered HTTP request body contains sensitive content",
        ));
    }
    Ok(body.len())
}

fn allowed_call_url(
    root: &Path,
    args: &ArgMatches,
    trace_store: Option<&TraceStore>,
    request_body_len: usize,
) -> Result<reqwest::Url, ExitCode> {
    let Some(url_text) = args.get_one::<String>("url") else {
        return Err(fail("a URL is required"));
    };
    let url = reqwest::Url::parse(url_text).map_err(|_| fail("invalid URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(fail("unsupported URL scheme"));
    }
    let Some(host) = url.host_str() else {
        return Err(fail("URL host is required"));
    };
    let policy = EgressNetworkPolicy::load(root).map_err(fail)?;
    let message = match policy.decision(host) {
        EgressDecision::Allow => return Ok(url),
        EgressDecision::BlockKnownProvider => {
            "brokered HTTP call blocked: LLM provider domains must use the LLM proxy"
        }
        EgressDecision::BlockDenied => {
            "brokered HTTP call blocked: domain is denied for this project"
        }
        EgressDecision::BlockUnknown => {
            "brokered HTTP call blocked: unknown domain; use `blindfold allow domain <host>`"
        }
    };
    Err(reject_call(
        trace_store,
        request_body_len,
        TraceIssue::RouteNotAllowed,
        message,
    ))
}

struct SanitizedCallResponse {
    text: String,
    replacements: Vec<TraceReplacement>,
}

fn sanitize_call_response(
    body: &[u8],
    secret: &str,
    env_name: &EnvironmentName,
) -> Result<SanitizedCallResponse, ExitCode> {
    let sanitizer = DetectorSanitizer::new()?;
    let output = String::from_utf8_lossy(body);
    let exact_occurrences = output.matches(secret).count();
    let exact_redacted = output.replace(secret, &format!("[REDACTED:{}]", env_name.as_str()));
    let Ok(redacted) = sanitizer.redactor.redact(
        &exact_redacted,
        RedactionOptions::new(RedactionMode::Placeholder),
    ) else {
        return Err(fail("could not sanitize brokered HTTP response"));
    };
    let mut grouped = BTreeMap::<TraceCategory, u32>::new();
    if let Ok(count) = u32::try_from(exact_occurrences)
        && count > 0
    {
        grouped.insert(TraceCategory::BearerToken, count);
    }
    for finding in redacted.findings() {
        *grouped.entry(trace_category(finding.kind())).or_default() += 1;
    }
    let replacements = grouped
        .into_iter()
        .enumerate()
        .map(|(index, (category, count))| {
            TraceReplacement::new(format!("S{}", index + 1), category, "/response", count)
        })
        .collect::<blindfold_trace::Result<Vec<_>>>()
        .map_err(|error| fail(&error.to_string()))?;
    Ok(SanitizedCallResponse {
        text: redacted.into_text(),
        replacements,
    })
}

async fn read_bounded_response(mut response: reqwest::Response) -> Result<Vec<u8>, &'static str> {
    if response
        .content_length()
        .is_some_and(|length| length > CALL_RESPONSE_LIMIT as u64)
    {
        return Err("brokered HTTP response is too large");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "could not read brokered HTTP response")?
    {
        if body.len().saturating_add(chunk.len()) > CALL_RESPONSE_LIMIT {
            return Err("brokered HTTP response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn reject_call(
    store: Option<&TraceStore>,
    request_body_len: usize,
    issue: TraceIssue,
    message: &str,
) -> ExitCode {
    match append_call_rejection_trace(store, request_body_len, issue) {
        Ok(()) => fail(message),
        Err(error) => fail(&error.to_string()),
    }
}

fn append_call_rejection_trace(
    store: Option<&TraceStore>,
    request_body_len: usize,
    issue: TraceIssue,
) -> blindfold_trace::Result<()> {
    let Some(store) = store else {
        return Ok(());
    };
    append_trace_to_store(
        store,
        TraceRoute::Call,
        TraceCoverage::Unprotected,
        TraceOutcome::Rejected,
        (u64::try_from(request_body_len).unwrap_or(u64::MAX), 0),
        (0, 0),
        Vec::new(),
        Some(issue),
    )
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
    prepare_project_storage_dir(parent)?;
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

fn prepare_project_storage_dir(path: &Path) -> Result<(), String> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err("project policy directory is unavailable".to_owned());
    }
    fs::create_dir_all(path)
        .map_err(|error| format!("could not create policy directory: {}", error.kind()))?;
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err("project policy directory is unavailable".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("could not secure policy directory: {}", error.kind()))?;
    }
    Ok(())
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
    append_trace_to_store(
        &store,
        route,
        coverage,
        outcome,
        bytes,
        (0, 0),
        replacements,
        issue,
    )
}

#[allow(clippy::too_many_arguments)]
fn append_trace_to_store(
    store: &TraceStore,
    route: TraceRoute,
    coverage: TraceCoverage,
    outcome: TraceOutcome,
    request_bytes: (u64, u64),
    response_bytes: (u64, u64),
    replacements: Vec<TraceReplacement>,
    issue: Option<TraceIssue>,
) -> blindfold_trace::Result<()> {
    let record = TraceRecord::now(
        next_trace_request_id(),
        route,
        coverage,
        outcome,
        request_bytes,
        response_bytes,
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
        TraceRoute::Mask => "mask",
        TraceRoute::Scan => "scan",
        TraceRoute::Exec => "exec",
        TraceRoute::Call => "call",
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
    let locked_boundary = env::var_os("BLINDFOLD_LOCKED_BOUNDARY").is_some();
    if locked_boundary && let Err(error) = boundary::verify_network_none() {
        return fail(&error);
    }
    let agent = args
        .get_one::<String>("agent")
        .map_or("claude", String::as_str);
    let adapter = match HarnessAdapter::load(agent) {
        Ok(adapter) => adapter,
        Err(error) => return fail(&error.to_string()),
    };
    let kind = adapter.kind();
    let agent_args = args
        .get_many::<String>("agent_arg")
        .map(|values| values.cloned().collect::<Vec<_>>())
        .unwrap_or_default();

    if let Some(message) = unsupported_agent_argument(kind, &agent_args) {
        return fail(message);
    }
    if kind == HarnessKind::Codex && codex_overrides_proxy(&agent_args) {
        return fail("Codex arguments override the managed OpenAI base URL; remove that override");
    }
    if kind == HarnessKind::Claude
        && (!adapter.supports_mode(NonInteractiveMode::Print)
            || claude_uses_interactive_mode(&agent_args))
    {
        return fail(
            "Claude interactive mode is not supported; use `blindfold run claude -- --print ...` or `blindfold run claude -- -p ...`",
        );
    }
    if kind == HarnessKind::Codex && codex_uses_interactive_mode(&adapter, &agent_args) {
        return fail(
            "Codex interactive mode is not supported; use `blindfold run codex -- exec ...` or `blindfold run codex -- review ...`",
        );
    }
    if kind == HarnessKind::OpenCode
        && (!adapter.supports_mode(NonInteractiveMode::Run)
            || opencode_uses_unproven_interactive_mode(&agent_args))
    {
        return fail(
            "OpenCode interactive/TUI mode is not supported; use `blindfold run opencode -- run ...`",
        );
    }
    let agent_command = match adapter.resolve_compatible_executable() {
        Ok(command) => command,
        Err(error) => return fail(&error.to_string()),
    };

    if locked_boundary {
        eprintln!("Blindfold locked container boundary active:");
    } else {
        eprintln!("Blindfold managed model boundary active (not whole-agent containment):");
    }
    eprintln!("- harness adapter: {} (version compatible)", adapter.id());
    eprintln!("- managed provider request/response proxy: available");
    eprintln!("- child stdout/stderr sanitization: enabled");
    if locked_boundary {
        eprintln!("- direct IP network egress: disabled by the agent container");
        eprintln!("- cross-container path: one Blindfold Unix socket");
        eprintln!("- generic web, package, Git, and CONNECT egress: unavailable");
    } else {
        eprintln!("- direct filesystem/network bypass prevention: unavailable");
        eprintln!("- proxy-aware provider egress blocking: enabled");
        eprintln!("- proxy-aware unknown egress domains: blocked unless allowed by project policy");
    }
    eprintln!(
        "- agent file reads: unmediated; if the agent opens .env directly, it can see raw contents"
    );
    eprintln!("- parent secret environment isolation: available");
    if locked_boundary {
        eprintln!("- provider credential: isolated in and injected by the gateway container");
    } else {
        eprintln!("- provider credential broker: unavailable; use the agent credential store");
    }
    eprintln!(
        "- payload-free request tracing: {}",
        if trace_enabled { "enabled" } else { "disabled" }
    );
    if trace_enabled {
        eprintln!(
            "- trace scope: command/session metadata and managed provider requests only; direct file reads are not observable"
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
    let upstreams = match agent_upstreams(kind, args) {
        Ok(upstreams) => upstreams,
        Err(code) => return code,
    };
    let proxy = match Proxy::new(
        ProxyConfig {
            bind_addr: listen,
            upstreams,
            ..ProxyConfig::default()
        },
        Arc::clone(&sanitizer) as Arc<dyn ProxySanitizer>,
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
    let policy = match EgressNetworkPolicy::load(root) {
        Ok(policy) => policy,
        Err(message) => {
            cancellation.cancel();
            let _ = proxy_task.await;
            return fail(message);
        }
    };
    let egress = match BoundEgressGuard::bind(policy, trace_sink.clone()).await {
        Ok(guard) => guard,
        Err(error) => {
            cancellation.cancel();
            let _ = proxy_task.await;
            return fail(&format!("could not start egress guard: {}", error.kind()));
        }
    };
    let egress_origin = format!("http://{}", egress.local_addr());
    eprintln!("- egress guard proxy: {egress_origin}");
    let egress_task = {
        let cancellation = cancellation.clone();
        tokio::spawn(egress.serve(cancellation))
    };

    let mut command = tokio::process::Command::new(agent_command);
    configure_managed_agent_environment(&mut command, locked_boundary);
    configure_agent_command(kind, &mut command, &agent_args, &proxy_origin);
    command.env("HTTP_PROXY", &egress_origin);
    command.env("HTTPS_PROXY", &egress_origin);
    command.env("ALL_PROXY", &egress_origin);
    command.env("NO_PROXY", "localhost,127.0.0.1,::1");
    let status = run_managed_agent_with_sanitized_output(&mut command, &sanitizer).await;
    cancellation.cancel();
    let _ = proxy_task.await;
    let _ = egress_task.await;
    if trace_sink.is_some_and(|sink| sink.failed()) {
        return fail("one or more request traces could not be persisted safely");
    }
    if trace_enabled
        && let Err(error) = append_degraded_run_trace(
            root,
            run_trace_route(kind),
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

async fn run_managed_agent_with_sanitized_output(
    command: &mut tokio::process::Command,
    sanitizer: &DetectorSanitizer,
) -> io::Result<std::process::ExitStatus> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("child stdout was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("child stderr was not captured"))?;
    let stdout_task = tokio::spawn(read_bounded_agent_output(stdout));
    let stderr_task = tokio::spawn(read_bounded_agent_output(stderr));
    let status = child.wait().await?;
    let stdout = join_agent_output(stdout_task).await?;
    let stderr = join_agent_output(stderr_task).await?;
    write_sanitized_agent_output(io::stdout().lock(), stdout, sanitizer)?;
    write_sanitized_agent_output(io::stderr().lock(), stderr, sanitizer)?;
    Ok(status)
}

struct AgentOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

async fn read_bounded_agent_output<R>(reader: R) -> io::Result<AgentOutput>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let limit = MANAGED_AGENT_OUTPUT_LIMIT.saturating_add(1);
    reader.take(limit as u64).read_to_end(&mut buffer).await?;
    let truncated = buffer.len() > MANAGED_AGENT_OUTPUT_LIMIT;
    if truncated {
        buffer.truncate(MANAGED_AGENT_OUTPUT_LIMIT);
    }
    Ok(AgentOutput {
        bytes: buffer,
        truncated,
    })
}

async fn join_agent_output(
    task: tokio::task::JoinHandle<io::Result<AgentOutput>>,
) -> io::Result<AgentOutput> {
    task.await
        .map_err(|_| io::Error::other("child output reader failed"))?
}

fn write_sanitized_agent_output<W: Write>(
    mut writer: W,
    output: AgentOutput,
    sanitizer: &DetectorSanitizer,
) -> io::Result<()> {
    let mut bytes = output.bytes;
    if output.truncated {
        let printable = bytes
            .len()
            .saturating_sub(MANAGED_AGENT_OUTPUT_TRUNCATION_OVERLAP);
        bytes.truncate(printable);
    }
    let text = String::from_utf8_lossy(&bytes);
    writer.write_all(sanitizer.sanitize_text(&text).as_bytes())?;
    if output.truncated {
        writer.write_all(
            b"\n[BLINDFOLD: child output exceeded capture limit; tail omitted before redaction]\n",
        )?;
    }
    Ok(())
}

const fn run_trace_route(kind: HarnessKind) -> TraceRoute {
    match kind {
        HarnessKind::Claude => TraceRoute::RunClaude,
        HarnessKind::Codex => TraceRoute::RunCodex,
        HarnessKind::OpenCode => TraceRoute::RunOpencode,
    }
}

fn configure_managed_agent_environment(
    command: &mut tokio::process::Command,
    locked_boundary: bool,
) {
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
    if locked_boundary {
        command.env("ANTHROPIC_API_KEY", "blindfold-managed-placeholder");
        command.env("OPENAI_API_KEY", "sk-blindfold-managed-placeholder");
        command.env(
            "OPENROUTER_API_KEY",
            "sk-or-v1-blindfold-managed-placeholder",
        );
    }
}

fn agent_upstreams(kind: HarnessKind, args: &ArgMatches) -> Result<Vec<Upstream>, ExitCode> {
    let anthropic = args
        .get_one::<String>("anthropic")
        .map_or("https://api.anthropic.com", String::as_str);
    let default_openai = if kind == HarnessKind::Codex {
        "https://chatgpt.com/backend-api/codex"
    } else {
        "https://api.openai.com"
    };
    let openai = args
        .get_one::<String>("openai")
        .map_or(default_openai, String::as_str);
    let openrouter = args
        .get_one::<String>("openrouter")
        .map_or("https://openrouter.ai/api", String::as_str);
    let upstream = |name, url, provider| {
        Upstream::new(name, url, provider).map_err(|error| fail(&error.to_string()))
    };
    match kind {
        HarnessKind::Claude => Ok(vec![upstream("anthropic", anthropic, Provider::Anthropic)?]),
        HarnessKind::Codex => Ok(vec![upstream("openai", openai, Provider::OpenAi)?]),
        HarnessKind::OpenCode => Ok(vec![
            upstream("anthropic", anthropic, Provider::Anthropic)?,
            upstream("openai", openai, Provider::OpenAi)?,
            upstream("openrouter", openrouter, Provider::OpenAi)?,
        ]),
    }
}

fn configure_agent_command(
    kind: HarnessKind,
    command: &mut tokio::process::Command,
    agent_args: &[String],
    proxy_origin: &str,
) {
    match kind {
        HarnessKind::Claude => {
            command.args(agent_args);
            command.env("ANTHROPIC_BASE_URL", format!("{proxy_origin}/anthropic"));
        }
        HarnessKind::Codex => {
            command.arg("-c");
            command.arg(format!("openai_base_url=\"{proxy_origin}/openai\""));
            command.args(agent_args);
        }
        HarnessKind::OpenCode => {
            command.args(agent_args);
            command.env(
                "OPENCODE_CONFIG_CONTENT",
                opencode_proxy_config(proxy_origin),
            );
        }
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

fn codex_uses_interactive_mode(adapter: &HarnessAdapter, args: &[String]) -> bool {
    match args.first().map(String::as_str) {
        Some("exec") => !adapter.supports_mode(NonInteractiveMode::Exec),
        Some("review") => !adapter.supports_mode(NonInteractiveMode::Review),
        _ => true,
    }
}

fn claude_uses_interactive_mode(args: &[String]) -> bool {
    !args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-p" | "--print"))
}

fn opencode_uses_unproven_interactive_mode(args: &[String]) -> bool {
    !matches!(args.first().map(String::as_str), Some("run"))
}

fn unsupported_agent_argument(kind: HarnessKind, args: &[String]) -> Option<&'static str> {
    let has = |flag: &str| args.iter().any(|arg| arg == flag);
    let starts = |prefix: &str| args.iter().any(|arg| arg.starts_with(prefix));
    let has_pair = |flag: &str, value: &str| {
        args.windows(2)
            .any(|pair| pair[0] == flag && pair[1] == value)
    };
    match kind {
        HarnessKind::Claude
            if has("--dangerously-skip-permissions")
                || has("--allow-dangerously-skip-permissions")
                || has("--remote-control")
                || starts("--remote-control=")
                || has("--tmux")
                || starts("--tmux=")
                || has("--worktree")
                || starts("--worktree=")
                || has("--plugin-url")
                || starts("--plugin-url=")
                || has("--continue")
                || has("-c")
                || has("--resume")
                || has("-r")
                || has("--from-pr")
                || has_pair("--permission-mode", "bypassPermissions")
                || starts("--permission-mode=bypassPermissions") =>
        {
            Some(
                "Claude arguments request an unsupported or dangerous mode; use explicit `--print` without resume, remote, worktree, plugin, or permission-bypass options",
            )
        }
        HarnessKind::Codex
            if has("--dangerously-bypass-approvals-and-sandbox")
                || has("--dangerously-bypass-hook-trust")
                || has("--search") =>
        {
            Some(
                "Codex arguments request an unsupported or dangerous mode; remove dangerous or search flags",
            )
        }
        HarnessKind::OpenCode
            if has("--interactive")
                || has("--dangerously-skip-permissions")
                || matches!(
                    args.first().map(String::as_str),
                    Some("serve" | "web" | "attach" | "acp" | "mcp" | "github" | "pr" | "plugin")
                ) =>
        {
            Some(
                "OpenCode arguments request an unsupported or dangerous mode; use `opencode run ...` without interactive, server, or plugin options",
            )
        }
        _ => None,
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
        blindfold_detectors::SecretKind::EmailAddress => TraceCategory::EmailAddress,
        blindfold_detectors::SecretKind::PhoneNumber => TraceCategory::PhoneNumber,
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
