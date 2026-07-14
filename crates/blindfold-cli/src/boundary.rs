//! Cross-container transport for the locked agent boundary.

use std::{
    env, fs,
    fs::File,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{ExitCode, Stdio},
    sync::Arc,
    time::Duration,
};

use blindfold_detectors::{DetectorSet, RedactionMode, RedactionOptions, Redactor};
use blindfold_proxy::{
    Config as ProxyConfig, Provider, Proxy, Sanitizer as ProxySanitizer, Upstream,
};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
};
use tokio_util::sync::CancellationToken;

const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;
const GATEWAY_CONNECT_ATTEMPTS: usize = 50;
const GATEWAY_CONNECT_DELAY: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GatewayProvider {
    Anthropic,
    OpenAi,
    OpenRouter,
}

impl GatewayProvider {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "anthropic" => Some(Self::Anthropic),
            "openai" => Some(Self::OpenAi),
            "openrouter" => Some(Self::OpenRouter),
            _ => None,
        }
    }

    const fn route(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
            Self::OpenRouter => "openrouter",
        }
    }

    const fn wire_provider(self) -> Provider {
        match self {
            Self::Anthropic => Provider::Anthropic,
            Self::OpenAi | Self::OpenRouter => Provider::OpenAi,
        }
    }
}

pub(crate) async fn run_gateway(
    socket_path: &Path,
    provider: GatewayProvider,
    upstream_url: &str,
    credential_file: &Path,
) -> Result<(), String> {
    validate_socket_path(socket_path)?;
    let credential = read_credential(credential_file)?;
    let upstream = Upstream::new(provider.route(), upstream_url, provider.wire_provider())
        .and_then(|upstream| upstream.with_gateway_credential(credential))
        .map(Upstream::with_trusted_proxy_hop)
        .map_err(|error| error.to_string())?;
    let sanitizer = Arc::new(BoundarySanitizer::new()?);
    let proxy = Proxy::new(
        ProxyConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            upstreams: vec![upstream],
            ..ProxyConfig::default()
        },
        sanitizer as Arc<dyn ProxySanitizer>,
    )
    .map_err(|error| error.to_string())?;
    let bound = proxy.bind().await.map_err(|error| error.to_string())?;
    let proxy_addr = bound.local_addr();
    let listener = bind_unix_listener(socket_path)?;
    let cancellation = CancellationToken::new();
    let proxy_task = tokio::spawn(bound.serve(cancellation.clone()));
    let relay_task = tokio::spawn(serve_gateway_relay(
        listener,
        proxy_addr,
        cancellation.clone(),
    ));

    eprintln!(
        "Blindfold locked gateway ready: provider={} transport=unix-socket",
        provider.route()
    );
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|error| format!("could not listen for shutdown: {}", error.kind()))?;
        }
        result = proxy_task => {
            result
                .map_err(|_| "gateway proxy task failed".to_owned())?
                .map_err(|error| format!("gateway proxy stopped: {}", error.kind()))?;
        }
        result = relay_task => {
            result
                .map_err(|_| "gateway relay task failed".to_owned())?
                .map_err(|error| format!("gateway relay stopped: {}", error.kind()))?;
        }
    }
    cancellation.cancel();
    let _ = fs::remove_file(socket_path);
    Ok(())
}

pub(crate) async fn run_agent(
    socket_path: &Path,
    agent: &str,
    agent_args: &[String],
) -> Result<ExitCode, String> {
    verify_network_none()?;
    validate_socket_path(socket_path)?;
    wait_for_gateway(socket_path).await?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("could not bind the agent relay: {}", error.kind()))?;
    let origin = format!(
        "http://{}",
        listener
            .local_addr()
            .map_err(|error| format!("could not inspect the agent relay: {}", error.kind()))?
    );
    let cancellation = CancellationToken::new();
    let relay_task = tokio::spawn(serve_agent_relay(
        listener,
        socket_path.to_path_buf(),
        cancellation.clone(),
    ));

    let executable = env::current_exe().map_err(|error| {
        format!(
            "could not resolve the Blindfold executable: {}",
            error.kind()
        )
    })?;
    let mut command = tokio::process::Command::new(executable);
    command
        .arg("run")
        .arg(agent)
        .arg("--anthropic-upstream")
        .arg(format!("{origin}/anthropic"))
        .arg("--openai-upstream")
        .arg(format!("{origin}/openai"))
        .arg("--openrouter-upstream")
        .arg(format!("{origin}/openrouter"))
        .arg("--")
        .args(agent_args)
        .env("BLINDFOLD_LOCKED_BOUNDARY", "1")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = command
        .status()
        .await
        .map_err(|error| format!("could not start the managed agent: {}", error.kind()))?;
    cancellation.cancel();
    let _ = relay_task.await;
    Ok(status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .map_or(ExitCode::FAILURE, ExitCode::from))
}

pub(crate) fn verify_network_none() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let ipv4 = fs::read_to_string("/proc/net/route")
            .map_err(|_| "could not verify the locked IPv4 route table".to_owned())?;
        if ipv4.len() > 64 * 1024
            || ipv4
                .lines()
                .skip(1)
                .filter(|line| !line.trim().is_empty())
                .any(|line| line.split_whitespace().next() != Some("lo"))
        {
            return Err(
                "locked agent requires a Linux network namespace with no non-loopback routes"
                    .to_owned(),
            );
        }
        let ipv6 = fs::read_to_string("/proc/net/ipv6_route")
            .map_err(|_| "could not verify the locked IPv6 route table".to_owned())?;
        if ipv6.len() > 64 * 1024
            || ipv6
                .lines()
                .filter(|line| !line.trim().is_empty())
                .any(|line| line.split_whitespace().next_back() != Some("lo"))
        {
            return Err(
                "locked agent requires a Linux network namespace with no non-loopback routes"
                    .to_owned(),
            );
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("locked agent must run inside a Linux container with network=none".to_owned())
    }
}

async fn serve_gateway_relay(
    listener: UnixListener,
    proxy_addr: SocketAddr,
    cancellation: CancellationToken,
) -> io::Result<()> {
    loop {
        let accepted = tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted,
        };
        let (mut client, _) = accepted?;
        tokio::spawn(async move {
            let Ok(mut proxy) = TcpStream::connect(proxy_addr).await else {
                let _ = client.shutdown().await;
                return;
            };
            let _ = copy_bidirectional(&mut client, &mut proxy).await;
        });
    }
}

async fn serve_agent_relay(
    listener: TcpListener,
    socket_path: PathBuf,
    cancellation: CancellationToken,
) -> io::Result<()> {
    loop {
        let accepted = tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted,
        };
        let (mut client, _) = accepted?;
        let socket_path = socket_path.clone();
        tokio::spawn(async move {
            let Ok(mut gateway) = UnixStream::connect(socket_path).await else {
                let _ = client.shutdown().await;
                return;
            };
            let _ = copy_bidirectional(&mut client, &mut gateway).await;
        });
    }
}

fn bind_unix_listener(socket_path: &Path) -> Result<UnixListener, String> {
    if let Ok(metadata) = fs::symlink_metadata(socket_path) {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() {
            return Err("gateway socket path already exists and is not a socket".to_owned());
        }
        fs::remove_file(socket_path).map_err(|error| {
            format!(
                "could not replace the stale gateway socket: {}",
                error.kind()
            )
        })?;
    }
    let listener = UnixListener::bind(socket_path)
        .map_err(|error| format!("could not bind the gateway socket: {}", error.kind()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o666)).map_err(|error| {
            format!("could not set gateway socket permissions: {}", error.kind())
        })?;
    }
    Ok(listener)
}

async fn wait_for_gateway(socket_path: &Path) -> Result<(), String> {
    for _ in 0..GATEWAY_CONNECT_ATTEMPTS {
        match UnixStream::connect(socket_path).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(_) => tokio::time::sleep(GATEWAY_CONNECT_DELAY).await,
        }
    }
    Err("locked gateway did not become ready".to_owned())
}

fn validate_socket_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("gateway socket path must be absolute".to_owned());
    }
    let Some(parent) = path.parent() else {
        return Err("gateway socket path has no parent".to_owned());
    };
    let metadata = fs::symlink_metadata(parent)
        .map_err(|_| "gateway socket parent is unavailable".to_owned())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("gateway socket parent must be a real directory".to_owned());
    }
    Ok(())
}

fn read_credential(path: &Path) -> Result<String, String> {
    let expected = fs::symlink_metadata(path)
        .map_err(|_| "gateway credential file is unavailable".to_owned())?;
    if !expected.is_file()
        || expected.file_type().is_symlink()
        || expected.len() > MAX_CREDENTIAL_BYTES
    {
        return Err("gateway credential must be a small regular file, not a symlink".to_owned());
    }
    let file = File::open(path).map_err(|_| "gateway credential file is unavailable".to_owned())?;
    let opened = file
        .metadata()
        .map_err(|_| "gateway credential file is unavailable".to_owned())?;
    if !same_file(&expected, &opened) || !opened.is_file() {
        return Err("gateway credential file changed while it was opened".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(MAX_CREDENTIAL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "gateway credential file could not be read".to_owned())?;
    let max_length = usize::try_from(MAX_CREDENTIAL_BYTES)
        .map_err(|_| "gateway credential size limit is unsupported".to_owned())?;
    if bytes.len() > max_length {
        return Err("gateway credential must be a small regular file, not a symlink".to_owned());
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| "gateway credential file is not valid UTF-8".to_owned())?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() || value.contains(['\r', '\n', '\0']) {
        return Err("gateway credential file contains an invalid value".to_owned());
    }
    Ok(value.to_owned())
}

#[cfg(unix)]
fn same_file(expected: &fs::Metadata, opened: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    expected.dev() == opened.dev() && expected.ino() == opened.ino()
}

#[cfg(not(unix))]
fn same_file(_expected: &fs::Metadata, _opened: &fs::Metadata) -> bool {
    false
}

struct BoundarySanitizer {
    redactor: Redactor,
}

impl BoundarySanitizer {
    fn new() -> Result<Self, String> {
        DetectorSet::new()
            .map(|detectors| Self {
                redactor: Redactor::new(detectors),
            })
            .map_err(|_| "could not initialize the gateway detector set".to_owned())
    }
}

impl ProxySanitizer for BoundarySanitizer {
    fn sanitize(&self, text: &str) -> String {
        self.redactor
            .redact(text, RedactionOptions::new(RedactionMode::Placeholder))
            .map_or_else(
                |_| "[BLOCKED]".to_owned(),
                blindfold_detectors::RedactionOutput::into_text,
            )
    }
}

#[cfg(test)]
mod tests {
    use super::{GatewayProvider, read_credential, validate_socket_path};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn parses_only_supported_gateway_providers() {
        assert_eq!(
            GatewayProvider::parse("anthropic"),
            Some(GatewayProvider::Anthropic)
        );
        assert_eq!(
            GatewayProvider::parse("openai"),
            Some(GatewayProvider::OpenAi)
        );
        assert_eq!(
            GatewayProvider::parse("openrouter"),
            Some(GatewayProvider::OpenRouter)
        );
        assert_eq!(GatewayProvider::parse("other"), None);
    }

    #[test]
    fn credential_reader_rejects_multiline_values() -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!(
            "blindfold-boundary-test-{}-{}",
            std::process::id(),
            NEXT_TEST.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory)?;
        let credential = directory.join("provider.key");
        fs::write(&credential, "first\nsecond\n")?;
        assert!(read_credential(&credential).is_err());
        fs::write(&credential, "test-credential\n")?;
        assert_eq!(read_credential(&credential)?, "test-credential");
        fs::write(&credential, vec![b'x'; 16 * 1024 + 1])?;
        assert!(read_credential(&credential).is_err());
        validate_socket_path(&directory.join("gateway.sock"))?;
        fs::remove_dir_all(directory)?;
        Ok(())
    }
}
