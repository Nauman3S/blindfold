use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

const SESSION_LABEL: &str = "io.blindfold.session";
const ROLE_LABEL: &str = "io.blindfold.role";
const SOCKET_DIRECTORY: &str = "/run/blindfold";
const SOCKET_PATH: &str = "/run/blindfold/gateway.sock";
const CONTAINER_CREDENTIAL_PATH: &str = "/run/secrets/blindfold-provider-key";
const LOCAL_DEVELOPMENT_IMAGE: &str = "blindfold-locked:local";
const MAX_WORKSPACE_ENTRIES: usize = 1_000_000;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A validated description of one Docker-isolated agent run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LockedRunSpec {
    agent: String,
    agent_args: Vec<String>,
    workspace: PathBuf,
    credential_file: PathBuf,
    upstream: String,
    provider: String,
    image: String,
}

impl LockedRunSpec {
    /// Validates all host-controlled values used to build Docker arguments.
    pub(crate) fn new(
        agent: &str,
        agent_args: Vec<String>,
        workspace: PathBuf,
        credential_file: PathBuf,
        upstream: String,
        provider: String,
        image: String,
    ) -> Result<Self, ContainerRunError> {
        if !matches!(agent, "claude" | "codex" | "opencode") {
            return Err(ContainerRunError::InvalidAgent);
        }
        validate_image_reference(&image)?;
        validate_boundary_pair(agent, &provider, &upstream)?;
        validate_canonical_directory(&workspace, "workspace")?;
        validate_credential_file(&credential_file)?;
        validate_workspace_tree(&workspace, &credential_file)?;
        validate_mount_source(&workspace)?;
        validate_mount_source(&credential_file)?;

        Ok(Self {
            agent: agent.to_owned(),
            agent_args,
            workspace,
            credential_file,
            upstream,
            provider,
            image,
        })
    }
}

/// Failures while validating or running the locked Docker boundary.
#[derive(Debug)]
pub(crate) enum ContainerRunError {
    InvalidAgent,
    InvalidPath(&'static str),
    InvalidCredentialFile,
    CredentialFileIsSymlink,
    CredentialExposedToAgent,
    UnsupportedMountPath,
    UnsafeWorkspaceEntry,
    WorkspaceEntryLimit,
    UnpinnedImage,
    InvalidArgument(&'static str),
    ClockUnavailable,
    DockerUnavailable,
    UntrustedDockerExecutable,
    RemoteDockerContext,
    SessionCollision,
    Interrupted,
    DockerOperation(&'static str),
    CleanupFailed,
}

impl fmt::Display for ContainerRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAgent => formatter.write_str("unsupported locked-run agent"),
            Self::InvalidPath(name) => write!(
                formatter,
                "{name} must be an existing canonical absolute directory"
            ),
            Self::InvalidCredentialFile => formatter.write_str(
                "credential file must be an existing canonical absolute regular file",
            ),
            Self::CredentialFileIsSymlink => {
                formatter.write_str("credential file must not be a symbolic link")
            }
            Self::CredentialExposedToAgent => formatter.write_str(
                "credential file is inside the agent workspace or hard-linked from it",
            ),
            Self::UnsupportedMountPath => formatter.write_str(
                "Docker mount source must be valid UTF-8 and must not contain a comma",
            ),
            Self::UnsafeWorkspaceEntry => formatter.write_str(
                "workspace contains a host IPC endpoint, special file, or nested mount",
            ),
            Self::WorkspaceEntryLimit => formatter.write_str(
                "workspace has too many entries to validate for the locked boundary",
            ),
            Self::UnpinnedImage => formatter.write_str(
                "container image must use an @sha256 digest (or blindfold-locked:local for local development)",
            ),
            Self::InvalidArgument(name) => {
                write!(formatter, "{name} must be non-empty and contain no control bytes")
            }
            Self::ClockUnavailable => {
                formatter.write_str("could not allocate a locked-run session identifier")
            }
            Self::DockerUnavailable => formatter.write_str(
                "Docker daemon is unavailable; start Docker and retry the locked run",
            ),
            Self::UntrustedDockerExecutable => formatter.write_str(
                "Docker executable must resolve outside the agent workspace",
            ),
            Self::RemoteDockerContext => formatter.write_str(
                "locked runs require a local Docker unix-socket or named-pipe context",
            ),
            Self::SessionCollision => {
                formatter.write_str("generated Docker session name already exists")
            }
            Self::Interrupted => formatter.write_str("locked run interrupted"),
            Self::DockerOperation(operation) => {
                write!(formatter, "Docker failed while attempting to {operation}")
            }
            Self::CleanupFailed => formatter.write_str(
                "locked run ended, but one or more exact session resources could not be removed",
            ),
        }
    }
}

impl std::error::Error for ContainerRunError {}

/// Runs an agent with no network namespace and a separate networked gateway.
pub(crate) async fn run_locked(mut spec: LockedRunSpec) -> Result<ExitStatus, ContainerRunError> {
    let docker_executable = resolve_docker_executable(&spec.workspace)?;
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let preflight = async {
        let docker = local_docker_client(docker_executable).await?;
        ensure_docker_available(&docker).await?;
        let image = resolve_session_image(&docker, &spec.image).await?;
        let identity = host_identity().await?;
        Ok::<_, ContainerRunError>((docker, image, identity))
    };
    let (docker, image, identity) = tokio::select! {
        result = preflight => result?,
        signal = interrupt.as_mut() => {
            signal.map_err(|_| ContainerRunError::DockerOperation("listen for an interrupt"))?;
            return Err(ContainerRunError::Interrupted);
        }
    };
    spec.image = image;
    let session = SessionNames::new()?;

    if docker_success(&docker, &volume_inspect_command(&session)).await? {
        return Err(ContainerRunError::SessionCollision);
    }
    let volume_create = volume_create_command(&session);
    let volume_future = run_required(&docker, &volume_create, "create the socket volume");
    tokio::pin!(volume_future);
    let (volume_outcome, mut signal_consumed) = tokio::select! {
        result = volume_future.as_mut() => (result, false),
        signal = interrupt.as_mut() => {
            let signal = signal
                .map_err(|_| ContainerRunError::DockerOperation("listen for an interrupt"));
            let _ = volume_future.await;
            (signal.and(Err(ContainerRunError::Interrupted)), true)
        },
    };
    let mut outcome = match volume_outcome {
        Ok(()) => {
            let (result, consumed) =
                run_after_volume_created(&docker, &spec, &session, &identity, interrupt.as_mut())
                    .await;
            signal_consumed = consumed;
            result
        }
        Err(error) => Err(error),
    };
    let cleanup = if signal_consumed {
        cleanup_session(&docker, &session).await
    } else {
        let cleanup = cleanup_session(&docker, &session);
        tokio::pin!(cleanup);
        tokio::select! {
            result = cleanup.as_mut() => result,
            signal = interrupt.as_mut() => {
                outcome = signal
                    .map_err(|_| ContainerRunError::DockerOperation("listen for an interrupt"))
                    .and(Err(ContainerRunError::Interrupted));
                cleanup.await
            }
        }
    };
    match (outcome, cleanup) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(error), Ok(())) | (_, Err(error)) => Err(error),
    }
}

async fn resolve_session_image(
    docker: &DockerClient,
    image: &str,
) -> Result<String, ContainerRunError> {
    if let Some(image_id) = inspect_image_id(docker, image).await? {
        return Ok(image_id);
    }
    if image == LOCAL_DEVELOPMENT_IMAGE {
        return Err(ContainerRunError::DockerOperation(
            "resolve the local evaluation image",
        ));
    }
    run_required(
        docker,
        &DockerInvocation::new(["pull", image]),
        "pull the digest-pinned image",
    )
    .await?;
    inspect_image_id(docker, image)
        .await?
        .ok_or(ContainerRunError::DockerOperation(
            "resolve the digest-pinned image",
        ))
}

async fn inspect_image_id(
    docker: &DockerClient,
    image: &str,
) -> Result<Option<String>, ContainerRunError> {
    let invocation = DockerInvocation::new(["image", "inspect", "--format", "{{.Id}}", image]);
    let output = command(docker, &invocation)
        .output()
        .await
        .map_err(|_| ContainerRunError::DockerOperation("inspect the session image"))?;
    if !output.status.success() {
        return Ok(None);
    }
    if output.stdout.len() > 128 {
        return Err(ContainerRunError::DockerOperation(
            "inspect the session image",
        ));
    }
    let image_id = std::str::from_utf8(&output.stdout)
        .map_err(|_| ContainerRunError::DockerOperation("inspect the session image"))?
        .trim();
    if !valid_image_id(image_id) {
        return Err(ContainerRunError::DockerOperation(
            "inspect the session image",
        ));
    }
    Ok(Some(image_id.to_owned()))
}

fn valid_image_id(image_id: &str) -> bool {
    image_id.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

async fn run_after_volume_created<F>(
    docker: &DockerClient,
    spec: &LockedRunSpec,
    session: &SessionNames,
    identity: &HostIdentity,
    mut interrupt: Pin<&mut F>,
) -> (Result<ExitStatus, ContainerRunError>, bool)
where
    F: Future<Output = std::io::Result<()>>,
{
    let gateway = gateway_run_command(spec, session);
    let gateway_future = run_required(docker, &gateway, "start the boundary gateway");
    tokio::pin!(gateway_future);
    let gateway_result = tokio::select! {
        result = gateway_future.as_mut() => result,
        signal = interrupt.as_mut() => {
            let signal = signal
                .map_err(|_| ContainerRunError::DockerOperation("listen for an interrupt"));
            let _ = gateway_future.await;
            return (signal.and(Err(ContainerRunError::Interrupted)), true);
        }
    };
    if let Err(error) = gateway_result {
        return (Err(error), false);
    }

    let Ok(mut child) = command(docker, &agent_run_command(spec, session, identity)).spawn() else {
        return (
            Err(ContainerRunError::DockerOperation("run the isolated agent")),
            false,
        );
    };
    tokio::select! {
        status = child.wait() => {
            let result = status
                .map_err(|_| ContainerRunError::DockerOperation("run the isolated agent"))
                .and_then(|status| {
                    if status.code() == Some(125) {
                        Err(ContainerRunError::DockerOperation("run the isolated agent"))
                    } else {
                        Ok(status)
                    }
                });
            (result, false)
        }
        signal = interrupt.as_mut() => {
            let signal = signal
                .map_err(|_| ContainerRunError::DockerOperation("listen for an interrupt"));
            let stopped = stop_agent_after_interrupt(docker, session, &mut child).await;
            (
                signal
                    .and(stopped)
                    .and(Err(ContainerRunError::Interrupted)),
                true,
            )
        }
    }
}

async fn stop_agent_after_interrupt(
    docker: &DockerClient,
    session: &SessionNames,
    child: &mut Child,
) -> Result<(), ContainerRunError> {
    loop {
        if child
            .try_wait()
            .map_err(|_| ContainerRunError::DockerOperation("stop the interrupted agent"))?
            .is_some()
        {
            return Ok(());
        }
        let _ = run_cleanup(docker, &agent_remove_command(session)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn ensure_docker_available(docker: &DockerClient) -> Result<(), ContainerRunError> {
    let invocation = DockerInvocation::new(["info", "--format", "{{.ServerVersion}}"]);
    let output = command(docker, &invocation)
        .output()
        .await
        .map_err(|_| ContainerRunError::DockerUnavailable)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(ContainerRunError::DockerUnavailable)
    }
}

async fn local_docker_client(executable: PathBuf) -> Result<DockerClient, ContainerRunError> {
    if let Some(host) = std::env::var_os("DOCKER_HOST") {
        let host = host
            .to_str()
            .ok_or(ContainerRunError::RemoteDockerContext)?;
        if is_local_docker_endpoint(host) {
            return Ok(DockerClient {
                executable,
                endpoint: host.to_owned(),
            });
        }
        return Err(ContainerRunError::RemoteDockerContext);
    }

    let invocation = DockerInvocation::new([
        "context",
        "inspect",
        "--format",
        "{{ (index .Endpoints \"docker\").Host }}",
    ]);
    let output = unpinned_command(&executable, &invocation)
        .output()
        .await
        .map_err(|_| ContainerRunError::DockerUnavailable)?;
    if !output.status.success() || output.stdout.len() > 4096 {
        return Err(ContainerRunError::DockerUnavailable);
    }
    let endpoint = std::str::from_utf8(&output.stdout)
        .map_err(|_| ContainerRunError::RemoteDockerContext)?
        .trim();
    if is_local_docker_endpoint(endpoint) {
        Ok(DockerClient {
            executable,
            endpoint: endpoint.to_owned(),
        })
    } else {
        Err(ContainerRunError::RemoteDockerContext)
    }
}

fn is_local_docker_endpoint(endpoint: &str) -> bool {
    !endpoint.is_empty()
        && !endpoint.chars().any(char::is_control)
        && (endpoint
            .strip_prefix("unix://")
            .is_some_and(|path| path.starts_with('/'))
            || endpoint.starts_with("npipe://"))
}

fn resolve_docker_executable(workspace: &Path) -> Result<PathBuf, ContainerRunError> {
    let path = std::env::var_os("PATH").ok_or(ContainerRunError::DockerUnavailable)?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join("docker");
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if !metadata.is_file() || !is_executable(&metadata) {
            continue;
        }
        return canonical_docker_executable(workspace, &candidate);
    }
    Err(ContainerRunError::DockerUnavailable)
}

fn canonical_docker_executable(
    workspace: &Path,
    candidate: &Path,
) -> Result<PathBuf, ContainerRunError> {
    let canonical =
        fs::canonicalize(candidate).map_err(|_| ContainerRunError::UntrustedDockerExecutable)?;
    if canonical.starts_with(workspace) {
        Err(ContainerRunError::UntrustedDockerExecutable)
    } else {
        Ok(canonical)
    }
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    true
}

async fn cleanup_session(
    docker: &DockerClient,
    session: &SessionNames,
) -> Result<(), ContainerRunError> {
    if !docker_success(
        docker,
        &DockerInvocation::new(["info", "--format", "{{.ServerVersion}}"]),
    )
    .await
    .unwrap_or(false)
    {
        return Err(ContainerRunError::CleanupFailed);
    }
    let mut failed = false;
    let agent_exists = checked_resource_exists(docker, &agent_inspect_command(session)).await?;
    if agent_exists {
        failed |= !run_cleanup(docker, &agent_remove_command(session)).await;
    }
    let gateway_exists = checked_resource_exists(docker, &gateway_inspect_command(session)).await?;
    if gateway_exists {
        failed |= !run_cleanup(docker, &gateway_stop_command(session)).await;
        if checked_resource_exists(docker, &gateway_inspect_command(session)).await? {
            failed |= !run_cleanup(docker, &gateway_remove_command(session)).await;
        }
    }
    if checked_resource_exists(docker, &volume_inspect_command(session)).await? {
        failed |= !run_cleanup(docker, &volume_remove_command(session)).await;
    }
    if failed {
        Err(ContainerRunError::CleanupFailed)
    } else {
        Ok(())
    }
}

async fn checked_resource_exists(
    docker: &DockerClient,
    invocation: &DockerInvocation,
) -> Result<bool, ContainerRunError> {
    if docker_success(docker, invocation).await? {
        return Ok(true);
    }
    let daemon_alive = docker_success(
        docker,
        &DockerInvocation::new(["info", "--format", "{{.ServerVersion}}"]),
    )
    .await?;
    if daemon_alive {
        Ok(false)
    } else {
        Err(ContainerRunError::CleanupFailed)
    }
}

async fn run_cleanup(docker: &DockerClient, invocation: &DockerInvocation) -> bool {
    command(docker, invocation)
        .output()
        .await
        .is_ok_and(|output| output.status.success())
}

#[derive(Debug, Eq, PartialEq)]
struct HostIdentity {
    uid: String,
    gid: String,
}

impl HostIdentity {
    fn docker_user(&self) -> String {
        format!("{}:{}", self.uid, self.gid)
    }

    fn home_tmpfs(&self) -> String {
        format!(
            "/home/agent:rw,nosuid,nodev,size=256m,uid={},gid={},mode=0700",
            self.uid, self.gid
        )
    }
}

async fn host_identity() -> Result<HostIdentity, ContainerRunError> {
    Ok(HostIdentity {
        uid: read_host_id("-u").await?,
        gid: read_host_id("-g").await?,
    })
}

async fn read_host_id(flag: &'static str) -> Result<String, ContainerRunError> {
    let mut child = Command::new("/usr/bin/id")
        .arg(flag)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ContainerRunError::DockerOperation("resolve the host user identity"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or(ContainerRunError::DockerOperation(
            "resolve the host user identity",
        ))?;
    let mut bytes = Vec::new();
    stdout
        .take(33)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ContainerRunError::DockerOperation("resolve the host user identity"))?;
    let status = child
        .wait()
        .await
        .map_err(|_| ContainerRunError::DockerOperation("resolve the host user identity"))?;
    let value = String::from_utf8(bytes)
        .map_err(|_| ContainerRunError::DockerOperation("resolve the host user identity"))?;
    let value = value.trim_end_matches(['\r', '\n']);
    if !status.success()
        || value.is_empty()
        || value.len() > 32
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ContainerRunError::DockerOperation(
            "resolve the host user identity",
        ));
    }
    Ok(value.to_owned())
}

async fn run_required(
    docker: &DockerClient,
    invocation: &DockerInvocation,
    operation: &'static str,
) -> Result<(), ContainerRunError> {
    let status = command(docker, invocation)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .await
        .map_err(|_| ContainerRunError::DockerOperation(operation))?;
    if status.success() {
        Ok(())
    } else {
        Err(ContainerRunError::DockerOperation(operation))
    }
}

async fn docker_success(
    docker: &DockerClient,
    invocation: &DockerInvocation,
) -> Result<bool, ContainerRunError> {
    command(docker, invocation)
        .output()
        .await
        .map(|output| output.status.success())
        .map_err(|_| ContainerRunError::DockerUnavailable)
}

fn command(docker: &DockerClient, invocation: &DockerInvocation) -> Command {
    let mut command = Command::new(&docker.executable);
    command
        .kill_on_drop(true)
        .arg("--host")
        .arg(&docker.endpoint)
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .args(&invocation.args);
    command
}

fn unpinned_command(executable: &Path, invocation: &DockerInvocation) -> Command {
    let mut command = Command::new(executable);
    command.kill_on_drop(true).args(&invocation.args);
    command
}

#[derive(Debug, Eq, PartialEq)]
struct DockerClient {
    executable: PathBuf,
    endpoint: String,
}

#[derive(Debug, Eq, PartialEq)]
struct DockerInvocation {
    args: Vec<OsString>,
}

impl DockerInvocation {
    fn new<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    fn push(&mut self, value: impl Into<OsString>) {
        self.args.push(value.into());
    }

    fn extend<I, S>(&mut self, values: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(values.into_iter().map(Into::into));
    }
}

#[derive(Debug, Eq, PartialEq)]
struct SessionNames {
    id: String,
    volume: String,
    gateway: String,
    agent: String,
}

impl SessionNames {
    fn new() -> Result<Self, ContainerRunError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ContainerRunError::ClockUnavailable)?
            .as_nanos();
        let counter = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
        Ok(Self::from_id(format!(
            "{}-{timestamp:x}-{counter:x}",
            std::process::id()
        )))
    }

    fn from_id(id: String) -> Self {
        Self {
            volume: format!("bf-socket-{id}"),
            gateway: format!("bf-gateway-{id}"),
            agent: format!("bf-agent-{id}"),
            id,
        }
    }

    fn label(&self) -> String {
        format!("{SESSION_LABEL}={}", self.id)
    }
}

fn volume_inspect_command(session: &SessionNames) -> DockerInvocation {
    DockerInvocation::new([
        "volume",
        "inspect",
        "--format",
        "{{.Name}}",
        session.volume.as_str(),
    ])
}

fn volume_create_command(session: &SessionNames) -> DockerInvocation {
    DockerInvocation::new([
        "volume",
        "create",
        "--label",
        session.label().as_str(),
        "--label",
        format!("{ROLE_LABEL}=socket").as_str(),
        session.volume.as_str(),
    ])
}

fn gateway_run_command(spec: &LockedRunSpec, session: &SessionNames) -> DockerInvocation {
    let mut args = DockerInvocation::new([
        "run",
        "--detach",
        "--rm",
        "--pull",
        "never",
        "--name",
        session.gateway.as_str(),
        "--label",
        session.label().as_str(),
        "--label",
        format!("{ROLE_LABEL}=gateway").as_str(),
        "--network",
        "bridge",
        "--ipc",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--read-only",
        "--log-driver",
        "none",
        "--pids-limit",
        "128",
        "--memory",
        "512m",
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=64m",
    ]);
    args.extend([
        OsString::from("--mount"),
        OsString::from(volume_mount(&session.volume, SOCKET_DIRECTORY, false)),
        OsString::from("--mount"),
        OsString::from(bind_mount(
            spec.credential_file.as_path(),
            CONTAINER_CREDENTIAL_PATH,
            true,
        )),
        OsString::from(&spec.image),
    ]);
    args.extend([
        "blindfold",
        "boundary",
        "gateway",
        "--socket",
        SOCKET_PATH,
        "--provider",
    ]);
    args.push(&spec.provider);
    args.push("--upstream");
    args.push(&spec.upstream);
    args.extend(["--credential-file", CONTAINER_CREDENTIAL_PATH]);
    args
}

fn agent_run_command(
    spec: &LockedRunSpec,
    session: &SessionNames,
    identity: &HostIdentity,
) -> DockerInvocation {
    let mut args = DockerInvocation::new([
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        session.agent.as_str(),
        "--label",
        session.label().as_str(),
        "--label",
        format!("{ROLE_LABEL}=agent").as_str(),
        "--network",
        "none",
        "--ipc",
        "none",
        "--init",
        "--user",
        identity.docker_user().as_str(),
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--read-only",
        "--log-driver",
        "none",
        "--pids-limit",
        "256",
        "--memory",
        "4g",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=512m",
        "--tmpfs",
        identity.home_tmpfs().as_str(),
        "--env",
        "HOME=/home/agent",
        "--workdir",
        "/workspace",
    ]);
    args.extend([
        OsString::from("--mount"),
        OsString::from(bind_mount(spec.workspace.as_path(), "/workspace", false)),
        OsString::from("--mount"),
        OsString::from(volume_mount(&session.volume, SOCKET_DIRECTORY, true)),
        OsString::from(&spec.image),
    ]);
    args.extend(["blindfold", "boundary", "agent", "--socket", SOCKET_PATH]);
    args.push(&spec.agent);
    args.push("--");
    args.extend(spec.agent_args.iter().map(OsString::from));
    args
}

fn agent_remove_command(session: &SessionNames) -> DockerInvocation {
    DockerInvocation::new(["rm", "--force", session.agent.as_str()])
}

fn agent_inspect_command(session: &SessionNames) -> DockerInvocation {
    DockerInvocation::new([
        "container",
        "inspect",
        "--format",
        "{{.Id}}",
        session.agent.as_str(),
    ])
}

fn gateway_inspect_command(session: &SessionNames) -> DockerInvocation {
    DockerInvocation::new([
        "container",
        "inspect",
        "--format",
        "{{.Id}}",
        session.gateway.as_str(),
    ])
}

fn gateway_stop_command(session: &SessionNames) -> DockerInvocation {
    DockerInvocation::new(["stop", "--time", "5", session.gateway.as_str()])
}

fn gateway_remove_command(session: &SessionNames) -> DockerInvocation {
    DockerInvocation::new(["rm", "--force", session.gateway.as_str()])
}

fn volume_remove_command(session: &SessionNames) -> DockerInvocation {
    DockerInvocation::new(["volume", "rm", "--force", session.volume.as_str()])
}

fn bind_mount(source: &Path, target: &str, read_only: bool) -> String {
    let mode = if read_only { ",readonly" } else { "" };
    format!(
        "type=bind,src={},dst={target}{mode}",
        source.to_string_lossy()
    )
}

fn volume_mount(source: &str, target: &str, read_only: bool) -> String {
    let mode = if read_only { ",readonly" } else { "" };
    format!("type=volume,src={source},dst={target}{mode}")
}

fn validate_canonical_directory(path: &Path, name: &'static str) -> Result<(), ContainerRunError> {
    if !path.is_absolute() || !path.is_dir() {
        return Err(ContainerRunError::InvalidPath(name));
    }
    let canonical = fs::canonicalize(path).map_err(|_| ContainerRunError::InvalidPath(name))?;
    if canonical != path {
        return Err(ContainerRunError::InvalidPath(name));
    }
    Ok(())
}

fn validate_credential_file(path: &Path) -> Result<(), ContainerRunError> {
    if !path.is_absolute() {
        return Err(ContainerRunError::InvalidCredentialFile);
    }
    let symlink_metadata =
        fs::symlink_metadata(path).map_err(|_| ContainerRunError::InvalidCredentialFile)?;
    if symlink_metadata.file_type().is_symlink() {
        return Err(ContainerRunError::CredentialFileIsSymlink);
    }
    if !symlink_metadata.is_file() {
        return Err(ContainerRunError::InvalidCredentialFile);
    }
    let canonical = fs::canonicalize(path).map_err(|_| ContainerRunError::InvalidCredentialFile)?;
    if canonical != path {
        return Err(ContainerRunError::InvalidCredentialFile);
    }
    Ok(())
}

fn validate_mount_source(path: &Path) -> Result<(), ContainerRunError> {
    match path.to_str() {
        Some(value) if !value.contains(',') => Ok(()),
        _ => Err(ContainerRunError::UnsupportedMountPath),
    }
}

#[cfg(unix)]
fn validate_workspace_tree(
    workspace: &Path,
    credential_file: &Path,
) -> Result<(), ContainerRunError> {
    use std::os::unix::fs::MetadataExt;

    let root_device = fs::symlink_metadata(workspace)
        .map_err(|_| ContainerRunError::InvalidPath("workspace"))?
        .dev();
    let credential_metadata = fs::symlink_metadata(credential_file)
        .map_err(|_| ContainerRunError::InvalidCredentialFile)?;
    let credential_identity = (credential_metadata.dev(), credential_metadata.ino());
    let mut pending = vec![workspace.to_path_buf()];
    let mut entries = 0_usize;
    while let Some(directory) = pending.pop() {
        let children =
            fs::read_dir(directory).map_err(|_| ContainerRunError::UnsafeWorkspaceEntry)?;
        for child in children {
            let child = child.map_err(|_| ContainerRunError::UnsafeWorkspaceEntry)?;
            entries = entries.saturating_add(1);
            if entries > MAX_WORKSPACE_ENTRIES {
                return Err(ContainerRunError::WorkspaceEntryLimit);
            }
            let metadata = fs::symlink_metadata(child.path())
                .map_err(|_| ContainerRunError::UnsafeWorkspaceEntry)?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                continue;
            }
            if metadata.dev() != root_device {
                return Err(ContainerRunError::UnsafeWorkspaceEntry);
            }
            if file_type.is_dir() {
                pending.push(child.path());
            } else if file_type.is_file() {
                if (metadata.dev(), metadata.ino()) == credential_identity {
                    return Err(ContainerRunError::CredentialExposedToAgent);
                }
            } else {
                return Err(ContainerRunError::UnsafeWorkspaceEntry);
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_workspace_tree(
    _workspace: &Path,
    _credential_file: &Path,
) -> Result<(), ContainerRunError> {
    Err(ContainerRunError::UnsafeWorkspaceEntry)
}

fn validate_boundary_pair(
    agent: &str,
    provider: &str,
    upstream: &str,
) -> Result<(), ContainerRunError> {
    let valid = matches!(
        (agent, provider, upstream),
        (
            "claude" | "opencode",
            "anthropic",
            "https://api.anthropic.com"
        ) | ("codex", "openai", "https://api.openai.com/v1")
            | ("opencode", "openai", "https://api.openai.com")
            | ("opencode", "openrouter", "https://openrouter.ai/api")
    );
    if valid {
        Ok(())
    } else {
        Err(ContainerRunError::InvalidArgument(
            "agent/provider/upstream combination",
        ))
    }
}

fn validate_image_reference(image: &str) -> Result<(), ContainerRunError> {
    if image == LOCAL_DEVELOPMENT_IMAGE {
        return Ok(());
    }
    let Some((repository, digest)) = image.rsplit_once("@sha256:") else {
        return Err(ContainerRunError::UnpinnedImage);
    };
    let repository_valid = repository
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric())
        && repository.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '/' | '-' | ':')
        });
    if !repository_valid
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContainerRunError::UnpinnedImage);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{error::Error, ffi::OsStr};

    fn fixture_spec() -> LockedRunSpec {
        LockedRunSpec {
            agent: "claude".to_owned(),
            agent_args: vec!["--print".to_owned(), "hello".to_owned()],
            workspace: PathBuf::from("/canonical/workspace"),
            credential_file: PathBuf::from("/canonical/provider-key"),
            upstream: "https://api.anthropic.com".to_owned(),
            provider: "anthropic".to_owned(),
            image: format!("example.invalid/blindfold@sha256:{}", "a".repeat(64)),
        }
    }

    fn fixture_session() -> SessionNames {
        SessionNames::from_id("test-session".to_owned())
    }

    fn fixture_identity() -> HostIdentity {
        HostIdentity {
            uid: "1000".to_owned(),
            gid: "1001".to_owned(),
        }
    }

    fn strings(invocation: DockerInvocation) -> Vec<String> {
        invocation
            .args
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn agent_argv_enforces_the_locked_boundary() {
        let arguments = strings(agent_run_command(
            &fixture_spec(),
            &fixture_session(),
            &fixture_identity(),
        ));
        assert_eq!(
            arguments,
            vec![
                "run",
                "--rm",
                "--pull",
                "never",
                "--name",
                "bf-agent-test-session",
                "--label",
                "io.blindfold.session=test-session",
                "--label",
                "io.blindfold.role=agent",
                "--network",
                "none",
                "--ipc",
                "none",
                "--init",
                "--user",
                "1000:1001",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--read-only",
                "--log-driver",
                "none",
                "--pids-limit",
                "256",
                "--memory",
                "4g",
                "--cpus",
                "2",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,size=512m",
                "--tmpfs",
                "/home/agent:rw,nosuid,nodev,size=256m,uid=1000,gid=1001,mode=0700",
                "--env",
                "HOME=/home/agent",
                "--workdir",
                "/workspace",
                "--mount",
                "type=bind,src=/canonical/workspace,dst=/workspace",
                "--mount",
                "type=volume,src=bf-socket-test-session,dst=/run/blindfold,readonly",
                &format!("example.invalid/blindfold@sha256:{}", "a".repeat(64)),
                "blindfold",
                "boundary",
                "agent",
                "--socket",
                "/run/blindfold/gateway.sock",
                "claude",
                "--",
                "--print",
                "hello",
            ]
        );
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains("provider-key"))
        );
    }

    #[test]
    fn gateway_argv_has_egress_and_only_the_required_mounts() {
        let arguments = strings(gateway_run_command(&fixture_spec(), &fixture_session()));
        assert_eq!(
            arguments,
            vec![
                "run",
                "--detach",
                "--rm",
                "--pull",
                "never",
                "--name",
                "bf-gateway-test-session",
                "--label",
                "io.blindfold.session=test-session",
                "--label",
                "io.blindfold.role=gateway",
                "--network",
                "bridge",
                "--ipc",
                "none",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--read-only",
                "--log-driver",
                "none",
                "--pids-limit",
                "128",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,size=64m",
                "--mount",
                "type=volume,src=bf-socket-test-session,dst=/run/blindfold",
                "--mount",
                "type=bind,src=/canonical/provider-key,dst=/run/secrets/blindfold-provider-key,readonly",
                &format!("example.invalid/blindfold@sha256:{}", "a".repeat(64)),
                "blindfold",
                "boundary",
                "gateway",
                "--socket",
                "/run/blindfold/gateway.sock",
                "--provider",
                "anthropic",
                "--upstream",
                "https://api.anthropic.com",
                "--credential-file",
                "/run/secrets/blindfold-provider-key",
            ]
        );
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains("workspace"))
        );
    }

    #[test]
    fn cleanup_targets_only_exact_session_names() {
        let session = fixture_session();
        assert_eq!(
            strings(agent_remove_command(&session)),
            ["rm", "--force", "bf-agent-test-session"]
        );
        assert_eq!(
            strings(gateway_stop_command(&session)),
            ["stop", "--time", "5", "bf-gateway-test-session"]
        );
        assert_eq!(
            strings(gateway_remove_command(&session)),
            ["rm", "--force", "bf-gateway-test-session"]
        );
        assert_eq!(
            strings(volume_remove_command(&session)),
            ["volume", "rm", "--force", "bf-socket-test-session"]
        );
    }

    #[test]
    fn image_reference_must_be_digest_pinned_or_explicitly_local() {
        assert!(validate_image_reference("blindfold:latest").is_err());
        assert!(validate_image_reference("registry.example/blindfold:1").is_err());
        assert!(validate_image_reference("--bad@sha256:aaaaaaaa").is_err());
        assert!(validate_image_reference(LOCAL_DEVELOPMENT_IMAGE).is_ok());
        assert!(
            validate_image_reference(&format!(
                "registry.example/blindfold@sha256:{}",
                "a5".repeat(32)
            ))
            .is_ok()
        );
        assert!(valid_image_id(&format!("sha256:{}", "a5".repeat(32))));
        assert!(!valid_image_id(&format!("sha256:{}", "A5".repeat(32))));
        assert!(!valid_image_id(&"a5".repeat(32)));
    }

    #[cfg(unix)]
    #[test]
    fn credential_symlink_is_rejected() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "blindfold-container-runner-{}-{}",
            std::process::id(),
            SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let credential = root.join("key");
        let link = root.join("key-link");
        fs::write(&credential, b"test-only")?;
        symlink(&credential, &link)?;

        assert!(matches!(
            validate_credential_file(&link),
            Err(ContainerRunError::CredentialFileIsSymlink)
        ));

        fs::remove_file(link)?;
        fs::remove_file(credential)?;
        fs::remove_dir(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn credential_hard_link_inside_workspace_is_rejected() -> Result<(), Box<dyn Error>> {
        let root = std::env::temp_dir().join(format!(
            "blindfold-credential-exposure-{}-{}",
            std::process::id(),
            SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let workspace = root.join("workspace");
        fs::create_dir(&root)?;
        fs::create_dir(&workspace)?;
        let credential = root.join("provider.key");
        let exposed = workspace.join("copy.key");
        fs::write(&credential, b"test-only")?;
        fs::hard_link(&credential, &exposed)?;

        assert!(matches!(
            validate_workspace_tree(&workspace, &credential),
            Err(ContainerRunError::CredentialExposedToAgent)
        ));

        fs::remove_file(exposed)?;
        fs::remove_file(credential)?;
        fs::remove_dir(workspace)?;
        fs::remove_dir(root)?;
        Ok(())
    }

    #[test]
    fn control_bytes_are_rejected_from_boundary_configuration() {
        assert!(matches!(
            validate_boundary_pair(
                "claude",
                "anthropic",
                "https://api.anthropic.com\n--network=host"
            ),
            Err(ContainerRunError::InvalidArgument(
                "agent/provider/upstream combination"
            ))
        ));
    }

    #[test]
    fn only_fixed_agent_provider_upstream_combinations_are_accepted() {
        assert!(validate_boundary_pair("claude", "anthropic", "https://api.anthropic.com").is_ok());
        assert!(validate_boundary_pair("codex", "openai", "https://api.openai.com/v1").is_ok());
        assert!(validate_boundary_pair("opencode", "openai", "https://api.openai.com").is_ok());
        assert!(
            validate_boundary_pair("codex", "openrouter", "https://openrouter.ai/api").is_err()
        );
        assert!(validate_boundary_pair("codex", "openai", "https://gateway.example/v1").is_err());
    }

    #[test]
    fn docker_endpoint_must_be_local() {
        assert!(is_local_docker_endpoint("unix:///var/run/docker.sock"));
        assert!(is_local_docker_endpoint("npipe:////./pipe/docker_engine"));
        assert!(!is_local_docker_endpoint("ssh://builder.example"));
        assert!(!is_local_docker_endpoint("tcp://127.0.0.1:2375"));
        assert!(!is_local_docker_endpoint("unix://relative.sock"));
        assert!(!is_local_docker_endpoint(
            "unix:///var/run/docker.sock\nssh://builder.example"
        ));
    }

    #[test]
    fn every_lifecycle_command_is_pinned_to_the_validated_endpoint() {
        let docker = DockerClient {
            executable: PathBuf::from("/usr/bin/docker"),
            endpoint: "unix:///var/run/docker.sock".to_owned(),
        };
        let invocation = DockerInvocation::new(["info"]);
        let command = command(&docker, &invocation);
        assert_eq!(command.as_std().get_program(), "/usr/bin/docker");
        let arguments = command
            .as_std()
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(arguments, ["--host", "unix:///var/run/docker.sock", "info"]);
        let environment = command.as_std().get_envs().collect::<Vec<_>>();
        assert!(environment.contains(&(OsStr::new("DOCKER_HOST"), None)));
        assert!(environment.contains(&(OsStr::new("DOCKER_CONTEXT"), None)));
    }

    #[cfg(unix)]
    #[test]
    fn docker_executable_inside_workspace_is_rejected() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "blindfold-fake-docker-{}-{}",
            std::process::id(),
            SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let executable = root.join("docker");
        fs::write(&executable, b"#!/bin/sh\nexit 0\n")?;
        let mut permissions = fs::metadata(&executable)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions)?;
        let workspace = fs::canonicalize(&root)?;

        assert!(matches!(
            canonical_docker_executable(&workspace, &executable),
            Err(ContainerRunError::UntrustedDockerExecutable)
        ));

        fs::remove_file(executable)?;
        fs::remove_dir(root)?;
        Ok(())
    }
}
