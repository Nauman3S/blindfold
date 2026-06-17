//! Listener lifecycle and forwarding implementation.

use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Path, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Uri,
        header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, TRANSFER_ENCODING, UPGRADE},
    },
    response::IntoResponse,
    routing::any,
};
use futures_util::StreamExt;
use reqwest::Url;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use blindfold_trace::{Category, Coverage, Issue, Outcome, Record, Replacement, Route};

use crate::{
    Config, ConfigError, ErrorCode, Provider, ProxyError, Sanitizer, Upstream,
    sanitize::{Observation, sanitize_json, sanitize_sse},
};

const LOOP_HEADER: HeaderName = HeaderName::from_static("x-blindfold-proxy-hop");
const LOOP_VALUE: HeaderValue = HeaderValue::from_static("1");
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
enum BodySource {
    Request,
    Response,
}

/// A validated proxy configuration and outbound client.
pub struct Proxy {
    config: Config,
    client: reqwest::Client,
    sanitizer: Arc<dyn Sanitizer>,
    trace_sink: Option<Arc<dyn TraceSink>>,
}

/// Receives payload-free trace records when tracing is explicitly enabled.
pub trait TraceSink: Send + Sync + 'static {
    /// Records one completed or rejected managed exchange.
    fn record(&self, record: Record);
}

/// A bound listener ready to serve until cancelled.
pub struct BoundProxy {
    listener: TcpListener,
    router: Router,
    local_addr: SocketAddr,
}

#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
    sanitizer: Arc<dyn Sanitizer>,
    upstreams: Arc<HashMap<String, Upstream>>,
    max_request_body: usize,
    max_response_body: usize,
    request_timeout: std::time::Duration,
    trace_sink: Option<Arc<dyn TraceSink>>,
}

impl Proxy {
    /// Validates configuration and creates an outbound client.
    ///
    /// # Errors
    ///
    /// Returns a safe [`ConfigError`] when limits, binding policy, upstreams, or
    /// sanitizer overlap requirements are invalid.
    pub fn new(config: Config, sanitizer: Arc<dyn Sanitizer>) -> Result<Self, ConfigError> {
        config.validate(sanitizer.required_overlap())?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ConfigError::InvalidUpstreamUrl)?;
        Ok(Self {
            config,
            client,
            sanitizer,
            trace_sink: None,
        })
    }

    /// Attaches an explicit payload-free trace sink.
    #[must_use]
    pub fn with_trace_sink(mut self, trace_sink: Arc<dyn TraceSink>) -> Self {
        self.trace_sink = Some(trace_sink);
        self
    }

    /// Binds the configured address and performs final loop checks.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::BindFailed`] if the listener cannot be created, or
    /// [`ConfigError::ProxyLoop`] if an upstream is the resulting listener.
    pub async fn bind(self) -> Result<BoundProxy, ConfigError> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .map_err(|_| ConfigError::BindFailed)?;
        let local_addr = listener.local_addr().map_err(|_| ConfigError::BindFailed)?;
        reject_direct_loops(local_addr, &self.config.upstreams)?;

        let upstreams = self
            .config
            .upstreams
            .into_iter()
            .map(|upstream| (upstream.name.clone(), upstream))
            .collect();
        let state = AppState {
            client: self.client,
            sanitizer: self.sanitizer,
            upstreams: Arc::new(upstreams),
            max_request_body: self.config.max_request_body,
            max_response_body: self.config.max_response_body,
            request_timeout: self.config.request_timeout,
            trace_sink: self.trace_sink,
        };
        let router = Router::new()
            .route("/{upstream}", any(forward_root))
            .route("/{upstream}/{*path}", any(forward_path))
            .with_state(state);
        Ok(BoundProxy {
            listener,
            router,
            local_addr,
        })
    }
}

impl BoundProxy {
    /// Returns the actual listener address, including an assigned ephemeral port.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serves until cancellation, then drains active connections gracefully.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the HTTP server fails while accepting connections.
    pub async fn serve(self, cancellation: CancellationToken) -> Result<(), std::io::Error> {
        axum::serve(self.listener, self.router)
            .with_graceful_shutdown(cancellation.cancelled_owned())
            .await
    }
}

async fn forward_root(
    State(state): State<AppState>,
    Path(upstream): Path<String>,
    request: Request<Body>,
) -> Response<Body> {
    forward(state, upstream, String::new(), request).await
}

async fn forward_path(
    State(state): State<AppState>,
    Path((upstream, path)): Path<(String, String)>,
    request: Request<Body>,
) -> Response<Body> {
    forward(state, upstream, path, request).await
}

async fn forward(
    state: AppState,
    upstream_name: String,
    path: String,
    request: Request<Body>,
) -> Response<Body> {
    let Some(upstream) = state.upstreams.get(&upstream_name) else {
        RequestTrace::unknown().emit(
            state.trace_sink.as_deref(),
            Some(ErrorCode::UpstreamNotAllowed),
        );
        return ProxyError::new(ErrorCode::UpstreamNotAllowed).into_response();
    };
    let mut trace = RequestTrace::new(upstream.provider);
    match tokio::time::timeout(
        state.request_timeout,
        forward_inner(&state, &upstream_name, &path, request, &mut trace),
    )
    .await
    {
        Ok(Ok(response)) => {
            trace.emit(state.trace_sink.as_deref(), None);
            response
        }
        Ok(Err(error)) => {
            trace.emit(state.trace_sink.as_deref(), Some(error.code()));
            error.into_response()
        }
        Err(_) => {
            trace.issue = Some(Issue::Timeout);
            trace.emit(state.trace_sink.as_deref(), Some(ErrorCode::Timeout));
            ProxyError::new(ErrorCode::Timeout).into_response()
        }
    }
}

async fn forward_inner(
    state: &AppState,
    upstream_name: &str,
    path: &str,
    request: Request<Body>,
    trace: &mut RequestTrace,
) -> Result<Response<Body>, ProxyError> {
    let upstream = state
        .upstreams
        .get(upstream_name)
        .ok_or_else(|| ProxyError::new(ErrorCode::UpstreamNotAllowed))?;
    if request.headers().contains_key(&LOOP_HEADER) {
        return Err(ProxyError::new(ErrorCode::ProxyLoop));
    }
    reject_unsupported_transport(request.headers())?;
    reject_unsupported_method(request.method())?;
    reject_oversize_content_length(request.headers(), state.max_request_body)?;

    let (parts, body) = request.into_parts();
    let body = to_bytes(body, state.max_request_body)
        .await
        .map_err(|_| ProxyError::new(ErrorCode::RequestTooLarge))?;
    trace.request_before = body.len();
    let request_type = content_type(&parts.headers);
    let (body, observations) = sanitize_body(
        upstream.provider,
        BodySource::Request,
        request_type,
        &body,
        state.sanitizer.as_ref(),
    )
    .inspect_err(|error| {
        trace.issue = Some(issue_for(error.code(), BodySource::Request));
    })?;
    trace.request_after = body.len();
    trace.observe(observations);
    let url = destination_url(&upstream.base_url, path, &parts.uri);

    let mut outbound = state.client.request(parts.method, url).body(body);
    for (name, value) in &parts.headers {
        if !is_hop_by_hop(name) {
            outbound = outbound.header(name, value);
        }
    }
    outbound = outbound.header(LOOP_HEADER, LOOP_VALUE);

    let upstream_response = outbound
        .send()
        .await
        .map_err(|_| ProxyError::new(ErrorCode::UpstreamFailure))?;
    reject_oversize_reqwest_length(&upstream_response, state.max_response_body)?;

    let status = upstream_response.status();
    let headers = upstream_response.headers().clone();
    let response_type = content_type(&headers);
    let body = collect_response(upstream_response, state.max_response_body).await?;
    trace.response_before = body.len();
    let (body, observations) = sanitize_body(
        upstream.provider,
        BodySource::Response,
        response_type,
        &body,
        state.sanitizer.as_ref(),
    )
    .inspect_err(|error| {
        trace.issue = Some(issue_for(error.code(), BodySource::Response));
    })?;
    trace.response_after = body.len();
    trace.observe(observations);

    let mut response = Response::builder().status(status);
    for (name, value) in &headers {
        if !is_hop_by_hop(name) {
            response = response.header(name, value);
        }
    }
    response
        .body(Body::from(body))
        .map_err(|_| ProxyError::new(ErrorCode::UpstreamFailure))
}

async fn collect_response(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, ProxyError> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ProxyError::new(ErrorCode::UpstreamFailure))?;
        let new_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| ProxyError::new(ErrorCode::ResponseTooLarge))?;
        if new_len > limit {
            return Err(ProxyError::new(ErrorCode::ResponseTooLarge));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn reject_unsupported_method(method: &Method) -> Result<(), ProxyError> {
    if method == Method::CONNECT || method == Method::TRACE {
        Err(ProxyError::new(ErrorCode::InvalidRequest))
    } else {
        Ok(())
    }
}

fn reject_unsupported_transport(headers: &HeaderMap) -> Result<(), ProxyError> {
    let has_upgrade_connection = headers
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
    if headers.contains_key(UPGRADE) || has_upgrade_connection {
        return Err(ProxyError::new(ErrorCode::UnsupportedTransport));
    }
    Ok(())
}

fn reject_oversize_content_length(headers: &HeaderMap, limit: usize) -> Result<(), ProxyError> {
    if headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > limit)
    {
        return Err(ProxyError::new(ErrorCode::RequestTooLarge));
    }
    Ok(())
}

fn reject_oversize_reqwest_length(
    response: &reqwest::Response,
    limit: usize,
) -> Result<(), ProxyError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(ProxyError::new(ErrorCode::ResponseTooLarge));
    }
    Ok(())
}

fn sanitize_body(
    provider: Provider,
    source: BodySource,
    content_type: Option<&str>,
    body: &[u8],
    sanitizer: &dyn Sanitizer,
) -> Result<(Vec<u8>, Vec<Observation>), ProxyError> {
    if body.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    if content_type.is_some_and(is_sse) {
        return sanitize_sse(provider, body, sanitizer)
            .map_err(|()| ProxyError::new(ErrorCode::InvalidJson));
    }
    if content_type.is_some_and(is_json) {
        let mut value: Value =
            serde_json::from_slice(body).map_err(|_| ProxyError::new(ErrorCode::InvalidJson))?;
        let observations = sanitize_json(provider, &mut value, sanitizer);
        let output =
            serde_json::to_vec(&value).map_err(|_| ProxyError::new(ErrorCode::InvalidJson))?;
        return Ok((output, observations));
    }
    Err(ProxyError::new(match source {
        BodySource::Request => ErrorCode::InvalidRequest,
        BodySource::Response => ErrorCode::UpstreamFailure,
    }))
}

struct RequestTrace {
    request_id: String,
    route: Route,
    request_before: usize,
    request_after: usize,
    response_before: usize,
    response_after: usize,
    observations: BTreeMap<(Category, String), u32>,
    issue: Option<Issue>,
}

impl RequestTrace {
    fn unknown() -> Self {
        Self::with_route(Route::Unknown)
    }

    fn new(provider: Provider) -> Self {
        Self::with_route(match provider {
            Provider::OpenAi => Route::OpenAi,
            Provider::Anthropic => Route::Anthropic,
        })
    }

    fn with_route(route: Route) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            request_id: format!("req_{timestamp:x}_{sequence:x}"),
            route,
            request_before: 0,
            request_after: 0,
            response_before: 0,
            response_after: 0,
            observations: BTreeMap::new(),
            issue: None,
        }
    }

    fn observe(&mut self, observations: Vec<Observation>) {
        for observation in observations {
            *self
                .observations
                .entry((observation.category, observation.pointer))
                .or_default() += 1;
        }
    }

    fn emit(&self, sink: Option<&dyn TraceSink>, error: Option<ErrorCode>) {
        let Some(sink) = sink else {
            return;
        };
        let issue = self
            .issue
            .or_else(|| error.map(|code| issue_for(code, BodySource::Request)));
        let coverage = if issue.is_none() {
            Coverage::Protected
        } else if self.request_after > 0 || self.response_after > 0 {
            Coverage::Degraded
        } else {
            Coverage::Unprotected
        };
        let outcome = match error {
            None => Outcome::Succeeded,
            Some(ErrorCode::Timeout) => Outcome::TimedOut,
            Some(ErrorCode::UpstreamFailure | ErrorCode::Cancelled) => Outcome::Failed,
            Some(_) => Outcome::Rejected,
        };
        let replacements = self
            .observations
            .iter()
            .enumerate()
            .filter_map(|(index, ((category, pointer), occurrences))| {
                Replacement::new(format!("S{}", index + 1), *category, pointer, *occurrences).ok()
            })
            .collect();
        let Ok(record) = Record::now(
            &self.request_id,
            self.route,
            coverage,
            outcome,
            (
                u64::try_from(self.request_before).unwrap_or(u64::MAX),
                u64::try_from(self.request_after).unwrap_or(u64::MAX),
            ),
            (
                u64::try_from(self.response_before).unwrap_or(u64::MAX),
                u64::try_from(self.response_after).unwrap_or(u64::MAX),
            ),
            replacements,
            issue,
        ) else {
            return;
        };
        sink.record(record);
    }
}

const fn issue_for(code: ErrorCode, source: BodySource) -> Issue {
    match code {
        ErrorCode::UpstreamNotAllowed => Issue::RouteNotAllowed,
        ErrorCode::ProxyLoop => Issue::ProxyLoop,
        ErrorCode::RequestTooLarge => Issue::RequestTooLarge,
        ErrorCode::ResponseTooLarge => Issue::ResponseTooLarge,
        ErrorCode::InvalidJson => Issue::InvalidPayload,
        ErrorCode::InvalidRequest | ErrorCode::UnsupportedTransport => Issue::UnsupportedRequest,
        ErrorCode::Timeout | ErrorCode::Cancelled => Issue::Timeout,
        ErrorCode::UpstreamFailure => match source {
            BodySource::Request => Issue::UpstreamFailure,
            BodySource::Response => Issue::UnsupportedResponse,
        },
    }
}

fn content_type(headers: &HeaderMap) -> Option<&str> {
    headers.get(CONTENT_TYPE)?.to_str().ok()
}

fn is_json(content_type: &str) -> bool {
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    media_type == "application/json" || media_type.ends_with("+json")
}

fn is_sse(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim() == "text/event-stream")
}

fn destination_url(base: &Url, path: &str, uri: &Uri) -> Url {
    let mut destination = base.clone();
    let mut joined_path = destination.path().trim_end_matches('/').to_owned();
    if !path.is_empty() {
        joined_path.push('/');
        joined_path.push_str(path);
    }
    destination.set_path(&joined_path);
    destination.set_query(uri.query());
    destination
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    if name == LOOP_HEADER {
        return true;
    }
    matches!(
        name,
        &CONNECTION | &CONTENT_LENGTH | &TRANSFER_ENCODING | &HOST
    ) || matches!(
        name.as_str(),
        "keep-alive" | "proxy-authenticate" | "proxy-authorization" | "te" | "trailer" | "upgrade"
    )
}

fn reject_direct_loops(listener: SocketAddr, upstreams: &[Upstream]) -> Result<(), ConfigError> {
    for upstream in upstreams {
        let Some(port) = upstream.base_url.port_or_known_default() else {
            continue;
        };
        let Some(host) = upstream.base_url.host_str() else {
            continue;
        };
        let Ok(ip) = host.parse::<IpAddr>() else {
            continue;
        };
        if port == listener.port() && same_listener_ip(listener.ip(), ip) {
            return Err(ConfigError::ProxyLoop);
        }
    }
    Ok(())
}

fn same_listener_ip(listener: IpAddr, upstream: IpAddr) -> bool {
    listener == upstream
        || (listener.is_unspecified() && upstream.is_loopback())
        || (listener.is_ipv4() && upstream == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
        || (listener.is_ipv6() && upstream == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use crate::{Config, ConfigError, ExactValueSanitizer, Provider, Proxy, Upstream};

    #[test]
    fn defaults_to_loopback() {
        assert!(Config::default().bind_addr.ip().is_loopback());
    }

    #[test]
    fn rejects_non_loopback_without_opt_in() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = Config {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            ..Config::default()
        };
        config.upstreams.push(Upstream::new(
            "api",
            "https://example.com",
            Provider::OpenAi,
        )?);
        let sanitizer = Arc::new(ExactValueSanitizer::new("secret", "[safe]")?);
        let error = Proxy::new(config, sanitizer)
            .err()
            .ok_or("configuration unexpectedly passed")?;
        assert_eq!(error, ConfigError::NonLoopbackBind);
        Ok(())
    }
}
