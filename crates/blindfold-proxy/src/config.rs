//! Proxy configuration and validation.

use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use reqwest::Url;

const DEFAULT_MAX_REQUEST_BODY: usize = 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BODY: usize = 8 * 1024 * 1024;

/// The supported JSON wire shape for an upstream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    /// OpenAI-compatible JSON and Responses WebSocket objects.
    OpenAi,
    /// Anthropic-compatible JSON and response SSE objects.
    Anthropic,
}

/// A named, allowlisted upstream origin.
#[derive(Clone, Debug)]
pub struct Upstream {
    pub(crate) name: String,
    pub(crate) base_url: Url,
    pub(crate) provider: Provider,
}

impl Upstream {
    /// Creates an upstream. The URL is validated when the proxy is built.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidUpstreamUrl`] when the URL cannot be parsed.
    pub fn new(
        name: impl Into<String>,
        base_url: impl AsRef<str>,
        provider: Provider,
    ) -> Result<Self, ConfigError> {
        let base_url =
            Url::parse(base_url.as_ref()).map_err(|_| ConfigError::InvalidUpstreamUrl)?;
        Ok(Self {
            name: name.into(),
            base_url,
            provider,
        })
    }

    /// Returns the route name used as the first proxy path segment.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the configured provider wire shape.
    #[must_use]
    pub const fn provider(&self) -> Provider {
        self.provider
    }
}

/// Runtime limits and allowlisted upstreams.
#[derive(Clone, Debug)]
pub struct Config {
    /// Address to bind. Defaults to an ephemeral IPv4 loopback port.
    pub bind_addr: SocketAddr,
    /// Explicit opt-in required before binding a non-loopback address.
    pub allow_non_loopback: bool,
    /// Maximum accepted request body size.
    pub max_request_body: usize,
    /// Maximum accepted upstream response body size.
    pub max_response_body: usize,
    /// End-to-end timeout for one upstream exchange.
    pub request_timeout: Duration,
    /// Named upstream allowlist.
    pub upstreams: Vec<Upstream>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            allow_non_loopback: false,
            max_request_body: DEFAULT_MAX_REQUEST_BODY,
            max_response_body: DEFAULT_MAX_RESPONSE_BODY,
            request_timeout: Duration::from_secs(30),
            upstreams: Vec::new(),
        }
    }
}

/// A safe configuration error that does not contain configured values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// A non-loopback bind was requested without explicit opt-in.
    NonLoopbackBind,
    /// At least one byte must be accepted in each direction.
    ZeroBodyLimit,
    /// The timeout must be non-zero.
    ZeroTimeout,
    /// No upstreams were configured.
    EmptyAllowlist,
    /// An upstream route name is empty or contains unsupported characters.
    InvalidUpstreamName,
    /// Two upstreams use the same route name.
    DuplicateUpstreamName,
    /// An upstream URL is malformed or is not an HTTP(S) origin/base path.
    InvalidUpstreamUrl,
    /// An upstream resolves directly to the proxy listener.
    ProxyLoop,
    /// The listener could not be created.
    BindFailed,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonLoopbackBind => "non-loopback binding requires explicit opt-in",
            Self::ZeroBodyLimit => "request and response body limits must be non-zero",
            Self::ZeroTimeout => "request timeout must be non-zero",
            Self::EmptyAllowlist => "at least one upstream must be allowlisted",
            Self::InvalidUpstreamName => "an upstream name is invalid",
            Self::DuplicateUpstreamName => "upstream names must be unique",
            Self::InvalidUpstreamUrl => "an upstream URL is invalid",
            Self::ProxyLoop => "an upstream points to the proxy listener",
            Self::BindFailed => "the proxy listener could not be created",
        })
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if !self.allow_non_loopback && !self.bind_addr.ip().is_loopback() {
            return Err(ConfigError::NonLoopbackBind);
        }
        if self.max_request_body == 0 || self.max_response_body == 0 {
            return Err(ConfigError::ZeroBodyLimit);
        }
        if self.request_timeout.is_zero() {
            return Err(ConfigError::ZeroTimeout);
        }
        if self.upstreams.is_empty() {
            return Err(ConfigError::EmptyAllowlist);
        }

        let mut names = HashSet::with_capacity(self.upstreams.len());
        for upstream in &self.upstreams {
            if upstream.name.is_empty()
                || !upstream
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(ConfigError::InvalidUpstreamName);
            }
            if !names.insert(upstream.name.as_str()) {
                return Err(ConfigError::DuplicateUpstreamName);
            }
            validate_url(&upstream.base_url)?;
        }
        Ok(())
    }
}

fn validate_url(url: &Url) -> Result<(), ConfigError> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::InvalidUpstreamUrl);
    }
    Ok(())
}
