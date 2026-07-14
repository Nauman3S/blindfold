//! Public, non-reflective proxy errors.

use std::fmt;

use axum::{
    body::Body,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};

/// Stable error codes suitable for safe logs and client handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    /// The selected upstream is not allowlisted.
    UpstreamNotAllowed,
    /// The request appears to have already traversed this proxy.
    ProxyLoop,
    /// The request body exceeds the configured limit.
    RequestTooLarge,
    /// The upstream response exceeds the configured limit.
    ResponseTooLarge,
    /// A supported JSON endpoint received invalid JSON.
    InvalidJson,
    /// The request cannot be represented safely upstream.
    InvalidRequest,
    /// A URL path, query, or non-provider-authentication header contains sensitive content.
    SensitiveMetadata,
    /// The transport cannot be inspected by this application proxy.
    UnsupportedTransport,
    /// The upstream exchange exceeded its deadline.
    Timeout,
    /// The operation was cancelled.
    Cancelled,
    /// The allowlisted upstream could not complete the exchange.
    UpstreamFailure,
}

impl ErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::UpstreamNotAllowed => "upstream_not_allowed",
            Self::ProxyLoop => "proxy_loop",
            Self::RequestTooLarge => "request_too_large",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidJson => "invalid_json",
            Self::InvalidRequest => "invalid_request",
            Self::SensitiveMetadata => "sensitive_metadata",
            Self::UnsupportedTransport => "unsupported_transport",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::UpstreamFailure => "upstream_failure",
        }
    }
}

/// A proxy error containing only a stable, non-sensitive classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyError {
    code: ErrorCode,
}

impl ProxyError {
    pub(crate) const fn new(code: ErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable classification for safe structured logging.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        self.code
    }

    const fn status(self) -> StatusCode {
        match self.code {
            ErrorCode::UpstreamNotAllowed => StatusCode::NOT_FOUND,
            ErrorCode::ProxyLoop => StatusCode::LOOP_DETECTED,
            ErrorCode::RequestTooLarge | ErrorCode::ResponseTooLarge => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            ErrorCode::InvalidJson
            | ErrorCode::InvalidRequest
            | ErrorCode::SensitiveMetadata
            | ErrorCode::UnsupportedTransport => StatusCode::BAD_REQUEST,
            ErrorCode::Timeout => StatusCode::GATEWAY_TIMEOUT,
            ErrorCode::Cancelled => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::UpstreamFailure => StatusCode::BAD_GATEWAY,
        }
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for ProxyError {}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let body = format!(
            r#"{{"error":{{"code":"{}","message":"{}"}}}}"#,
            self.code.as_str(),
            self.code.message()
        );
        Response::builder()
            .status(self.status())
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }
}

impl ErrorCode {
    const fn message(self) -> &'static str {
        match self {
            Self::UpstreamNotAllowed => "proxy route is not allowlisted",
            Self::ProxyLoop => "proxy loop rejected",
            Self::RequestTooLarge => "request body is too large",
            Self::ResponseTooLarge => "upstream response is too large",
            Self::InvalidJson => "JSON or supported SSE payload could not be sanitized",
            Self::InvalidRequest => "request method or content type is unsupported",
            Self::SensitiveMetadata => "request metadata contains sensitive content",
            Self::UnsupportedTransport => "request transport is unsupported and was not forwarded",
            Self::Timeout => "upstream exchange timed out",
            Self::Cancelled => "proxy exchange was cancelled",
            Self::UpstreamFailure => "upstream response could not be sanitized or completed",
        }
    }
}
