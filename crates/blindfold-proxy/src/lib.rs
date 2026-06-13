//! A bounded, explicitly configured application-level HTTP proxy.
//!
//! The proxy accepts ordinary HTTP traffic only. It does not implement CONNECT,
//! transparent routing, certificate generation, or TLS interception.

#![forbid(unsafe_code)]

mod config;
mod error;
mod proxy;
mod sanitize;

pub use config::{Config, ConfigError, Provider, Upstream};
pub use error::{ErrorCode, ProxyError};
pub use proxy::{BoundProxy, Proxy, TraceSink};
pub use sanitize::{ExactValueSanitizer, SanitizedText, Sanitizer};
