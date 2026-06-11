//! Scoped MCP JSON-RPC protection for newline-delimited stdio transports.
//!
//! This preview transforms individual JSON-RPC messages. It does not implement network
//! transports, process supervision, MCP capability negotiation, or an OS sandbox.

#![forbid(unsafe_code)]

use std::fmt;

use blindfold_core::{SafeRef, SecretValue};
use serde_json::Value;

/// Direction of one MCP message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Agent/client message being sent to a trusted MCP server.
    ToServer,
    /// MCP server message being returned to an untrusted agent/client.
    ToAgent,
}

/// Safe metadata emitted for one transformed message.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Audit {
    /// Number of references restored into approved server argument fields.
    pub restored: usize,
    /// Number of strings sanitized before returning to the agent.
    pub sanitized: usize,
    /// Number of references rejected because their field was not approved.
    pub rejected: usize,
}

/// Scoped `SafeRef` resolver used only for approved server-bound fields.
pub trait Resolver {
    /// Returns whether one JSON pointer may receive plaintext for this tool call.
    fn allows(&self, server: &str, tool: &str, pointer: &str) -> bool;

    /// Resolves an authenticated, scoped reference.
    ///
    /// Returning `None` rejects forged, expired, cross-scope, or unknown references.
    fn resolve(&self, safe_ref: &SafeRef) -> Option<SecretValue>;
}

/// Sanitizer for server responses and error text.
pub trait Sanitizer {
    /// Replaces sensitive content and returns replacement count.
    fn sanitize(&self, text: &str) -> (String, usize);
}

/// Safely reportable MCP transformation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Input was not one bounded JSON object.
    InvalidJson,
    /// A `SafeRef` appeared outside an approved field or could not be resolved.
    ReferenceRejected,
    /// The transformed message exceeded the configured maximum.
    MessageTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidJson => "invalid MCP JSON-RPC message",
            Self::ReferenceRejected => "MCP reference resolution was rejected",
            Self::MessageTooLarge => "MCP message exceeds the configured size limit",
        })
    }
}

impl std::error::Error for Error {}

/// Stateless transformer for MCP stdio JSON-RPC messages.
pub struct Transformer<R, S> {
    resolver: R,
    sanitizer: S,
    max_bytes: usize,
}

impl<R, S> Transformer<R, S>
where
    R: Resolver,
    S: Sanitizer,
{
    /// Creates a transformer with a required non-zero byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MessageTooLarge`] when the limit is zero.
    pub fn new(resolver: R, sanitizer: S, max_bytes: usize) -> Result<Self, Error> {
        if max_bytes == 0 {
            return Err(Error::MessageTooLarge);
        }
        Ok(Self {
            resolver,
            sanitizer,
            max_bytes,
        })
    }

    /// Transforms one newline-delimited JSON-RPC message.
    ///
    /// Server-bound resolution is limited to `tools/call` argument fields explicitly
    /// approved by the resolver. Agent-bound messages recursively sanitize every string,
    /// including tool descriptions and error data.
    ///
    /// # Errors
    ///
    /// Returns a safe [`Error`] for malformed, oversized, forged, or unauthorized input.
    pub fn transform(
        &self,
        direction: Direction,
        server: &str,
        input: &str,
    ) -> Result<(String, Audit), Error> {
        if input.len() > self.max_bytes {
            return Err(Error::MessageTooLarge);
        }
        let mut value: Value = serde_json::from_str(input).map_err(|_| Error::InvalidJson)?;
        if !value.is_object() {
            return Err(Error::InvalidJson);
        }
        let mut audit = Audit::default();
        match direction {
            Direction::ToServer => self.restore_server_message(server, &mut value, &mut audit)?,
            Direction::ToAgent => sanitize_value(&self.sanitizer, &mut value, &mut audit),
        }
        let output = serde_json::to_string(&value).map_err(|_| Error::InvalidJson)?;
        if output.len() > self.max_bytes {
            return Err(Error::MessageTooLarge);
        }
        Ok((output, audit))
    }

    fn restore_server_message(
        &self,
        server: &str,
        value: &mut Value,
        audit: &mut Audit,
    ) -> Result<(), Error> {
        let method = value.get("method").and_then(Value::as_str);
        if method != Some("tools/call") {
            return reject_any_reference(value, audit);
        }
        let tool = value
            .pointer("/params/name")
            .and_then(Value::as_str)
            .ok_or(Error::InvalidJson)?
            .to_owned();
        let arguments = value
            .pointer_mut("/params/arguments")
            .ok_or(Error::InvalidJson)?;
        restore_value(
            &self.resolver,
            &self.sanitizer,
            server,
            &tool,
            "/params/arguments",
            arguments,
            audit,
        )
    }
}

fn restore_value<R: Resolver, S: Sanitizer>(
    resolver: &R,
    sanitizer: &S,
    server: &str,
    tool: &str,
    pointer: &str,
    value: &mut Value,
    audit: &mut Audit,
) -> Result<(), Error> {
    match value {
        Value::String(text) => {
            let Ok(safe_ref) = SafeRef::parse(text) else {
                let (replacement, count) = sanitizer.sanitize(text);
                *text = replacement;
                audit.sanitized += count;
                return Ok(());
            };
            if !resolver.allows(server, tool, pointer) {
                audit.rejected += 1;
                return Err(Error::ReferenceRejected);
            }
            let Some(secret) = resolver.resolve(&safe_ref) else {
                audit.rejected += 1;
                return Err(Error::ReferenceRejected);
            };
            secret.expose_secret().clone_into(text);
            audit.restored += 1;
        }
        Value::Array(values) => {
            for (index, child) in values.iter_mut().enumerate() {
                restore_value(
                    resolver,
                    sanitizer,
                    server,
                    tool,
                    &format!("{pointer}/{index}"),
                    child,
                    audit,
                )?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                restore_value(
                    resolver,
                    sanitizer,
                    server,
                    tool,
                    &format!("{pointer}/{}", escape_pointer(key)),
                    child,
                    audit,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_any_reference(value: &Value, audit: &mut Audit) -> Result<(), Error> {
    match value {
        Value::String(text) if SafeRef::parse(text).is_ok() => {
            audit.rejected += 1;
            Err(Error::ReferenceRejected)
        }
        Value::Array(values) => {
            for child in values {
                reject_any_reference(child, audit)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for child in values.values() {
                reject_any_reference(child, audit)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn sanitize_value<S: Sanitizer>(sanitizer: &S, value: &mut Value, audit: &mut Audit) {
    match value {
        Value::String(text) => {
            let (replacement, count) = sanitizer.sanitize(text);
            *text = replacement;
            audit.sanitized += count;
        }
        Value::Array(values) => {
            for child in values {
                sanitize_value(sanitizer, child, audit);
            }
        }
        Value::Object(values) => {
            for child in values.values_mut() {
                sanitize_value(sanitizer, child, audit);
            }
        }
        _ => {}
    }
}

fn escape_pointer(input: &str) -> String {
    input.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use blindfold_core::{SafeRef, SafeRefKind, SecretValue};

    use super::{Direction, Error, Resolver, Sanitizer, Transformer};

    const REFERENCE: &str = "{{BLINDFOLD:v1:SECRET:0123456789abcdef0123456789abcdef}}";
    const RAW: &str = "sk-test-blindfold-fake-value";

    struct ScopedResolver;

    impl Resolver for ScopedResolver {
        fn allows(&self, server: &str, tool: &str, pointer: &str) -> bool {
            server == "demo" && tool == "customers" && pointer == "/params/arguments/api_key"
        }

        fn resolve(&self, safe_ref: &SafeRef) -> Option<SecretValue> {
            (safe_ref.kind() == SafeRefKind::Secret).then(|| SecretValue::new(RAW))
        }
    }

    struct ExactSanitizer;

    impl Sanitizer for ExactSanitizer {
        fn sanitize(&self, text: &str) -> (String, usize) {
            (text.replace(RAW, "[REDACTED]"), text.matches(RAW).count())
        }
    }

    fn transformer() -> Transformer<ScopedResolver, ExactSanitizer> {
        Transformer::new(ScopedResolver, ExactSanitizer, 16 * 1024)
            .unwrap_or_else(|error| unreachable!("valid transformer: {error}"))
    }

    #[test]
    fn resolves_only_approved_tool_field() {
        let input = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"customers","arguments":{{"api_key":"{REFERENCE}"}}}}}}"#
        );
        let (output, audit) = transformer()
            .transform(Direction::ToServer, "demo", &input)
            .unwrap_or_else(|error| unreachable!("approved reference: {error}"));
        assert!(output.contains(RAW));
        assert_eq!(audit.restored, 1);
    }

    #[test]
    fn rejects_reference_in_unapproved_field() {
        let input = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"customers","arguments":{{"query":"{REFERENCE}"}}}}}}"#
        );
        assert_eq!(
            transformer().transform(Direction::ToServer, "demo", &input),
            Err(Error::ReferenceRejected)
        );
    }

    #[test]
    fn sanitizes_all_agent_bound_strings() {
        let input = format!(
            r#"{{"jsonrpc":"2.0","id":1,"error":{{"message":"failed {RAW}","data":{{"description":"use {RAW}"}}}}}}"#
        );
        let (output, audit) = transformer()
            .transform(Direction::ToAgent, "demo", &input)
            .unwrap_or_else(|error| unreachable!("valid response: {error}"));
        assert!(!output.contains(RAW));
        assert_eq!(audit.sanitized, 2);
    }
}
