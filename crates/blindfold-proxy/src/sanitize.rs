//! Provider-aware JSON text sanitization.

use serde_json::Value;

use crate::Provider;

/// Replaces sensitive text before it crosses the proxy boundary.
///
/// `required_overlap` is the number of trailing raw bytes a streaming adapter
/// must retain to detect a value split at a boundary.
pub trait Sanitizer: Send + Sync + 'static {
    /// Sanitizes one complete text field.
    fn sanitize(&self, text: &str) -> String;

    /// Returns the required raw-byte overlap for split-boundary detection.
    fn required_overlap(&self) -> usize;
}

/// A deterministic sanitizer for tests and exact-value policies.
#[derive(Clone, Debug)]
pub struct ExactValueSanitizer {
    value: String,
    replacement: String,
}

impl ExactValueSanitizer {
    /// Creates a sanitizer that replaces every exact, non-empty value.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is empty.
    pub fn new(
        value: impl Into<String>,
        replacement: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty() {
            return Err("exact sanitizer value must not be empty");
        }
        Ok(Self {
            value,
            replacement: replacement.into(),
        })
    }
}

impl Sanitizer for ExactValueSanitizer {
    fn sanitize(&self, text: &str) -> String {
        text.replace(&self.value, &self.replacement)
    }

    fn required_overlap(&self) -> usize {
        self.value.len().saturating_sub(1)
    }
}

pub(crate) fn sanitize_json(provider: Provider, value: &mut Value, sanitizer: &dyn Sanitizer) {
    match provider {
        Provider::OpenAi => sanitize_openai(value, sanitizer),
        Provider::Anthropic => sanitize_anthropic(value, sanitizer),
    }
}

fn sanitize_openai(value: &mut Value, sanitizer: &dyn Sanitizer) {
    let Value::Object(object) = value else {
        return;
    };

    for key in ["prompt", "input", "instructions", "output_text"] {
        if let Some(field) = object.get_mut(key) {
            sanitize_text_value(field, sanitizer);
        }
    }
    for key in ["messages", "choices", "output"] {
        if let Some(Value::Array(items)) = object.get_mut(key) {
            for item in items {
                sanitize_openai(item, sanitizer);
            }
        }
    }
    for key in ["message", "delta"] {
        if let Some(field) = object.get_mut(key) {
            sanitize_openai(field, sanitizer);
        }
    }
    if let Some(content) = object.get_mut("content") {
        sanitize_text_value(content, sanitizer);
    }
    if matches!(
        object.get("type").and_then(Value::as_str),
        Some("input_text" | "output_text")
    ) && let Some(text) = object.get_mut("text")
    {
        sanitize_text_value(text, sanitizer);
    }
}

fn sanitize_anthropic(value: &mut Value, sanitizer: &dyn Sanitizer) {
    let Value::Object(object) = value else {
        return;
    };

    if let Some(system) = object.get_mut("system") {
        sanitize_text_value(system, sanitizer);
    }
    for key in ["messages", "content"] {
        if let Some(Value::Array(items)) = object.get_mut(key) {
            for item in items {
                sanitize_anthropic(item, sanitizer);
            }
        }
    }
    for key in ["delta", "message"] {
        if let Some(field) = object.get_mut(key) {
            sanitize_anthropic(field, sanitizer);
        }
    }
    if matches!(
        object.get("type").and_then(Value::as_str),
        Some("text" | "text_delta" | "input_text")
    ) && let Some(text) = object.get_mut("text")
    {
        sanitize_text_value(text, sanitizer);
    }
    if let Some(Value::String(content)) = object.get_mut("content") {
        *content = sanitizer.sanitize(content);
    }
}

fn sanitize_text_value(value: &mut Value, sanitizer: &dyn Sanitizer) {
    match value {
        Value::String(text) => *text = sanitizer.sanitize(text),
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::String(text) => *text = sanitizer.sanitize(text),
                    Value::Object(_) => {
                        if let Some(text) = item.get_mut("text") {
                            sanitize_text_value(text, sanitizer);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn sanitize_sse(
    provider: Provider,
    body: &[u8],
    sanitizer: &dyn Sanitizer,
) -> Result<Vec<u8>, ()> {
    let text = std::str::from_utf8(body).map_err(|_| ())?;
    let mut output = String::with_capacity(text.len());

    for segment in text.split_inclusive('\n') {
        let line = segment.strip_suffix('\n').unwrap_or(segment);
        let ending = if segment.ends_with('\n') { "\n" } else { "" };
        if let Some(data) = line.strip_prefix("data:") {
            let padding = if data.starts_with(' ') { " " } else { "" };
            let payload = data.strip_prefix(' ').unwrap_or(data);
            if payload == "[DONE]" {
                output.push_str(line);
            } else {
                let mut json: Value = serde_json::from_str(payload).map_err(|_| ())?;
                sanitize_json(provider, &mut json, sanitizer);
                output.push_str("data:");
                output.push_str(padding);
                output.push_str(&serde_json::to_string(&json).map_err(|_| ())?);
            }
        } else {
            output.push_str(line);
        }
        output.push_str(ending);
    }

    Ok(output.into_bytes())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ExactValueSanitizer, sanitize_json, sanitize_sse};
    use crate::Provider;

    #[test]
    fn sanitizes_openai_text_without_touching_metadata() -> Result<(), &'static str> {
        let sanitizer = ExactValueSanitizer::new("raw-secret", "[safe]")?;
        let mut value = json!({
            "model": "raw-secret",
            "messages": [{"role": "user", "content": "use raw-secret"}]
        });
        sanitize_json(Provider::OpenAi, &mut value, &sanitizer);
        assert_eq!(value["model"], "raw-secret");
        assert_eq!(value["messages"][0]["content"], "use [safe]");
        Ok(())
    }

    #[test]
    fn sanitizes_anthropic_sse_text_delta() -> Result<(), &'static str> {
        let sanitizer = ExactValueSanitizer::new("raw-secret", "[safe]")?;
        let body = b"event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"raw-secret\"}}\n\n";
        let output = sanitize_sse(Provider::Anthropic, body, &sanitizer).map_err(|()| "SSE")?;
        let text = std::str::from_utf8(&output).map_err(|_| "UTF-8")?;
        assert!(!text.contains("raw-secret"));
        assert!(text.contains("[safe]"));
        Ok(())
    }
}
