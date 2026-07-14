//! Provider-aware JSON text sanitization.

use serde_json::Value;

use blindfold_trace::Category;

use crate::Provider;

/// Sanitized text plus closed detector categories.
pub struct SanitizedText {
    text: String,
    categories: Vec<Category>,
}

impl SanitizedText {
    /// Creates a traced sanitization result.
    #[must_use]
    pub const fn new(text: String, categories: Vec<Category>) -> Self {
        Self { text, categories }
    }

    pub(crate) fn into_parts(self) -> (String, Vec<Category>) {
        (self.text, self.categories)
    }
}

/// Replaces sensitive text before it crosses the proxy boundary.
pub trait Sanitizer: Send + Sync + 'static {
    /// Sanitizes one complete text field.
    fn sanitize(&self, text: &str) -> String;

    /// Sanitizes text and reports only closed replacement categories.
    ///
    /// Implementations without category metadata receive a safe generic category
    /// when the output differs.
    fn sanitize_traced(&self, text: &str) -> SanitizedText {
        let sanitized = self.sanitize(text);
        let categories = if sanitized == text {
            Vec::new()
        } else {
            vec![Category::Sensitive]
        };
        SanitizedText::new(sanitized, categories)
    }
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
}

pub(crate) fn sanitize_json(
    _provider: Provider,
    value: &mut Value,
    sanitizer: &dyn Sanitizer,
) -> Result<Vec<Observation>, ()> {
    let mut observations = Vec::new();
    sanitize_textual_leaves(value, sanitizer, "", &mut observations)?;
    Ok(observations)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Observation {
    pub(crate) category: Category,
    pub(crate) pointer: String,
}

impl Observation {
    pub(crate) fn new(category: Category, pointer: impl Into<String>) -> Self {
        Self {
            category,
            pointer: pointer.into(),
        }
    }
}

fn sanitize_textual_leaves(
    value: &mut Value,
    sanitizer: &dyn Sanitizer,
    pointer: &str,
    observations: &mut Vec<Observation>,
) -> Result<(), ()> {
    match value {
        Value::String(text) => sanitize_string(text, sanitizer, pointer, observations),
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                sanitize_textual_leaves(
                    item,
                    sanitizer,
                    &format!("{pointer}/{index}"),
                    observations,
                )?;
            }
        }
        Value::Object(object) => {
            for (key, field) in object {
                if sanitizer.sanitize(key) != *key {
                    return Err(());
                }
                let key = key.replace('~', "~0").replace('/', "~1");
                sanitize_textual_leaves(
                    field,
                    sanitizer,
                    &format!("{pointer}/{key}"),
                    observations,
                )?;
            }
        }
        Value::Number(number) => {
            let text = number.to_string();
            if sanitizer.sanitize(&text) != text {
                return Err(());
            }
        }
        Value::Null | Value::Bool(_) => {}
    }
    Ok(())
}

fn sanitize_string(
    text: &mut String,
    sanitizer: &dyn Sanitizer,
    pointer: &str,
    observations: &mut Vec<Observation>,
) {
    let (replacement, categories) = sanitizer.sanitize_traced(text).into_parts();
    for category in categories {
        observations.push(Observation {
            category,
            pointer: pointer.to_owned(),
        });
    }
    *text = replacement;
}

pub(crate) fn sanitize_sse(
    body: &[u8],
    provider: Provider,
    sanitizer: &dyn Sanitizer,
) -> Result<(Vec<u8>, Vec<Observation>), ()> {
    let text = std::str::from_utf8(body).map_err(|_| ())?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut observations = Vec::new();
    let mut output = String::with_capacity(normalized.len());
    let mut event = SseEvent::default();

    for line in normalized.split('\n') {
        if line.is_empty() {
            event.write_sanitized(&mut output, provider, sanitizer, &mut observations)?;
            continue;
        }
        event.push(line);
    }
    event.write_sanitized(&mut output, provider, sanitizer, &mut observations)?;

    Ok((output.into_bytes(), observations))
}

#[derive(Default)]
struct SseEvent {
    event: Option<String>,
    id: Option<String>,
    retry: Option<String>,
    data: Vec<String>,
}

impl SseEvent {
    fn push(&mut self, line: &str) {
        if line.starts_with(':') {
            return;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => self.event = Some(value.to_owned()),
            "data" => self.data.push(value.to_owned()),
            "id" if !value.contains('\0') => self.id = Some(value.to_owned()),
            "retry" if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
                self.retry = Some(value.to_owned());
            }
            _ => {}
        }
    }

    fn write_sanitized(
        &mut self,
        output: &mut String,
        provider: Provider,
        sanitizer: &dyn Sanitizer,
        observations: &mut Vec<Observation>,
    ) -> Result<(), ()> {
        if self.event.is_none() && self.id.is_none() && self.retry.is_none() && self.data.is_empty()
        {
            return Ok(());
        }

        if let Some(event) = self.event.take() {
            write_sse_text_field(
                output,
                "event",
                &event,
                sanitizer,
                "/sse/event",
                observations,
            )?;
        }
        if let Some(id) = self.id.take() {
            write_sse_text_field(output, "id", &id, sanitizer, "/sse/id", observations)?;
        }
        if let Some(retry) = self.retry.take() {
            if sanitizer.sanitize(&retry) != retry {
                return Err(());
            }
            output.push_str("retry: ");
            output.push_str(&retry);
            output.push('\n');
        }
        if !self.data.is_empty() {
            let payload = self.data.join("\n");
            self.data.clear();
            if provider == Provider::OpenAi && payload == "[DONE]" {
                output.push_str("data: [DONE]\n\n");
                return Ok(());
            }
            let mut json: Value = serde_json::from_str(&payload).map_err(|_| ())?;
            observations.extend(sanitize_json(provider, &mut json, sanitizer)?);
            output.push_str("data: ");
            output.push_str(&serde_json::to_string(&json).map_err(|_| ())?);
            output.push('\n');
        }
        output.push('\n');
        Ok(())
    }
}

fn write_sse_text_field(
    output: &mut String,
    name: &str,
    value: &str,
    sanitizer: &dyn Sanitizer,
    pointer: &str,
    observations: &mut Vec<Observation>,
) -> Result<(), ()> {
    let (safe, categories) = sanitizer.sanitize_traced(value).into_parts();
    if safe.contains(['\r', '\n', '\0']) {
        return Err(());
    }
    observations.extend(
        categories
            .into_iter()
            .map(|category| Observation::new(category, pointer)),
    );
    output.push_str(name);
    output.push_str(": ");
    output.push_str(&safe);
    output.push('\n');
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ExactValueSanitizer, sanitize_json, sanitize_sse};
    use crate::Provider;

    #[test]
    fn sanitizes_every_openai_string_value() -> Result<(), &'static str> {
        let sanitizer = ExactValueSanitizer::new("raw-secret", "[safe]")?;
        let mut value = json!({
            "model": "raw-secret",
            "messages": [{"role": "user", "content": "use raw-secret"}]
        });
        sanitize_json(Provider::OpenAi, &mut value, &sanitizer).map_err(|()| "JSON")?;
        assert_eq!(value["model"], "[safe]");
        assert_eq!(value["messages"][0]["content"], "use [safe]");
        Ok(())
    }

    #[test]
    fn sanitizes_anthropic_sse_text_delta() -> Result<(), &'static str> {
        let sanitizer = ExactValueSanitizer::new("raw-secret", "[safe]")?;
        let body = b"event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"raw-secret\"}}\n\n";
        let (output, _) =
            sanitize_sse(body, Provider::Anthropic, &sanitizer).map_err(|()| "SSE")?;
        let text = std::str::from_utf8(&output).map_err(|_| "UTF-8")?;
        assert!(!text.contains("raw-secret"));
        assert!(text.contains("[safe]"));
        Ok(())
    }

    #[test]
    fn sanitizes_standard_crlf_sse_framing_and_metadata() -> Result<(), &'static str> {
        let sanitizer = ExactValueSanitizer::new("raw-secret", "[safe]")?;
        let body = b"\xef\xbb\xbf: keepalive raw-secret\r\nid: raw-secret\r\nretry: 1000\r\nevent: content_block_delta\r\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"raw-secret\"}}\r\n\r\n";
        let (output, observations) =
            sanitize_sse(body, Provider::Anthropic, &sanitizer).map_err(|()| "standard SSE")?;
        let text = std::str::from_utf8(&output).map_err(|_| "UTF-8")?;

        assert!(!text.contains("raw-secret"));
        assert!(!text.contains("keepalive"));
        assert!(text.contains("id: [safe]\n"));
        assert!(text.contains("retry: 1000\n"));
        assert!(text.contains("\"text\":\"[safe]\""));
        assert!(
            observations
                .iter()
                .any(|observation| observation.pointer == "/sse/id")
        );
        Ok(())
    }

    #[test]
    fn rejects_non_json_sse_data_and_sensitive_numbers() -> Result<(), &'static str> {
        let sanitizer = ExactValueSanitizer::new("4111111111111111", "[safe]")?;

        assert!(
            sanitize_sse(
                b"event: done\ndata: [DONE]\n\n",
                Provider::Anthropic,
                &sanitizer
            )
            .is_err()
        );
        assert!(
            sanitize_sse(
                b"event: number\ndata: {\"account\":4111111111111111}\n\n",
                Provider::Anthropic,
                &sanitizer
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn sanitizes_openai_sse_and_accepts_only_exact_done() -> Result<(), &'static str> {
        let sanitizer = ExactValueSanitizer::new("raw-secret", "[safe]")?;
        let body = b"data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"raw-secret\"}}]}\n\ndata: [DONE]\n\n";
        let (output, observations) =
            sanitize_sse(body, Provider::OpenAi, &sanitizer).map_err(|()| "OpenAI SSE")?;
        let text = std::str::from_utf8(&output).map_err(|_| "UTF-8")?;

        assert!(!text.contains("raw-secret"));
        assert!(text.contains("[safe]"));
        assert!(text.ends_with("data: [DONE]\n\n"));
        assert!(!observations.is_empty());
        assert!(sanitize_sse(b"data: [DONE] \n\n", Provider::OpenAi, &sanitizer).is_err());
        Ok(())
    }

    #[test]
    fn sanitizes_openai_nested_tool_arguments() -> Result<(), &'static str> {
        let sanitizer = ExactValueSanitizer::new("raw-secret", "[safe]")?;
        let mut value = json!({
            "model": "raw-secret",
            "messages": [{
                "role": "assistant",
                "tool_calls": [{
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "arguments": "{\"query\":\"raw-secret\",\"nested\":{\"note\":\"raw-secret\"}}"
                    }
                }]
            }],
            "output": [{
                "type": "function_call",
                "arguments": {"query": "raw-secret", "nested": ["raw-secret"]}
            }]
        });
        sanitize_json(Provider::OpenAi, &mut value, &sanitizer).map_err(|()| "JSON")?;
        assert_eq!(value["model"], "[safe]");
        assert_eq!(
            value["messages"][0]["tool_calls"][0]["function"]["arguments"],
            "{\"query\":\"[safe]\",\"nested\":{\"note\":\"[safe]\"}}"
        );
        assert_eq!(value["output"][0]["arguments"]["query"], "[safe]");
        assert_eq!(value["output"][0]["arguments"]["nested"][0], "[safe]");
        Ok(())
    }

    #[test]
    fn sanitizes_anthropic_tool_input_and_json_delta() -> Result<(), &'static str> {
        let sanitizer = ExactValueSanitizer::new("raw-secret", "[safe]")?;
        let mut value = json!({
            "model": "raw-secret",
            "content": [{
                "type": "tool_use",
                "name": "lookup",
                "input": {
                    "query": "raw-secret",
                    "nested": ["raw-secret", {"note": "raw-secret"}]
                }
            }],
            "delta": {
                "type": "input_json_delta",
                "partial_json": "{\"query\":\"raw-secret\"}"
            }
        });
        sanitize_json(Provider::Anthropic, &mut value, &sanitizer).map_err(|()| "JSON")?;
        assert_eq!(value["model"], "[safe]");
        assert_eq!(value["content"][0]["input"]["query"], "[safe]");
        assert_eq!(value["content"][0]["input"]["nested"][0], "[safe]");
        assert_eq!(value["content"][0]["input"]["nested"][1]["note"], "[safe]");
        assert_eq!(value["delta"]["partial_json"], "{\"query\":\"[safe]\"}");
        Ok(())
    }
}
