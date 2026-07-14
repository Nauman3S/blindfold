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
        _ => {}
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
    sanitizer: &dyn Sanitizer,
) -> Result<(Vec<u8>, Vec<Observation>), ()> {
    let text = std::str::from_utf8(body).map_err(|_| ())?;
    let (text, categories) = sanitizer.sanitize_traced(text).into_parts();
    let mut observations = categories
        .into_iter()
        .map(|category| Observation::new(category, "/sse"))
        .collect::<Vec<_>>();
    let mut output = String::with_capacity(text.len());

    for segment in text.split_inclusive('\n') {
        let line = segment.strip_suffix('\n').unwrap_or(segment);
        let ending = if segment.ends_with('\n') { "\n" } else { "" };
        if let Some(data) = line.strip_prefix("data:") {
            let padding = if data.starts_with(' ') { " " } else { "" };
            let payload = data.strip_prefix(' ').unwrap_or(data);
            let mut json: Value = serde_json::from_str(payload).map_err(|_| ())?;
            observations.extend(sanitize_json(Provider::Anthropic, &mut json, sanitizer)?);
            output.push_str("data:");
            output.push_str(padding);
            output.push_str(&serde_json::to_string(&json).map_err(|_| ())?);
        } else if line.is_empty() || line.starts_with("event:") {
            output.push_str(line);
        } else {
            return Err(());
        }
        output.push_str(ending);
    }

    Ok((output.into_bytes(), observations))
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
        let (output, _) = sanitize_sse(body, &sanitizer).map_err(|()| "SSE")?;
        let text = std::str::from_utf8(&output).map_err(|_| "UTF-8")?;
        assert!(!text.contains("raw-secret"));
        assert!(text.contains("[safe]"));
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
