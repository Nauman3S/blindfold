use std::fmt;

/// Severity for a safe operational event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EventLevel {
    /// Detailed development information containing safe metadata only.
    Debug,
    /// Normal operational information.
    Info,
    /// A degraded or suspicious condition.
    Warning,
    /// An operation failed.
    Error,
}

/// A field that has been explicitly reviewed as safe to log.
///
/// Construction accepts only static keys and values. Dynamic paths, labels, payloads,
/// command arguments, and secret-derived strings must not be converted into this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafeField {
    key: &'static str,
    value: &'static str,
}

impl SafeField {
    /// Creates a reviewed static log field.
    #[must_use]
    pub const fn new(key: &'static str, value: &'static str) -> Self {
        Self { key, value }
    }

    /// Returns the static field key.
    #[must_use]
    pub const fn key(self) -> &'static str {
        self.key
    }

    /// Returns the static field value.
    #[must_use]
    pub const fn value(self) -> &'static str {
        self.value
    }
}

/// A structured event whose printable state is restricted to reviewed static text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeEvent {
    level: EventLevel,
    name: &'static str,
    message: &'static str,
    fields: Vec<SafeField>,
}

impl SafeEvent {
    /// Creates a safe event.
    #[must_use]
    pub fn new(
        level: EventLevel,
        name: &'static str,
        message: &'static str,
        fields: impl IntoIterator<Item = SafeField>,
    ) -> Self {
        Self {
            level,
            name,
            message,
            fields: fields.into_iter().collect(),
        }
    }

    /// Returns the event severity.
    #[must_use]
    pub const fn level(&self) -> EventLevel {
        self.level
    }

    /// Returns the stable event name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the safe static message.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// Returns reviewed static fields.
    #[must_use]
    pub fn fields(&self) -> &[SafeField] {
        &self.fields
    }
}

impl fmt::Display for SafeEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "level={:?} event={} message={}",
            self.level, self.name, self.message
        )?;
        for field in &self.fields {
            write!(formatter, " {}={}", field.key, field.value)?;
        }
        Ok(())
    }
}

/// Consumer for safe structured operational events.
pub trait SafeEventSink {
    /// Records an event containing only reviewed safe metadata.
    fn record(&self, event: &SafeEvent);
}

#[cfg(test)]
mod tests {
    use super::{EventLevel, SafeEvent, SafeField};

    #[test]
    fn formats_only_static_reviewed_state() {
        let event = SafeEvent::new(
            EventLevel::Info,
            "proxy.started",
            "local proxy started",
            [SafeField::new("bind_scope", "loopback")],
        );

        assert_eq!(
            event.to_string(),
            "level=Info event=proxy.started message=local proxy started bind_scope=loopback"
        );
    }
}
