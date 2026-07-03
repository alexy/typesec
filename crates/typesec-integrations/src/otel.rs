//! OpenTelemetry audit sink: one span per policy decision.
//!
//! Enable with the `otel` feature and install process-wide:
//!
//! ```rust,ignore
//! use typesec_core::policy::set_audit_sink;
//! use typesec_integrations::OtelAuditSink;
//!
//! let tracer = opentelemetry::global::tracer("typesec");
//! set_audit_sink(std::sync::Arc::new(OtelAuditSink::new(tracer)));
//! ```
//!
//! Every `mint_capability*` decision then lands in your tracing backend as a
//! `typesec.decision` span with `typesec.subject` / `typesec.action` /
//! `typesec.resource` / `typesec.verdict` (and `typesec.reason` on
//! deny/delegate) attributes, timestamped with the decision time.

use std::time::SystemTime;

use opentelemetry::KeyValue;
use opentelemetry::trace::{Span, Tracer};
use typesec_core::policy::{AuditEvent, AuditSink, PolicyResult};

/// Span name emitted for each decision.
pub const DECISION_SPAN_NAME: &str = "typesec.decision";

/// An [`AuditSink`] that emits one OpenTelemetry span per decision.
///
/// Generic over the tracer so it works with `global::tracer(...)`
/// (`BoxedTracer`) and with SDK tracers alike.
pub struct OtelAuditSink<T> {
    tracer: T,
}

impl<T> OtelAuditSink<T> {
    /// Wrap a tracer as an audit sink.
    pub fn new(tracer: T) -> Self {
        Self { tracer }
    }
}

impl<T> AuditSink for OtelAuditSink<T>
where
    T: Tracer + Send + Sync,
    T::Span: Send + Sync + 'static,
{
    fn record(&self, event: &AuditEvent) {
        let (verdict, reason) = match &event.result {
            PolicyResult::Allow => ("allow", None),
            PolicyResult::Deny(reason) => ("deny", Some(reason.clone())),
            PolicyResult::Delegate(reason) => ("delegate", Some(reason.to_string())),
            _ => ("unknown", None),
        };
        let mut attributes = vec![
            KeyValue::new("typesec.subject", event.subject.to_string()),
            KeyValue::new("typesec.action", event.action.clone()),
            KeyValue::new("typesec.resource", event.resource.to_string()),
            KeyValue::new("typesec.verdict", verdict),
        ];
        if let Some(reason) = reason {
            attributes.push(KeyValue::new("typesec.reason", reason));
        }
        let mut span = self
            .tracer
            .span_builder(DECISION_SPAN_NAME)
            .with_start_time(SystemTime::from(event.timestamp))
            .with_attributes(attributes)
            .start(&self.tracer);
        span.end_with_timestamp(SystemTime::from(event.timestamp));
    }
}

#[cfg(test)]
mod tests;
