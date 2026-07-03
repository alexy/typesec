use super::*;
use chrono::{TimeZone, Utc};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
use typesec_core::policy::DelegationReason;
use typesec_core::{ResourceId, SubjectId};

fn event(result: PolicyResult) -> AuditEvent {
    AuditEvent {
        subject: SubjectId::from("agent:analyst"),
        action: "read".into(),
        resource: ResourceId::from("reports/q1"),
        result,
        timestamp: Utc.with_ymd_and_hms(2026, 7, 3, 12, 0, 0).unwrap(),
    }
}

#[test]
fn decisions_become_spans_with_verdict_attributes() {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let sink = OtelAuditSink::new(provider.tracer("typesec-test"));

    sink.record(&event(PolicyResult::Allow));
    sink.record(&event(PolicyResult::Deny("no grant".into())));
    sink.record(&event(PolicyResult::Delegate(DelegationReason::new(
        "rbac",
        "uncovered",
    ))));
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 3);
    for span in &spans {
        assert_eq!(span.name, DECISION_SPAN_NAME);
        let get = |key: &str| {
            span.attributes
                .iter()
                .find(|kv| kv.key.as_str() == key)
                .map(|kv| kv.value.to_string())
        };
        assert_eq!(get("typesec.subject").as_deref(), Some("agent:analyst"));
        assert_eq!(get("typesec.resource").as_deref(), Some("reports/q1"));
        assert!(get("typesec.verdict").is_some());
    }
    let verdicts: Vec<String> = spans
        .iter()
        .map(|span| {
            span.attributes
                .iter()
                .find(|kv| kv.key.as_str() == "typesec.verdict")
                .unwrap()
                .value
                .to_string()
        })
        .collect();
    assert_eq!(verdicts, ["allow", "deny", "delegate"]);
    assert!(
        spans[1]
            .attributes
            .iter()
            .any(|kv| kv.key.as_str() == "typesec.reason" && kv.value.to_string() == "no grant")
    );
}
