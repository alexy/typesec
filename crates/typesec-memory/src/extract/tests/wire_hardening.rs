use super::*;
use crate::EntityRef;

#[test]
fn cognition_proposal_rejects_unknown_draft_fields() {
    assert_nested_unknown_rejected("draft", |value| {
        insert_unknown(&mut value["drafts"][0]);
    });
}

#[test]
fn cognition_proposal_rejects_unknown_content_fields() {
    assert_nested_unknown_rejected("content", |value| {
        insert_unknown(&mut value["drafts"][0]["content"]);
    });
}

#[test]
fn cognition_proposal_rejects_unknown_entity_fields() {
    assert_nested_unknown_rejected("entity", |value| {
        insert_unknown(&mut value["drafts"][0]["entities"][0]);
    });
}

#[test]
fn cognition_proposal_rejects_unknown_plan_fields() {
    assert_nested_unknown_rejected("plan", |value| {
        insert_unknown(&mut value["plan"]);
    });
}

#[test]
fn cognition_proposal_rejects_unknown_step_fields() {
    assert_nested_unknown_rejected("step", |value| {
        insert_unknown(&mut value["plan"]["steps"][0]["Supersede"]);
    });
}

#[test]
fn cognition_proposal_rejects_unknown_provenance_fields() {
    assert_nested_unknown_rejected("provenance", |value| {
        insert_unknown(&mut value["drafts"][0]["provenance"]);
    });
}

fn assert_nested_unknown_rejected(name: &str, mutate: impl FnOnce(&mut serde_json::Value)) {
    let mut value = proposal_value();
    serde_json::from_value::<CognitionProposal>(value.clone())
        .unwrap_or_else(|error| panic!("valid nested proposal wire format failed: {error}"));
    mutate(&mut value);
    assert!(
        serde_json::from_value::<CognitionProposal>(value).is_err(),
        "accepted unknown {name} field"
    );
}

fn insert_unknown(value: &mut serde_json::Value) {
    value
        .as_object_mut()
        .expect("nested proposal object")
        .insert("authorizationOverride".into(), serde_json::json!(true));
}

fn proposal_value() -> serde_json::Value {
    let source = MemoryId::from_string("mem-source");
    let draft = MemoryDraft::new(
        MemoryKind::Semantic,
        MemoryContent::text("derived summary"),
        Provenance::GuardedTool {
            tool: "trusted-tool".into(),
            call_id: Some("call-1".into()),
        },
    )
    .with_entities([EntityRef::new("Alice", "person")]);
    let proposal = CognitionProposal::new(
        "job-1",
        digest('1'),
        digest('2'),
        "community-summary",
        "model-v3",
        vec![source.clone()],
        Label::Internal,
    )
    .with_drafts(vec![draft.clone()])
    .with_plan(ConsolidationPlan::new().then(ConsolidationStep::Supersede {
        superseded: vec![source],
        replacement: draft,
    }));
    serde_json::to_value(proposal).expect("proposal JSON")
}
