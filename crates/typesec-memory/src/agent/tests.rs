use super::*;
use crate::InMemoryStore;
use serde_json::json;
use std::sync::Arc;
use typesec_agent::interop::{ToolCallGuard, ToolCallRequest};
use typesec_core::policy::{RequestContext, SubjectId};

const POLICY: &str = r#"
roles:
  - name: keeper
    permissions: [read, write, delete]
    resources: ["memory/**"]
  - name: reader
    permissions: [read]
    resources: ["memory/user:alice/**"]
assignments:
  - subject: "agent:keeper"
    roles: [keeper]
  - subject: "agent:reader"
    roles: [reader]
"#;

fn engine() -> Arc<dyn typesec_core::policy::PolicyEngine> {
    Arc::new(typesec_rbac::RbacEngine::from_yaml(POLICY).expect("policy parses"))
}

fn router() -> MemoryToolRouter<InMemoryStore> {
    MemoryToolRouter::new(MemoryVault::new(InMemoryStore::new()), engine())
}

fn call(tool: &str, args: Value) -> ToolCallRequest {
    ToolCallRequest::new(tool, args)
}

#[test]
fn bindings_map_tools_onto_the_action_resource_plane() {
    let bindings = memory_bindings();
    assert_eq!(bindings.len(), 3);
    let remember = bindings
        .iter()
        .find(|b| b.tool_name == TOOL_REMEMBER)
        .unwrap();
    assert_eq!(remember.action, "write");
    assert_eq!(remember.resource_arg.as_deref(), Some("space"));
    assert_eq!(remember.required_args, ["text"]);
}

#[test]
fn guard_denies_memory_tools_the_subject_cannot_reach() {
    // The reader may only read memory/user:alice/**; a guard built from the
    // memory bindings must deny a write and an out-of-scope read.
    let guard = ToolCallGuard::new(engine());
    let mut guard = guard;
    for binding in memory_bindings() {
        guard = guard.bind(binding);
    }
    let subject = SubjectId::from("agent:reader");
    let ctx = RequestContext::default();

    let read_ok = guard.check(
        &subject,
        call(TOOL_RECALL, json!({"space": "memory/user:alice/profile"})),
        &ctx,
    );
    assert!(read_ok.verdict.is_allowed());

    let write_denied = guard.check(
        &subject,
        call(
            TOOL_REMEMBER,
            json!({"space": "memory/user:alice/profile", "text": "x"}),
        ),
        &ctx,
    );
    assert!(!write_denied.verdict.is_allowed(), "reader cannot write");

    let other_space = guard.check(
        &subject,
        call(TOOL_RECALL, json!({"space": "memory/user:bob/profile"})),
        &ctx,
    );
    assert!(
        !other_space.verdict.is_allowed(),
        "reader cannot read bob's memory"
    );
}

#[test]
fn router_remembers_then_recalls_through_tool_calls() {
    let router = router();
    let ctx = RequestContext::default();

    let remembered = router
        .handle(
            "agent:keeper",
            &call(
                TOOL_REMEMBER,
                json!({"space": "memory/user:alice/profile", "text": "likes espresso", "kind": "profile"}),
            ),
            &ctx,
        )
        .unwrap();
    assert!(remembered["id"].as_str().unwrap().starts_with("mem-"));

    let recalled = router
        .handle(
            "agent:keeper",
            &call(TOOL_RECALL, json!({"space": "memory/user:alice/profile"})),
            &ctx,
        )
        .unwrap();
    let hits = recalled["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["text"], "likes espresso");
}

#[test]
fn router_recall_clearance_redacts_hotter_records() {
    let router = router();
    let ctx = RequestContext::default();
    // Seed a Sensitive record directly via the vault (operator provenance).
    router
        .handle(
            "agent:keeper",
            &call(
                TOOL_REMEMBER,
                json!({"space": "memory/user:alice/profile", "text": "public note"}),
            ),
            &ctx,
        )
        .unwrap();

    // Recall at Public: the Conversation-provenance record defaults to
    // Internal, so it's redacted at a Public ceiling.
    let public = router
        .handle(
            "agent:keeper",
            &call(
                TOOL_RECALL,
                json!({"space": "memory/user:alice/profile", "clearance": "public"}),
            ),
            &ctx,
        )
        .unwrap();
    assert!(public["hits"].as_array().unwrap().is_empty());
    assert_eq!(public["redacted"].as_array().unwrap().len(), 1);
}

#[test]
fn router_denies_when_engine_denies_mint() {
    let router = router();
    let err = router
        .handle(
            "agent:reader",
            &call(
                TOOL_REMEMBER,
                json!({"space": "memory/user:alice/profile", "text": "x"}),
            ),
            &RequestContext::default(),
        )
        .unwrap_err();
    assert!(matches!(err, crate::MemoryError::PolicyDenied { .. }));
}
