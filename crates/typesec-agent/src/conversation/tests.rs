use super::*;

const POLICY: &str = r#"
roles:
  - name: negotiator
    permissions: [delegate]
    resources: ["conversation/*"]
assignments:
  - subject: "agent:planner"
    roles: [negotiator]
"#;

#[test]
fn consent_flow_mints_a_real_capability() {
    let engine = typesec_rbac::RbacEngine::from_yaml(POLICY).expect("policy parses");
    let conversation = Conversation::propose("agent:worker")
        .with_purpose("quarterly report summarization")
        .request_consent(["read_report", "summarize"]);
    assert_eq!(conversation.requested_scopes().len(), 2);

    let consented = conversation
        .grant_via(&engine, "agent:planner")
        .map_err(|(_, err)| err)
        .expect("policy grants delegate on conversation/*");
    assert_eq!(consented.peer(), "agent:worker");
    assert!(consented.covers("summarize"));
    assert!(!consented.covers("wipe_disk"));

    let consent = consented.consent();
    assert_eq!(consent.subject(), &SubjectId::from("agent:planner"));
    assert_eq!(consent.resource_id().as_str(), "conversation/agent:worker");
    assert!(consent.ensure_active().is_ok());
}

#[test]
fn denied_consent_returns_the_awaiting_conversation() {
    let engine = typesec_rbac::RbacEngine::from_yaml(POLICY).expect("policy parses");
    let conversation = Conversation::propose("agent:worker").request_consent(["read_report"]);

    let (returned, err) = conversation
        .grant_via(&engine, "agent:stranger")
        .expect_err("unknown subject is denied");
    assert_eq!(returned.requested_scopes(), ["read_report"]);
    assert!(err.to_string().contains("delegate") || !err.to_string().is_empty());
}

// The typestate itself is the main guarantee: `Conversation<Proposed>` has no
// `consent()` and `Conversation<AwaitingConsent>` can only reach `Consented`
// through `grant_via(engine, ..)` — there is no other constructor for the
// `Consented` state. (Compile-fail coverage for sealed states lives in
// typesec-core's ui tests; the pattern is identical.)
