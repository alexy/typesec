use super::*;
use typesec_core::policy::DelegationReason;

const OLD_POLICY: &str = r#"
roles:
  - name: analyst
    permissions: [read, write]
    resources: ["reports/*"]
assignments:
  - subject: "agent:analyst"
    roles: [analyst]
"#;

/// The edited policy revokes `write`.
const NEW_POLICY: &str = r#"
roles:
  - name: analyst
    permissions: [read]
    resources: ["reports/*"]
assignments:
  - subject: "agent:analyst"
    roles: [analyst]
"#;

fn record(action: &str, decision: &str) -> DecisionRecord {
    DecisionRecord {
        ts: "2026-07-03T00:00:00.000Z".into(),
        subject: "agent:analyst".into(),
        action: action.into(),
        resource: "reports/q1".into(),
        purpose: None,
        decision: decision.into(),
        reason: None,
    }
}

#[test]
fn replay_flags_only_changed_verdicts() {
    let engine = typesec_rbac::RbacEngine::from_yaml(NEW_POLICY).expect("policy parses");
    let (replayed, changes) = replay_records(
        &engine,
        vec![record("read", "allow"), record("write", "allow")],
    );
    assert_eq!(replayed, 2);
    assert_eq!(changes.len(), 1, "only the revoked write changes");
    assert_eq!(changes[0].record.action, "write");
    assert_eq!(changes[0].new_decision, "deny");
    assert!(changes[0].new_reason.is_some());
}

#[test]
fn replay_is_clean_when_the_policy_is_unchanged() {
    let engine = typesec_rbac::RbacEngine::from_yaml(OLD_POLICY).expect("policy parses");
    let (replayed, changes) = replay_records(
        &engine,
        vec![record("read", "allow"), record("write", "allow")],
    );
    assert_eq!(replayed, 2);
    assert!(changes.is_empty());
}

#[test]
fn decision_parts_covers_all_verdicts() {
    assert_eq!(decision_parts(&PolicyResult::Allow), ("allow", None));
    let (kind, reason) = decision_parts(&PolicyResult::Deny("nope".into()));
    assert_eq!(kind, "deny");
    assert_eq!(reason.as_deref(), Some("nope"));
    let (kind, reason) = decision_parts(&PolicyResult::Delegate(DelegationReason::new(
        "rbac",
        "uncovered",
    )));
    assert_eq!(kind, "delegate");
    assert!(reason.unwrap().contains("uncovered"));
}

#[test]
fn records_round_trip_through_jsonl() {
    let record = DecisionRecord::new(
        "agent:analyst",
        "read",
        "reports/q1",
        Some("analytics"),
        &PolicyResult::Allow,
    );
    let line = serde_json::to_string(&record).unwrap();
    let parsed: DecisionRecord = serde_json::from_str(&line).unwrap();
    assert_eq!(parsed.subject, "agent:analyst");
    assert_eq!(parsed.purpose.as_deref(), Some("analytics"));
    assert_eq!(parsed.decision, "allow");
}
