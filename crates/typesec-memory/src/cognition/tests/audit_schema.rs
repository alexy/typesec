use super::*;
use chrono::TimeDelta;

#[test]
fn committed_audit_carries_versioned_grant_snapshot_and_phase_evidence() {
    let fixture = Fixture::new();
    let expected_authority = authority_for(&fixture.binding);
    let outcome = fixture
        .vault
        .apply_cognition(
            &fixture.space,
            &fixture.write,
            &fixture.proposal(),
            &fixture.context,
        )
        .expect("valid cognition commit");

    assert_eq!(
        outcome.audit.schema_version,
        CognitionAuditEvidence::SCHEMA_VERSION
    );
    assert_eq!(
        outcome.audit.governed_scan_digest,
        fixture.binding.governed_scan_digest
    );
    assert_eq!(
        outcome.audit.snapshot_digest,
        fixture.binding.snapshot_digest
    );
    assert_ne!(
        outcome.audit.governed_scan_digest,
        outcome.audit.snapshot_digest
    );
    assert_eq!(
        outcome.audit.authority_revalidated_at,
        expected_authority.authority_revalidated_at
    );
    assert!(outcome.audit.authority_revalidated_at <= outcome.audit.prepared_at);
    assert!(outcome.audit.prepared_at <= outcome.committed_at);
}

#[test]
fn recovered_audit_rejects_schema_snapshot_and_phase_tampering() {
    let mutations: [fn(&mut CognitionCommitOutcome); 4] = [
        |outcome| outcome.audit.schema_version += 1,
        |outcome| outcome.audit.snapshot_digest = digest("wrong snapshot"),
        |outcome| {
            outcome.audit.snapshot_digest = outcome.audit.governed_scan_digest.clone();
        },
        |outcome| {
            outcome.audit.authority_revalidated_at =
                outcome.audit.prepared_at + TimeDelta::nanoseconds(1);
        },
    ];

    for mutate in mutations {
        let fixture = Fixture::new();
        let proposal = fixture.proposal();
        fixture
            .vault
            .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
            .expect("initial commit");
        fixture.store.state().preflight_outcome_mutation = Some(mutate);

        assert!(matches!(
            fixture.vault.apply_cognition(
                &fixture.space,
                &fixture.write,
                &proposal,
                &fixture.context
            ),
            Err(MemoryError::CognitionCommit(
                CognitionCommitError::InvalidOutcome
            ))
        ));
    }
}

#[test]
fn newly_applied_outcome_must_return_the_exact_expanded_audit() {
    let mutations: [fn(&mut CognitionCommitOutcome); 3] = [
        |outcome| outcome.audit.schema_version += 1,
        |outcome| outcome.audit.snapshot_digest = digest("wrong snapshot"),
        |outcome| {
            outcome.audit.authority_revalidated_at =
                outcome.audit.prepared_at + TimeDelta::nanoseconds(1);
        },
    ];

    for mutate in mutations {
        let fixture = Fixture::new();
        fixture.store.state().commit_outcome_mutation = Some(mutate);
        assert!(matches!(
            fixture.vault.apply_cognition(
                &fixture.space,
                &fixture.write,
                &fixture.proposal(),
                &fixture.context
            ),
            Err(MemoryError::CognitionCommit(
                CognitionCommitError::InvalidOutcome
            ))
        ));
    }
}

#[test]
fn missing_audit_schema_fails_strict_wire_decoding() {
    let fixture = Fixture::new();
    let outcome = fixture
        .vault
        .apply_cognition(
            &fixture.space,
            &fixture.write,
            &fixture.proposal(),
            &fixture.context,
        )
        .expect("valid cognition commit");
    let mut encoded = serde_json::to_value(outcome).unwrap();
    encoded["audit"]
        .as_object_mut()
        .unwrap()
        .remove("schemaVersion");

    assert!(serde_json::from_value::<CognitionCommitOutcome>(encoded).is_err());
}

#[test]
fn future_authority_time_fails_before_store_access() {
    let fixture = Fixture::new();
    let mut future = authority_for(&fixture.binding);
    future.authority_revalidated_at = DateTime::<Utc>::MAX_UTC;
    fixture.authority.set(future);
    let before_gets = fixture.store.state().get_calls;

    assert!(matches!(
        fixture.vault.apply_cognition(
            &fixture.space,
            &fixture.write,
            &fixture.proposal(),
            &fixture.context
        ),
        Err(MemoryError::Cognition(CognitionApplyError::Authority))
    ));
    assert_eq!(fixture.store.state().recovery_calls, 0);
    assert_eq!(fixture.store.state().get_calls, before_gets);
}

#[test]
fn later_revalidation_recovers_the_original_historical_audit() {
    let fixture = Fixture::new();
    let proposal = fixture.proposal();
    let first = fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
        .expect("initial commit");
    let mut later = authority_for(&fixture.binding);
    later.authority_revalidated_at = first.audit.authority_revalidated_at + TimeDelta::seconds(1);
    later.policy_decision_id = "policy-decision-8".into();
    fixture.authority.set(later);

    let recovered = fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
        .expect("idempotent retry with fresh authority evidence");
    assert_eq!(recovered.status, CognitionCommitStatus::AlreadyApplied);
    assert_eq!(recovered.audit, first.audit);
}
