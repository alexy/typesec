use super::*;
use chrono::{TimeDelta, TimeZone};

#[test]
fn committed_audit_carries_versioned_grant_snapshot_and_phase_evidence() {
    let fixture = Fixture::new();
    let authority_revalidated_at = Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap();
    let prepared_at = authority_revalidated_at + TimeDelta::seconds(1);
    let mut clock = [authority_revalidated_at, prepared_at].into_iter();
    let outcome = fixture
        .vault
        .apply_cognition_with_clock(
            &fixture.space,
            &fixture.write,
            &fixture.proposal(),
            &fixture.context,
            || clock.next().expect("expected cognition phase timestamp"),
        )
        .expect("valid cognition commit");
    assert!(clock.next().is_none());

    assert_eq!(
        outcome.audit.schema_version,
        CognitionAuditEvidence::SCHEMA_VERSION
    );
    assert_eq!(outcome.effect, CognitionEffect::Mutated);
    assert_eq!(outcome.audit.effect, CognitionEffect::Mutated);
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
        authority_revalidated_at
    );
    assert_eq!(outcome.audit.prepared_at, prepared_at);
    assert_eq!(outcome.committed_at, prepared_at);
}

#[test]
fn recovered_audit_rejects_schema_snapshot_and_phase_tampering() {
    let mutations: [fn(&mut CognitionCommitOutcome); 5] = [
        |outcome| {
            outcome.audit.schema_version = CognitionAuditEvidence::SCHEMA_VERSION - 1;
        },
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
    let mutations: [fn(&mut CognitionCommitOutcome); 4] = [
        |outcome| {
            outcome.audit.schema_version = CognitionAuditEvidence::SCHEMA_VERSION - 1;
        },
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
fn later_revalidation_recovers_the_original_historical_audit() {
    let fixture = Fixture::new();
    let proposal = fixture.proposal();
    let first = fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
        .expect("initial commit");
    let mut later = authority_for(&fixture.binding);
    later.policy_decision_id = "policy-decision-8".into();
    fixture.authority.set(later);

    let recovered = fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
        .expect("idempotent retry with fresh authority evidence");
    assert_eq!(recovered.status, CognitionCommitStatus::AlreadyApplied);
    assert_eq!(recovered.audit, first.audit);
    assert_eq!(fixture.authority.calls(), 2);
}
