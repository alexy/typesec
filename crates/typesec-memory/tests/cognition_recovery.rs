#[path = "cognition_recovery/support.rs"]
mod support;

use std::sync::Arc;
use std::time::Duration;

use chrono::TimeDelta;
use typesec_core::policy::{MintOptions, RequestContext, mint_capability_for_id};
use typesec_core::{CanWrite, CapabilityRevocationList, CapabilityUseError, Resource};
use typesec_memory::{
    CognitionCommitOutcome, CognitionCommitStatus, CognitionRecoveryError, MemoryError, MemoryId,
    MemorySpace, MemoryVault,
};

use support::{Fixture, JOB_ID, OTHER_SUBJECT, capability, digest};

type OutcomeMutation = (&'static str, fn(&mut CognitionCommitOutcome));

#[test]
fn response_loss_recovery_is_proposal_free_and_idempotent() {
    let fixture = Fixture::new();
    assert_eq!(fixture.authority_calls(), 1);

    let first = fixture.recover().expect("first recovery");
    let second = fixture.recover().expect("idempotent recovery");

    assert_eq!(first, second);
    assert_eq!(first.status, CognitionCommitStatus::AlreadyApplied);
    assert_eq!(fixture.store.counts().0, 1, "recovery must not reapply");
    assert_eq!(
        fixture.authority_calls(),
        1,
        "historical recovery must not rerun mutation authority"
    );
}

#[test]
fn malformed_or_denied_requests_never_reach_the_store() {
    let fixture = Fixture::new();
    let before = fixture.store.counts().1;

    let no_policy = MemoryVault::new(fixture.store.clone());
    assert!(matches!(
        no_policy.recover_cognition_outcome(
            &fixture.space,
            &fixture.write,
            JOB_ID,
            &fixture.proposal_digest,
            &fixture.context,
        ),
        Err(MemoryError::CognitionRecovery(
            CognitionRecoveryError::PolicyUnavailable
        ))
    ));
    assert_eq!(fixture.store.counts().1, before);

    for (job, digest_value, context) in [
        (
            " job-response-loss",
            fixture.proposal_digest.as_str(),
            fixture.context.clone(),
        ),
        (
            JOB_ID,
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            fixture.context.clone(),
        ),
        (
            JOB_ID,
            fixture.proposal_digest.as_str(),
            RequestContext::new().with_purpose(" research"),
        ),
    ] {
        assert!(matches!(
            fixture.vault().recover_cognition_outcome(
                &fixture.space,
                &fixture.write,
                job,
                digest_value,
                &context,
            ),
            Err(MemoryError::CognitionRecovery(
                CognitionRecoveryError::InvalidRequest
            ))
        ));
        assert_eq!(fixture.store.counts().1, before);
    }

    let wrong_purpose = RequestContext::new().with_purpose("support");
    assert!(matches!(
        fixture.vault().recover_cognition_outcome(
            &fixture.space,
            &fixture.write,
            JOB_ID,
            &fixture.proposal_digest,
            &wrong_purpose,
        ),
        Err(MemoryError::PolicyDenied { .. })
    ));
    assert_eq!(fixture.store.counts().1, before);

    let other_space = MemorySpace::new("tenant:acme", "other");
    assert!(matches!(
        fixture.vault().recover_cognition_outcome(
            &other_space,
            &fixture.write,
            JOB_ID,
            &fixture.proposal_digest,
            &fixture.context,
        ),
        Err(MemoryError::SpaceMismatch { .. })
    ));
    assert_eq!(fixture.store.counts().1, before);
}

#[test]
fn expired_and_revoked_capabilities_never_reach_the_store() {
    let fixture = Fixture::new();
    let before = fixture.store.counts().1;
    let expired = mint_capability_for_id::<CanWrite, MemorySpace>(
        fixture.policy.as_ref(),
        "did:key:researcher",
        fixture.space.resource_id(),
        &MintOptions {
            ttl: Duration::ZERO,
            context: fixture.context.clone(),
            ..MintOptions::default()
        },
    )
    .expect("policy-minted expiring capability");
    let expired_error = fixture
        .vault()
        .recover_cognition_outcome(
            &fixture.space,
            &expired,
            JOB_ID,
            &fixture.proposal_digest,
            &fixture.context,
        )
        .expect_err("expired capability");
    assert!(matches!(
        expired_error,
        MemoryError::Capability(CapabilityUseError::Expired { .. })
    ));
    assert_eq!(fixture.store.counts().1, before);

    let revocations = Arc::new(CapabilityRevocationList::new());
    let revoked = mint_capability_for_id::<CanWrite, MemorySpace>(
        fixture.policy.as_ref(),
        "did:key:researcher",
        fixture.space.resource_id(),
        &MintOptions {
            context: fixture.context.clone(),
            ..MintOptions::default()
        }
        .with_revocation_list(revocations.clone()),
    )
    .expect("policy-minted revocable capability");
    revocations.revoke(revoked.id());
    let revoked_error = fixture
        .vault()
        .recover_cognition_outcome(
            &fixture.space,
            &revoked,
            JOB_ID,
            &fixture.proposal_digest,
            &fixture.context,
        )
        .expect_err("revoked capability");
    assert!(matches!(
        revoked_error,
        MemoryError::Capability(CapabilityUseError::RevokedById { .. })
    ));
    assert_eq!(fixture.store.counts().1, before);
}

#[test]
fn tampered_recovered_evidence_fails_closed() {
    let fixture = Fixture::new();
    let baseline = fixture.store.outcome(&fixture.key);
    let mutations: &[OutcomeMutation] = &[
        ("job", |value| value.audit.operation_id = "other-job".into()),
        ("space", |value| {
            value.audit.space_id = "memory/other".into()
        }),
        ("proposal", |value| {
            value.audit.proposal_digest = digest("other")
        }),
        ("subject", |value| {
            value.audit.subject = OTHER_SUBJECT.into()
        }),
        ("purpose", |value| value.audit.purpose = "support".into()),
        ("binding digest", |value| {
            value.audit.binding_digest = "bad".into()
        }),
        ("audit schema", |value| value.audit.schema_version += 1),
        ("snapshot syntax", |value| {
            value.audit.snapshot_digest = "bad".into()
        }),
        ("grant substituted for snapshot", |value| {
            value.audit.snapshot_digest = value.audit.governed_scan_digest.clone()
        }),
        ("policy decision", |value| {
            value.audit.policy_decision_id = " decision ".into();
        }),
        ("authority time", |value| {
            value.audit.authority_revalidated_at =
                value.audit.prepared_at + TimeDelta::nanoseconds(1);
        }),
        ("affected ids", |value| {
            value.affected_ids.push(MemoryId::from_string("mem-extra"));
        }),
        ("affected id order", |value| {
            let ids = vec![
                MemoryId::from_string("mem-z"),
                MemoryId::from_string("mem-a"),
            ];
            value.affected_ids.clone_from(&ids);
            value.audit.affected_ids = ids;
        }),
        ("backend commit", |value| {
            value.backend_commit_hash = " backend ".into();
        }),
        ("version transition", |value| {
            value.resulting_version.clone_from(&value.prior_version);
        }),
        ("commit time", |value| {
            value.committed_at = value.audit.prepared_at - TimeDelta::nanoseconds(1);
        }),
    ];

    for (name, mutate) in mutations {
        let mut tampered = baseline.clone();
        mutate(&mut tampered);
        fixture.store.replace_outcome(&fixture.key, tampered);
        assert_unavailable(fixture.recover().expect_err(name));
    }

    fixture.store.replace_outcome(&fixture.key, baseline);
    fixture
        .store
        .force_recovery_status(Some(CognitionCommitStatus::Applied));
    assert_unavailable(fixture.recover().expect_err("applied status"));
}

#[test]
fn absence_conflicts_cross_subjects_and_adapter_errors_are_indistinguishable() {
    let fixture = Fixture::new();
    let vault = fixture.vault();

    let absent = vault
        .recover_cognition_outcome(
            &fixture.space,
            &fixture.write,
            "job-absent",
            &fixture.proposal_digest,
            &fixture.context,
        )
        .expect_err("absent outcome");
    let conflict = vault
        .recover_cognition_outcome(
            &fixture.space,
            &fixture.write,
            JOB_ID,
            &digest("different proposal"),
            &fixture.context,
        )
        .expect_err("proposal conflict");

    let other = capability::<CanWrite>(
        &fixture.policy,
        OTHER_SUBJECT,
        &fixture.space,
        &fixture.context,
    );
    let cross_subject = vault
        .recover_cognition_outcome(
            &fixture.space,
            &other,
            JOB_ID,
            &fixture.proposal_digest,
            &fixture.context,
        )
        .expect_err("cross-subject outcome");

    fixture.store.fail_recovery(true);
    let adapter = vault
        .recover_cognition_outcome(
            &fixture.space,
            &fixture.write,
            JOB_ID,
            &fixture.proposal_digest,
            &fixture.context,
        )
        .expect_err("adapter failure");

    for error in [&absent, &conflict, &cross_subject, &adapter] {
        assert!(matches!(
            error,
            MemoryError::CognitionRecovery(CognitionRecoveryError::Unavailable)
        ));
        assert_eq!(
            error.to_string(),
            "completed cognition outcome is unavailable"
        );
        assert!(!error.to_string().contains("adapter secret"));
    }
}

fn assert_unavailable(error: MemoryError) {
    assert!(matches!(
        error,
        MemoryError::CognitionRecovery(CognitionRecoveryError::Unavailable)
    ));
}
