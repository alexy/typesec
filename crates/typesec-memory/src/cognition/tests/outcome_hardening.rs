use super::*;

type OutcomeMutation = fn(&mut CognitionCommitOutcome);

#[test]
fn preflight_rejects_tampered_commit_outcomes() {
    let mutations: [(&str, OutcomeMutation); 15] = [
        ("status", |outcome| {
            outcome.status = CognitionCommitStatus::Applied;
        }),
        ("subject", |outcome| {
            outcome.audit.subject = "did:key:wrong-subject".into();
        }),
        ("purpose", |outcome| {
            outcome.audit.purpose = "wrong-purpose".into();
        }),
        ("proposal digest", |outcome| {
            outcome.audit.proposal_digest = digest("wrong proposal");
        }),
        ("binding audit digest", |outcome| {
            outcome.audit.binding_digest = digest("wrong binding");
        }),
        ("outcome effect", |outcome| {
            outcome.effect = CognitionEffect::NoChange;
        }),
        ("audit effect", |outcome| {
            outcome.audit.effect = CognitionEffect::NoChange;
        }),
        ("matching no-change effects", |outcome| {
            outcome.effect = CognitionEffect::NoChange;
            outcome.audit.effect = CognitionEffect::NoChange;
        }),
        ("outcome affected IDs", |outcome| {
            outcome.affected_ids.clear();
        }),
        ("audit affected IDs", |outcome| {
            let affected = vec![MemoryId::from_string("mem-wrong")];
            outcome.affected_ids.clone_from(&affected);
            outcome.audit.affected_ids = affected;
        }),
        (
            "oversized matching affected IDs",
            set_oversized_affected_ids,
        ),
        ("version transition", |outcome| {
            outcome.resulting_version.clone_from(&outcome.prior_version);
        }),
        ("version syntax", |outcome| {
            outcome.prior_version = " bad-version".into();
        }),
        ("backend commit syntax", |outcome| {
            outcome.backend_commit_hash = "bad-commit\nforged".into();
        }),
        ("commit timestamp", |outcome| {
            outcome.committed_at = outcome.audit.prepared_at - chrono::TimeDelta::nanoseconds(1);
        }),
    ];

    for (name, mutate) in mutations {
        let fixture = Fixture::new();
        let proposal = fixture.proposal();
        fixture
            .vault
            .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
            .expect("initial commit");
        fixture.store.state().preflight_outcome_mutation = Some(mutate);

        assert_invalid_outcome(
            fixture.vault.apply_cognition(
                &fixture.space,
                &fixture.write,
                &proposal,
                &fixture.context,
            ),
            name,
        );
    }
}

#[test]
fn post_commit_rejects_tampered_commit_outcomes() {
    let mutations: [(&str, OutcomeMutation); 16] = [
        ("subject", |outcome| {
            outcome.audit.subject = "did:key:wrong-subject".into();
        }),
        ("purpose", |outcome| {
            outcome.audit.purpose = "wrong-purpose".into();
        }),
        ("proposal digest", |outcome| {
            outcome.audit.proposal_digest = digest("wrong proposal");
        }),
        ("binding audit digest", |outcome| {
            outcome.audit.binding_digest = digest("wrong binding");
        }),
        ("outcome effect", |outcome| {
            outcome.effect = CognitionEffect::NoChange;
        }),
        ("audit effect", |outcome| {
            outcome.audit.effect = CognitionEffect::NoChange;
        }),
        ("matching no-change effects", |outcome| {
            outcome.effect = CognitionEffect::NoChange;
            outcome.audit.effect = CognitionEffect::NoChange;
        }),
        ("outcome affected IDs", |outcome| {
            outcome.affected_ids.clear();
        }),
        ("audit affected IDs", |outcome| {
            let affected = vec![MemoryId::from_string("mem-wrong")];
            outcome.affected_ids.clone_from(&affected);
            outcome.audit.affected_ids = affected;
        }),
        (
            "oversized matching affected IDs",
            set_oversized_affected_ids,
        ),
        ("version transition", |outcome| {
            outcome.resulting_version.clone_from(&outcome.prior_version);
        }),
        ("version syntax", |outcome| {
            outcome.resulting_version = "bad-version ".into();
        }),
        ("backend commit syntax", |outcome| {
            outcome.backend_commit_hash = "bad-commit\0forged".into();
        }),
        ("commit timestamp", |outcome| {
            outcome.committed_at = outcome.audit.prepared_at - chrono::TimeDelta::nanoseconds(1);
        }),
        ("prepared timestamp", |outcome| {
            outcome.audit.prepared_at += chrono::TimeDelta::seconds(1);
        }),
        ("prepared policy decision", |outcome| {
            outcome.audit.policy_decision_id = "different-policy-decision".into();
        }),
    ];

    for (name, mutate) in mutations {
        let fixture = Fixture::new();
        fixture.store.state().commit_outcome_mutation = Some(mutate);

        assert_invalid_outcome(
            fixture.vault.apply_cognition(
                &fixture.space,
                &fixture.write,
                &fixture.proposal(),
                &fixture.context,
            ),
            name,
        );
    }
}

#[test]
fn post_commit_accepts_an_exact_already_applied_race_result() {
    let fixture = Fixture::new();
    fixture.store.state().commit_outcome_mutation = Some(|outcome| {
        outcome.status = CognitionCommitStatus::AlreadyApplied;
    });

    let outcome = fixture
        .vault
        .apply_cognition(
            &fixture.space,
            &fixture.write,
            &fixture.proposal(),
            &fixture.context,
        )
        .expect("exact race outcome");
    assert_eq!(outcome.status, CognitionCommitStatus::AlreadyApplied);
}

fn assert_invalid_outcome(outcome: Result<CognitionCommitOutcome, MemoryError>, mutation: &str) {
    assert!(
        matches!(
            outcome,
            Err(MemoryError::CognitionCommit(
                CognitionCommitError::InvalidOutcome
            ))
        ),
        "accepted tampered {mutation}"
    );
}

fn set_oversized_affected_ids(outcome: &mut CognitionCommitOutcome) {
    let affected: Vec<_> = (0..=MAX_COGNITION_MUTATIONS)
        .map(|index| MemoryId::from_string(format!("mem-over-{index:05}")))
        .collect();
    outcome.affected_ids.clone_from(&affected);
    outcome.audit.affected_ids = affected;
}
