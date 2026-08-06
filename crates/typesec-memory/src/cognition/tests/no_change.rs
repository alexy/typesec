use super::*;

#[test]
fn no_change_commits_full_evidence_without_memory_or_outbox_mutations() {
    let fixture = Fixture::new();
    let proposal = fixture.no_change_proposal();
    let before_source =
        serde_json::to_value(&fixture.store.state().records[&fixture.source]).unwrap();
    let before_gets = fixture.store.state().get_calls;

    let outcome = fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
        .expect("no-change cognition decision");

    assert_eq!(outcome.status, CognitionCommitStatus::Applied);
    assert_eq!(outcome.effect, CognitionEffect::NoChange);
    assert_eq!(outcome.audit.effect, CognitionEffect::NoChange);
    assert!(outcome.affected_ids.is_empty());
    assert_eq!(outcome.prior_version, outcome.resulting_version);
    assert_eq!(
        fixture.authority.calls(),
        1,
        "authority was freshly resolved"
    );

    let state = fixture.store.state();
    assert_eq!(state.get_calls, before_gets + 1, "sources were reloaded");
    assert_eq!(state.records.len(), 1);
    assert_eq!(
        serde_json::to_value(&state.records[&fixture.source]).unwrap(),
        before_source
    );
    assert!(state.outbox.is_empty());
    assert_eq!(
        state.audits.as_slice(),
        std::slice::from_ref(&outcome.audit)
    );
    assert_eq!(state.applications.len(), 1);
    assert_eq!(
        state.last_prepared_shape,
        Some((CognitionEffect::NoChange, 1, 0, 0))
    );
}

#[test]
fn no_change_recovery_is_stable_and_does_not_reapply() {
    let fixture = Fixture::new();
    let proposal = fixture.no_change_proposal();
    let first = fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
        .expect("initial no-change decision");
    let gets_after_commit = fixture.store.state().get_calls;

    let recovered = fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
        .expect("recover no-change decision");

    assert_eq!(recovered.status, CognitionCommitStatus::AlreadyApplied);
    assert_eq!(recovered.effect, CognitionEffect::NoChange);
    assert_eq!(recovered.backend_commit_hash, first.backend_commit_hash);
    assert_eq!(recovered.audit, first.audit);
    let state = fixture.store.state();
    assert_eq!(state.get_calls, gets_after_commit);
    assert_eq!(state.applications.len(), 1);
    assert_eq!(state.audits.len(), 1);
    assert!(state.outbox.is_empty());
}

#[test]
fn proposal_effect_and_operations_must_agree() {
    let fixture = Fixture::new();
    let mut no_change_with_mutations = fixture.proposal();
    no_change_with_mutations.effect = CognitionEffect::NoChange;
    assert!(matches!(
        fixture.vault.apply_cognition(
            &fixture.space,
            &fixture.write,
            &no_change_with_mutations,
            &fixture.context,
        ),
        Err(MemoryError::Cognition(CognitionApplyError::InvalidPlan(message)))
            if message == "no-change proposal contains mutations"
    ));

    let mut mutation_without_operations = fixture.no_change_proposal();
    mutation_without_operations.effect = CognitionEffect::Mutated;
    assert!(matches!(
        fixture.vault.apply_cognition(
            &fixture.space,
            &fixture.write,
            &mutation_without_operations,
            &fixture.context,
        ),
        Err(MemoryError::Cognition(CognitionApplyError::InvalidPlan(message)))
            if message == "mutated proposal has no mutations"
    ));
    assert_eq!(fixture.authority.calls(), 0);
    assert!(fixture.store.state().applications.is_empty());
}

#[test]
fn no_change_still_fails_when_bound_sources_change() {
    let fixture = Fixture::new();
    let proposal = fixture.no_change_proposal();
    let mut changed = fixture.store.state().records[&fixture.source].clone();
    changed.label = Label::Secret;
    fixture.store.put(changed).unwrap();

    assert!(matches!(
        fixture
            .vault
            .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context),
        Err(MemoryError::Cognition(
            CognitionApplyError::SourceManifestMismatch
        ))
    ));
    assert_eq!(fixture.authority.calls(), 1);
    assert!(fixture.store.state().applications.is_empty());
}

#[test]
fn no_change_effect_is_part_of_deterministic_proposal_identity() {
    let fixture = Fixture::new();
    let mutated = CognitionProposal::new(
        "job-unbound",
        fixture.binding.snapshot_digest.clone(),
        fixture.binding.source_manifest_digest.clone(),
        "marciana.summarize.sail",
        "1",
        vec![fixture.source.clone()],
        Label::Sensitive,
    );
    let no_change = mutated.with_effect(CognitionEffect::NoChange);
    let mut retry = no_change.clone();
    retry.created_at += chrono::TimeDelta::minutes(1);

    assert_ne!(
        CognitionProposal::new(
            "job-unbound",
            fixture.binding.snapshot_digest,
            fixture.binding.source_manifest_digest,
            "marciana.summarize.sail",
            "1",
            vec![fixture.source],
            Label::Sensitive,
        )
        .canonical_digest()
        .unwrap(),
        no_change.canonical_digest().unwrap()
    );
    assert_eq!(
        no_change.canonical_digest().unwrap(),
        retry.canonical_digest().unwrap()
    );
}

#[test]
fn recovered_effect_tampering_fails_closed() {
    let mutations: [fn(&mut CognitionCommitOutcome); 3] = [
        |outcome| outcome.effect = CognitionEffect::Mutated,
        |outcome| outcome.audit.effect = CognitionEffect::Mutated,
        |outcome| {
            outcome.effect = CognitionEffect::Mutated;
            outcome.audit.effect = CognitionEffect::Mutated;
        },
    ];
    for mutate in mutations {
        let fixture = Fixture::new();
        let proposal = fixture.no_change_proposal();
        fixture
            .vault
            .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
            .unwrap();
        fixture.store.state().preflight_outcome_mutation = Some(mutate);

        assert!(matches!(
            fixture.vault.apply_cognition(
                &fixture.space,
                &fixture.write,
                &proposal,
                &fixture.context,
            ),
            Err(MemoryError::CognitionCommit(
                CognitionCommitError::InvalidOutcome
            ))
        ));
    }
}

#[test]
fn current_outcome_and_audit_wires_require_effect() {
    let fixture = Fixture::new();
    let outcome = fixture
        .vault
        .apply_cognition(
            &fixture.space,
            &fixture.write,
            &fixture.no_change_proposal(),
            &fixture.context,
        )
        .unwrap();
    let encoded = serde_json::to_value(outcome).unwrap();

    for path in ["outcome", "audit"] {
        let mut missing_effect = encoded.clone();
        match path {
            "outcome" => {
                missing_effect.as_object_mut().unwrap().remove("effect");
            }
            "audit" => {
                missing_effect["audit"]
                    .as_object_mut()
                    .unwrap()
                    .remove("effect");
            }
            _ => unreachable!(),
        }
        assert!(
            serde_json::from_value::<CognitionCommitOutcome>(missing_effect).is_err(),
            "accepted current {path} wire without effect"
        );
    }
}

#[test]
fn outcome_wire_requires_its_own_effect() {
    let fixture = Fixture::new();
    let outcome = fixture
        .vault
        .apply_cognition(
            &fixture.space,
            &fixture.write,
            &fixture.no_change_proposal(),
            &fixture.context,
        )
        .unwrap();
    let mut encoded = serde_json::to_value(outcome).unwrap();
    encoded.as_object_mut().unwrap().remove("effect");

    assert!(serde_json::from_value::<CognitionCommitOutcome>(encoded).is_err());
}
