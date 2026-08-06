use super::*;

#[test]
fn valid_application_commits_joined_lineage_and_id_only_evidence() {
    let fixture = Fixture::new();
    let outcome = fixture
        .vault
        .apply_cognition(
            &fixture.space,
            &fixture.write,
            &fixture.proposal(),
            &fixture.context,
        )
        .expect("apply cognition");
    assert_eq!(outcome.status, CognitionCommitStatus::Applied);

    let state = fixture.store.state();
    assert_eq!(state.applications.len(), 1);
    assert_eq!(state.audits.len(), 1);
    assert_eq!(state.outbox.len(), 2);
    let created = outcome
        .affected_ids
        .iter()
        .find(|id| *id != &fixture.source)
        .expect("created id");
    let record = state.records.get(created).expect("derived record");
    assert_eq!(record.label, Label::Sensitive, "worker cannot lower join");
    assert_eq!(record.purposes, ["research"]);
    assert!(matches!(
        &record.provenance,
        Provenance::Cognition { job_id, source_ids, .. }
            if job_id == "job-42" && source_ids == std::slice::from_ref(&fixture.source)
    ));
    assert!(state.records[&fixture.source].invalid_at.is_some());
    assert!(state.outbox.iter().all(|mutation| matches!(
        mutation,
        IndexMutation::Upsert(_) | IndexMutation::Remove(_)
    )));
    let audit_json = serde_json::to_string(&state.audits).expect("audit serialization");
    assert!(!audit_json.contains("private source text"));
    assert!(!audit_json.contains("derived summary"));
}

#[test]
fn retry_recovers_one_commit_and_conflicting_payload_is_rejected() {
    let fixture = Fixture::new();
    let proposal = fixture.proposal();
    let first = fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
        .expect("first apply");
    let retry = fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
        .expect("idempotent retry");
    assert_eq!(retry.status, CognitionCommitStatus::AlreadyApplied);
    assert_eq!(retry.backend_commit_hash, first.backend_commit_hash);
    assert_eq!(retry.affected_ids, first.affected_ids);
    assert_eq!(fixture.store.state().audits.len(), 1);

    let mut conflicting = proposal;
    conflicting.evidence.push("different proposal bytes".into());
    assert!(matches!(
        fixture.vault.apply_cognition(
            &fixture.space,
            &fixture.write,
            &conflicting,
            &fixture.context
        ),
        Err(MemoryError::CognitionCommit(
            CognitionCommitError::IdempotencyConflict
        ))
    ));
    assert_eq!(fixture.store.state().audits.len(), 1);
}

#[test]
fn policy_verifier_binding_and_plan_checks_fail_closed() {
    let fixture = Fixture::new();
    let proposal = fixture.proposal();
    let no_policy =
        MemoryVault::new(fixture.store.clone()).with_cognition_authority(fixture.authority.clone());
    assert!(matches!(
        no_policy.apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context),
        Err(MemoryError::Cognition(
            CognitionApplyError::PolicyUnavailable
        ))
    ));
    let no_verifier = MemoryVault::new(fixture.store.clone()).with_policy(fixture.policy.clone());
    assert!(matches!(
        no_verifier.apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context),
        Err(MemoryError::Cognition(
            CognitionApplyError::AuthorityVerifierUnavailable
        ))
    ));

    let mut changed = authority_for(&fixture.binding);
    changed.snapshot_digest = digest("new snapshot");
    fixture.authority.set(changed);
    assert!(matches!(
        fixture
            .vault
            .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context),
        Err(MemoryError::Cognition(
            CognitionApplyError::BindingMismatch("snapshot digest")
        ))
    ));
    fixture.authority.set(authority_for(&fixture.binding));

    let mut outside = fixture.proposal();
    outside.plan = ConsolidationPlan::new().then(ConsolidationStep::Invalidate {
        ids: vec![MemoryId::from_string("other-source")],
    });
    assert!(matches!(
        fixture
            .vault
            .apply_cognition(&fixture.space, &fixture.write, &outside, &fixture.context),
        Err(MemoryError::Cognition(CognitionApplyError::InvalidPlan(_)))
    ));
    let state = fixture.store.state();
    assert!(state.applications.is_empty());
    assert!(state.outbox.is_empty());
}

#[test]
fn source_change_and_transaction_race_leave_no_partial_cognition_state() {
    let fixture = Fixture::new();
    let proposal = fixture.proposal();
    let mut changed = fixture
        .store
        .get(&fixture.source)
        .expect("store")
        .expect("source");
    changed.label = Label::Secret;
    fixture.store.put(changed).expect("replace source revision");
    assert!(matches!(
        fixture
            .vault
            .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context),
        Err(MemoryError::Cognition(
            CognitionApplyError::SourceManifestMismatch
        ))
    ));
    assert!(fixture.store.state().applications.is_empty());

    let fresh = Fixture::new();
    fresh.store.fail_next_precondition();
    assert!(matches!(
        fresh.vault.apply_cognition(
            &fresh.space,
            &fresh.write,
            &fresh.proposal(),
            &fresh.context
        ),
        Err(MemoryError::CognitionCommit(
            CognitionCommitError::StaleSource(_)
        ))
    ));
    let state = fresh.store.state();
    assert!(state.applications.is_empty());
    assert!(state.outbox.is_empty());
    assert!(state.audits.is_empty());
    assert!(state.records[&fresh.source].invalid_at.is_none());
}

#[test]
fn proposal_and_plan_round_trip_for_durable_job_storage() {
    let fixture = Fixture::new();
    let proposal = fixture.proposal();
    let encoded = serde_json::to_vec(&proposal).expect("serialize proposal");
    let decoded: CognitionProposal =
        serde_json::from_slice(&encoded).expect("deserialize proposal");
    assert_eq!(decoded.job_id, proposal.job_id);
    assert_eq!(decoded.binding, proposal.binding);
    assert_eq!(decoded.plan.steps.len(), 1);
}

#[test]
fn proposal_digest_is_stable_across_worker_retry_time() {
    let fixture = Fixture::new();
    let first = fixture.proposal();
    let mut retry = first.clone();
    retry.created_at += chrono::TimeDelta::minutes(5);

    assert_eq!(
        first.canonical_digest().unwrap(),
        retry.canonical_digest().unwrap()
    );

    retry.algorithm_version.push_str("-changed");
    assert_ne!(
        first.canonical_digest().unwrap(),
        retry.canonical_digest().unwrap()
    );
}
