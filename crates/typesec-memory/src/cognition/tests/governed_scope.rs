use super::*;

fn scope(fill: char) -> GovernedSourceScope {
    GovernedSourceScope::from_digest(format!("sha256:{}", fill.to_string().repeat(64))).unwrap()
}

fn cognition_error(error: MemoryError) -> CognitionApplyError {
    match error {
        MemoryError::Cognition(error) => error,
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn successful_governed_application_preserves_scope_everywhere() {
    let expected = scope('a');
    let fixture = Fixture::new_with_scope(Some(expected.clone()));
    let outcome = fixture
        .vault
        .apply_cognition(
            &fixture.space,
            &fixture.write,
            &fixture.proposal(),
            &fixture.context,
        )
        .unwrap();

    assert_eq!(outcome.audit.governed_source_scope, Some(expected.clone()));
    let state = fixture.store.state();
    let derived = state
        .records
        .values()
        .find(|record| matches!(record.provenance, Provenance::Cognition { .. }))
        .expect("derived record");
    assert_eq!(derived.governed_source_scope(), Some(&expected));
}

#[test]
fn authority_cannot_substitute_a_source_scope() {
    let fixture = Fixture::new_with_scope(Some(scope('a')));
    let mut authority = authority_for(&fixture.binding);
    authority.governed_source_scope = Some(scope('b'));
    fixture.authority.set(authority);

    assert!(matches!(
        cognition_error(
            fixture
                .vault
                .apply_cognition(
                    &fixture.space,
                    &fixture.write,
                    &fixture.proposal(),
                    &fixture.context,
                )
                .unwrap_err()
        ),
        CognitionApplyError::BindingMismatch("governed source scope")
    ));
}

#[test]
fn authoritative_reload_rejects_missing_or_wrong_scope() {
    let fixture = Fixture::new_with_scope(Some(scope('a')));
    {
        let mut state = fixture.store.state();
        let record = state.records.get_mut(&fixture.source).unwrap();
        let mut encoded = serde_json::to_value(&*record).unwrap();
        encoded.as_object_mut().unwrap().insert(
            "governed_source_scope".into(),
            serde_json::json!(scope('b')),
        );
        *record = serde_json::from_value(encoded).unwrap();
    }

    assert!(matches!(
        cognition_error(
            fixture
                .vault
                .apply_cognition(
                    &fixture.space,
                    &fixture.write,
                    &fixture.proposal(),
                    &fixture.context,
                )
                .unwrap_err()
        ),
        CognitionApplyError::SourceScopeMismatch
    ));
}

#[test]
fn schema_v1_cannot_downgrade_a_bound_proposal() {
    for fixture in [Fixture::new(), Fixture::new_with_scope(Some(scope('a')))] {
        let mut proposal = fixture.proposal();
        assert_eq!(proposal.schema_version, CognitionProposal::SCHEMA_VERSION);
        proposal.schema_version = CognitionProposal::MIN_SCHEMA_VERSION;

        assert!(matches!(
            proposal.canonical_digest().unwrap_err(),
            CognitionApplyError::InvalidBinding(message)
                if message == "bound proposals require schemaVersion 3"
        ));
    }
}

#[test]
fn ambiguous_governed_schema_v2_is_rejected_instead_of_reinterpreted() {
    let fixture = Fixture::new_with_scope(Some(scope('a')));
    let mut proposal = fixture.proposal();
    proposal.schema_version = 2;

    assert!(matches!(
        proposal.canonical_digest().unwrap_err(),
        CognitionApplyError::UnsupportedSchema(2)
    ));
}

#[test]
fn local_and_governed_bound_proposals_share_one_current_schema() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.proposal().schema_version,
        CognitionProposal::SCHEMA_VERSION
    );
    assert_eq!(
        Fixture::new_with_scope(Some(scope('a')))
            .proposal()
            .schema_version,
        CognitionProposal::SCHEMA_VERSION
    );
}

#[test]
fn unbound_proposals_keep_v1_and_cannot_claim_v3_without_a_binding() {
    let mut proposal = CognitionProposal::new(
        "job-unbound",
        digest("snapshot"),
        digest("source manifest"),
        "marciana.test",
        "1",
        vec![MemoryId::from_string("mem-source")],
        Label::Internal,
    );
    assert_eq!(
        proposal.schema_version,
        CognitionProposal::MIN_SCHEMA_VERSION
    );

    proposal.schema_version = CognitionProposal::SCHEMA_VERSION;
    assert!(matches!(
        proposal.canonical_digest().unwrap_err(),
        CognitionApplyError::InvalidBinding(message)
            if message == "schemaVersion 3 requires a binding"
    ));
}

#[test]
fn scope_is_bound_into_binding_proposal_and_source_digests() {
    let local = Fixture::new();
    let governed = Fixture::new_with_scope(Some(scope('a')));

    let mut local_binding = governed.binding.clone();
    local_binding.governed_source_scope = None;
    assert_ne!(
        governed.binding.canonical_digest().unwrap(),
        local_binding.canonical_digest().unwrap()
    );

    let mut local_proposal = governed.proposal();
    local_proposal
        .binding
        .as_mut()
        .unwrap()
        .governed_source_scope = None;
    assert_ne!(
        governed.proposal().canonical_digest().unwrap(),
        local_proposal.canonical_digest().unwrap()
    );

    let governed_record = governed.store.get(&governed.source).unwrap().unwrap();
    let mut local_encoded = serde_json::to_value(&governed_record).unwrap();
    local_encoded
        .as_object_mut()
        .unwrap()
        .remove("governed_source_scope");
    let local_record: StoredRecord = serde_json::from_value(local_encoded).unwrap();
    assert_ne!(
        CognitionSourcePrecondition::for_record(&local_record)
            .unwrap()
            .record_digest,
        CognitionSourcePrecondition::for_record(&governed_record)
            .unwrap()
            .record_digest
    );
    assert!(local.store.get(&local.source).unwrap().is_some());
}

#[test]
fn prepared_precondition_closes_scope_replacement_race() {
    let fixture = Fixture::new_with_scope(Some(scope('a')));
    fixture.store.replace_scope_before_precondition(scope('b'));

    assert!(matches!(
        fixture.vault.apply_cognition(
            &fixture.space,
            &fixture.write,
            &fixture.proposal(),
            &fixture.context,
        ),
        Err(MemoryError::CognitionCommit(
            CognitionCommitError::StaleSource(_)
        ))
    ));
    assert_eq!(fixture.store.state().applications.len(), 0);
}
