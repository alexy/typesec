use super::*;

#[test]
fn authority_binds_job_algorithm_and_version_before_store_access() {
    let mutations: [fn(&mut CognitionProposal); 3] = [
        |proposal: &mut CognitionProposal| proposal.job_id = "job-other".into(),
        |proposal: &mut CognitionProposal| proposal.algorithm = "other.algorithm".into(),
        |proposal: &mut CognitionProposal| proposal.algorithm_version = "2".into(),
    ];
    for mutate in mutations {
        let fixture = Fixture::new();
        let mut proposal = fixture.proposal();
        mutate(&mut proposal);
        let before_gets = fixture.store.state().get_calls;

        assert!(matches!(
            fixture.vault.apply_cognition(
                &fixture.space,
                &fixture.write,
                &proposal,
                &fixture.context
            ),
            Err(MemoryError::Cognition(
                CognitionApplyError::BindingMismatch(_)
            ))
        ));
        assert_eq!(fixture.authority.calls(), 1);
        assert_eq!(fixture.store.state().recovery_calls, 0);
        assert_eq!(fixture.store.state().get_calls, before_gets);
    }
}

#[test]
fn proposal_identity_rejects_control_characters_before_authority_or_store() {
    let mutations: [fn(&mut CognitionProposal); 3] = [
        |proposal| proposal.job_id = "job\nforged".into(),
        |proposal| proposal.algorithm = "trusted\nforged".into(),
        |proposal| proposal.algorithm_version = "1\0forged".into(),
    ];
    for mutate in mutations {
        let fixture = Fixture::new();
        let mut proposal = fixture.proposal();
        mutate(&mut proposal);
        assert!(matches!(
            proposal.canonical_digest(),
            Err(CognitionApplyError::InvalidPlan(_))
        ));
        let before_gets = fixture.store.state().get_calls;
        assert!(matches!(
            fixture.vault.apply_cognition(
                &fixture.space,
                &fixture.write,
                &proposal,
                &fixture.context
            ),
            Err(MemoryError::Cognition(CognitionApplyError::InvalidPlan(_)))
        ));
        assert_eq!(fixture.authority.calls(), 0);
        assert_eq!(fixture.store.state().recovery_calls, 0);
        assert_eq!(fixture.store.state().get_calls, before_gets);
    }
}

#[test]
fn scoped_job_keys_are_canonical_and_hide_authority_principals() {
    let first = CognitionIdempotencyKey::for_authority(
        "memory/tenant/vault",
        "did:key:first",
        "research",
        "job-1",
    )
    .unwrap();
    let other_subject = CognitionIdempotencyKey::for_authority(
        "memory/tenant/vault",
        "did:key:second",
        "research",
        "job-1",
    )
    .unwrap();
    let other_purpose = CognitionIdempotencyKey::for_authority(
        "memory/tenant/vault",
        "did:key:first",
        "support",
        "job-1",
    )
    .unwrap();

    assert_ne!(first, other_subject);
    assert_ne!(first, other_purpose);
    assert!(super::super::canonical::is_canonical_sha256(
        first.authority_scope_digest()
    ));
    let encoded = serde_json::to_string(&first).unwrap();
    assert!(!encoded.contains("did:key:first"));
    assert!(!encoded.contains("research"));
}

#[test]
fn same_space_and_job_are_isolated_by_verified_subject() {
    let fixture = Fixture::new();
    let first = add_only_proposal(&fixture, fixture.binding.clone(), "first result");
    fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &first, &fixture.context)
        .expect("first subject commit");

    let other_subject = "did:key:other";
    let other_write = mint_capability_for_id::<CanWrite, MemorySpace>(
        fixture.policy.as_ref(),
        other_subject,
        fixture.space.resource_id(),
        &MintOptions {
            context: fixture.context.clone(),
            ..MintOptions::default()
        },
    )
    .expect("other subject capability");
    let mut other_binding = fixture.binding.clone();
    other_binding.subject = other_subject.into();
    fixture.authority.set(authority_for(&other_binding));
    let second = add_only_proposal(&fixture, other_binding, "second result");
    fixture
        .vault
        .apply_cognition(&fixture.space, &other_write, &second, &fixture.context)
        .expect("second subject commit");

    let state = fixture.store.state();
    assert_eq!(state.applications.len(), 2);
    let scopes: std::collections::BTreeSet<_> = state
        .applications
        .keys()
        .map(|key| key.authority_scope_digest())
        .collect();
    assert_eq!(scopes.len(), 2);
    assert!(
        state
            .applications
            .keys()
            .all(|key| key.job_id() == "job-42")
    );
}

#[test]
fn malformed_authority_digests_fail_before_commit() {
    type DigestMutation = fn(&mut CognitionBinding, String);
    let fields: [DigestMutation; 5] = [
        |binding, value| binding.governed_scan_digest = value,
        |binding, value| binding.plan_task_digest = value,
        |binding, value| binding.authorization_receipt_digest = value,
        |binding, value| binding.source_manifest_digest = value,
        |binding, value| binding.typedid_request_digest = value,
    ];
    let malformed = [
        "sha256:short".to_owned(),
        format!("sha256:{}", "A".repeat(64)),
        format!("blake3:{}", "a".repeat(64)),
        format!("sha256:{}", "a".repeat(63)),
    ];
    for mutate in fields {
        for value in &malformed {
            let fixture = Fixture::new();
            let mut binding = fixture.binding.clone();
            mutate(&mut binding, value.clone());
            fixture.authority.set(authority_for(&binding));
            let mut proposal = fixture.proposal();
            proposal.input_snapshot = binding.governed_scan_digest.clone();
            proposal.source_digest = binding.source_manifest_digest.clone();
            proposal.binding = Some(binding);
            let before_gets = fixture.store.state().get_calls;

            assert!(matches!(
                fixture.vault.apply_cognition(
                    &fixture.space,
                    &fixture.write,
                    &proposal,
                    &fixture.context
                ),
                Err(MemoryError::Cognition(CognitionApplyError::InvalidBinding(
                    _
                )))
            ));
            assert_eq!(fixture.authority.calls(), 0);
            assert_eq!(fixture.store.state().recovery_calls, 0);
            assert_eq!(fixture.store.state().get_calls, before_gets);
            assert!(fixture.store.state().applications.is_empty());
        }
    }
}

#[test]
fn snapshot_identity_accepts_canonical_non_digest_text() {
    let fixture = Fixture::new();
    let mut binding = fixture.binding.clone();
    binding.snapshot_digest = "lakecat:snapshot/42".into();
    fixture.authority.set(authority_for(&binding));
    let mut proposal = fixture.proposal();
    proposal.binding = Some(binding);

    fixture
        .vault
        .apply_cognition(&fixture.space, &fixture.write, &proposal, &fixture.context)
        .expect("canonical immutable snapshot identity");
}

#[test]
fn source_budget_fails_without_consuming_the_rejected_item() {
    let mut budget = CognitionSourceBudget::new();
    let oversized = "x".repeat(MAX_COGNITION_SOURCE_BYTES + 1);
    assert!(matches!(
        budget.try_add("mem-1", &oversized),
        Err(CognitionApplyError::LimitExceeded("source bytes"))
    ));
    assert!(budget.try_add("mem-1", "small").is_ok());
}

#[test]
fn adapter_failures_have_one_fixed_public_error() {
    struct FailingAuthority;

    impl CognitionAuthorityVerifier for FailingAuthority {
        fn revalidate(
            &self,
            _binding: &CognitionBinding,
            _context: &RequestContext,
        ) -> Result<CognitionAuthorityEvidence, CognitionAuthorityError> {
            Err(CognitionAuthorityError::Unavailable)
        }
    }

    let fixture = Fixture::new();
    let vault = MemoryVault::new(fixture.store.clone())
        .with_policy(fixture.policy.clone())
        .with_cognition_authority(Arc::new(FailingAuthority));
    let error = vault
        .apply_cognition(
            &fixture.space,
            &fixture.write,
            &fixture.proposal(),
            &fixture.context,
        )
        .expect_err("authority failure");
    assert!(matches!(
        error,
        MemoryError::Cognition(CognitionApplyError::Authority)
    ));
    assert_eq!(error.to_string(), "cognition authority revalidation failed");
}

#[test]
fn oversized_adapter_projection_is_rejected_before_canonicalization() {
    let fixture = Fixture::new();
    let mut authority = authority_for(&fixture.binding);
    authority.effective_projection = (0..=MAX_COGNITION_PROJECTION_FIELDS)
        .map(|index| format!("field-{index}"))
        .collect();
    fixture.authority.set(authority);

    assert!(matches!(
        fixture.vault.apply_cognition(
            &fixture.space,
            &fixture.write,
            &fixture.proposal(),
            &fixture.context
        ),
        Err(MemoryError::Cognition(
            CognitionApplyError::BindingMismatch("effective projection")
        ))
    ));
    assert_eq!(fixture.store.state().recovery_calls, 0);
}

fn add_only_proposal(
    fixture: &Fixture,
    binding: CognitionBinding,
    text: &str,
) -> CognitionProposal {
    CognitionProposal::new(
        "job-42",
        binding.governed_scan_digest.clone(),
        binding.source_manifest_digest.clone(),
        "marciana.summarize.sail",
        "1",
        vec![fixture.source.clone()],
        Label::Sensitive,
    )
    .with_drafts(vec![MemoryDraft::new(
        MemoryKind::Semantic,
        MemoryContent::text(text),
        Provenance::Operator,
    )])
    .with_binding(binding)
}
