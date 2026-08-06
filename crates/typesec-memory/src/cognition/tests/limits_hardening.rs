use super::*;

#[test]
fn source_count_is_inclusive_and_rejected_before_store_reads() {
    let fixture = Fixture::new();
    let mut proposal = fixture.proposal();
    proposal.source_ids = source_ids(&fixture, MAX_COGNITION_SOURCE_COUNT);
    assert!(proposal.canonical_digest().is_ok());
    proposal
        .source_ids
        .push(MemoryId::from_string("mem-over-limit"));
    assert!(matches!(
        proposal.canonical_digest(),
        Err(CognitionApplyError::LimitExceeded("source count"))
    ));

    let before = fixture.store.state().get_calls;
    let read = mint::<CanRead>(&fixture.policy, &fixture.space, &fixture.context);
    assert!(matches!(
        fixture.vault.cognition_source_manifest(
            &fixture.space,
            &read,
            &proposal.source_ids,
            &fixture.context
        ),
        Err(MemoryError::Cognition(CognitionApplyError::LimitExceeded(
            "source count"
        )))
    ));
    assert_eq!(fixture.store.state().get_calls, before);
}

#[test]
fn source_byte_budget_is_inclusive_and_checked_for_overflow() {
    let mut exact = CognitionSourceBudget::new();
    assert!(
        exact
            .try_add("m", &"x".repeat(MAX_COGNITION_SOURCE_BYTES - 1))
            .is_ok()
    );
    assert!(matches!(
        exact.try_add("m", ""),
        Err(CognitionApplyError::LimitExceeded("source bytes"))
    ));

    let mut over = CognitionSourceBudget::new();
    assert!(matches!(
        over.try_add("m", &"x".repeat(MAX_COGNITION_SOURCE_BYTES)),
        Err(CognitionApplyError::LimitExceeded("source bytes"))
    ));

    let mut overflow = super::super::limits::CognitionSourceBudget::with_usage(usize::MAX, 0);
    assert!(matches!(
        overflow.try_add("m", "x"),
        Err(CognitionApplyError::LimitExceeded("source count"))
    ));
    let mut overflow = super::super::limits::CognitionSourceBudget::with_usage(0, usize::MAX);
    assert!(matches!(
        overflow.try_add("m", "x"),
        Err(CognitionApplyError::LimitExceeded("source bytes"))
    ));
}

#[test]
fn projection_and_evidence_counts_are_inclusive() {
    let fixture = Fixture::new();
    let mut binding = fixture.binding.clone();
    binding.effective_projection = fields(MAX_COGNITION_PROJECTION_FIELDS);
    assert!(binding.canonical_digest().is_ok());
    binding.effective_projection.push("field-over".into());
    assert!(matches!(
        binding.canonical_digest(),
        Err(CognitionApplyError::LimitExceeded("effective projection"))
    ));

    let mut proposal = fixture.proposal();
    proposal.evidence = vec![String::new(); MAX_COGNITION_EVIDENCE_ITEMS];
    assert!(proposal.canonical_digest().is_ok());
    proposal.evidence.push(String::new());
    assert!(matches!(
        proposal.canonical_digest(),
        Err(CognitionApplyError::LimitExceeded("evidence count"))
    ));
}

#[test]
fn output_step_and_target_limits_are_inclusive() {
    let fixture = Fixture::new();
    let mut outputs = fixture.proposal();
    outputs.plan = ConsolidationPlan::new();
    outputs.drafts = vec![draft(); MAX_COGNITION_MUTATIONS];
    assert!(outputs.canonical_digest().is_ok());
    outputs.drafts.push(draft());
    assert!(matches!(
        outputs.canonical_digest(),
        Err(CognitionApplyError::LimitExceeded("mutation count"))
    ));

    let ids = source_ids(&fixture, MAX_COGNITION_MUTATIONS);
    let mut steps = fixture.proposal();
    steps.source_ids.clone_from(&ids);
    steps.drafts.clear();
    steps.plan.steps = ids
        .iter()
        .cloned()
        .map(|id| ConsolidationStep::Invalidate { ids: vec![id] })
        .collect();
    assert!(steps.canonical_digest().is_ok());
    steps.plan.steps.push(ConsolidationStep::Invalidate {
        ids: vec![ids[0].clone()],
    });
    assert!(matches!(
        steps.canonical_digest(),
        Err(CognitionApplyError::LimitExceeded("plan step count"))
    ));

    let mut targets = fixture.proposal();
    targets.source_ids.clone_from(&ids);
    targets.drafts.clear();
    targets.plan =
        ConsolidationPlan::new().then(ConsolidationStep::Invalidate { ids: ids.clone() });
    assert!(targets.canonical_digest().is_ok());
    if let ConsolidationStep::Invalidate { ids } = &mut targets.plan.steps[0] {
        ids.push(ids[0].clone());
    }
    assert!(matches!(
        targets.canonical_digest(),
        Err(CognitionApplyError::LimitExceeded("mutation target count"))
    ));
}

#[test]
fn total_authoritative_mutations_are_inclusive() {
    let fixture = Fixture::new();
    let target_count = MAX_COGNITION_MUTATIONS - 1;
    let ids = source_ids(&fixture, target_count);
    let mut proposal = fixture.proposal();
    proposal.source_ids = ids.clone();
    proposal.drafts = vec![draft(); MAX_COGNITION_MUTATIONS - target_count];
    proposal.plan = ConsolidationPlan::new().then(ConsolidationStep::Invalidate { ids });
    assert!(proposal.canonical_digest().is_ok());
    proposal.drafts.push(draft());
    assert!(matches!(
        proposal.canonical_digest(),
        Err(CognitionApplyError::LimitExceeded("mutation count"))
    ));
}

#[test]
fn proposal_identity_limits_are_inclusive_and_fail_before_adapters() {
    type IdentitySetter = fn(&mut CognitionProposal, String);
    let cases: [(&str, usize, IdentitySetter, &str); 3] = [
        (
            "job",
            MAX_COGNITION_IDENTITY_BYTES,
            |proposal, value| proposal.job_id = value,
            "job identity",
        ),
        (
            "algorithm",
            MAX_COGNITION_ALGORITHM_BYTES,
            |proposal, value| proposal.algorithm = value,
            "algorithm identity",
        ),
        (
            "algorithm version",
            MAX_COGNITION_ALGORITHM_BYTES,
            |proposal, value| proposal.algorithm_version = value,
            "algorithm identity",
        ),
    ];

    for (name, maximum, set, limit_name) in cases {
        let fixture = Fixture::new();
        let mut exact = fixture.proposal();
        set(&mut exact, "x".repeat(maximum));
        fixture
            .authority
            .set(authority_for_proposal(&fixture.binding, &exact));
        assert!(exact.canonical_digest().is_ok(), "exact {name} limit");
        fixture
            .vault
            .apply_cognition(&fixture.space, &fixture.write, &exact, &fixture.context)
            .unwrap_or_else(|error| panic!("exact {name} limit: {error}"));

        let fixture = Fixture::new();
        let mut over = fixture.proposal();
        set(&mut over, "x".repeat(maximum + 1));
        let before_gets = fixture.store.state().get_calls;
        assert!(matches!(
            fixture.vault.apply_cognition(
                &fixture.space,
                &fixture.write,
                &over,
                &fixture.context
            ),
            Err(MemoryError::Cognition(CognitionApplyError::LimitExceeded(
                actual
            ))) if actual == limit_name
        ));
        assert_eq!(fixture.authority.calls(), 0, "over-limit {name}");
        assert_eq!(fixture.store.state().recovery_calls, 0, "over-limit {name}");
        assert_eq!(
            fixture.store.state().get_calls,
            before_gets,
            "over-limit {name}"
        );
    }
}

#[test]
fn proposal_byte_limit_is_inclusive() {
    let fixture = Fixture::new();

    let mut proposal = fixture.proposal();
    proposal.evidence = vec![String::new()];
    let base = serde_json::to_vec(&proposal).unwrap().len();
    proposal.evidence[0] = "x".repeat(MAX_COGNITION_PROPOSAL_BYTES - base);
    assert_eq!(
        serde_json::to_vec(&proposal).unwrap().len(),
        MAX_COGNITION_PROPOSAL_BYTES
    );
    assert!(proposal.canonical_digest().is_ok());
    proposal.evidence[0].push('x');
    assert_eq!(
        serde_json::to_vec(&proposal).unwrap().len(),
        MAX_COGNITION_PROPOSAL_BYTES + 1
    );
    assert!(matches!(
        proposal.canonical_digest(),
        Err(CognitionApplyError::LimitExceeded("proposal bytes"))
    ));
}

#[test]
fn untrusted_json_is_bounded_before_deserialization() {
    let fixture = Fixture::new();
    let mut proposal = fixture.proposal();
    proposal.evidence = vec![String::new()];
    let base = serde_json::to_vec(&proposal).unwrap().len();
    proposal.evidence[0] = "x".repeat(MAX_COGNITION_PROPOSAL_BYTES - base);

    let mut encoded = serde_json::to_vec(&proposal).unwrap();
    assert_eq!(encoded.len(), MAX_COGNITION_PROPOSAL_BYTES);
    let decoded = CognitionProposal::from_json_slice(&encoded).expect("inclusive raw limit");
    assert_eq!(
        decoded.canonical_digest().unwrap(),
        proposal.canonical_digest().unwrap()
    );

    encoded.push(b' ');
    assert!(matches!(
        CognitionProposal::from_json_slice(&encoded),
        Err(CognitionApplyError::LimitExceeded("proposal bytes"))
    ));
}

fn source_ids(fixture: &Fixture, count: usize) -> Vec<MemoryId> {
    std::iter::once(fixture.source.clone())
        .chain((1..count).map(|index| MemoryId::from_string(format!("mem-{index:04}"))))
        .collect()
}

fn fields(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("field-{index:04}"))
        .collect()
}

fn draft() -> MemoryDraft {
    MemoryDraft::new(
        MemoryKind::Semantic,
        MemoryContent::text("derived"),
        Provenance::Operator,
    )
}
