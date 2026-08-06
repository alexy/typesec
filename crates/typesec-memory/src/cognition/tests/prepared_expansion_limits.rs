use super::*;

#[test]
fn lineage_reference_count_is_inclusive_and_preflighted() {
    let fixture = Fixture::new();
    let mut exact = proposal_with_shape(&fixture, short_source_ids(64), 64);
    assert!(exact.canonical_digest().is_ok());

    exact
        .source_ids
        .push(MemoryId::from_string("mem-lineage-over"));
    assert!(matches!(
        exact.canonical_digest(),
        Err(CognitionApplyError::LimitExceeded(
            "lineage reference count"
        ))
    ));
    assert_rejected_before_adapters(&fixture, &exact, "lineage reference count");
}

#[test]
fn lineage_id_bytes_are_inclusive_and_preflighted() {
    let fixture = Fixture::new();
    let exact_ids = ids_with_total_bytes(1_025, MAX_COGNITION_SOURCE_BYTES / 2);
    let mut exact = proposal_with_shape(&fixture, exact_ids, 2);
    assert!(exact.canonical_digest().is_ok());

    exact.source_ids[0] = MemoryId::from_string(format!("{}x", exact.source_ids[0].as_str()));
    assert!(matches!(
        exact.canonical_digest(),
        Err(CognitionApplyError::LimitExceeded("lineage bytes"))
    ));
    assert_rejected_before_adapters(&fixture, &exact, "lineage bytes");
}

#[test]
fn invalidation_only_source_id_bytes_are_inclusive_and_preflighted() {
    let fixture = Fixture::new();
    let exact_ids = ids_with_total_bytes(1_025, MAX_COGNITION_SOURCE_BYTES);
    let invalidated = exact_ids[0].clone();
    let mut exact = proposal_with_shape(&fixture, exact_ids, 0);
    exact.plan = ConsolidationPlan::new().then(ConsolidationStep::Invalidate {
        ids: vec![invalidated],
    });
    assert!(exact.canonical_digest().is_ok());

    exact.source_ids[1] = MemoryId::from_string(format!("{}x", exact.source_ids[1].as_str()));
    assert!(matches!(
        exact.canonical_digest(),
        Err(CognitionApplyError::LimitExceeded("source id bytes"))
    ));
    assert_rejected_before_adapters(&fixture, &exact, "source id bytes");
}

#[test]
fn affected_id_bytes_match_the_receipt_boundary() {
    let mut exact = ids_with_total_bytes(1_025, MAX_COGNITION_SOURCE_BYTES);
    assert!(super::super::limits::validate_affected_id_budget(&exact).is_ok());

    exact[0] = MemoryId::from_string(format!("{}x", exact[0].as_str()));
    assert!(matches!(
        super::super::limits::validate_affected_id_budget(&exact),
        Err(CognitionApplyError::LimitExceeded("affected id bytes"))
    ));
}

#[test]
fn lineage_arithmetic_overflow_fails_closed() {
    assert!(matches!(
        super::super::limits::validate_lineage_dimensions_for_test(usize::MAX, 1, 2),
        Err(CognitionApplyError::LimitExceeded(
            "lineage reference count"
        ))
    ));
    assert!(matches!(
        super::super::limits::validate_lineage_dimensions_for_test(1, usize::MAX, 2),
        Err(CognitionApplyError::LimitExceeded("lineage bytes"))
    ));
}

fn proposal_with_shape(
    fixture: &Fixture,
    source_ids: Vec<MemoryId>,
    output_count: usize,
) -> CognitionProposal {
    let mut proposal = fixture.proposal();
    proposal.source_ids = source_ids;
    proposal.plan = ConsolidationPlan::new();
    proposal.drafts = vec![draft(); output_count];
    proposal
}

fn short_source_ids(count: usize) -> Vec<MemoryId> {
    (0..count)
        .map(|index| MemoryId::from_string(format!("mem-lineage-{index:04}")))
        .collect()
}

fn ids_with_total_bytes(count: usize, total_bytes: usize) -> Vec<MemoryId> {
    let base = total_bytes / count;
    let remainder = total_bytes % count;
    let mut ids: Vec<_> = (0..count)
        .map(|index| {
            let length = base + usize::from(index < remainder);
            let suffix = format!("{index:04x}");
            assert!(suffix.len() <= length);
            MemoryId::from_string(format!("{}{}", "x".repeat(length - suffix.len()), suffix))
        })
        .collect();
    ids.sort();
    assert_eq!(
        ids.iter().map(|id| id.as_str().len()).sum::<usize>(),
        total_bytes
    );
    ids
}

fn assert_rejected_before_adapters(
    fixture: &Fixture,
    proposal: &CognitionProposal,
    expected_limit: &str,
) {
    let before_gets = fixture.store.state().get_calls;
    assert!(matches!(
        fixture.vault.apply_cognition(
            &fixture.space,
            &fixture.write,
            proposal,
            &fixture.context
        ),
        Err(MemoryError::Cognition(CognitionApplyError::LimitExceeded(
            actual
        ))) if actual == expected_limit
    ));
    assert_eq!(fixture.authority.calls(), 0);
    assert_eq!(fixture.store.state().recovery_calls, 0);
    assert_eq!(fixture.store.state().get_calls, before_gets);
}

fn draft() -> MemoryDraft {
    MemoryDraft::new(
        MemoryKind::Semantic,
        MemoryContent::text("derived"),
        Provenance::Operator,
    )
}
