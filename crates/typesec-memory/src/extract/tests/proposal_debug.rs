use super::*;
use crate::cognition::CognitionBinding;
use crate::record::{MemoryContent, MemoryDraft, Provenance};
use crate::space::{MemoryId, MemoryKind};
use crate::vault::{ConsolidationPlan, ConsolidationStep};

#[test]
fn cognition_proposal_debug_redacts_all_plaintext_payloads() {
    let source_secret = "secret-source-id";
    let draft_secret = "draft plaintext must never be logged";
    let replacement_secret = "replacement plaintext must never be logged";
    let evidence_secret = "evidence plaintext must never be logged";
    let binding_secret = "secret-binding-subject";
    let job_secret = "secret-job-identity";
    let algorithm_secret = "secret-algorithm-identity";
    let algorithm_version_secret = "secret-algorithm-version";
    let grant_digest = format!("sha256:{}", "a".repeat(64));
    let snapshot_digest = format!("sha256:{}", "b".repeat(64));
    let source_digest = format!("sha256:{}", "c".repeat(64));

    let mut proposal = CognitionProposal::new(
        job_secret,
        snapshot_digest.clone(),
        source_digest.clone(),
        algorithm_secret,
        algorithm_version_secret,
        vec![MemoryId::from_string(source_secret)],
        Label::Sensitive,
    )
    .with_drafts(vec![MemoryDraft::new(
        MemoryKind::Semantic,
        MemoryContent::text(draft_secret),
        Provenance::Operator,
    )])
    .with_plan(ConsolidationPlan::new().then(ConsolidationStep::Supersede {
        superseded: vec![MemoryId::from_string(source_secret)],
        replacement: MemoryDraft::new(
            MemoryKind::Semantic,
            MemoryContent::text(replacement_secret),
            Provenance::Operator,
        ),
    }));
    proposal.evidence = vec![evidence_secret.into()];
    proposal.binding = Some(CognitionBinding {
        space_id: "memory/secret-space".into(),
        subject: binding_secret.into(),
        purpose: "secret-purpose".into(),
        governed_source_scope: None,
        governed_scan_digest: grant_digest.clone(),
        snapshot_digest: snapshot_digest.clone(),
        plan_task_digest: grant_digest.clone(),
        authorization_receipt_digest: grant_digest.clone(),
        effective_projection: vec!["secret-projection".into()],
        source_manifest_digest: source_digest.clone(),
        typedid_request_digest: grant_digest.clone(),
    });

    let rendered = format!("{proposal:?}");
    for secret in [
        source_secret,
        draft_secret,
        replacement_secret,
        evidence_secret,
        binding_secret,
        job_secret,
        algorithm_secret,
        algorithm_version_secret,
        grant_digest.as_str(),
        snapshot_digest.as_str(),
        source_digest.as_str(),
        "secret-purpose",
        "secret-projection",
    ] {
        assert!(!rendered.contains(secret), "debug leaked {secret}");
    }
    for summary in [
        "source_id_count: 1",
        "draft_count: 1",
        "plan_step_count: 1",
        "evidence_count: 1",
        "has_binding: true",
    ] {
        assert!(rendered.contains(summary), "missing {summary}: {rendered}");
    }
}
