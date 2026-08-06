//! Fail-closed validation of authoritative cognition results.

use super::canonical::{is_canonical_sha256, is_canonical_text};
use super::identity::CognitionCommitIdentity;
use super::limits::{MAX_COGNITION_MUTATIONS, affected_ids_within_byte_budget};
use super::{
    CognitionAuditEvidence, CognitionCommitError, CognitionCommitOutcome, CognitionCommitStatus,
};
use crate::MemoryId;

pub(super) fn validate_preflight_outcome(
    outcome: &CognitionCommitOutcome,
    identity: &CognitionCommitIdentity,
) -> Result<(), CognitionCommitError> {
    if outcome.status != CognitionCommitStatus::AlreadyApplied
        || !validate_shape(outcome)
        || !identity.matches_audit(&outcome.audit)
    {
        return Err(CognitionCommitError::InvalidOutcome);
    }
    Ok(())
}

pub(super) fn validate_commit_outcome(
    outcome: &CognitionCommitOutcome,
    identity: &CognitionCommitIdentity,
    prepared_audit: &CognitionAuditEvidence,
) -> Result<(), CognitionCommitError> {
    if !validate_shape(outcome) || !identity.matches_audit(&outcome.audit) {
        return Err(CognitionCommitError::InvalidOutcome);
    }
    match outcome.status {
        CognitionCommitStatus::Applied if &outcome.audit == prepared_audit => Ok(()),
        CognitionCommitStatus::AlreadyApplied => Ok(()),
        CognitionCommitStatus::Applied => Err(CognitionCommitError::InvalidOutcome),
    }
}

pub(super) fn validate_shape(outcome: &CognitionCommitOutcome) -> bool {
    canonical_affected_ids(&outcome.affected_ids)
        && canonical_affected_ids(&outcome.audit.affected_ids)
        && outcome.affected_ids == outcome.audit.affected_ids
        && is_canonical_text(&outcome.backend_commit_hash)
        && is_canonical_text(&outcome.prior_version)
        && is_canonical_text(&outcome.resulting_version)
        && outcome.prior_version != outcome.resulting_version
        && canonical_audit(&outcome.audit)
        && outcome.committed_at >= outcome.audit.prepared_at
}

fn canonical_audit(audit: &CognitionAuditEvidence) -> bool {
    audit.schema_version == CognitionAuditEvidence::SCHEMA_VERSION
        && audit.authority_revalidated_at <= audit.prepared_at
        && audit.governed_scan_digest != audit.snapshot_digest
        && [
            audit.operation_id.as_str(),
            audit.subject.as_str(),
            audit.space_id.as_str(),
            audit.purpose.as_str(),
            audit.policy_decision_id.as_str(),
        ]
        .into_iter()
        .all(is_canonical_text)
        && [
            audit.proposal_digest.as_str(),
            audit.binding_digest.as_str(),
            audit.source_manifest_digest.as_str(),
            audit.typedid_request_digest.as_str(),
            audit.governed_scan_digest.as_str(),
            audit.snapshot_digest.as_str(),
            audit.authorization_receipt_digest.as_str(),
            audit.evidence_digest.as_str(),
        ]
        .into_iter()
        .all(is_canonical_sha256)
}

fn canonical_affected_ids(ids: &[MemoryId]) -> bool {
    !ids.is_empty()
        && ids.len() <= MAX_COGNITION_MUTATIONS
        && affected_ids_within_byte_budget(ids)
        && ids.iter().all(|id| is_canonical_text(id.as_str()))
        && ids.windows(2).all(|pair| pair[0] < pair[1])
}
