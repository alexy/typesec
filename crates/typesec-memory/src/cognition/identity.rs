//! Digest-safe identity for one validated cognition mutation.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use typesec_core::Resource;

use super::digest::{binding_digest, evidence_digest};
use super::limits::proposal_output_count;
use super::{
    CognitionApplyError, CognitionAuditEvidence, CognitionBinding, CognitionEffect,
    CognitionIdempotencyKey,
};
use crate::{CognitionProposal, ConsolidationStep, GovernedSourceScope, MemoryId, MemorySpace};

pub(super) const COGNITION_OUTPUT_ID_PREFIX: &str = "mem-cog-";
pub(super) const COGNITION_OUTPUT_ID_BYTES: usize = COGNITION_OUTPUT_ID_PREFIX.len() + 64;

pub(super) struct CognitionCommitIdentity {
    pub(super) key: CognitionIdempotencyKey,
    pub(super) proposal_digest: String,
    pub(super) binding_digest: String,
    pub(super) evidence_digest: String,
    pub(super) expected_affected_ids: Vec<MemoryId>,
    effect: CognitionEffect,
    job_id: String,
    subject: String,
    space_id: String,
    purpose: String,
    governed_source_scope: Option<GovernedSourceScope>,
    source_manifest_digest: String,
    typedid_request_digest: String,
    governed_scan_digest: String,
    snapshot_digest: String,
    authorization_receipt_digest: String,
}

impl CognitionCommitIdentity {
    pub(super) fn from_validated(
        space: &MemorySpace,
        proposal: &CognitionProposal,
        binding: &CognitionBinding,
        proposal_digest: String,
    ) -> Result<Self, CognitionApplyError> {
        let key = CognitionIdempotencyKey::for_authority(
            &binding.space_id,
            &binding.subject,
            &binding.purpose,
            &proposal.job_id,
        )?;
        Ok(Self {
            expected_affected_ids: expected_affected_ids(space, proposal, &proposal_digest)?,
            effect: proposal.effect,
            proposal_digest,
            binding_digest: binding_digest(binding)?,
            evidence_digest: evidence_digest(&proposal.evidence)?,
            key,
            job_id: proposal.job_id.clone(),
            subject: binding.subject.clone(),
            space_id: binding.space_id.clone(),
            purpose: binding.purpose.clone(),
            governed_source_scope: binding.governed_source_scope.clone(),
            source_manifest_digest: binding.source_manifest_digest.clone(),
            typedid_request_digest: binding.typedid_request_digest.clone(),
            governed_scan_digest: binding.governed_scan_digest.clone(),
            snapshot_digest: binding.snapshot_digest.clone(),
            authorization_receipt_digest: binding.authorization_receipt_digest.clone(),
        })
    }

    pub(super) fn matches_audit(&self, audit: &CognitionAuditEvidence) -> bool {
        audit.schema_version == CognitionAuditEvidence::SCHEMA_VERSION
            && audit.effect == self.effect
            && audit.operation_id == self.job_id
            && audit.subject == self.subject
            && audit.space_id == self.space_id
            && audit.purpose == self.purpose
            && audit.governed_source_scope == self.governed_source_scope
            && audit.proposal_digest == self.proposal_digest
            && audit.binding_digest == self.binding_digest
            && audit.source_manifest_digest == self.source_manifest_digest
            && audit.typedid_request_digest == self.typedid_request_digest
            && audit.governed_scan_digest == self.governed_scan_digest
            && audit.snapshot_digest == self.snapshot_digest
            && audit.authorization_receipt_digest == self.authorization_receipt_digest
            && audit.evidence_digest == self.evidence_digest
            && audit.affected_ids == self.expected_affected_ids
    }
}

fn expected_affected_ids(
    space: &MemorySpace,
    proposal: &CognitionProposal,
    proposal_digest: &str,
) -> Result<Vec<MemoryId>, CognitionApplyError> {
    let mut affected: BTreeSet<_> = proposal
        .plan
        .steps
        .iter()
        .flat_map(|step| match step {
            ConsolidationStep::Supersede { superseded, .. } => superseded.iter(),
            ConsolidationStep::Invalidate { ids } => ids.iter(),
        })
        .cloned()
        .collect();
    let output_count = proposal_output_count(proposal)?;
    affected.extend(
        (0..output_count).map(|ordinal| {
            deterministic_output_id(space, proposal, proposal_digest, ordinal as u64)
        }),
    );
    Ok(affected.into_iter().collect())
}

pub(super) fn deterministic_output_id(
    space: &MemorySpace,
    proposal: &CognitionProposal,
    proposal_digest: &str,
    ordinal: u64,
) -> MemoryId {
    let mut digest = Sha256::new();
    digest.update(b"typesec.marciana.output-id.v1\0");
    for field in [
        space.resource_id(),
        proposal.job_id.as_str(),
        proposal_digest,
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    digest.update(ordinal.to_be_bytes());
    MemoryId::from_string(format!(
        "{COGNITION_OUTPUT_ID_PREFIX}{:x}",
        digest.finalize()
    ))
}
