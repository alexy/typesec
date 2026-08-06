use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

use super::PreparedCognitionCommit;
use super::identity::{CognitionCommitIdentity, deterministic_output_id};
use super::limits::{
    MAX_COGNITION_MUTATIONS, proposal_output_count, validate_affected_id_budget,
    validate_prepared_expansion,
};
use super::types::{
    CognitionApplyError, CognitionAuditEvidence, CognitionAuthorityEvidence, CognitionBinding,
    CognitionSourceManifest,
};
use crate::CognitionProposal;
use crate::index::IndexMutation;
use crate::record::{MemoryDraft, Provenance, StoredRecord};
use crate::space::{MemoryId, MemorySpace};
use crate::store::StoreBatchOp;
use crate::vault::{ConsolidationStep, build_record_with_id_at};

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_commit(
    space: &MemorySpace,
    proposal: &CognitionProposal,
    binding: &CognitionBinding,
    authority: &CognitionAuthorityEvidence,
    sources: &[StoredRecord],
    manifest: CognitionSourceManifest,
    identity: &CognitionCommitIdentity,
    now: DateTime<Utc>,
) -> Result<PreparedCognitionCommit, CognitionApplyError> {
    let output_count = proposal_output_count(proposal)?;
    validate_prepared_expansion(proposal, output_count)?;
    let mut builder = CommitBuilder::new(
        space,
        proposal,
        binding,
        output_count,
        sources,
        manifest.joined_label,
        &identity.proposal_digest,
        now,
    );
    builder.add_drafts();
    builder.add_plan();
    let parts = builder.finish();
    validate_affected_id_budget(&parts.affected_ids)?;
    if parts.affected_ids != identity.expected_affected_ids
        || parts.operations.len() != parts.affected_ids.len()
        || parts.index_outbox.len() != parts.affected_ids.len()
        || parts.affected_ids.len() > MAX_COGNITION_MUTATIONS
    {
        return Err(CognitionApplyError::InvalidPlan(
            "prepared mutation identity drift".to_owned(),
        ));
    }

    Ok(PreparedCognitionCommit::new(
        identity.key.clone(),
        identity.proposal_digest.clone(),
        manifest.sources,
        parts.operations,
        parts.index_outbox,
        CognitionAuditEvidence {
            operation_id: proposal.job_id.clone(),
            subject: binding.subject.clone(),
            space_id: binding.space_id.clone(),
            purpose: binding.purpose.clone(),
            proposal_digest: identity.proposal_digest.clone(),
            binding_digest: identity.binding_digest.clone(),
            source_manifest_digest: binding.source_manifest_digest.clone(),
            typedid_request_digest: binding.typedid_request_digest.clone(),
            governed_scan_digest: binding.governed_scan_digest.clone(),
            authorization_receipt_digest: binding.authorization_receipt_digest.clone(),
            policy_decision_id: authority.policy_decision_id.clone(),
            evidence_digest: identity.evidence_digest.clone(),
            affected_ids: parts.affected_ids,
            prepared_at: now,
        },
    ))
}

struct CommitBuilder<'a> {
    space: &'a MemorySpace,
    proposal: &'a CognitionProposal,
    binding: &'a CognitionBinding,
    label_floor: crate::Label,
    retention_ceiling: Option<DateTime<Utc>>,
    canonical_source_ids: Vec<MemoryId>,
    proposal_digest: &'a str,
    operations: Vec<StoreBatchOp>,
    index_outbox: BTreeMap<MemoryId, IndexMutation>,
    affected: BTreeSet<MemoryId>,
    output_ordinal: u64,
    prepared_at: DateTime<Utc>,
}

struct CommitParts {
    operations: Vec<StoreBatchOp>,
    index_outbox: Vec<IndexMutation>,
    affected_ids: Vec<MemoryId>,
}

impl<'a> CommitBuilder<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        space: &'a MemorySpace,
        proposal: &'a CognitionProposal,
        binding: &'a CognitionBinding,
        output_count: usize,
        sources: &[StoredRecord],
        label_floor: crate::Label,
        proposal_digest: &'a str,
        prepared_at: DateTime<Utc>,
    ) -> Self {
        let mut canonical_source_ids = if output_count == 0 {
            Vec::new()
        } else {
            proposal.source_ids.clone()
        };
        canonical_source_ids.sort();
        Self {
            space,
            proposal,
            binding,
            label_floor,
            retention_ceiling: sources.iter().filter_map(|record| record.expires_at).min(),
            canonical_source_ids,
            proposal_digest,
            operations: Vec::new(),
            index_outbox: BTreeMap::new(),
            affected: BTreeSet::new(),
            output_ordinal: 0,
            prepared_at,
        }
    }

    fn add_drafts(&mut self) {
        for draft in &self.proposal.drafts {
            self.add_record(draft.clone());
        }
    }

    fn add_plan(&mut self) {
        for step in &self.proposal.plan.steps {
            match step {
                ConsolidationStep::Invalidate { ids } => {
                    self.add_invalidations(ids);
                }
                ConsolidationStep::Supersede {
                    superseded,
                    replacement,
                } => {
                    self.add_invalidations(superseded);
                    self.add_record(replacement.clone());
                }
            }
        }
    }

    fn add_invalidations(&mut self, ids: &[MemoryId]) {
        for id in ids {
            self.operations.push(StoreBatchOp::Invalidate {
                id: id.clone(),
                at: self.prepared_at,
            });
            self.index_outbox
                .insert(id.clone(), IndexMutation::Remove(id.clone()));
            self.affected.insert(id.clone());
        }
    }

    fn add_record(&mut self, draft: MemoryDraft) {
        let id = deterministic_output_id(
            self.space,
            self.proposal,
            self.proposal_digest,
            self.output_ordinal,
        );
        self.output_ordinal += 1;
        let draft = secure_derived_draft(
            draft,
            self.proposal,
            self.binding,
            &self.canonical_source_ids,
            self.retention_ceiling,
        );
        let record = build_record_with_id_at(
            self.space,
            draft,
            Some(self.label_floor),
            id.clone(),
            self.prepared_at,
        );
        self.operations.push(StoreBatchOp::Put(Box::new(record)));
        self.index_outbox
            .insert(id.clone(), IndexMutation::Upsert(id.clone()));
        self.affected.insert(id);
    }

    fn finish(self) -> CommitParts {
        CommitParts {
            operations: self.operations,
            index_outbox: self.index_outbox.into_values().collect(),
            affected_ids: self.affected.into_iter().collect(),
        }
    }
}

fn secure_derived_draft(
    mut draft: MemoryDraft,
    proposal: &CognitionProposal,
    binding: &CognitionBinding,
    canonical_source_ids: &[MemoryId],
    retention_ceiling: Option<DateTime<Utc>>,
) -> MemoryDraft {
    draft.provenance = Provenance::Cognition {
        job_id: proposal.job_id.clone(),
        source_ids: canonical_source_ids.to_vec(),
        source_digest: proposal.source_digest.clone(),
        algorithm: proposal.algorithm.clone(),
        algorithm_version: proposal.algorithm_version.clone(),
    };
    draft.purposes = vec![binding.purpose.clone()];
    if let Some(ceiling) = retention_ceiling {
        draft.expires_at = Some(
            draft
                .expires_at
                .map_or(ceiling, |expiry| expiry.min(ceiling)),
        );
    }
    draft
}
