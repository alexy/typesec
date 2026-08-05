use std::collections::{BTreeMap, BTreeSet, HashSet};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use typesec_core::Resource;

use super::digest::{binding_digest, evidence_digest};
use super::types::{
    CognitionApplyError, CognitionAuditEvidence, CognitionAuthorityEvidence, CognitionBinding,
    CognitionIdempotencyKey, CognitionSourceManifest, PreparedCognitionCommit,
};
use crate::CognitionProposal;
use crate::index::IndexMutation;
use crate::record::{MemoryDraft, Provenance, StoredRecord};
use crate::space::{MemoryId, MemorySpace};
use crate::store::StoreBatchOp;
use crate::vault::{ConsolidationStep, build_record_with_id};

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_commit(
    space: &MemorySpace,
    proposal: &CognitionProposal,
    binding: &CognitionBinding,
    authority: &CognitionAuthorityEvidence,
    sources: &[StoredRecord],
    manifest: CognitionSourceManifest,
    proposal_digest: String,
    now: DateTime<Utc>,
) -> Result<PreparedCognitionCommit, CognitionApplyError> {
    let mut builder = CommitBuilder::new(
        space,
        proposal,
        binding,
        sources,
        manifest.joined_label,
        &proposal_digest,
        now,
    );
    builder.add_drafts();
    builder.add_plan()?;
    let parts = builder.finish()?;

    Ok(PreparedCognitionCommit {
        idempotency_key: CognitionIdempotencyKey {
            space_id: binding.space_id.clone(),
            job_id: proposal.job_id.clone(),
        },
        proposal_digest: proposal_digest.clone(),
        source_preconditions: manifest.sources,
        operations: parts.operations,
        index_outbox: parts.index_outbox,
        audit: CognitionAuditEvidence {
            operation_id: proposal.job_id.clone(),
            subject: binding.subject.clone(),
            space_id: binding.space_id.clone(),
            purpose: binding.purpose.clone(),
            proposal_digest,
            binding_digest: binding_digest(binding)?,
            source_manifest_digest: binding.source_manifest_digest.clone(),
            typedid_request_digest: binding.typedid_request_digest.clone(),
            governed_scan_digest: binding.governed_scan_digest.clone(),
            authorization_receipt_digest: binding.authorization_receipt_digest.clone(),
            policy_decision_id: authority.policy_decision_id.clone(),
            evidence_digest: evidence_digest(&proposal.evidence)?,
            affected_ids: parts.affected_ids,
            prepared_at: now,
        },
    })
}

struct CommitBuilder<'a> {
    space: &'a MemorySpace,
    proposal: &'a CognitionProposal,
    binding: &'a CognitionBinding,
    label_floor: crate::Label,
    retention_ceiling: Option<DateTime<Utc>>,
    proposal_digest: &'a str,
    invalidated: HashSet<MemoryId>,
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
        sources: &[StoredRecord],
        label_floor: crate::Label,
        proposal_digest: &'a str,
        prepared_at: DateTime<Utc>,
    ) -> Self {
        Self {
            space,
            proposal,
            binding,
            label_floor,
            retention_ceiling: sources.iter().filter_map(|record| record.expires_at).min(),
            proposal_digest,
            invalidated: HashSet::new(),
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

    fn add_plan(&mut self) -> Result<(), CognitionApplyError> {
        let source_set: HashSet<_> = self.proposal.source_ids.iter().cloned().collect();
        for step in &self.proposal.plan.steps {
            match step {
                ConsolidationStep::Invalidate { ids } => {
                    self.add_invalidations(ids, &source_set)?;
                }
                ConsolidationStep::Supersede {
                    superseded,
                    replacement,
                } => {
                    self.add_invalidations(superseded, &source_set)?;
                    self.add_record(replacement.clone());
                }
            }
        }
        Ok(())
    }

    fn add_invalidations(
        &mut self,
        ids: &[MemoryId],
        source_set: &HashSet<MemoryId>,
    ) -> Result<(), CognitionApplyError> {
        if ids.is_empty() {
            return Err(CognitionApplyError::InvalidPlan(
                "mutation step has no targets".to_owned(),
            ));
        }
        for id in ids {
            if !source_set.contains(id) {
                return Err(CognitionApplyError::InvalidPlan(format!(
                    "target '{id}' is not a proposal source"
                )));
            }
            if !self.invalidated.insert(id.clone()) {
                return Err(CognitionApplyError::InvalidPlan(format!(
                    "target '{id}' appears more than once"
                )));
            }
            self.operations.push(StoreBatchOp::Invalidate {
                id: id.clone(),
                at: self.prepared_at,
            });
            self.index_outbox
                .insert(id.clone(), IndexMutation::Remove(id.clone()));
            self.affected.insert(id.clone());
        }
        Ok(())
    }

    fn add_record(&mut self, draft: MemoryDraft) {
        let id = deterministic_output_id(
            self.space,
            self.proposal,
            self.proposal_digest,
            self.output_ordinal,
        );
        self.output_ordinal += 1;
        let draft =
            secure_derived_draft(draft, self.proposal, self.binding, self.retention_ceiling);
        let record = build_record_with_id(self.space, draft, Some(self.label_floor), id.clone());
        self.operations.push(StoreBatchOp::Put(Box::new(record)));
        self.index_outbox
            .insert(id.clone(), IndexMutation::Upsert(id.clone()));
        self.affected.insert(id);
    }

    fn finish(self) -> Result<CommitParts, CognitionApplyError> {
        if self.operations.is_empty() {
            return Err(CognitionApplyError::InvalidPlan(
                "proposal has no mutations".to_owned(),
            ));
        }
        Ok(CommitParts {
            operations: self.operations,
            index_outbox: self.index_outbox.into_values().collect(),
            affected_ids: self.affected.into_iter().collect(),
        })
    }
}

fn secure_derived_draft(
    mut draft: MemoryDraft,
    proposal: &CognitionProposal,
    binding: &CognitionBinding,
    retention_ceiling: Option<DateTime<Utc>>,
) -> MemoryDraft {
    let mut source_ids = proposal.source_ids.clone();
    source_ids.sort();
    draft.provenance = Provenance::Cognition {
        job_id: proposal.job_id.clone(),
        source_ids,
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

fn deterministic_output_id(
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
    MemoryId::from_string(format!("mem-cog-{:x}", digest.finalize()))
}
