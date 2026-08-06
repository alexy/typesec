use std::collections::HashSet;

use chrono::{DateTime, Utc};
use typesec_core::policy::RequestContext;
use typesec_core::{CanWrite, Capability, Resource};

use super::canonical::is_canonical_text;
use super::limits::{CognitionSourceBudget, MAX_COGNITION_SOURCE_COUNT, validate_proposal_budget};
use super::types::{CognitionApplyError, CognitionAuthorityEvidence, CognitionBinding};
use crate::CognitionProposal;
use crate::error::MemoryError;
use crate::record::StoredRecord;
use crate::space::{MemoryId, MemorySpace};
use crate::store::MemoryStore;
use crate::vault::ConsolidationStep;
use crate::vault::MemoryVault;
use crate::vault::visibility::RecordVisibility;

pub(super) fn required_purpose(context: &RequestContext) -> Result<&str, CognitionApplyError> {
    context
        .purpose
        .as_deref()
        .filter(|purpose| is_canonical_text(purpose))
        .ok_or(CognitionApplyError::MissingPurpose)
}

pub(super) fn validate_proposal_shape(
    proposal: &CognitionProposal,
) -> Result<(), CognitionApplyError> {
    validate_proposal(proposal, false)
}

pub(super) fn validate_proposal_for_application(
    proposal: &CognitionProposal,
) -> Result<(), CognitionApplyError> {
    validate_proposal(proposal, true)
}

fn validate_proposal(
    proposal: &CognitionProposal,
    require_mutation: bool,
) -> Result<(), CognitionApplyError> {
    validate_proposal_budget(proposal)?;
    if !(CognitionProposal::MIN_SCHEMA_VERSION..=CognitionProposal::SCHEMA_VERSION)
        .contains(&proposal.schema_version)
    {
        return Err(CognitionApplyError::UnsupportedSchema(
            proposal.schema_version,
        ));
    }
    if proposal.schema_version == CognitionProposal::MIN_SCHEMA_VERSION
        && proposal
            .binding
            .as_ref()
            .and_then(|binding| binding.governed_source_scope.as_ref())
            .is_some()
    {
        return Err(CognitionApplyError::InvalidBinding(
            "governedSourceScope requires schemaVersion 2".to_owned(),
        ));
    }
    if !is_canonical_text(&proposal.job_id) {
        return Err(CognitionApplyError::InvalidPlan(
            "job id is not canonical".to_owned(),
        ));
    }
    if !is_canonical_text(&proposal.algorithm) || !is_canonical_text(&proposal.algorithm_version) {
        return Err(CognitionApplyError::InvalidPlan(
            "algorithm identity is not canonical".to_owned(),
        ));
    }
    validate_source_ids(&proposal.source_ids)?;
    validate_mutation_plan(proposal, require_mutation)
}

pub(super) fn validate_request_binding(
    space: &MemorySpace,
    capability: &Capability<CanWrite, MemorySpace>,
    proposal: &CognitionProposal,
    binding: &CognitionBinding,
    purpose: &str,
) -> Result<(), CognitionApplyError> {
    if binding.space_id != space.resource_id() {
        return Err(CognitionApplyError::BindingMismatch("space"));
    }
    if binding.subject != capability.subject().as_str() {
        return Err(CognitionApplyError::BindingMismatch("subject"));
    }
    if binding.purpose != purpose {
        return Err(CognitionApplyError::BindingMismatch("purpose"));
    }
    if binding.governed_scan_digest != proposal.input_snapshot {
        return Err(CognitionApplyError::BindingMismatch("governed scan digest"));
    }
    if binding.source_manifest_digest != proposal.source_digest {
        return Err(CognitionApplyError::BindingMismatch(
            "source manifest digest",
        ));
    }
    Ok(())
}

pub(super) fn validate_authority(
    proposal: &CognitionProposal,
    binding: &CognitionBinding,
    authority: &CognitionAuthorityEvidence,
) -> Result<(), CognitionApplyError> {
    for (name, matches) in [
        ("space", binding.space_id == authority.space_id),
        ("subject", binding.subject == authority.subject),
        ("purpose", binding.purpose == authority.purpose),
        (
            "governed source scope",
            binding.governed_source_scope == authority.governed_source_scope,
        ),
        ("job", proposal.job_id == authority.job_id),
        ("algorithm", proposal.algorithm == authority.algorithm),
        (
            "algorithm version",
            proposal.algorithm_version == authority.algorithm_version,
        ),
        (
            "governed scan digest",
            binding.governed_scan_digest == authority.governed_scan_digest,
        ),
        (
            "snapshot digest",
            binding.snapshot_digest == authority.snapshot_digest,
        ),
        (
            "plan task digest",
            binding.plan_task_digest == authority.plan_task_digest,
        ),
        (
            "authorization receipt digest",
            binding.authorization_receipt_digest == authority.authorization_receipt_digest,
        ),
        (
            "TypeDID request digest",
            binding.typedid_request_digest == authority.typedid_request_digest,
        ),
    ] {
        if !matches {
            return Err(CognitionApplyError::BindingMismatch(name));
        }
    }
    if authority.effective_projection.len() != binding.effective_projection.len() {
        return Err(CognitionApplyError::BindingMismatch("effective projection"));
    }
    if authority
        .effective_projection
        .iter()
        .any(|field| !is_canonical_text(field))
        || authority
            .effective_projection
            .iter()
            .collect::<HashSet<_>>()
            .len()
            != authority.effective_projection.len()
    {
        return Err(CognitionApplyError::Authority);
    }
    if canonical_projection(&binding.effective_projection)
        != canonical_projection(&authority.effective_projection)
    {
        return Err(CognitionApplyError::BindingMismatch("effective projection"));
    }
    if !is_canonical_text(&authority.policy_decision_id) {
        return Err(CognitionApplyError::Authority);
    }
    Ok(())
}

pub(super) fn load_sources<S: MemoryStore>(
    vault: &MemoryVault<S>,
    space: &MemorySpace,
    source_ids: &[MemoryId],
    purpose: &str,
    now: DateTime<Utc>,
) -> Result<Vec<StoredRecord>, MemoryError> {
    validate_source_ids(source_ids)?;
    let visibility = RecordVisibility::new(space.resource_id(), Some(purpose), now, now, false);
    let mut budget = CognitionSourceBudget::new();
    let mut records = Vec::with_capacity(source_ids.len());
    for id in source_ids {
        let record = vault
            .fetch_in_space(space, id)
            .map_err(|error| match error {
                MemoryError::NotFound(_) => CognitionApplyError::InvalidSource {
                    id: id.clone(),
                    reason: "missing or outside target space",
                }
                .into(),
                other => other,
            })?;
        validate_source(&record, &visibility)?;
        budget.try_add_record(&record)?;
        records.push(record);
    }
    Ok(records)
}

fn canonical_projection(projection: &[String]) -> Vec<&str> {
    let mut canonical: Vec<_> = projection.iter().map(String::as_str).collect();
    canonical.sort_unstable();
    canonical
}

fn validate_source_ids(source_ids: &[MemoryId]) -> Result<(), CognitionApplyError> {
    if source_ids.len() > MAX_COGNITION_SOURCE_COUNT {
        return Err(CognitionApplyError::LimitExceeded("source count"));
    }
    if source_ids.is_empty() {
        return Err(CognitionApplyError::InvalidSourceSet(
            "at least one source is required".to_owned(),
        ));
    }
    if source_ids.iter().any(|id| !is_canonical_text(id.as_str())) {
        return Err(CognitionApplyError::InvalidSourceSet(
            "source ids are not canonical".to_owned(),
        ));
    }
    let unique: HashSet<_> = source_ids.iter().collect();
    if unique.len() != source_ids.len() {
        return Err(CognitionApplyError::InvalidSourceSet(
            "source ids contain duplicates".to_owned(),
        ));
    }
    Ok(())
}

fn validate_mutation_plan(
    proposal: &CognitionProposal,
    require_mutation: bool,
) -> Result<(), CognitionApplyError> {
    let source_set: HashSet<_> = proposal.source_ids.iter().collect();
    let mut invalidated = HashSet::new();
    for step in &proposal.plan.steps {
        let ids = match step {
            ConsolidationStep::Supersede { superseded, .. } => superseded,
            ConsolidationStep::Invalidate { ids } => ids,
        };
        if ids.is_empty() {
            return Err(CognitionApplyError::InvalidPlan(
                "mutation step has no targets".to_owned(),
            ));
        }
        for id in ids {
            if !source_set.contains(id) {
                return Err(CognitionApplyError::InvalidPlan(
                    "mutation target is not a proposal source".to_owned(),
                ));
            }
            if !invalidated.insert(id) {
                return Err(CognitionApplyError::InvalidPlan(
                    "mutation target appears more than once".to_owned(),
                ));
            }
        }
    }
    let replacements = proposal
        .plan
        .steps
        .iter()
        .filter(|step| matches!(step, ConsolidationStep::Supersede { .. }))
        .count();
    if require_mutation && proposal.drafts.is_empty() && replacements == 0 && invalidated.is_empty()
    {
        return Err(CognitionApplyError::InvalidPlan(
            "proposal has no mutations".to_owned(),
        ));
    }
    Ok(())
}

fn validate_source(
    record: &StoredRecord,
    visibility: &RecordVisibility<'_>,
) -> Result<(), CognitionApplyError> {
    match visibility.check(record) {
        Err(rejection) => Err(CognitionApplyError::InvalidSource {
            id: record.id.clone(),
            reason: rejection.reason(),
        }),
        Ok(()) => Ok(()),
    }
}
