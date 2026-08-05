use std::collections::HashSet;

use chrono::{DateTime, Utc};
use typesec_core::policy::RequestContext;
use typesec_core::{CanWrite, Capability, Resource};

use super::types::{CognitionApplyError, CognitionAuthorityEvidence, CognitionBinding};
use crate::CognitionProposal;
use crate::error::MemoryError;
use crate::record::StoredRecord;
use crate::space::{MemoryId, MemorySpace};
use crate::store::MemoryStore;
use crate::vault::MemoryVault;

pub(super) fn required_purpose(context: &RequestContext) -> Result<&str, CognitionApplyError> {
    context
        .purpose
        .as_deref()
        .filter(|purpose| !purpose.trim().is_empty())
        .ok_or(CognitionApplyError::MissingPurpose)
}

pub(super) fn validate_proposal_shape(
    proposal: &CognitionProposal,
) -> Result<(), CognitionApplyError> {
    if proposal.schema_version != CognitionProposal::SCHEMA_VERSION {
        return Err(CognitionApplyError::UnsupportedSchema(
            proposal.schema_version,
        ));
    }
    if proposal.job_id.trim().is_empty() {
        return Err(CognitionApplyError::InvalidPlan(
            "job id is empty".to_owned(),
        ));
    }
    if proposal.algorithm.trim().is_empty() || proposal.algorithm_version.trim().is_empty() {
        return Err(CognitionApplyError::InvalidPlan(
            "algorithm identity is empty".to_owned(),
        ));
    }
    validate_source_ids(&proposal.source_ids)
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
    binding: &CognitionBinding,
    authority: &CognitionAuthorityEvidence,
) -> Result<(), CognitionApplyError> {
    for (name, matches) in [
        ("space", binding.space_id == authority.space_id),
        ("subject", binding.subject == authority.subject),
        ("purpose", binding.purpose == authority.purpose),
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
    if canonical_projection(&binding.effective_projection)
        != canonical_projection(&authority.effective_projection)
    {
        return Err(CognitionApplyError::BindingMismatch("effective projection"));
    }
    if authority.policy_decision_id.trim().is_empty() {
        return Err(CognitionApplyError::Authority(
            "policy decision id is empty".to_owned(),
        ));
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
    source_ids
        .iter()
        .map(|id| {
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
            validate_source(&record, purpose, now)?;
            Ok(record)
        })
        .collect()
}

fn canonical_projection(projection: &[String]) -> Vec<&str> {
    let mut canonical: Vec<_> = projection.iter().map(String::as_str).collect();
    canonical.sort_unstable();
    canonical
}

fn validate_source_ids(source_ids: &[MemoryId]) -> Result<(), CognitionApplyError> {
    if source_ids.is_empty() {
        return Err(CognitionApplyError::InvalidSourceSet(
            "at least one source is required".to_owned(),
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

fn validate_source(
    record: &StoredRecord,
    purpose: &str,
    now: DateTime<Utc>,
) -> Result<(), CognitionApplyError> {
    let reason = if record.quarantined {
        Some("quarantined")
    } else if !record.is_valid_at(now) {
        Some("not currently valid")
    } else if record.is_expired_at(now) {
        Some("retention expired")
    } else if !record.purposes.is_empty()
        && !record.purposes.iter().any(|allowed| allowed == purpose)
    {
        Some("purpose is not allowed")
    } else {
        None
    };
    match reason {
        Some(reason) => Err(CognitionApplyError::InvalidSource {
            id: record.id.clone(),
            reason,
        }),
        None => Ok(()),
    }
}
