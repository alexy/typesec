//! Authorized recovery of completed cognition results after response loss.

use thiserror::Error;
use typesec_core::policy::RequestContext;
use typesec_core::{CanWrite, Capability, Resource};

use super::canonical::{is_canonical_sha256, is_canonical_text};
use super::{
    CognitionAuditEvidence, CognitionCommitOutcome, CognitionCommitStatus, CognitionCommitStore,
    CognitionIdempotencyKey,
};
use crate::error::MemoryError;
use crate::space::{MemoryId, MemorySpace};
use crate::vault::{MemoryVault, audit};

/// An immutable completed cognition outcome could not be disclosed safely.
///
/// Lookup absence, idempotency conflicts, corrupt evidence, and backend
/// failures deliberately share [`Unavailable`](Self::Unavailable). Callers
/// cannot use this boundary to probe another subject's jobs or observe
/// adapter-controlled error text. These errors concern historical-result
/// disclosure only; they never grant mutation authority.
#[derive(Debug, Error)]
pub enum CognitionRecoveryError {
    /// A live policy engine is mandatory for immutable-result disclosure.
    #[error("cognition outcome recovery requires a configured policy engine")]
    PolicyUnavailable,
    /// A caller-supplied lookup identity or purpose was not canonical.
    #[error("cognition outcome recovery request is not canonical")]
    InvalidRequest,
    /// No outcome can be disclosed for this authorized request.
    #[error("completed cognition outcome is unavailable")]
    Unavailable,
}

impl<S: CognitionCommitStore> MemoryVault<S> {
    /// Recover an already-completed cognition result after response loss.
    ///
    /// This historical path takes only the exact job id and TypeSec canonical
    /// proposal digest. It neither reconstructs nor persists the potentially
    /// plaintext-bearing proposal, and it never reapplies the mutation.
    /// Unlike [`apply_cognition`](Self::apply_cognition), recovery does not
    /// re-run LakeCat/TypeDID mutation-authority verification: the committed,
    /// plaintext-free audit is historical evidence. A current `CanWrite`
    /// capability and configured policy still authorize disclosure under the
    /// complete request context before the store is queried.
    pub fn recover_cognition_outcome(
        &self,
        space: &MemorySpace,
        capability: &Capability<CanWrite, MemorySpace>,
        job_id: &str,
        proposal_digest: &str,
        context: &RequestContext,
    ) -> Result<CognitionCommitOutcome, MemoryError> {
        if !self.has_policy() {
            return Err(CognitionRecoveryError::PolicyUnavailable.into());
        }
        let purpose = validate_request(space, capability, job_id, proposal_digest, context)?;
        self.authorize(space, capability, context)?;

        let key = CognitionIdempotencyKey {
            space_id: space.resource_id().to_owned(),
            job_id: job_id.to_owned(),
        };
        let outcome = match self.store().recover_cognition(&key, proposal_digest) {
            Ok(Some(outcome)) => outcome,
            Ok(None) | Err(_) => return Err(CognitionRecoveryError::Unavailable.into()),
        };
        validate_outcome(
            &outcome,
            space,
            capability,
            job_id,
            proposal_digest,
            purpose,
        )
        .map_err(|()| MemoryError::from(CognitionRecoveryError::Unavailable))?;

        audit(
            "memory:cognition_recover",
            capability.subject(),
            space,
            &format!("affected={}", outcome.affected_ids.len()),
        );
        Ok(outcome)
    }
}

fn validate_request<'a>(
    space: &MemorySpace,
    capability: &Capability<CanWrite, MemorySpace>,
    job_id: &str,
    proposal_digest: &str,
    context: &'a RequestContext,
) -> Result<&'a str, CognitionRecoveryError> {
    let purpose = context
        .purpose
        .as_deref()
        .ok_or(CognitionRecoveryError::InvalidRequest)?;
    if !is_canonical_text(space.resource_id())
        || !is_canonical_text(capability.subject().as_str())
        || !is_canonical_text(job_id)
        || !is_canonical_sha256(proposal_digest)
        || !is_canonical_text(purpose)
    {
        return Err(CognitionRecoveryError::InvalidRequest);
    }
    Ok(purpose)
}

fn validate_outcome(
    outcome: &CognitionCommitOutcome,
    space: &MemorySpace,
    capability: &Capability<CanWrite, MemorySpace>,
    job_id: &str,
    proposal_digest: &str,
    purpose: &str,
) -> Result<(), ()> {
    let audit = &outcome.audit;
    if outcome.status != CognitionCommitStatus::AlreadyApplied
        || audit.operation_id != job_id
        || audit.space_id != space.resource_id()
        || audit.proposal_digest != proposal_digest
        || audit.subject != capability.subject().as_str()
        || audit.purpose != purpose
        || outcome.affected_ids != audit.affected_ids
        || !canonical_affected_ids(&outcome.affected_ids)
        || !canonical_outcome_identity(outcome)
        || !canonical_audit(audit)
        || outcome.committed_at < audit.prepared_at
    {
        return Err(());
    }
    Ok(())
}

fn canonical_outcome_identity(outcome: &CognitionCommitOutcome) -> bool {
    is_canonical_text(&outcome.backend_commit_hash)
        && is_canonical_text(&outcome.prior_version)
        && is_canonical_text(&outcome.resulting_version)
        && outcome.prior_version != outcome.resulting_version
}

fn canonical_audit(audit: &CognitionAuditEvidence) -> bool {
    is_canonical_text(&audit.policy_decision_id)
        && [
            audit.proposal_digest.as_str(),
            audit.binding_digest.as_str(),
            audit.source_manifest_digest.as_str(),
            audit.typedid_request_digest.as_str(),
            audit.governed_scan_digest.as_str(),
            audit.authorization_receipt_digest.as_str(),
            audit.evidence_digest.as_str(),
        ]
        .into_iter()
        .all(is_canonical_sha256)
}

fn canonical_affected_ids(ids: &[MemoryId]) -> bool {
    !ids.is_empty()
        && ids.iter().all(|id| is_canonical_text(id.as_str()))
        && ids.windows(2).all(|pair| pair[0] < pair[1])
}
