//! Governed, transactional application of inert cognition proposals.
//!
//! This module owns backend-neutral authority bindings and the no-fallback
//! transaction seam. Cognition engines remain untrusted proposal producers;
//! only [`crate::MemoryVault::apply_cognition`] can turn their output into
//! memory mutations.

mod apply;
mod canonical;
mod digest;
mod identity;
mod input;
mod limits;
mod outcome;
mod prepare;
mod prepared;
mod recovery;
mod source_scope;
mod types;
mod validate;

pub use input::AuthorizedCognitionInput;
pub use limits::{
    CognitionSourceBudget, MAX_COGNITION_ALGORITHM_BYTES, MAX_COGNITION_EVIDENCE_ITEMS,
    MAX_COGNITION_IDENTITY_BYTES, MAX_COGNITION_MUTATIONS, MAX_COGNITION_PROJECTION_FIELDS,
    MAX_COGNITION_PROPOSAL_BYTES, MAX_COGNITION_SOURCE_BYTES, MAX_COGNITION_SOURCE_COUNT,
};
pub use prepared::PreparedCognitionCommit;
pub use recovery::CognitionRecoveryError;
pub use types::{
    CognitionApplyError, CognitionAuditEvidence, CognitionAuthorityError,
    CognitionAuthorityEvidence, CognitionAuthorityVerifier, CognitionBinding, CognitionCommitError,
    CognitionCommitOutcome, CognitionCommitStatus, CognitionCommitStore, CognitionIdempotencyKey,
    CognitionSourceManifest, CognitionSourcePrecondition,
};

impl crate::CognitionProposal {
    /// Decode one untrusted JSON proposal behind the fixed raw-body budget.
    ///
    /// Direct serde deserialization remains available for already-bounded,
    /// trusted persistence formats. Network and model-produced bytes must use
    /// this entry point so an oversized document is rejected before parsing.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, CognitionApplyError> {
        if bytes.len() > MAX_COGNITION_PROPOSAL_BYTES {
            return Err(CognitionApplyError::LimitExceeded("proposal bytes"));
        }
        let proposal: Self = serde_json::from_slice(bytes)
            .map_err(|_| CognitionApplyError::Serialization("invalid proposal JSON".to_owned()))?;
        validate::validate_proposal_shape(&proposal)?;
        if let Some(binding) = &proposal.binding {
            binding.validate()?;
        }
        Ok(proposal)
    }

    /// Domain-separated canonical digest used for durable proposal identity.
    ///
    /// Projection order is normalized and observational `created_at` metadata
    /// is excluded, so a later worker retry of the same governed mutation has
    /// the same identity without reimplementing TypeSec internals.
    pub fn canonical_digest(&self) -> Result<String, CognitionApplyError> {
        validate::validate_proposal_shape(self)?;
        if let Some(binding) = &self.binding {
            binding.validate()?;
        }
        digest::proposal_digest(self)
    }
}

impl CognitionBinding {
    /// Domain-separated canonical digest of governed authority evidence.
    pub fn canonical_digest(&self) -> Result<String, CognitionApplyError> {
        self.validate()?;
        digest::binding_digest(self)
    }
}

#[cfg(test)]
mod tests;
